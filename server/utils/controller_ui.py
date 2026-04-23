#!/usr/bin/env python3
"""
Hydrangea C2 Controller — terminal UI
Single UI class + standalone display functions. No external dependencies.
"""

import json
import re as _re
import shutil
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional


# ── helpers ───────────────────────────────────────────────────────────────────

def _isatty() -> bool:
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


_ANSI_RE = _re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def human_size(n: Any) -> str:
    try:
        n = int(n)
    except Exception:
        return str(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024.0:
            return f"{n:.0f} {unit}"
        n /= 1024.0
    return f"{n:.0f} PB"


def human_time(epoch: Any) -> str:
    try:
        return datetime.fromtimestamp(int(epoch)).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "-"


# ── UI class ──────────────────────────────────────────────────────────────────

class UI:
    """
    All terminal primitives for the Hydrangea controller.
    Instantiate once and pass around; use standalone print_* functions for data.
    """

    _COLORS = {
        "reset":   "\x1b[0m",
        "dim":     "\x1b[2m",
        "bold":    "\x1b[1m",
        "red":     "\x1b[31m",
        "green":   "\x1b[32m",
        "yellow":  "\x1b[33m",
        "blue":    "\x1b[34m",
        "magenta": "\x1b[35m",
        "cyan":    "\x1b[36m",
        "gray":    "\x1b[90m",
    }

    def __init__(
        self,
        use_color: bool = True,
        show_banner: bool = True,
        quiet: bool = False,
    ):
        self.use_color = use_color and _isatty()
        self.show_banner_flag = show_banner
        self.quiet = quiet

    # ── colour primitive ──────────────────────────────────────────────────────

    def c(self, s: Any, color: str) -> str:
        if not self.use_color:
            return str(s)
        return f"{self._COLORS.get(color, '')}{s}{self._COLORS['reset']}"

    # ── tags ──────────────────────────────────────────────────────────────────

    @property
    def TAG_OK(self) -> str:
        return self.c("[+]", "green")

    @property
    def TAG_ERR(self) -> str:
        return self.c("[!]", "red")

    @property
    def TAG_INF(self) -> str:
        return self.c("[*]", "cyan")

    @property
    def TAG_QUE(self) -> str:
        return self.c("[~]", "yellow")

    # ── layout ────────────────────────────────────────────────────────────────

    def rule(self, label: str = "") -> None:
        width = shutil.get_terminal_size((80, 20)).columns
        if label:
            inner = f" {label} "
            dashes = max(0, width - len(inner) - 2)
            print(self.c(f"-- {inner}" + "-" * dashes, "gray"))
        else:
            print(self.c("-" * width, "gray"))

    def hr(self) -> None:
        self.rule()

    def kv(self, key: str, value: Any, key_color: str = "blue") -> None:
        """Print a key-value row with aligned columns."""
        k = str(key)
        pad = " " * max(0, 16 - len(k))
        print(f"  {self.c(k, key_color)}{pad}  {value}")

    def headline(self, text: str) -> None:
        print(self.c(str(text), "bold"))

    def info(self, text: str) -> None:
        print(f"{self.TAG_INF} {text}")

    def success(self, text: str) -> None:
        print(f"{self.TAG_OK} {text}")

    def error(self, text: str) -> None:
        print(f"{self.TAG_ERR} {text}")

    def warning(self, text: str) -> None:
        print(f"{self.TAG_QUE} {text}")

    # ── banner / welcome / goodbye ────────────────────────────────────────────

    def banner(self, version: str) -> None:
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
"""
        print(self.c(art, "magenta"))

    def welcome(self, version: str, host: str, port: int) -> None:
        self.banner(version)
        if self.quiet:
            return
        self.rule()
        self.kv("Version", f"v{version}")
        self.kv("Server",  f"{host}:{port}")
        self.kv("Started", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.rule()
        print(f"\n  Type {self.c('help', 'cyan')} for available commands.\n")

    def goodbye(self, command_count: int, session_start: datetime) -> None:
        duration = int((datetime.now() - session_start).total_seconds())
        print(
            f"\n{self.c(f'Session closed  —  {command_count} commands  {duration}s', 'dim')}\n"
        )

    # ── REPL prompt ───────────────────────────────────────────────────────────

    def prompt(self, current_client: Optional[str]) -> str:
        """Display the prompt and return the stripped input line."""
        if current_client:
            p = (
                self.c("[", "gray")
                + "hydrangea"
                + self.c(" | ", "gray")
                + self.c(current_client, "cyan")
                + self.c("]", "gray")
                + " "
                + self.c(">>", "bold")
                + " "
            )
        else:
            p = (
                self.c("[", "gray")
                + "hydrangea"
                + self.c("]", "gray")
                + " "
                + self.c(">>", "bold")
                + " "
            )
        return input(p).strip()

    # ── REPL helpers ──────────────────────────────────────────────────────────

    def show_no_client_error(self) -> None:
        self.error("No client specified.")
        print(
            f"  {self.c('Hint:', 'dim')} "
            f"use {self.c('use <id>', 'cyan')} or pass {self.c('--client <id>', 'cyan')}"
        )

    def show_client_switch(self, prev: Optional[str], new: str) -> None:
        if prev and prev != new:
            print(
                f"{self.TAG_INF} {self.c(prev, 'dim')} -> {self.c(new, 'cyan')}"
            )
        else:
            print(f"{self.TAG_OK} Active client: {self.c(new, 'cyan')}")

    def show_client_clear(self, prev: Optional[str]) -> None:
        if prev:
            print(f"{self.TAG_INF} Cleared: {self.c(prev, 'dim')}")
        else:
            print(f"{self.TAG_INF} No active client was set.")

    def help_menu(self, sub_map: Dict[str, Any]) -> None:
        self.rule(" help ")
        categories: List[tuple] = [
            ("Client",  ["clients", "use", "unuse", "ping", "session"]),
            ("Files",   ["list", "pull", "push"]),
            ("Exec",    ["exec", "reverse-shell", "port-forward"]),
            ("Build",   ["build-client"]),
            ("Server",  ["server-status", "local"]),
        ]
        descs: Dict[str, str] = {
            "clients":       "List connected clients",
            "use":           "Set active client context",
            "unuse":         "Clear active client context",
            "ping":          "Ping a client",
            "session":       "Get session info from client",
            "list":          "List directory on client",
            "pull":          "Pull file from client to server",
            "push":          "Push local file to client",
            "exec":          "Run a command on client",
            "reverse-shell": "Start a reverse shell",
            "port-forward":  "Upload and run Ligolo agent",
            "build-client":  "Compile Go clients",
            "server-status": "Server health status",
            "local":         "Run a local command",
        }
        for cat, cmds in categories:
            print(f"\n  {self.c(cat, 'bold')}")
            for cmd in cmds:
                desc = descs.get(cmd, "")
                pad = " " * max(0, 18 - len(cmd))
                print(
                    f"    {self.c(cmd, 'cyan')}{pad}  {self.c(desc, 'dim')}"
                )
        print(
            f"\n    {self.c('exit / quit', 'cyan')}"
            + " " * max(0, 18 - len("exit / quit"))
            + f"  {self.c('Leave the console', 'dim')}"
        )
        print(f"\n  {self.c('help <command>', 'dim')} for detailed usage.")
        self.rule()

    def command_help(self, cmd: str, subparser: Any) -> None:
        self.rule(f" help: {cmd} ")
        subparser.print_help()
        self.rule()

    def build_summary(self, ns: Any) -> None:
        self.rule(" build ")
        self.kv("Server",  f"{ns.server_host}:{ns.server_port}")
        self.kv("Client ID", ns.client_id or "(auto / hostname)")
        self.kv("Output",  ns.out)
        os_targets = ns.os or ["linux", "windows"]
        self.kv("Targets", f"{', '.join(os_targets)} / {ns.arch}")
        self.rule()


# ── standalone display functions ──────────────────────────────────────────────

def print_error(ui: UI, resp: dict) -> None:
    err = resp.get("error") or resp.get("message") or resp.get("type", "unknown")
    detail = {k: v for k, v in resp.items() if k not in ("type", "size", "error")}
    msg = str(err)
    if detail:
        msg += f"  {ui.c(str(detail), 'dim')}"
    print(f"{ui.TAG_ERR} {msg}")


def print_queued(ui: UI, resp: dict) -> None:
    order = resp.get("order", "?")
    extras = []
    for k in ("path", "src", "save_as", "dest", "bytes", "filename", "controller_addr"):
        if k in resp:
            extras.append(f"{k}={resp[k]}")
    tail = "  " + "  ".join(extras) if extras else ""
    print(f"{ui.TAG_QUE} queued: {ui.c(order, 'bold')}{ui.c(tail, 'dim')}")


def print_clients(ui: UI, clients: List[str]) -> None:
    ui.rule(" clients ")
    if not clients:
        print(f"  {ui.c('No clients connected.', 'dim')}")
    else:
        count_str = ui.c(str(len(clients)), "bold")
        print(f"  {count_str} connected\n")
        for cid in clients:
            print(f"  {ui.TAG_OK}  {ui.c(cid, 'cyan')}")
    ui.rule()


def print_exec(ui: UI, target: str, resp: dict, payload: bytes) -> None:
    if resp.get("type") != "RESULT_EXEC":
        print_error(ui, resp)
        return
    try:
        result = json.loads(payload.decode("utf-8")) if payload else {}
    except Exception:
        result = {}

    rc = result.get("rc")
    stdout = (result.get("stdout") or "").rstrip("\n")
    stderr = (result.get("stderr") or "").rstrip("\n")
    rc_tag = ui.TAG_OK if rc == 0 else ui.TAG_ERR

    ui.rule(f" exec: {target} ")
    print(f"  rc  {rc_tag} {rc}")
    if stderr:
        ui.rule(" stderr ")
        print(stderr)
    if stdout or not stderr:
        ui.rule(" stdout ")
        print(stdout if stdout else ui.c("(no output)", "dim"))
    ui.rule()


def print_list(ui: UI, path: str, resp: dict, payload: bytes) -> None:
    if resp.get("type") == "QUEUED":
        print_queued(ui, resp)
        return
    if resp.get("type") != "RESULT_LIST_DIR":
        print_error(ui, resp)
        return
    try:
        entries = json.loads(payload.decode("utf-8")) if payload else []
    except Exception:
        entries = []

    ui.rule(f" {path} ")
    if not entries:
        print(f"  {ui.c('(empty)', 'dim')}")
        ui.rule()
        return

    name_w = min(50, max(10, max(len(e.get("name", "")) for e in entries)))
    # Header — plain text so width is correct, then dim the whole line
    hdr = f"  {'TYPE':<6}  {'NAME':<{name_w}}  {'SIZE':>8}  MODIFIED"
    print(ui.c(hdr, "dim"))
    print(ui.c(f"  {'-' * (6 + name_w + 22)}", "dim"))

    for e in entries:
        is_dir = e.get("is_dir", False)
        tp_raw = "DIR" if is_dir else "FIL"
        tp = ui.c(tp_raw, "cyan") if is_dir else ui.c(tp_raw, "dim")
        nm = e.get("name", "")
        nm_display = ui.c(nm, "bold") if is_dir else nm
        sz = human_size(e.get("bytes", 0))
        mt = human_time(e.get("mtime", 0))
        # Pad name based on raw length to stay column-aligned
        nm_pad = " " * max(0, name_w - len(nm))
        print(f"  {tp}  {nm_display}{nm_pad}  {sz:>8}  {mt}")
    ui.rule()


def print_session(ui: UI, target: str, resp: dict, payload: bytes) -> None:
    if resp.get("type") != "RESULT_SESSION_INFO":
        print_error(ui, resp)
        return
    try:
        info = json.loads(payload.decode("utf-8")) if payload else {}
    except Exception:
        info = {}

    ui.rule(f" session: {target} ")
    ui.kv("hostname",  info.get("hostname", "?"))
    ui.kv("system",    f"{info.get('system', '?')} / {info.get('machine', '?')}")
    ui.kv("user",      f"{info.get('user', '?')}  (pid {info.get('pid', '?')})")
    ui.kv("cwd",       info.get("cwd", "?"))
    ui.kv("root",      info.get("root", "?"))
    ui.kv("version",   info.get("version", "?"))
    ui.kv("exe",       info.get("executable", "?"))
    ui.rule()


def print_server_health(ui: UI, resp: dict) -> None:
    if resp.get("type") != "HEALTH_STATUS":
        print_error(ui, resp)
        return
    ui.rule(" server health ")
    status = resp.get("status", "?")
    agents = resp.get("connected_agents", 0)
    status_col = "green" if status == "running" else "red"
    ui.kv("status",  ui.c(status, status_col))
    ui.kv("agents",  str(agents))
    logs = resp.get("recent_logs", [])
    if logs:
        ui.rule(" recent logs ")
        for entry in logs[-5:]:
            print(f"  {ui.c(str(entry), 'dim')}")
    ui.rule()
