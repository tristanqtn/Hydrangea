#!/usr/bin/env python3
"""Hydrangea C2 Controller — terminal UI (powered by Rich + prompt_toolkit)."""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style
from rich import box
from rich.console import Console
from rich.table import Table
from rich.theme import Theme

# ---------------------------------------------------------------------------
# Controller banner (ASCII art — no Rich markup, printed verbatim)
# ---------------------------------------------------------------------------

_CTL_ART = r"""
   ▄█    █▄    ▄██   ▄   ████████▄     ▄████████    ▄████████ ███▄▄▄▄      ▄██████▄     ▄████████    ▄████████
  ███    ███   ███   ██▄ ███   ▀███   ███    ███   ███    ███ ███▀▀▀██▄   ███    ███   ███    ███   ███    ███
  ███    ███   ███▄▄▄███ ███    ███   ███    ███   ███    ███ ███   ███   ███    █▀    ███    █▀    ███    ███
 ▄███▄▄▄▄███▄▄ ▀▀▀▀▀▀███ ███    ███  ▄███▄▄▄▄██▀   ███    ███ ███   ███  ▄███         ▄███▄▄▄       ███    ███
▀▀███▀▀▀▀███▀  ▄██   ███ ███    ███ ▀▀███▀▀▀▀▀   ▀███████████ ███   ███ ▀▀███ ████▄  ▀▀███▀▀▀     ▀███████████
  ███    ███   ███   ███ ███    ███ ▀███████████   ███    ███ ███   ███   ███    ███   ███    █▄    ███    ███
  ███    ███   ███   ███ ███   ▄███   ███    ███   ███    ███ ███   ███   ███    ███   ███    ███   ███    ███
  ███    █▀     ▀█████▀  ████████▀    ███    ███   ███    █▀   ▀█   █▀    ████████▀    ██████████   ███    █▀
                                      ███    ███

              Hydrangea C2  •  Controller
"""

# ---------------------------------------------------------------------------
# prompt_toolkit style (input line only — output is handled by Rich)
# ---------------------------------------------------------------------------

_PT_STYLE = Style.from_dict(
    {
        "app":    "#666666",
        "client": "#00aaff bold",
        "arrow":  "#444444",
        "ask":    "#888888",
    }
)

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------

_THEME = Theme(
    {
        "ok":     "bold green",
        "err":    "bold red",
        "warn":   "yellow",
        "info":   "cyan",
        "muted":  "bright_black",
        "accent": "steel_blue1",
        "hi":     "bold",
    }
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def human_size(n: Any) -> str:
    try:
        n = int(n)
    except (ValueError, TypeError):
        return str(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def human_time(epoch: Any) -> str:
    try:
        return datetime.fromtimestamp(int(epoch)).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "—"


# ---------------------------------------------------------------------------
# UI class
# ---------------------------------------------------------------------------


class UI:
    """Single console wrapper — one instance per controller session."""

    def __init__(
        self,
        use_color: bool = True,
        show_banner: bool = True,
        quiet: bool = False,
        commands: Optional[List[str]] = None,
    ) -> None:
        self._con = Console(theme=_THEME, highlight=False, no_color=not use_color)
        self._show_banner = show_banner
        self.quiet = quiet
        hist_path = os.path.expanduser("~/.hydrangea_history")
        self._session: PromptSession = PromptSession(
            history=FileHistory(hist_path),
            auto_suggest=AutoSuggestFromHistory(),
            completer=WordCompleter(commands or [], sentence=True),
            complete_while_typing=False,
            style=_PT_STYLE,
        )

    # -- colour shortcut (used by go_builder and ctl call-sites) -------------

    def c(self, s: Any, style: str) -> str:
        """Wrap *s* in a Rich markup span.  Maps old ANSI names to Rich styles."""
        _MAP = {"gray": "muted", "magenta": "magenta", "dim": "muted"}
        style = _MAP.get(style, style)
        return f"[{style}]{s}[/{style}]"

    # -- status tags ----------------------------------------------------------

    @property
    def TAG_OK(self) -> str:
        return "[ok]✓[/ok]"

    @property
    def TAG_ERR(self) -> str:
        return "[err]✗[/err]"

    @property
    def TAG_INF(self) -> str:
        return "[info]·[/info]"

    @property
    def TAG_QUE(self) -> str:
        return "[warn]~[/warn]"

    # -- layout primitives ----------------------------------------------------

    def rule(self, label: str = "") -> None:
        self._con.rule(label, style="muted")

    def hr(self) -> None:
        self.rule()

    def kv(self, key: str, value: Any, key_color: str = "accent") -> None:
        self._con.print(f"  [{key_color}]{key:<16}[/{key_color}]  {value}")

    def headline(self, text: str) -> None:
        self._con.print(f"[hi]{text}[/hi]")

    def info(self, text: str) -> None:
        self._con.print(f"{self.TAG_INF} {text}")

    def success(self, text: str) -> None:
        self._con.print(f"{self.TAG_OK} {text}")

    def error(self, text: str) -> None:
        self._con.print(f"{self.TAG_ERR} [err]{text}[/err]")

    def warning(self, text: str) -> None:
        self._con.print(f"{self.TAG_QUE} [warn]{text}[/warn]")

    # -- welcome / goodbye ----------------------------------------------------

    def welcome(self, version: str, host: str, port: int) -> None:
        if self.quiet:
            return
        self._con.print()
        if self._show_banner:
            self._con.print(_CTL_ART, markup=False, highlight=False)
        self._con.rule(style="muted")
        self._con.print(f"  [accent]version[/]   v{version}")
        self._con.print(f"  [accent]server[/]    {host}:{port}")
        self._con.print(
            f"  [accent]started[/]   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self._con.rule(style="muted")
        self._con.print(f"\n  Type [info]help[/info] for available commands.\n")

    def goodbye(self, command_count: int, session_start: datetime) -> None:
        duration = int((datetime.now() - session_start).total_seconds())
        self._con.print(
            f"\n[muted]session closed · {command_count} commands · {duration}s[/]\n"
        )

    # -- REPL prompt ----------------------------------------------------------

    async def prompt(self, current_client: Optional[str]) -> str:
        if current_client:
            msg = HTML(f"<app>hydrangea</app> <client>{current_client}</client> <arrow> ❯ </arrow>")
        else:
            msg = HTML("<app>hydrangea</app><arrow> ❯ </arrow>")
        return (await self._session.prompt_async(msg)).strip()

    async def confirm_exit(self) -> bool:
        """Ask the user to confirm before exiting. Returns True if confirmed."""
        try:
            answer = (
                await self._session.prompt_async(HTML("<ask>  exit? [y/N] </ask>"))
            ).strip().lower()
            return answer in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return True

    # -- REPL helpers ---------------------------------------------------------

    def show_no_client_error(self) -> None:
        self.error("No client selected — run [info]use <id>[/info] first.")

    def show_client_switch(self, prev: Optional[str], new: str) -> None:
        if prev and prev != new:
            self._con.print(f"  [muted]{prev}[/]  →  [info]{new}[/info]")
        else:
            self._con.print(f"{self.TAG_OK} active: [info]{new}[/info]")

    def show_client_clear(self, prev: Optional[str]) -> None:
        if prev:
            self._con.print(f"{self.TAG_INF} cleared [muted]{prev}[/]")
        else:
            self._con.print(f"{self.TAG_INF} no active client was set")

    def help_menu(self, sub_map: Dict[str, Any]) -> None:
        categories: List[tuple] = [
            ("Client", ["clients", "use", "unuse", "ping", "session"]),
            ("Files",  ["list", "pull", "push"]),
            ("Exec",   ["exec", "reverse-shell", "port-forward"]),
            ("Build",  ["build-client"]),
            ("Server", ["server-status", "server-config", "server-exec",
                        "add-agent-token", "add-agent-port", "local"]),
        ]
        descs: Dict[str, str] = {
            "clients":         "List connected clients",
            "use":             "Set active client context",
            "unuse":           "Clear active client context",
            "ping":            "Ping a client",
            "session":         "Get session info from client",
            "list":            "List directory on client",
            "pull":            "Pull file from client to server",
            "push":            "Push local file to client",
            "exec":            "Run a command on client",
            "reverse-shell":   "Start a reverse shell",
            "port-forward":    "Upload and run Ligolo agent",
            "build-client":    "Compile Go clients",
            "server-status":   "Server health and recent logs",
            "server-config":   "Show port / token configuration",
            "server-exec":     "Run a command on the server host",
            "add-agent-token": "Register a new agent token (global or port-bound)",
            "add-agent-port":  "Open a new agent listening port at runtime",
            "local":           "Run a command locally (controller machine)",
        }
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column(style="accent", no_wrap=True)
        t.add_column(style="muted")

        for cat, cmds in categories:
            t.add_row(f"[hi]{cat}[/hi]", "")
            for cmd in cmds:
                t.add_row(f"  [info]{cmd}[/info]", descs.get(cmd, ""))
            t.add_row("", "")

        t.add_row("[info]exit / quit[/info]", "Leave the console")

        self._con.print()
        self._con.print(t)
        self._con.print("  [muted]help <command>[/muted] for detailed usage.\n")

    def command_help(self, cmd: str, subparser: Any) -> None:
        self.rule(cmd)
        subparser.print_help()
        self._con.print()

    def build_summary(self, ns: Any) -> None:
        self.rule("build")
        self.kv("server",    f"{ns.server_host}:{ns.server_port}")
        self.kv("client-id", ns.client_id or "[muted](auto / hostname)[/muted]")
        self.kv("output",    ns.out)
        os_targets = ns.os or ["linux", "windows"]
        self.kv("targets",   f"{', '.join(os_targets)} / {ns.arch}")
        self._con.print()


# ---------------------------------------------------------------------------
# Standalone display functions
# ---------------------------------------------------------------------------


def print_error(ui: UI, resp: dict) -> None:
    err = resp.get("error") or resp.get("message") or resp.get("type", "unknown")
    detail = {k: v for k, v in resp.items() if k not in ("type", "size", "error")}
    msg = str(err)
    if detail:
        ui._con.print(f"{ui.TAG_ERR} [err]{msg}[/err]  [muted]{detail}[/muted]")
    else:
        ui._con.print(f"{ui.TAG_ERR} [err]{msg}[/err]")


def print_queued(ui: UI, resp: dict) -> None:
    order = resp.get("order", "?")
    extras = []
    for k in ("path", "src", "save_as", "dest", "bytes", "filename", "controller_addr"):
        if k in resp:
            extras.append(f"{k}={resp[k]}")
    tail = "  " + "  ".join(extras) if extras else ""
    ui._con.print(f"{ui.TAG_QUE} queued [hi]{order}[/hi][muted]{tail}[/muted]")


def print_clients(ui: UI, clients: List[Any]) -> None:
    if not clients:
        ui._con.print("\n  [muted]no clients connected[/]\n")
        return
    t = Table(box=box.SIMPLE, show_header=True, header_style="muted", padding=(0, 1))
    t.add_column("id", style="info")
    t.add_column("srv port", style="accent", no_wrap=True)
    t.add_column("beacon addr", style="muted", no_wrap=True)
    t.add_column("status")
    for entry in clients:
        if isinstance(entry, dict):
            cid = entry.get("id", "?")
            port = f":{entry.get('port', '?')}"
            peer = entry.get("peer", "?")
        else:
            cid, port, peer = str(entry), "?", "?"
        t.add_row(cid, port, peer, "[ok]● online[/ok]")
    ui._con.print()
    ui._con.print(t)


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
    rc_style = "ok" if rc == 0 else "err"

    ui.rule(f"exec · {target}")
    ui._con.print(f"  rc  [{rc_style}]{rc}[/{rc_style}]")
    if stderr:
        ui._con.rule("stderr", style="muted")
        ui._con.print(f"[muted]{stderr}[/muted]")
    if stdout or not stderr:
        ui._con.rule("stdout", style="muted")
        ui._con.print(stdout if stdout else "[muted](no output)[/muted]")
    ui._con.rule(style="muted")


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

    ui.rule(path)
    if not entries:
        ui._con.print("  [muted](empty)[/muted]")
        return

    t = Table(box=box.SIMPLE, show_header=True, header_style="muted", padding=(0, 1))
    t.add_column("", width=2, no_wrap=True)
    t.add_column("name")
    t.add_column("size", justify="right", style="muted", no_wrap=True)
    t.add_column("modified", style="muted", no_wrap=True)

    for e in entries:
        is_dir = e.get("is_dir", False)
        icon = "[bold blue]▸[/]" if is_dir else " "
        nm = e.get("name", "")
        name_text = f"[bold blue]{nm}[/]" if is_dir else nm
        sz = "—" if is_dir else human_size(e.get("bytes", 0))
        mt = human_time(e.get("mtime", 0))
        t.add_row(icon, name_text, sz, mt)

    ui._con.print(t)


def print_session(ui: UI, target: str, resp: dict, payload: bytes) -> None:
    if resp.get("type") != "RESULT_SESSION_INFO":
        print_error(ui, resp)
        return
    try:
        info = json.loads(payload.decode("utf-8")) if payload else {}
    except Exception:
        info = {}

    ui.rule(f"session · {target}")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="accent", no_wrap=True)
    t.add_column()
    rows = [
        ("hostname", info.get("hostname", "?")),
        ("system",   f"{info.get('system', '?')} {info.get('machine', '?')}"),
        ("user",     f"{info.get('user', '?')}  [muted]pid {info.get('pid', '?')}[/muted]"),
        ("cwd",      info.get("cwd", "?")),
        ("root",     info.get("root", "?")),
        ("runtime",  info.get("version", "?")),
        ("exe",      info.get("executable", "?")),
    ]
    for k, v in rows:
        t.add_row(k, str(v))
    ui._con.print(t)


def print_server_health(ui: UI, resp: dict) -> None:
    if resp.get("type") != "HEALTH_STATUS":
        print_error(ui, resp)
        return

    status = resp.get("status", "?")
    agents = resp.get("connected_agents", 0)
    status_style = "ok" if status == "running" else "err"

    ui.rule("server")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="accent", no_wrap=True)
    t.add_column()
    t.add_row("status", f"[{status_style}]{status}[/{status_style}]")
    t.add_row("agents", str(agents))
    ui._con.print(t)

    logs = resp.get("recent_logs", [])
    if logs:
        ui.rule("recent logs")
        for entry in logs[-5:]:
            ui._con.print(f"  [muted]{entry}[/muted]")
    ui._con.print()


def print_server_config(ui: UI, resp: dict) -> None:
    if resp.get("type") != "SERVER_CONFIG":
        print_error(ui, resp)
        return

    ui.rule("server config")

    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="accent", no_wrap=True)
    t.add_column()
    t.add_row("admin port", f":{resp.get('admin_port', '?')}  [muted](controller only)[/muted]")

    agent_ports = resp.get("agent_ports", [])
    bound_ports = set(int(p) for p in resp.get("port_bindings", {}).keys())
    port_cells = []
    for p in agent_ports:
        marker = "  [muted](exclusive)[/muted]" if p in bound_ports else ""
        port_cells.append(f":{p}{marker}")
    t.add_row("agent ports", "\n".join(port_cells) if port_cells else "[muted](none)[/muted]")

    global_tokens = resp.get("global_tokens", [])
    t.add_row(
        "global tokens",
        "  ".join(f"[info]{tok}[/info]" for tok in global_tokens)
        if global_tokens else "[muted](none)[/muted]",
    )
    ui._con.print(t)

    bindings = resp.get("port_bindings", {})
    if bindings:
        ui.rule("port-bound tokens")
        bt = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        bt.add_column(style="cyan", no_wrap=True)
        bt.add_column()
        for port_str, tokens in sorted(bindings.items(), key=lambda x: int(x[0])):
            bt.add_row(
                f":{port_str}",
                "  ".join(f"[info]{tok}[/info]" for tok in tokens),
            )
        ui._con.print(bt)

    ui._con.print()
