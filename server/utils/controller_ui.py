#!/usr/bin/env python3
"""
Enhanced UI helper for Hydrangea C2 Controller
Provides stylish interface components and improved user experience
"""

import os
import time
import json
import sys
import shutil
import re as _re
from typing import Optional, List, Dict, Any
from datetime import datetime

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

    def banner(self, version):
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

              Hydrangea C2 Controller
"""
        print(self.c(art, "magenta"))
        print(self.c(f"  V{version} by Tristan @tristanqtn", "magenta"))

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
        
    def info(self, text):
        print(f"{self.TAG_INF} {text}")
        
    def success(self, text):
        print(f"{self.TAG_OK} {text}")
        
    def error(self, text):
        print(f"{self.TAG_ERR} {text}")
        
    def warning(self, text):
        print(f"{self.TAG_QUE} {text}")

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
    ui.rule(" Connected Clients ")
    ui.headline(f"{ui.TAG_OK} Found {len(clients)} active client(s)")
    
    if not clients:
        print(f"  {ui.c('No clients connected', 'dim')}")
        ui.rule()
        return []
        
    print(f"  {ui.c('ID', 'blue'):<20}")
    print(f"  {ui.c('-'*20, 'dim')}")
    for cid in clients:
        print(f"  {ui.c('•', 'green')} {ui.c(cid, 'bold')}")
    ui.rule()
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
    ui.kv("CWD", info.get('cwd', '?'))
    ui.kv("Root base", info.get('root', '?'))
    ui.kv("Platform", info.get('platform', '?'))
    ui.kv("Version", info.get('version', '?'))
    ui.kv("Executable", info.get('executable', '?'))
    ui.rule()




class ControllerUI:
    """Enhanced UI helper for Hydrangea C2 Controller with stylish interface components"""
    
    def __init__(self, ui: UI):
        self.ui = ui
        self.session_start = datetime.now()
        self.command_count = 0
        
    def show_welcome_screen(self, version: str, host: str, port: int):
        """Display an enhanced welcome screen with system info"""
        self.ui.banner(version)
        
        # Connection info panel
        self.ui.rule(" connection info ")
        self.ui.kv("Server", f"{host}:{port}")
        self.ui.kv("Session started", self.session_start.strftime("%Y-%m-%d %H:%M:%S"))
        self.ui.kv("Interface", "Enhanced Controller UI v1.0")
        self.ui.rule()
        
    def show_help_menu(self, commands: List[str], sub_map: Dict[str, Any]):
        """Display an organized help menu with categories"""
        self.ui.rule(" hydrangea c2 controller help ")
        
        # Command descriptions mapping
        command_descriptions = {
            # Client Management
            "clients": "List all connected clients",
            "use": "Set the active client for subsequent commands",
            "unuse": "Clear the active client context",
            "ping": "Send a ping to test client connectivity",
            "session": "Get detailed session info from a client",
            
            # File Operations
            "list": "List directory contents on remote client",
            "pull": "Download a file from client to server",
            "push": "Upload a file from server to client",
            
            # Command Execution
            "exec": "Execute a command on the remote client",
            "reverse-shell": "Start a reverse shell connection",
            
            # Build & Deploy
            "build-client": "Compile Go clients with server configuration",
            
            # Server Operations
            "server-status": "Check server health and connected clients",
            "local": "Run a command on the local server"
        }
        
        # Categorize commands with icons and colors
        categories = [
            ("👥 Client Management", ["clients", "use", "unuse", "ping", "session"], "green"),
            ("📁 File Operations", ["list", "pull", "push"], "blue"),
            ("⚡ Command Execution", ["exec", "reverse-shell"], "yellow"),
            ("🔨 Build & Deploy", ["build-client"], "magenta"),
            ("🖥️ Server Operations", ["server-status", "local"], "cyan")
        ]
        
        for category_name, category_commands, color in categories:
            self.ui.headline(f"{self.ui.c(category_name, color)}")
            for cmd in category_commands:
                if cmd in commands:
                    desc = command_descriptions.get(cmd, "No description available")
                    print(f"  {self.ui.c(f'{cmd:<15}', 'bold')} {self.ui.c(desc, 'dim')}")
            print()
        
        print(f"\n  {self.ui.c('💡 Pro Tips:', 'yellow')}")
        print(f"    {self.ui.c('•', 'dim')} Use {self.ui.c('help <command>', 'cyan')} for detailed command usage")
        print(f"    {self.ui.c('•', 'dim')} Commands without --client use the active client context")
        print(f"    {self.ui.c('•', 'dim')} Type {self.ui.c('quit', 'cyan')} or {self.ui.c('exit', 'cyan')} to leave the console")

        self.ui.rule()
    
    def show_command_help(self, cmd: str, subparser):
        """Display detailed help for a specific command"""
        self.ui.rule(f" help: {cmd} ")
        
        # Add command category and icon
        cmd_icons = {
            "clients": "👥", "use": "🎯", "unuse": "⭕", "ping": "🏓", "session": "📊",
            "list": "📁", "pull": "⬇️", "push": "⬆️",
            "exec": "⚡", "reverse-shell": "🔄",
            "build-client": "🔨",
            "server-status": "🖥️", "local": "💻"
        }
        
        icon = cmd_icons.get(cmd, "🔧")
        print(f"{icon} {self.ui.c(cmd.upper(), 'bold')}")
        
        if subparser.description:
            print(f"{self.ui.c('Description:', 'blue')} {subparser.description}")
            print()
        
        # Show formatted help
        help_text = subparser.format_help()
        
        # Enhance the help text formatting
        lines = help_text.split('\n')
        for line in lines:
            if line.startswith('usage:'):
                print(f"{self.ui.c('Usage:', 'green')} {line[6:].strip()}")
            elif line.strip().startswith('-'):
                # Highlight options
                if line.strip().startswith('--'):
                    parts = line.split(None, 1)
                    option = parts[0] if parts else line
                    desc = parts[1] if len(parts) > 1 else ""
                    print(f"  {self.ui.c(option, 'cyan')} {desc}")
                else:
                    print(f"  {line}")
            elif line.strip() and not line.startswith('  '):
                print(f"{self.ui.c(line.strip(), 'yellow')}")
            else:
                print(line)
        
        self.ui.rule()
    
    def show_status_bar(self, host: str, port: int, current_client: Optional[str], show_stats: bool = True):
        """Display an enhanced status bar with session info"""
        uptime = datetime.now() - self.session_start
        uptime_str = f"{uptime.total_seconds():.0f}s"
        
        left_parts = [
            f"Hydrangea C2",
            f"{host}:{port}",
        ]
        
        if show_stats:
            left_parts.append(f"⏱ {uptime_str}")
            left_parts.append(f"📊 {self.command_count} cmds")
        
        left = " • ".join(left_parts)
        
        client_status = f"client: {self.ui.c(current_client, 'bold')}" if current_client else "client: (none)"
        right = f"🎯 {client_status}    "
        
        self.ui.statusbar(f"\n{left}", right)
    
    def show_command_prompt(self) -> str:
        """Display the command prompt and get user input"""
        prompt = f"  {self.ui.c('>', 'cyan')}{self.ui.c('>', 'cyan')} "
        return input(prompt).strip()
    
    def increment_command_count(self):
        """Track command usage for statistics"""
        self.command_count += 1
    
    def show_client_switch_notification(self, prev_client: Optional[str], new_client: str):
        """Show a stylish notification when switching clients"""
        if prev_client and prev_client != new_client:
            print(f"{self.ui.TAG_INF} Client context switched:")
            print(f"  {self.ui.c('FROM:', 'dim')} {self.ui.c(prev_client, 'yellow')}")
            print(f"  {self.ui.c('TO:', 'dim')}   {self.ui.c(new_client, 'green')}")
        else:
            print(f"{self.ui.TAG_OK} Active client set to {self.ui.c(new_client, 'bold')}")
    
    def show_client_clear_notification(self, cleared_client: Optional[str]):
        """Show notification when clearing active client"""
        if cleared_client:
            print(f"{self.ui.TAG_OK} Cleared active client {self.ui.c(cleared_client, 'bold')}")
        else:
            print(f"{self.ui.TAG_INF} No active client to clear")
    
    def show_error_with_suggestions(self, error_msg: str, suggestions: List[str] = None):
        """Display error with helpful suggestions"""
        print(f"{self.ui.TAG_ERR} {error_msg}")
        if suggestions:
            print(f"{self.ui.c('💡 Suggestions:', 'yellow')}")
            for suggestion in suggestions:
                print(f"  {self.ui.c('•', 'dim')} {suggestion}")
    
    def show_no_client_error(self):
        """Show a helpful error when no client is specified"""
        suggestions = [
            "Set an active client with: use <client_id>",
            "Or specify directly with: --client <client_id>",
            "List available clients with: clients"
        ]
        self.show_error_with_suggestions("No client specified", suggestions)
    
    def show_operation_success(self, operation: str, target: str, details: str = ""):
        """Show a success message for operations"""
        msg = f"{operation} → {self.ui.c(target, 'bold')}"
        if details:
            msg += f" {self.ui.c(f'({details})', 'dim')}"
        print(f"{self.ui.TAG_OK} {msg}")
    
    def show_operation_queued(self, operation: str, target: str, details: str = ""):
        """Show a queued operation message"""
        msg = f"{operation} → {self.ui.c(target, 'bold')}"
        if details:
            msg += f" {self.ui.c(f'({details})', 'dim')}"
        print(f"{self.ui.TAG_QUE} Queued: {msg}")
    
    def show_file_transfer_info(self, action: str, src: str, dest: str, target: str):
        """Display file transfer information in a nice format"""
        self.ui.rule(f" {action} ")
        print(f"{self.ui.c('Source:', 'blue')} {src}")
        print(f"{self.ui.c('Destination:', 'blue')} {dest}")
        print(f"{self.ui.c('Target client:', 'blue')} {self.ui.c(target, 'bold')}")
        
        if action.lower() == "push" and os.path.isfile(src):
            size = human_size(os.path.getsize(src))
            print(f"{self.ui.c('File size:', 'blue')} {size}")
        
        self.ui.rule()
    
    def show_build_summary(self, build_config: Dict[str, Any]):
        """Display build configuration summary"""
        self.ui.rule(" build configuration ")
        self.ui.kv("Server Host", build_config.get("server_host", "N/A"))
        self.ui.kv("Server Port", str(build_config.get("server_port", "N/A")))
        self.ui.kv("Client ID", build_config.get("client_id", "auto-generated"))
        self.ui.kv("Output Directory", build_config.get("out", "./dist"))
        
        # Get OS list with proper type handling
        # Handle OS list with proper defaults matching the build system
        os_list = build_config.get("os")
        
        # If not specified, use default platforms that the build system uses
        if os_list is None:
            os_list = ["linux", "windows"]  # Default platforms
        elif isinstance(os_list, str):
            os_list = [os_list]  # Convert string to list
        elif not isinstance(os_list, list):
            try:
                os_list = list(os_list)
            except:
                os_list = ["linux", "windows"]  # Fallback to defaults
        
        # Ensure all elements are strings
        os_list = [str(os) for os in os_list]
        
        # Get architecture(s)
        arch = build_config.get("arch", "amd64")
        if isinstance(arch, list):
            arch_str = ", ".join(str(a) for a in arch)
        else:
            arch_str = str(arch)
        
        self.ui.kv("Target Platforms", f"{', '.join(os_list)} ({arch_str})")
        self.ui.rule()
    def show_server_health(self, health_data: Dict[str, Any]):
        """Display server health status in an organized way"""
        self.ui.rule(" server health dashboard ")
        
        status = health_data.get("status", "unknown")
        status_color = "green" if status == "healthy" else "red"
        print(f"{self.ui.c('Status:', 'blue')} {self.ui.c(status.upper(), status_color)}")
        
        agents = health_data.get("connected_agents", 0)
        agent_color = "green" if agents > 0 else "yellow"
        print(f"{self.ui.c('Connected Agents:', 'blue')} {self.ui.c(str(agents), agent_color)}")
        
        # Show recent logs if available
        logs = health_data.get("recent_logs", [])
        if logs:
            self.ui.rule(" recent activity ")
            for log_entry in logs[-5:]:  # Show last 5 entries
                print(f"{self.ui.c('•', 'dim')} {log_entry}")
        
        self.ui.rule()
    
    def show_session_summary(self, target: str, session_info: Dict[str, Any]):
        """Display session information in an enhanced format"""
        self.ui.rule(" client session info ")
        print(f"{self.ui.c('Client:', 'blue')} {self.ui.c(target, 'bold')}")
        
        # System information
        hostname = session_info.get('hostname', '?')
        system = session_info.get('system', '?')
        release = session_info.get('release', '?')
        machine = session_info.get('machine', '?')
        
        print(f"{self.ui.c('System:', 'blue')} {hostname} ({system} {release}, {machine})")
        print(f"{self.ui.c('User/PID:', 'blue')} {session_info.get('user', '?')} / {session_info.get('pid', '?')}")
        print(f"{self.ui.c('Working Dir:', 'blue')} {session_info.get('cwd', '?')}")
        print(f"{self.ui.c('Root Path:', 'blue')} {session_info.get('root', '?')}")
        
        # Runtime information  
        print(f"{self.ui.c('Platform:', 'blue')} {session_info.get('platform', '?')}")
        print(f"{self.ui.c('Version:', 'blue')} {session_info.get('version', '?')}")
        print(f"{self.ui.c('Executable:', 'blue')} {session_info.get('executable', '?')}")
        
        self.ui.rule()
    
    def show_goodbye_message(self):
        """Display a stylish goodbye message"""
        uptime = datetime.now() - self.session_start
        uptime_str = f"{uptime.total_seconds():.1f} seconds"
        
        print(f"\n{self.ui.c('Thanks for using Hydrangea C2!', 'cyan')}")
        print(f"{self.ui.c('Session stats:', 'dim')}")
        print(f"  {self.ui.c('•', 'dim')} Duration: {uptime_str}")
        print(f"  {self.ui.c('•', 'dim')} Commands executed: {self.command_count}")
        print(f"{self.ui.c('Goodbye! 👋', 'magenta')}\n")


class EnhancedClientFormatter:
    """Enhanced formatting for client information"""
    
    def __init__(self, ui: UI):
        self.ui = ui
    
    def format_clients_table(self, clients: List[str]) -> None:
        """Display clients in an enhanced table format"""
        if not clients:
            print(f"  {self.ui.c('No clients currently connected', 'dim')}")
            print(f"  {self.ui.c('💡 Clients will appear here when they connect to the server', 'yellow')}")
            return
        
        self.ui.rule(" connected clients ")
        print(f"{self.ui.TAG_OK} Found {self.ui.c(str(len(clients)), 'bold')} active client(s)")
        print()
        
        # Header
        print(f"  {self.ui.c('STATUS', 'dim'):>8}  {self.ui.c('   CLIENT ID', 'dim'):<30}")
        print(f"  {self.ui.c('─' * 9, 'dim'):>8}  {self.ui.c('─' * 30, 'dim'):<30}")
        
        # Client rows
        for i, client_id in enumerate(clients, 1):
            status_icon = self.ui.c('🟢 ONLINE', 'green')
            client_name = self.ui.c(client_id, 'bold')
            
            print(f"  {status_icon}  {client_name:<30}")
        
        print()
        print(self.ui.c("💡 Tip: Use 'use <client_id>' to set an active client.", "dim"))
        self.ui.rule()


def create_enhanced_ui(ui: UI) -> ControllerUI:
    """Factory function to create an enhanced UI instance"""
    return ControllerUI(ui)
