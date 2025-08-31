# Hydrangea C2

```
   ▄█    █▄    ▄██   ▄   ████████▄     ▄████████    ▄████████ ███▄▄▄▄      ▄██████▄     ▄████████    ▄████████ 
  ███    ███   ███   ██▄ ███   ▀███   ███    ███   ███    ███ ███▀▀▀██▄   ███    ███   ███    ███   ███    ███ 
  ███    ███   ███▄▄▄███ ███    ███   ███    ███   ███    ███ ███   ███   ███    █▀    ███    █▀    ███    ███ 
 ▄███▄▄▄▄███▄▄ ▀▀▀▀▀▀███ ███    ███  ▄███▄▄▄▄██▀   ███    ███ ███   ███  ▄███         ▄███▄▄▄       ███    ███ 
▀▀███▀▀▀▀███▀  ▄██   ███ ███    ███ ▀▀███▀▀▀▀▀   ▀███████████ ███   ███ ▀▀███ ████▄  ▀▀███▀▀▀     ▀███████████ 
  ███    ███   ███   ███ ███    ███ ▀███████████   ███    ███ ███   ███   ███    ███   ███    █▄    ███    ███ 
  ███    ███   ███   ███ ███   ▄███   ███    ███   ███    ███ ███   ███   ███    ███   ███    ███   ███    ███ 
  ███    █▀     ▀█████▀  ████████▀    ███    ███   ███    █▀   ▀█   █▀    ████████▀    ██████████   ███    █▀  
                                      ███    ███                                                               

              Hydrangea C2 •  V2.0
```

Hydrangea C2 is a modular command-and-control (C2) framework designed for secure, authorized remote administration. It features a Python-based server and controller, plus a Go client agent, enabling efficient management of multiple endpoints over TCP. Hydrangea supports file transfers, remote command execution, session info retrieval, and more, all with a focus on clarity, minimalism, and explicit control. Intended for trusted environments, it emphasizes ease of use, extensibility, and security best practices.

---

## Table of Contents

* [Overview](#overview)
* [Architecture](#architecture)
* [Install & Run](#install--run)
* [Controller UX](#controller-ux)
  * [Classic CLI](#classic-cli)
  * [REPL](#repl)
* [Agent builder (Go)](#agent-builder-go)
* [Orders & Methods](#orders--methods)

  * [Admin actions](#admin-actions)
  * [Client orders (server → client)](#client-orders-server--client)
  * [Client responses (client → server)](#client-responses-client--server)
* [Protocol](#protocol)
* [Storage & Paths](#storage--paths)
* [Security Notes](#security-notes)
* [Troubleshooting](#troubleshooting)
* [Roadmap](#roadmap)
* [Disclaimer](#disclaimer)

---

## Overview

Hydrangea C2 has three parts:

* **Server** — listens on multiple ports, tracks connected clients, relays orders, stores incoming files.
* **Client (Go)** — registers to the server, executes orders (list, file xfer, exec, session info).
* **Controller (CLI)** — sends admin actions and renders results with a clean TUI / REPL.

> Tip: Use on **trusted networks/hosts** with explicit authorization.

---

## Architecture

```
[ Controller (serverctl) ]  <--ADMIN RPC-->  [ Server ]  ===orders==>   [ Client(s) ]
                                                         <==results==
```

* Transport is plain TCP using a compact **length-prefixed JSON header + binary payload** frame.
* The server accepts both admin (controller) connections and client connections on the same ports.
* Responses that should flow back to the controller (e.g., `list --wait`, `exec`, `session`) are correlated with a `req_id`.

---

## Install & Run

Requires Python **3.10+** (server + controller).
For building Go clients, requires Go **1.21+**.

```bash
# Server (single or multi-port)
python Hydrangea-server.py --ports 9000 9001 --storage ./server_storage --auth-token supersecret

# Build Go agents (see "Agent builder (Go)" below)
python Hydrangea-ctl.py --port 9000 --auth-token supersecret \
  build-client --server-host 127.0.0.1 --server-port 9000 --build-auth-token supersecret

# Run a built Go client
./dist/hydrangea-client-linux-amd64 \
  --server 127.0.0.1 --port 9000 --auth-token supersecret --client-id laptop1

# Start server from controller
python Hydrangea-ctl.py --port 9000 --auth-token supersecret --start-srv
```

> The **auth token** must match across server, clients, and controller.

Lazy run : 

```bash
python3 Hydrangea-ctl.py --host 0.0.0.0 --port 9000 --auth-token supersecret --start-srv

[...]

>> build-client --server-host 127.0.0.1 --server-port 9000 --build-auth-token supersecret


---

## Controller UX

### Classic CLI

```bash
# Connected clients
python Hydrangea-ctl.py --port 9000 --auth-token supersecret clients

# Directory listing (waits and renders a table)
python Hydrangea-ctl.py --port 9000 --auth-token supersecret \
  list --client laptop1 --path /var/log --wait

# Remote exec (shows stdout/stderr blocks)
python Hydrangea-ctl.py --port 9000 --auth-token supersecret \
  exec --client laptop1 --command "uname -a" --shell

# Session info (OS/user/cwd/host)
python Hydrangea-ctl.py --port 9000 --auth-token supersecret \
  session --client laptop1
```

### REPL

You can run the controller as an interactive console, and **pin** a client context so you don’t have to pass `--client` every time.

```bash
# Start REPL (you can also just omit a subcommand)
python Hydrangea-ctl.py --port 9000 --auth-token supersecret --repl
```

Inside the REPL:

```
>> clients
>> use laptop1           # sets active client context
>> exec --command "uname -a"
>> list --path / --wait
>> unuse                 # clears active context
>> use laptop3
>> session
```

* `use <client_id>` sets the active client.
* `unuse` clears it (or `unuse <client_id>` only clears if it matches).
* In REPL, `--client` becomes **optional**; commands will use the active client if provided.

---

## Agent builder (Go)

Hydrangea ships a **builder** in the controller to compile the Go client located at `./client/go/` and **embed server details** at build time.

**Requirements**

* Go **>= 1.21**
* Source files present at:
  * `client/go/main.go`
  * `client/go/go.mod`

**Build command**

```bash
# Build Linux + Windows agents (amd64) with embedded server host/port/token
python Hydrangea-ctl.py --port 9000 --auth-token supersecret \
  build-client --server-host 192.168.1.10 --server-port 9000 \
  --build-auth-token supersecret --out ./dist

# REPL
>> build-client --server-host 127.0.0.1 --server-port 9000 --build-auth-token supersecret
```

Options:

* `--server-host` (defaults to controller `--host` if omitted)
* `--server-port` (defaults to controller `--port`)
* `--build-auth-token` (defaults to controller `--auth-token`)
* `--client-id` (optional fixed ID; otherwise client uses its hostname or code default)
* `--os` (`linux`, `windows`; repeatable; default: both)
* `--arch` (`amd64`, `arm64`; default: `amd64`)
* `--out` output directory (default: `./dist`)

**How embedding works**

The builder uses Go’s `-ldflags -X` to set variables expected by the client code:

* `main.DefaultServerHost`
* `main.DefaultServerPort`
* `main.DefaultAuthToken`
* `main.DefaultClientID`

Your Go client should read these as defaults on startup (and may allow runtime flags like `--server`, `--port`, etc., to override).

**Output binaries**

* `dist/hydrangea-client-linux-amd64`
* `dist/hydrangea-client-windows-amd64.exe`
* (and/or `arm64` variants if requested)

---

## Orders & Methods

Hydrangea exposes a small, explicit surface. Anything not listed here isn’t implemented.

### Admin actions

Run from the controller (`Hydrangea-ctl.py`):

* `clients` — List connected client IDs.
* `ping --client <id>` — Send a ping to a client (server doesn’t wait for a reply).
* `list --client <id> [--path <p>] [--wait] [--timeout <sec>]` — Request a directory listing on the client.

  * With `--wait`, the controller blocks and renders the result.
  * Without `--wait`, the order is queued; result is logged server-side.
* `pull --client <id> --src <client_path> --dest <server_path>` — Ask the client to **send a file to the server**.

  * If `--dest` is **absolute**, the server writes exactly there.
  * If `--dest` is relative, it saves under `server_storage/<client_id>/`.
* `push --client <id> --src <local_path> --dest <client_path>` — Send a local file **from the controller machine** to the client.
* `exec --client <id> --command "<str|json list>" [--shell] [--cwd <client_path>] [--timeout <sec>]` — Execute a system command on the client and return `rc/stdout/stderr`.
* `session --client <id> [--timeout <sec>]` — Fetch basic session info (platform, system, release, machine, runtime, pid, user, cwd, hostname, root base, interpreter path).
* `build-client [options]` — **Compile Go clients** from `./client/go` and embed server details (see [Agent builder (Go)](#agent-builder-go)).

> **REPL-only meta:** `use <id>` / `unuse` to manage active client context (no network call; it only changes REPL behavior).

## Storage & Paths

* **Server side**

  * Default save location for pulled files: `server_storage/<client_id>/`.
  * If a **destination is absolute** (e.g., `/tmp/out.bin`), the file is written **exactly there** on the server host.

* **Client side (Go)**

  * The client allows absolute paths (e.g., `/etc/hosts`) and can also resolve **relative** paths against its configured root base (see your client’s flags/implementation).
  * When pushing, the client creates parent directories for the destination file if needed.

> Use absolute paths sparingly and only where appropriate.

---

## Disclaimer

Hydrangea C2 is provided **solely for lawful, authorized use** — such as lab work, education, internal administration, and environments where you **own or have explicit permission** to manage the systems involved.
Using this software to access, monitor, or modify computers **without consent** may violate laws and regulations. **You are responsible** for complying with all applicable laws, policies, and contractual obligations. The authors and distributors **do not accept liability** for misuse, damage, loss of data, or any consequences arising from the use of this software. Use responsibly.
