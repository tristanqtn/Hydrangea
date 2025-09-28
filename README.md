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

              Hydrangea C2 •  V3.0
```

Hydrangea is a modular command-and-control (C2) framework designed for simple and reliable post exploitation fleet management. It features a Python-based server and controller, plus a Go client agent, enabling efficient management of multiple endpoints over TCP. Hydrangea supports **file transfers**, **remote command execution**, **reverse shell management**, **port forwarding**, and more, all with a focus on clarity, minimalism, and explicit control. Intended for trusted environments, it emphasizes ease of use, extensibility, and security best practices.

--- 

For a detailed documentation please consider reading the [Wiki](https://github.com/tristanqtn/Hydrangea-C2/wiki). 

---

## Table of Contents

* [Overview](#overview)
* [Disclaimer](#disclaimer)
* [Architecture](#architecture)
* [Install & Run](#install--run)
* [Orders & Methods](#orders--methods)
* [Storage & Paths](#storage--paths)
* [Roadmap](#roadmap)


---

## Overview

Hydrangea C2 has three parts:

* **Server** — listens on multiple ports, tracks connected clients, relays orders, stores incoming files.
* **Client (Go)** — registers to the server, executes orders (list, file xfer, exec, session info).
* **Controller (CLI)** — sends admin actions and renders results with a clean TUI / REPL.

> Tip: Use on **trusted networks/hosts** with explicit authorization.

---

## Disclaimer

> [!CAUTION]
> Hydrangea C2 is provided **solely for lawful, authorized use** — such as lab work, education, internal administration, and environments where you **own or have explicit permission** to manage the systems involved. Using this software to access, monitor, or modify computers **without consent** may violate laws and regulations. **You are responsible** for complying with all applicable laws, policies, and contractual obligations. The authors and distributors **do not accept liability** for misuse, damage, loss of data, or any consequences arising from the use of this software. Use responsibly.

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
>> build-client --server-host 127.0.0.1 --server-port 9000 --build-auth-token supersecret

# Run a built Go client
hydrangea-client-linux-amd64 --server 127.0.0.1 --port 9000 --auth-token supersecret --client-id laptop1

# Start server from controller
python Hydrangea-ctl.py --port 9000 --auth-token supersecret --start-srv
```

> The **auth token** must match across server, clients, and controller.

## Orders & Methods

Hydrangea exposes a small, explicit surface. Anything not listed here isn’t implemented.

### Admin actions

Run from the controller (`Hydrangea-ctl.py`):

* `clients` — List connected client IDs.
* `ping --client <id>` — Send a ping to a client (server doesn’t wait for a reply).
* `list --client <id> [--path <p>] [--wait] [--timeout <sec>]` — Request a directory listing on the client.

#### File Operations:
* `list [--client <id>] [--path <p>] [--wait] [--timeout <sec>]` — Request a directory listing on the client.
  * With `--wait`, the controller blocks and renders the result.
  * Without `--wait`, the order is queued; result is logged server-side.
* `pull [--client <id>] --src <client_path> --dest <server_path>` — Ask the client to **send a file to the server**.
  * If `--dest` is **absolute**, the server writes exactly there.
  * If `--dest` is relative, it saves under `server_storage/<client_id>/`.
* `push [--client <id>] --src <local_path> --dest <client_path>` — Send a local file **from the controller machine** to the client.

#### Command Execution:
* `exec [--client <id>] --command "<str|json list>" [--shell] [--cwd <client_path>] [--timeout <sec>]` — Execute a system command on the client and return `rc/stdout/stderr`.
* `local --command "<command>"` — Execute a command locally on the controller machine.

#### Advanced Features:
* `reverse-shell [--client <id>] --controller-addr <host:port>` — Start a reverse shell from the client back to the controller.
* `port-forward [--client <id>] --proxy-ip <ip> --proxy-port <port> --ligolo-path <path>` — Set up port forwarding using Ligolo agent.

#### System:
* `build-client [options]` — **Compile Go clients** from `./client/go` and embed server details (see [Agent builder (Go)](#agent-builder-go)).
* `server-status` — Check the health status of the server.

> **Note:** When using the REPL interface with an active client context (set via `use <id>`), the `--client` parameter becomes **optional** for all commands.

## Storage & Paths

* **Server side**

  * Default save location for pulled files: `server_storage/<client_id>/`.
  * If a **destination is absolute** (e.g., `/tmp/out.bin`), the file is written **exactly there** on the server host.

* **Client side (Go)**

  * The client allows absolute paths (e.g., `/etc/hosts`) and can also resolve **relative** paths against its configured root base (see your client’s flags/implementation).
  * When pushing, the client creates parent directories for the destination file if needed.

> Use absolute paths sparingly and only where appropriate.

---