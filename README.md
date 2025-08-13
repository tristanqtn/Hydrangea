# Hydrangea C2

Lightweight, Python/asyncio command-and-control for **managed endpoints**. Built for labs, internal automation, and education — not for abuse.

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

              Hydrangea C2 •  V1.1
```

---

## Table of Contents

* [Overview](#overview)
* [Architecture](#architecture)
* [Install & Run](#install--run)
* [Controller UX](#controller-ux)
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
* **Client** — registers to the server, executes orders (list, file xfer, exec, session info).
* **Controller (CLI)** — sends admin actions and renders results with a clean TUI.

> Tip: Use on **trusted networks/hosts** with explicit authorization.

---

## Architecture

```
[ Controller (serverctl) ]  <--ADMIN RPC-->  [ Server ]  ==orders=>  [ Client(s) ]
                                                     <==results==
```

* Transport is plain TCP using a compact **length-prefixed JSON header + binary payload** frame.
* The server accepts both admin (controller) connections and client connections on the same ports.
* Responses that should flow back to the controller (e.g., `list --wait`, `exec`, `session`) are correlated with a `req_id`.

---

## Install & Run

Requires Python **3.10+**.

```bash
# Server (multi-port)
python server.py --ports 9000 9001 --storage ./server_storage --auth-token supersecret

# Client (relative paths base)
python client.py --server 127.0.0.1 --port 9000 --client-id laptop1 \
  --auth-token supersecret --root ./client_root

# Client (allow absolute paths on the machine)
python client.py --server 127.0.0.1 --port 9000 --client-id laptop1 \
  --auth-token supersecret --root /
```

> The **auth token** must match across server, clients, and controller.

---

## Controller UX

Hydrangea’s controller prints **clean, human-friendly** output with tags:

* **\[+]** success **\[\~]** queued/pending **\[\*]** info **\[!]** error
* ASCII banner and colors can be disabled: `--no-banner`, `--no-color`, or tone down with `--quiet`.

Examples:

```bash
# Connected clients
python serverctl.py --port 9000 --auth-token supersecret clients
# [+] Connected clients: 2
#   • laptop1
#   • lab-vm

# Directory listing (waits and renders a table)
python serverctl.py --port 9000 --auth-token supersecret \
  list --client laptop1 --path /var/log --wait

# Remote exec (shows stdout/stderr blocks)
python serverctl.py --port 9000 --auth-token supersecret \
  exec --client laptop1 --command "uname -a" --shell

# Session info (OS/user/cwd/host)
python serverctl.py --port 9000 --auth-token supersecret \
  session --client laptop1
```

---

## Orders & Methods

Hydrangea exposes a small, explicit surface. Anything not listed here isn’t implemented.

### Admin actions

Run from the controller (`serverctl.py`):

* `clients`
  List connected client IDs.

* `ping --client <id>`
  Send a ping to a client (server doesn’t wait for a reply).

* `list --client <id> [--path <p>] [--wait] [--timeout <sec>]`
  Request a directory listing on the client.

  * With `--wait`, the controller blocks and renders the result.
  * Without `--wait`, the order is queued; result is logged server-side.

* `pull --client <id> --src <client_path> [--dest <server_save_as>]`
  Ask the client to **send a file to the server**.

  * If `--dest` is **absolute**, the server writes exactly there.
  * If `--dest` is relative or omitted, it saves under `server_storage/<client_id>/`.

* `push --client <id> --src <local_path> --dest <client_path>`
  Send a local file **from the controller machine** to the client.

* `exec --client <id> --command "<str|json list>" [--shell] [--cwd <client_path>] [--timeout <sec>]`
  Execute a system command on the client and return `rc`, `stdout`, `stderr`.

  * `--shell` to run via shell; otherwise pass a JSON list for exact argv (e.g., `["ls","-la"]`).
  * `--cwd` sets the working directory on the client (absolute or relative).

* `session --client <id> [--timeout <sec>]`
  Fetch basic session info (platform, system, release, machine, python, pid, user, cwd, hostname, root base, interpreter path).

### Client orders (server → client)

* `PING`
  Health check. Client replies `PONG`.

* `LIST_DIR {path, req_id?}`
  List contents of a directory.

* `PULL_FILE {src_path, save_as}`
  Client reads `src_path` and ships the bytes to the server.

* `PUSH_FILE {dest_path, src_name} + payload`
  Server sends file bytes; client writes them to `dest_path`.

* `EXEC {cmd, shell, cwd, timeout, req_id}`
  Run a program and capture output.

* `SESSION_INFO {req_id}`
  Gather basic environment details.

### Client responses (client → server)

* `PONG`
  Response to `PING`.

* `RESULT_LIST_DIR {path, entries_count, req_id?} + payload(JSON)`
  Payload is a JSON array with entries like:
  `{"name":"...", "is_dir":true|false, "bytes":123, "mtime":1710000000}`

* `FILE {src_path, save_as, sha256} + payload(bytes)`
  Raw file bytes in payload.

* `RESULT_EXEC {rc, req_id} + payload(JSON)`
  Payload JSON: `{"rc": int|null, "stdout": "...", "stderr": "..."}`

* `RESULT_SESSION_INFO {req_id} + payload(JSON)`
  Payload JSON: session info fields (see `session` action).

* `LOG {message}`
  Free-form informational message.

---

## Protocol

Every frame on the wire:

```
uint32_be  header_len
bytes      header_json (UTF-8, compact)
bytes      payload (optional; exactly header["size"] bytes)
```

* The header is a JSON object; the sender sets `"size"` automatically.
* **Correlation**: orders that expect a direct reply include a unique `req_id`. The server pairs `RESULT_*` frames with the waiting admin connection.

---

## Storage & Paths

* **Server side**

  * Default save location for pulled files: `server_storage/<client_id>/`.
  * If a **destination is absolute** (e.g., `/tmp/out.bin`), the file is written **exactly there** on the server host.

* **Client side**

  * `--root` defines the base for **relative** paths.
  * **Absolute paths are allowed** (e.g., `/etc/hosts`) so you can operate on the full filesystem when intended.
  * The client creates parent directories when pushing to `dest_path`.

> Use absolute paths sparingly and only where appropriate; they bypass the relative base.

---

## Security Notes

* **Auth**: one shared token (minimal). Rotate it, keep it secret.
* **Transport**: plain TCP by default. For production-grade scenarios, wrap with **TLS** (and consider mTLS).
* **Scope**: Remote exec runs with the client’s user privileges. Prefer least-privilege users and constrained environments.
* **Network**: Bind the server to trusted interfaces, firewall the listening ports, and avoid exposing to the public internet.
* **Audit**: Logs record orders and events; ship them to your log stack for traceability.
* **Data**: Transfers are buffered in memory in this reference build; avoid multi-GB files unless you extend streaming.

---

## Troubleshooting

* `unknown_target`
  The client ID isn’t connected. Run `clients` and check the ID spelling.

* `Path traversal detected` (server)
  Returned file tried to escape the relative save area. Use an **absolute** `--dest` or keep it relative.

* No output from `exec`
  Use `--shell` if you passed a single command string that relies on shell features; otherwise pass a JSON list.

* Listing errors like `No such file or directory`
  Verify the path exists on the client and that the client process has permissions.

* Timeouts
  Increase `--timeout`, verify connectivity and client load.

---

## Roadmap

* TLS/mTLS knobs
* Chunked/streaming transfers + resume
* Server-side verification of file checksums
* Structured logging / metrics endpoint
* Role-based admin tokens & per-client ACLs

---

## Disclaimer

Hydrangea C2 is provided **solely for lawful, authorized use** — such as lab work, education, internal administration, and environments where you **own or have explicit permission** to manage the systems involved.
Using this software to access, monitor, or modify computers **without consent** may violate laws and regulations. **You are responsible** for complying with all applicable laws, policies, and contractual obligations. The authors and distributors **do not accept liability** for misuse, damage, loss of data, or any consequences arising from the use of this software. Use responsibly.
