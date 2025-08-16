# Hydrangea C2 — Agents (Go & Python)

> This page explains how Hydrangea agents are built (Go and Python), how to embed server defaults, cross‑compile, and how the agents behave on the wire once connected. It assumes you’ve read the Architecture page.

---

## 1) What an Agent Does

An *agent* is a lightweight program that connects to the Hydrangea server, registers with a `client_id` and shared token, then waits for orders. It executes file and process operations locally and returns structured results or raw file bytes via the common **frame protocol** (length‑prefixed JSON header + optional payload).

Supported orders:

* `PING` → replies `PONG`.
* `LIST_DIR {path, req_id?}` → returns a JSON array of entries.
* `PULL_FILE {src_path, save_as}` → sends file bytes + `sha256` digest in a `FILE` frame.
* `PUSH_FILE {dest_path, src_name} + payload` → writes bytes to disk and logs a message.
* `EXEC {cmd, shell, cwd, timeout, req_id}` → runs a process and returns `{rc, stdout, stderr}`.
* `SESSION_INFO {req_id}` → returns platform/user/host/runtime info.

**Path policy:** absolute paths are always honored. Relative paths are resolved against a configurable *root base* (runtime flag or compile‑time default).

---

## 2) Building the Go Agent

The Go agent is a single binary compiled from `main.go`. At build time you can **embed server defaults** (host, port, auth token, client id, and root base) using Go linker flags (`-ldflags -X ...`). At runtime, flags can still override these defaults.

### 2.1 Prerequisites

* Go 1.21+ (recommended 1.22+)
* A shell (PowerShell/CMD on Windows, Bash/Zsh on Unix)

### 2.2 Direct build with Go

**Basic local build (current OS/arch):**

```bash
# From repo root
mkdir -p build
GOFLAGS="-trimpath" go build \
  -ldflags "-s -w \
    -X 'main.DefaultServerHost=10.0.0.5' \
    -X 'main.DefaultServerPort=9000' \
    -X 'main.DefaultAuthToken=REPLACE_ME' \
    -X 'main.DefaultClientID=' \
    -X 'main.DefaultRootBase=.'" \
  -o build/hydrangea-client main.go
```

Notes:

* Leave `DefaultClientID` empty to auto‑use the host’s hostname at runtime.
* `DefaultRootBase` controls where **relative** paths resolve; absolute paths are unaffected.

**Cross‑compile examples:**

```bash
# Linux amd64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X 'main.DefaultServerHost=10.0.0.5' -X 'main.DefaultServerPort=9000' -X 'main.DefaultAuthToken=REPLACE_ME' -X 'main.DefaultClientID=' -X 'main.DefaultRootBase=/opt/hydrangea'" \
  -o build/hydrangea-client-linux-amd64 main.go

# Linux arm64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
  -ldflags "-s -w -X 'main.DefaultServerHost=10.0.0.5' -X 'main.DefaultServerPort=9000' -X 'main.DefaultAuthToken=REPLACE_ME' -X 'main.DefaultClientID=' -X 'main.DefaultRootBase=/opt/hydrangea'" \
  -o build/hydrangea-client-linux-arm64 main.go

# Windows amd64
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go build -trimpath ^
  -ldflags "-s -w -X main.DefaultServerHost=10.0.0.5 -X main.DefaultServerPort=9000 -X main.DefaultAuthToken=REPLACE_ME -X main.DefaultClientID= -X main.DefaultRootBase=C:\\Hydrangea" ^
  -o build/hydrangea-client-windows-amd64.exe main.go
```

**Run‑time overrides** (flags take precedence over embedded defaults):

```bash
./hydrangea-client \
  --server 10.0.0.5 --port 9000 \
  --auth-token REPLACE_ME \
  --client-id lab-laptop \
  --root /var/tmp
```

### 2.3 Building via the wrapper

The controller allows you to build directly the agent : 

```bash
# CLI
python Hydrangea-ctl.py --port 9000 --auth-token supersecret \
  build-client --server-host 127.0.0.1 --server-port 9000 --build-auth-token supersecret

# REPL
>> build-client --server-host 127.0.0.1 --server-port 9000 --build-auth-token supersecret
```

The wrapper sets `GOOS/GOARCH/CGO_ENABLED=0`, injects the `-X main.Default*` flags, and emits binaries named like `hydrangea-client-<os>-<arch>[.exe]` into the output folder.

---

## 3) Building the Python Agent

The Python agent (`client.py`) can be run directly with CPython or packaged into a standalone executable.

### 3.1 Run directly (recommended for development)

```bash
python3 client.py \
  --server 10.0.0.5 --port 9000 \
  --client-id lab-desktop \
  --auth-token REPLACE_ME \
  --root .
```

**Project layout tip:** the client imports the project’s `common` helpers. Ensure your `PYTHONPATH` includes the repo root (or keep the `server/common.py` package layout). Example:

```bash
export PYTHONPATH=.
python3 client.py ...
```

### 3.2 Package as a single binary (optional)

Using \[PyInstaller], you can build a self‑contained executable:

```bash
pip install pyinstaller
pyinstaller --onefile --name hydrangea-client-py \
  --paths . \
  client.py
```

* On Windows, the output is `dist/hydrangea-client-py.exe`; on Unix, `dist/hydrangea-client-py`.
* Adjust `--paths` or package layout so that the `common` module is importable at runtime.

---

## 4) Deep Dive — Agent Behavior & Frames

### 4.1 Startup & Registration

1. Parse flags (or use embedded defaults for Go).
2. Establish a TCP connection to the server (`host:port`).
3. Send a `REGISTER` frame with `{client_id, token}`.
4. Expect a `REGISTERED` frame; otherwise exit with an error.

### 4.2 Frame protocol (shared by both agents)

```
uint32_be   header_len
bytes       header_json (UTF‑8)
bytes       payload (optional, exactly header["size"] bytes)
```

* Each frame has a `type` field (`PING`, `EXEC`, `FILE`, etc.).
* For request/response flows, orders carry a `req_id` that the agent echoes in the `RESULT_*` frame so the server can correlate.

### 4.3 Orders & Handlers

**PING → PONG**

* Liveness check. No payload.

**LIST\_DIR {path, req\_id?} → RESULT\_LIST\_DIR**

* Resolve `path` (absolute honored; relative based on *root base*).
* Return array: `{name, is_dir, bytes, mtime}` and set `entries_count` in the header.

**PULL\_FILE {src\_path, save\_as} → FILE**

* Read bytes from `src_path` and return a `FILE` frame with header fields `{src_path, save_as, sha256}`.
* The server saves to an absolute `save_as` verbatim, or into its storage root when `save_as` is relative.

**PUSH\_FILE {dest\_path, src\_name} + payload → LOG**

* Create the destination’s parent directories if needed, write bytes, and log a success message.

**EXEC {cmd, shell, cwd, timeout, req\_id} → RESULT\_EXEC**

* Two modes:

  * `shell=true` executes through the platform shell (`sh -c` / `cmd.exe /C`).
  * `shell=false` uses tokenized argv (`cmd` can be a JSON list or a string split naïvely by spaces).
* Optional `cwd` is resolved using the same path policy.
* Returns `rc` (exit code), plus `stdout` and `stderr` as strings.
* On timeout, the process is terminated and the result indicates a timeout (see language notes below).

**SESSION\_INFO {req\_id} → RESULT\_SESSION\_INFO**

* Returns platform/system/version, machine/arch, current user, PID, cwd, hostname, root base, and executable path.

### 4.4 Path Resolution Policy

* **Absolute** paths: always allowed and resolved to real paths.
* **Relative** paths: resolved against the agent’s *root base*:

  * Go: `--root` flag or embedded `DefaultRootBase`.
  * Python: `--root` flag (defaults to `.`). `..` segments are permitted; the intent is operability rather than chroot‑style confinement.

### 4.5 Language‑specific Behavior Notes

* **Go agent**

  * Embeds defaults via `-ldflags -X`. If `DefaultClientID` is empty, it falls back to the machine hostname.
  * Exit code on timeout is reported as `rc = -1` and `stderr` includes `timeout`.
  * Windows vs. Unix shell wrappers are handled automatically for `shell=true`.

* **Python agent**

  * Uses `asyncio` for non‑blocking I/O and process execution.
  * On timeout, returns `rc = null` and `stderr = "timeout"`.
  * Logs disconnections and handler errors at INFO/ERROR levels.

---

## 5) Operational Guidance

* **Auth token** must match the server’s expectation; rotate regularly.
* **Networking**: run agents only on hosts and networks you control. Avoid exposing server ports publicly.
* **Resource limits**: for large files, consider chunking/streaming in future iterations; current frames buffer in memory.
* **Observability**: use `SESSION_INFO` to verify environment and `PING` for liveness.

---

## 6) Troubleshooting

* *Registration failed*: verify host/port reachability and token; check server logs.
* *Header/JSON errors*: ensure the agent and server speak the same frame protocol.
* *File writes failing*: confirm destination directories are writable and that path resolution produced the expected absolute path.
* *EXEC quoting issues*: prefer `cmd` as a JSON list when arguments contain spaces or special characters.
* *Windows paths*: remember to escape backslashes when embedding via `-ldflags` (e.g., `C:\\Hydrangea`).
