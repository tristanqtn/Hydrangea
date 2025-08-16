# Hydrangea C2 — Architecture

> This page explains the overall design of Hydrangea C2: the roles of the **Controller**, **Server**, and **Client**, how they speak using a compact **frame protocol**, and how requests/results flow through the system. It also covers storage, path resolution, logging/health, and the Go client build pipeline.

---

## 1) High‑level Overview

```
[ Controller (Hydrangea‑ctl) ]  <--ADMIN RPC-->  [ Server ]  === orders ===>  [ Client(s) ]
                                                    ^                          (Go agent)
                                                    └── results / files  <====
```

* The **Controller** connects as an *admin* to send actions ("orders") and, for some actions, wait for results.
* The **Server** listens on one or more TCP ports, authenticates both controller and clients, fans out orders toward the right client, and relays results back when required. It also saves incoming files to disk and exposes a brief health view.
* The **Client** (Go) registers to the server, waits for orders, executes them on the host, and sends structured results or file bytes back.

All communication uses **length‑prefixed JSON headers with an optional binary payload**. Orders that expect a reply carry a `req_id` so the server can correlate the response to the waiting admin connection.

---

## 2) Components

### 2.1 Controller (Hydrangea‑ctl)

* Two UX modes:

  * **Classic CLI** (subcommands like `clients`, `list`, `exec`, `session`, `pull`, `push`).
  * **Interactive REPL** with a *pinned client context* via `use <client_id>`/`unuse` so `--client` can be omitted in subsequent commands.
* Each admin call opens a short TCP connection, sends a frame with `{type:"ADMIN", token, action:..., ...}`, and (optionally) waits for a reply.
* Extras:

  * **Go agent builder** (`build-client`) to compile cross‑platform Go clients and embed server defaults.
  * Pretty TUI rendering (tables, tags, banners) and a minimal server starter (`--start-srv`).

#### Supported admin actions (summary)

* `clients` — list connected client IDs.
* `ping --client <id>` — send a heartbeat to a client.
* `list --client <id> [--path <p>] [--wait] [--timeout <s>]` — request directory listing (optionally wait and render).
* `pull --client <id> --src <client_path> --dest <server_path>` — have the client send a file to the server.
* `push --client <id> --src <local_path> --dest <client_path>` — send a local file to the client.
* `exec --client <id> --command "<str|json list>" [--shell] [--cwd <p>] [--timeout <s>]` — run a process on the client and return `rc/stdout/stderr`.
* `session --client <id> [--timeout <s>]` — fetch host/session details from the client.
* `server-status` (REPL or classic) — get server health snapshot (status, connected agent count, recent logs).

### 2.2 Server

* Listens on one or more TCP ports; accepts both **REGISTER** (clients) and **ADMIN** (controller) initial frames on the same sockets.
* Verifies a shared **auth token**. Unauthenticated peers receive an error and are dropped.
* Tracks connected clients (by `client_id`) and maintains, per client, a queue of outbound orders and a `pending` map for requests awaiting replies (keyed by `req_id`).
* For actions that **don’t** require an immediate response (e.g., `list` without `--wait`, `push`, `pull`), the server **queues** the order to the client and immediately acknowledges to the controller as `QUEUED`.
* For actions that **do** require a response (`list --wait`, `exec`, `session`), the server creates a future, tags the outgoing order with a unique `req_id`, and waits for a matching `RESULT_*` frame from the client before replying back to the controller.
* **File storage:** when clients send a `FILE` frame, the server writes the payload either to an **absolute path** (verbatim) or, if the name is relative, under `server_storage/<client_id>/`, using strict path‑join protection to avoid traversal.
* **Health/Logging:** logs to file and keeps a small in‑memory buffer exposed via the `server-status` admin action.

### 2.3 Client (Go agent)

* On start, dials the server, sends a `REGISTER` frame with its `client_id` and shared token, then enters a loop reading orders.
* Supported orders and behaviors:

  * `PING` → reply `PONG`.
  * `LIST_DIR {path, req_id?}` → enumerate entries (name/dir/size/mtime) and send `RESULT_LIST_DIR` with a JSON payload.
  * `PULL_FILE {src_path, save_as}` → read file bytes and send a `FILE` frame with a SHA‑256 digest in the header.
  * `PUSH_FILE {dest_path, src_name} + payload` → write the received bytes to the destination path and log success.
  * `EXEC {cmd, shell, cwd, timeout, req_id}` → run a process (either via shell for string commands or as tokenized argv for JSON lists). Capture stdout/stderr and return `RESULT_EXEC` with `rc` and output.
  * `SESSION_INFO {req_id}` → return platform/user/pid/cwd/hostname/runtime information in `RESULT_SESSION_INFO`.
* **Path resolution policy:** absolute client paths are honored; relative paths resolve against a configurable *root base*. This allows safe, predictable use of `./` paths while still enabling full‑system operations when an absolute path is explicitly used.

---

## 3) Wire Protocol (frames)

### 3.1 Frame layout

```
uint32_be   header_len
bytes       header_json (UTF‑8, compact)
bytes       payload (optional; exactly header["size"] bytes)
```

* The header is a JSON object. The sender sets `"size"` to the payload length.
* Every message carries a `type` field (e.g., `ADMIN`, `REGISTER`, `LIST_DIR`, `RESULT_EXEC`, `FILE`, `LOG`, ...).

### 3.2 Correlation with `req_id`

Orders that expect a direct response include a unique `req_id`. The client copies that value into the corresponding `RESULT_*` header. The server uses it to resolve the awaiting future for the originating admin connection.

### 3.3 Order & response catalog

**Server → Client (orders)**

* `PING`
* `LIST_DIR {path, req_id?}`
* `PULL_FILE {src_path, save_as}`
* `PUSH_FILE {dest_path, src_name} + payload`
* `EXEC {cmd, shell, cwd, timeout, req_id}`
* `SESSION_INFO {req_id}`

**Client → Server (responses / events)**

* `PONG`
* `RESULT_LIST_DIR {path, entries_count, req_id?} + payload(JSON array)`
* `FILE {src_path, save_as, sha256} + payload(bytes)`
* `RESULT_EXEC {rc, req_id} + payload(JSON: {rc, stdout, stderr})`
* `RESULT_SESSION_INFO {req_id} + payload(JSON)`
* `LOG {message}`

---

## 4) Storage & Paths

### 4.1 Server side

* Default destination for files **pulled** from a client is `server_storage/<client_id>/...` when the provided `save_as` is relative.
* If `save_as` is **absolute** (e.g., `/tmp/out.bin`), the server writes **exactly there**.
* A strict `safe_join` check prevents directory traversal outside the server’s storage root when using relative paths.

### 4.2 Client side

* The client will:

  * Allow **absolute paths** like `/etc/hosts` or `C:\Windows\...`.
  * Resolve **relative** paths against its configured `root` base (defaults are embedded at build time but can be overridden by flags at runtime).
  * Create parent directories for `PUSH_FILE` writes when needed.

---

## 5) Build & Deployment (Go client)

Hydrangea includes a builder that compiles the Go client from `./client/go` and **embeds** server defaults via Go linker flags:

* Embedded defaults: `DefaultServerHost`, `DefaultServerPort`, `DefaultAuthToken`, `DefaultClientID`.
* Cross‑compile targets: `linux/windows` and `amd64/arm64` (configurable).
* Environment for builds: `GOOS`, `GOARCH`, `CGO_ENABLED=0`.
* Output binaries are named like `hydrangea-client-<os>-<arch>[.exe]` into the chosen `--out` directory.

At runtime, the client still accepts flags (`--server`, `--port`, `--auth-token`, `--client-id`, `--root`) to override embedded defaults when desired.

---

## 6) Health, Logs & Observability

* The server writes a standard log file and keeps a short in‑memory ring buffer of recent log lines.
* The controller’s `server-status` action returns:

  * `status` (running),
  * `connected_agents` count,
  * a tail of `recent_logs` rendered in the TUI.

---

## 7) Security Posture & Recommendations

* **Auth**: a single shared token across controller/server/clients — rotate and keep secret.
* **Transport**: plain TCP by default; for production‑like environments, front with TLS (or mTLS) at the socket or proxy layer.
* **Least privilege**: run clients with minimal rights; avoid public exposure of server ports; firewall appropriately.
* **Data handling**: current file transfers are buffered in memory; consider chunked/streaming extensions before moving very large files.

---

## 8) Typical Flows (mini sequence diagrams)

### 8.1 `list --wait` flow

```
Controller → Server: ADMIN {action:"list", target_id, path, wait:true}
Server → Client:     LIST_DIR {path, req_id}
Client → Server:     RESULT_LIST_DIR {req_id} + JSON(entries)
Server → Controller: RESULT_LIST_DIR + JSON(entries)
```

### 8.2 `pull` flow

```
Controller → Server: ADMIN {action:"pull", target_id, src, dest}
Server → Client:     PULL_FILE {src_path:src, save_as:dest}
Client → Server:     FILE {src_path, save_as, sha256} + bytes
Server:              save bytes to absolute dest OR storage/<client_id>/save_as
Server → Controller: QUEUED {order:"pull", src, save_as}
```

### 8.3 `exec` flow

```
Controller → Server: ADMIN {action:"exec", target_id, cmd, shell?, cwd?, timeout}
Server → Client:     EXEC {cmd, shell, cwd, timeout, req_id}
Client → Server:     RESULT_EXEC {rc, req_id} + JSON({rc,stdout,stderr})
Server → Controller: RESULT_EXEC + JSON
```
