#!/usr/bin/env python3

import os
import re
import shutil
import subprocess
from typing import List, Optional, Tuple
from .controller_ui import UI

_MIN_GO = (1, 23)


def _check_go(ui: UI) -> str:
    go = shutil.which("go")
    if not go:
        raise RuntimeError(
            "Go toolchain not found in PATH.\n"
            f"  Install Go >= {_MIN_GO[0]}.{_MIN_GO[1]} from https://go.dev/dl/"
        )
    result = subprocess.run([go, "version"], capture_output=True, text=True)
    m = re.search(r"go(\d+)\.(\d+)", result.stdout)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        if (major, minor) < _MIN_GO:
            raise RuntimeError(
                f"Go {major}.{minor} found but Go >= {_MIN_GO[0]}.{_MIN_GO[1]} is required.\n"
                f"  Update from https://go.dev/dl/"
            )
    return go


def _ensure_go_sources_exist(ui: UI, src_root: str):
    main_go = os.path.join(src_root, "main.go")
    go_mod = os.path.join(src_root, "go.mod")
    if not os.path.isfile(main_go) or not os.path.isfile(go_mod):
        raise RuntimeError(
            f"Go client sources not found at {src_root}. "
            f"Expected {src_root}/main.go and {src_root}/go.mod"
        )
    return main_go, go_mod


def _build_one(
    ui: UI,
    go_bin: str,
    src_root: str,
    out_dir: str,
    goos: str,
    goarch: str,
    host: str,
    port: int,
    token: str,
    client_id: Optional[str],
    tls_enabled: bool = False,
    tls_fingerprint: str = "",
) -> str:
    os.makedirs(out_dir, exist_ok=True)
    out_name = f"hydrangea-client-{goos}-{goarch}" + (
        ".exe" if goos == "windows" else ""
    )
    out_path = os.path.join(out_dir, out_name)

    # Inject build-time defaults into the Go variables with -ldflags -X
    ldvars = [
        ("main.DefaultServerHost", host),
        ("main.DefaultServerPort", str(port)),
        ("main.DefaultAuthToken", token),
        ("main.DefaultClientID", client_id or "default"),
        ("main.DefaultTLSEnabled", "true" if tls_enabled else "false"),
        ("main.DefaultTLSFingerprint", tls_fingerprint or ""),
    ]
    ldflags = " ".join([f"-X {k}={v}" for k, v in ldvars])

    env = os.environ.copy()
    env["GOOS"] = goos
    env["GOARCH"] = goarch
    env["CGO_ENABLED"] = "0"

    cmd = [go_bin, "build", "-trimpath", "-ldflags", ldflags, "-o", out_path, "."]
    ui.kv("Building", f"{goos}/{goarch} -> {out_path}")
    proc = subprocess.run(
        cmd,
        cwd=src_root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"build failed ({goos}/{goarch}): {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return out_path


def build_go_clients(ui: UI, args, agent_path: str = ""):
    if agent_path != "":
        ui.rule(" build go client from custom path ")
        src_root = os.path.abspath(agent_path)
    else:
        ui.rule(" build go client from default path ")
        src_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "client", "go"))

    _ensure_go_sources_exist(ui, src_root)
    go_bin = _check_go(ui)

    # targets
    targets: List[Tuple[str, str]] = []
    if not args.os:
        targets = [("linux", args.arch), ("windows", args.arch)]
    else:
        for osname in args.os:
            targets.append((osname, args.arch))

    # Resolve output directory to an absolute path NOW, before _build_one changes
    # the working directory to src_root — otherwise a relative --out path would be
    # interpreted relative to the Go source tree instead of the caller's CWD.
    out_dir = os.path.abspath(args.out)

    built = []
    build_tls = getattr(args, "build_tls", False) or bool(getattr(args, "build_tls_fingerprint", ""))
    build_tls_fp = getattr(args, "build_tls_fingerprint", "") or ""
    for goos, goarch in targets:
        p = _build_one(
            ui,
            go_bin,
            src_root,
            out_dir,
            goos,
            goarch,
            args.server_host or args.host,
            args.server_port or args.port,
            args.build_auth_token or args.auth_token,
            args.client_id,
            tls_enabled=build_tls,
            tls_fingerprint=build_tls_fp,
        )
        built.append(p)

    ui.rule(" build result ")
    ui.headline(f"{ui.TAG_OK} built {len(built)} client(s)")
    for p in built:
        ui.kv("output", p)
