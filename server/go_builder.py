#!/usr/bin/env python3

import os
import shutil
import subprocess
from typing import Dict, Optional, Tuple
from .UI import UI


def _check_go(ui: UI) -> str:
    go = shutil.which("go")
    if not go:
        raise RuntimeError("Go toolchain not found in PATH. Install Go >= 1.21.")
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


def build_go_clients(ui: UI, args):
    # sources must be under ./client/go
    src_root = os.path.abspath(os.path.join(os.getcwd(), "client", "go"))
    _ensure_go_sources_exist(ui, src_root)
    go_bin = _check_go(ui)

    # targets
    targets: List[Tuple[str, str]] = []
    if not args.os:
        targets = [("linux", args.arch), ("windows", args.arch)]
    else:
        for osname in args.os:
            targets.append((osname, args.arch))

    built = []
    for goos, goarch in targets:
        p = _build_one(
            ui,
            go_bin,
            src_root,
            args.out,
            goos,
            goarch,
            args.server_host or args.host,
            args.server_port or args.port,
            args.build_auth_token or args.auth_token,
            args.client_id,
        )
        built.append(p)

    ui.rule(" build result ")
    ui.headline(f"{ui.TAG_OK} built {len(built)} client(s)")
    for p in built:
        ui.kv("output", src_root+p[2:])
