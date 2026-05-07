{
  description = "Hydrangea C2 a quietly elegant command-and-control.";

  inputs = {
    nixpkgs.url     = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    poetry2nix = {
      url = "github:nix-community/poetry2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, poetry2nix }:
  let
    version     = "4.0.0";
    src         = ./.;

    # Go cross-compilation only works reliably from x86_64-linux.
    # These are built once for the fixed host and conditionally exposed
    # under packages only when the evaluated system matches.
    linuxSystem = "x86_64-linux";
    linuxPkgs   = import nixpkgs { system = linuxSystem; };
    mkClient    = import ./nix/mkClient.nix { pkgs = linuxPkgs; inherit version src; };

  in
  flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs { inherit system; };

      # poetry2nix must be instantiated per-system so it uses the correct pkgs.
      inherit (poetry2nix.lib.mkPoetry2Nix { inherit pkgs; })
        mkPoetryApplication defaultPoetryOverrides;

      hydrangeaApp = import ./nix/mkPythonApp.nix {
        inherit pkgs src mkPoetryApplication defaultPoetryOverrides;
      };

    in {

      # ── Packages ────────────────────────────────────────────────────────────

      packages = {
        # Python server + controller — available on all systems
        hydrangea         = hydrangeaApp;
        default           = hydrangeaApp;   # nix build

      } // pkgs.lib.optionalAttrs (system == linuxSystem) {
        # Go agents — cross-compiled, x86_64-linux build host only
        hydrangea-client-linux       = mkClient "gnu64";
        hydrangea-client-linux-arm64 = mkClient "aarch64-multiplatform";
        hydrangea-client-windows     = mkClient "mingwW64";
      };

      # ── Apps (nix run) ───────────────────────────────────────────────────────

      apps = {
        hydrangea-server = {
          type    = "app";
          program = "${hydrangeaApp}/bin/hydrangea-server";
        };
        hydrangea-ctl = {
          type    = "app";
          program = "${hydrangeaApp}/bin/hydrangea-ctl";
        };
        # nix run → controller (most common interactive entry point)
        default = {
          type    = "app";
          program = "${hydrangeaApp}/bin/hydrangea-ctl";
        };
      };

      # ── Checks (nix flake check) ─────────────────────────────────────────────

      checks = {
        # Python — ruff lint
        ruff = pkgs.runCommand "ruff-check" { buildInputs = [ pkgs.ruff ]; } ''
          ruff check ${src}/server/
          touch $out
        '';

        # Go — vet + build for all three targets (fast, no linking)
        go-vet = pkgs.runCommand "go-vet" {
          buildInputs = [ pkgs.go ];
          # go needs a writable HOME for its module cache
          HOME = "/tmp";
        } ''
          cd ${src}/client/go
          go vet ./...
          touch $out
        '';
      };

      # ── Formatter (nix fmt) ──────────────────────────────────────────────────

      formatter = pkgs.nixfmt-rfc-style;

      # ── Development shell ────────────────────────────────────────────────────

      devShells.default = pkgs.mkShell {
        packages = with pkgs; [
          # Python runtime + package manager
          # mkPoetryEnv is intentionally avoided: poetry2nix evaluates wheel metadata
          # for every package in poetry.lock (including ruff's riscv64 wheels) and hits
          # a missing-attribute bug in pep600.nix regardless of the `groups` setting.
          # The shellHook below bootstraps a local .venv via `poetry install` instead.
          python312
          poetry

          # Python tooling sourced directly from nixpkgs (no poetry2nix evaluation)
          ruff          # linter / formatter
          pyright       # type checker / language server

          # Go toolchain — CGO disabled; cross-compilation to linux/arm64/windows
          # needs only GOOS/GOARCH env vars, no extra C toolchain required
          go
          gopls         # Go language server (IDE support)
          gotools       # goimports, godoc, etc.
          golangci-lint # unified Go linter

          # Infra / TLS
          openssl       # cert generation for --tls-auto
          git
          direnv        # auto-activates this shell on `cd` via .envrc (use flake)
        ];

        shellHook = ''
          # Bootstrap a project-local virtualenv on first entry (or after lock changes).
          # --without dev: ruff is in the dev group and ships as a generic-Linux binary
          # wheel that cannot run on NixOS; pkgs.ruff from nixpkgs is used instead.
          export POETRY_VIRTUALENVS_IN_PROJECT=true
          if [ ! -d .venv ] || [ pyproject.toml -nt .venv ] || [ poetry.lock -nt .venv ]; then
            echo "  → running poetry install …"
            poetry install --without dev --quiet
          fi
          source .venv/bin/activate

          echo ""
          echo "  Hydrangea C2 — development shell"
          echo "  ─────────────────────────────────────────────────────────────────────"
          echo "  Python venv active (.venv/). Re-runs 'poetry install' when"
          echo "  pyproject.toml or poetry.lock is newer than the venv."
          echo ""
          echo "  Server / Controller"
          echo "    hydrangea-server --admin-port 9000 --ports 9001 \\"
          echo "      --admin-token <tok> --agent-token <tok>"
          echo "    hydrangea-ctl --host 127.0.0.1 --port 9000 --auth-token <tok>"
          echo ""
          echo "  Agent (local, current platform)"
          echo "    cd client/go && go build ."
          echo ""
          echo "  Agent (cross-compile — CGO disabled, no extra toolchain needed)"
          echo "    cd client/go"
          echo "    GOOS=linux   GOARCH=amd64 go build -o hydrangea-client-linux64 ."
          echo "    GOOS=linux   GOARCH=arm64 go build -o hydrangea-client-arm64  ."
          echo "    GOOS=windows GOARCH=amd64 go build -o hydrangea-client.exe    ."
          echo ""
          echo "  Lint"
          echo "    ruff check server/          # Python"
          echo "    golangci-lint run ./...      # Go (run from client/go)"
          echo "  ─────────────────────────────────────────────────────────────────────"
          echo ""
        '';
      };

    }
  );
}
