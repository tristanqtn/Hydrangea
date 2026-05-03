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
        hydrangea = hydrangeaApp;

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
      };

      # ── Development shell ────────────────────────────────────────────────────

      devShells.default = pkgs.mkShell {
        packages = with pkgs; [
          python312   # runtime matches mkPythonApp.nix
          poetry      # Python dependency management
          go          # Go toolchain (nixos-unstable tracks latest stable, ≥ 1.23)
          ruff        # Python linter / formatter
          openssl     # TLS cert generation (--tls-auto)
        ];
        shellHook = ''
          echo ""
          echo "  Hydrangea C2 — development shell"
          echo "  ─────────────────────────────────────────────────────"
          echo "  poetry install              install Python dependencies"
          echo "  poetry run hydrangea-server start the server"
          echo "  poetry run hydrangea-ctl    start the controller"
          echo "  cd client/go && go build .  build the Go agent locally"
          echo "  poetry run ruff check server/  lint"
          echo ""
        '';
      };

    }
  );
}
