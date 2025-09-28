{
  description = "Hydrangea C2 a quietly elegant command-and-control.";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
  let
    system = "x86_64-linux";
    version = "0.1.0";
    pkgs = import nixpkgs { inherit system; };
    src = ./.;

    mkClient = import ./nix/mkClient.nix { inherit pkgs version src; };

  in
  {
    packages.${system} = {

    # --- Linux Client ---
      hydrangea-client-linux = mkClient "gnu64";

    # --- Windows Client ---
      hydrangea-client-windows = mkClient "mingwW64";

    };
  };
}
