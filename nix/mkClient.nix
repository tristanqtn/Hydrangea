{ pkgs, version, src ? ./. }:
target:
  pkgs.pkgsCross.${target}.buildGoModule {
    pname = "hydrangea-client-${target}";
    inherit version;
    inherit src;
    modRoot = "client/go";
    # Required to unsure dependacy are consistent
    vendorHash = "sha256-y5DvzFpXa2a2+ZZmM+JUhfjdrxpSR9gIj/JPOvKhAd4=";

    env.CGO_ENABLED = "0";

    dontStrip = true;

    postInstall = ''
      for f in $out/bin/*; do
        if [ "${target}" = "mingwW64" ]; then
          mv "$f" "$out/bin/hydrangea-client-${target}-${version}.exe"
        else
          mv "$f" "$out/bin/hydrangea-client-${target}-${version}"
        fi
      done
    '';

    meta = with pkgs.lib; {
      description = "Hydrangea C2 Go client for ${target} - ${version}";
      homepage = "https://github.com/tristanqtn/Hydrangea-C2";
      license = licenses.asl20;
      platforms = platforms.all;
      mainProgram = "hydrangea-client-${target}-${version}";
    };
  }
