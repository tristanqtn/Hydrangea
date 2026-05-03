{ pkgs, src, mkPoetryApplication, defaultPoetryOverrides }:
mkPoetryApplication {
  projectDir = src;
  python = pkgs.python312;

  # defaultPoetryOverrides covers the full set of common pure-Python packages
  # including rich, prompt_toolkit, and their transitive dependencies.
  # The extend hook is left in place for any future overrides.
  overrides = defaultPoetryOverrides.extend (final: prev: { });

  # Exclude the dev dependency group (ruff) from the runtime package.
  groups = [ ];
  checkGroups = [ ];

  meta = with pkgs.lib; {
    description = "Hydrangea C2 — server and controller";
    homepage    = "https://github.com/tristanqtn/Hydrangea-C2";
    license     = licenses.asl20;
    mainProgram = "hydrangea-ctl";
  };
}
