# pre-commit-check.nix - Pre-commit hooks configuration package
#
# Defines the pre-commit hooks that run automatically before each commit
# to ensure code quality, formatting, and basic validation.

{
  pre-commit,
  system,
  config,
  pkgs,
}:

let
  # pre-commit in nixpkgs bundles heavyweight test-only dependencies
  # (dotnet-sdk, nodejs, go, coursier, …) into nativeBuildInputs via
  # its preCheck string interpolation, even though doCheck is already
  # false on Darwin. Filter them out so `direnv allow` / `nix develop`
  # doesn't have to build dotnet from source.
  pre-commit-lightweight = pkgs.pre-commit.overridePythonAttrs {
    nativeCheckInputs = [ ];
    doCheck = false;
    doInstallCheck = false;
    dontUsePytestCheck = true;
    preCheck = "";
    postCheck = "";
  };
in

pre-commit.lib.${system}.run {
  src = ./../..; # Root of the project
  package = pre-commit-lightweight;

  # Configure the pre-commit hooks to run
  hooks = {
    # Use treefmt for code formatting (disabled by default, enabled via package)
    treefmt.enable = false;
    treefmt.package = config.treefmt.build.wrapper;

    # Shell script validation
    check-executables-have-shebangs.enable = true;
    check-shebang-scripts-are-executable.enable = true;

    # File system checks
    check-case-conflicts.enable = true;
    check-symlinks.enable = true;
    check-merge-conflicts.enable = true;
    check-added-large-files.enable = true;

    # Commit message formatting
    commitizen.enable = true;

    renovate-config-validator = {
      enable = true;
      name = "Renovate config validator";
      entry = "${pkgs.renovate}/bin/renovate-config-validator";
      files = "renovate\\.json$";
      language = "system";
      pass_filenames = true;
    };

    actionlint = {
      enable = true;
      files = "^\\.github/workflows/.*\\.yaml$";
    };

    pinact = {
      enable = true;
      name = "pinact";
      description = "Check GitHub Action refs are SHA-pinned and resolvable";
      entry = "${pkgs.writeShellScript "pinact-check" ''
        token="''${GITHUB_TOKEN:-''${GH_TOKEN:-$(${pkgs.gh}/bin/gh auth token 2>/dev/null || true)}}"
        if [ -z "$token" ]; then
          echo "pinact: skipping — no GITHUB_TOKEN/GH_TOKEN and gh not authenticated" >&2
          exit 0
        fi
        export GITHUB_TOKEN="$token"
        exec ${pkgs.pinact}/bin/pinact run --check
      ''}";
      files = "^\\.github/workflows/.*\\.ya?ml$";
      language = "system";
      pass_filenames = false;
    };

    dependabot-validator = {
      enable = true;
      name = "Dependabot config validator";
      entry = "${pkgs.check-jsonschema}/bin/check-jsonschema --builtin-schema vendor.dependabot";
      files = "\\.github/dependabot\\.yml$";
      language = "system";
      pass_filenames = true;
    };
  };

  # Exclude certain paths from pre-commit checks
  excludes = [
    "vendor/" # Third-party code
  ];
}
