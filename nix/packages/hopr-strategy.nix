# hopr-strategy.nix - hopr-strategy library package definitions
#
# Defines all variants of the hopr-strategy library for different platforms.
# hopr-strategy is a Rust library crate implementing HOPR channel strategies.

{
  lib,
  builders,
  sources,
  hoprStrategyCrateInfo,
  rev,
  nixLib,
}:

let
  # Common build arguments for hopr-strategy variants
  mkHoprStrategyBuildArgs =
    { src, depsSrc }:
    {
      inherit src depsSrc rev;
      cargoToml = ./../../Cargo.toml;
    };

  localArgs = mkHoprStrategyBuildArgs {
    src = sources.main;
    depsSrc = sources.deps;
  };

  mkHoprStrategyPlatformPackages =
    platform:
    let
      name = "lib-hopr-strategy-${platform}";
    in
    {
      "${name}" = builders.${platform}.callPackage nixLib.mkRustLibrary localArgs;
    }
    // lib.optionalAttrs (lib.hasSuffix "-linux" platform) {
      "${name}-dev" = builders.${platform}.callPackage nixLib.mkRustLibrary (
        localArgs // { CARGO_PROFILE = "dev"; }
      );
    };

  hoprStrategyPlatformPackages = builtins.foldl' (a: b: a // b) { } (
    map mkHoprStrategyPlatformPackages [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ]
  );
in
{
  lib-hopr-strategy = builders.local.callPackage nixLib.mkRustLibrary localArgs;

  clippy = builders.local.callPackage nixLib.mkRustLibrary (
    localArgs
    // {
      runClippy = true;
    }
  );
}
// hoprStrategyPlatformPackages
