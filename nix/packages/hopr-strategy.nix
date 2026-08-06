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
      cargoExtraArgs = "--all-features";
    };

  localArgs = mkHoprStrategyBuildArgs {
    src = sources.main;
    depsSrc = sources.deps;
  };

  clippyDerivation = builders.local.callPackage nixLib.mkRustLibrary (
    localArgs
    // {
      runClippy = true;
    }
  );

  # Reuse Clippy's dev-profile dependency artifacts for the standalone
  # `cargo check` validation performed by `just quick`.
  checkDerivation = clippyDerivation.overrideAttrs (_: {
    pname = "hopr-strategy-check";
    buildPhase = ''
      runHook preBuild
      cargo check --all-features
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p "$out"
    '';
  });

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

  check = checkDerivation;

  clippy = clippyDerivation;

  # Cacheable nextest archive. The archive is built in the Nix sandbox, while
  # `nix run .#test-integration` executes it on the host where Docker is usable.
  integration-tests = builders.local.callPackage ./integration-tests.nix {
    inherit sources rev;
  };

  # Run the unit-test suite under cargo-llvm-cov and expose the LCOV report as
  # the derivation output so CI can restore both dependencies and results from
  # the binary cache.
  coverage = builders.localCoverage.callPackage nixLib.mkRustPackage {
    src = sources.test;
    depsSrc = sources.deps;
    cargoToml = ./../../Cargo.toml;
    inherit rev;
    runCoverage = true;
    cargoExtraArgs = "--all-features --lib";
  };
}
// hoprStrategyPlatformPackages
