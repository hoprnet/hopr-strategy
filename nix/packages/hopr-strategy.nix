# hopr-strategy.nix - hopr-strategy library package definitions
#
# Defines all variants of the hopr-strategy library for different platforms.
# hopr-strategy is a Rust library crate implementing HOPR channel strategies.

{
  lib,
  pkgs,
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

  doc = builders.local.callPackage nixLib.mkRustLibrary (localArgs // { runDoc = true; });

  # Bans, licenses and sources from deny.toml. Advisories need network and run in `nix run .#audit`.
  deny = builders.local.callPackage nixLib.mkRustLibrary (localArgs // { runDeny = true; });

  # All test targets of the library (no `--lib`); the integration crate has its own package.
  test =
    (builders.local.callPackage nixLib.mkRustLibrary (
      localArgs
      // {
        src = sources.test;
        runTests = true;
        extraNativeBuildInputs = [ pkgs.cargo-nextest ];
      }
    )).overrideAttrs
      (_: {
        checkPhase = ''
          cargo nextest run --all-features --no-fail-fast
        '';
      });

  # nextest does not run doctests
  test-doc =
    (builders.local.callPackage nixLib.mkRustLibrary (
      localArgs
      // {
        src = sources.test;
        runTests = true;
      }
    )).overrideAttrs
      (_: {
        checkPhase = ''
          cargo test --doc --all-features
        '';
      });

  integration-tests = builders.local.callPackage nixLib.mkRustPackage (
    (mkHoprStrategyBuildArgs {
      src = sources.test;
      depsSrc = sources.deps;
    })
    // {
      cargoToml = ./../../tests/integration/Cargo.toml;
      runNextest = true;
      prependPackageName = false;
      cargoExtraArgs = "-p hopr-strategy-integration-tests";
    }
  );

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

  # The same for the integration suite.  It drives whole strategies against a
  # stub chain, so it is what covers the failure paths — lost events, stalled
  # confirmations, exhausted budgets — that no unit test can reach; without this
  # they count as uncovered.
  coverage-integration = builders.localCoverage.callPackage nixLib.mkRustPackage {
    src = sources.test;
    depsSrc = sources.deps;
    cargoToml = ./../../Cargo.toml;
    inherit rev;
    runCoverage = true;
    # Selects targets, not packages: the library has to stay in scope to be
    # reported on, so excluding it — or naming the integration crate with `-p`,
    # which the builder's own `--workspace` forbids — yields a report covering
    # only the test crate's source.  `--tests` therefore also re-runs the lib's
    # unit tests, which costs a few seconds and makes this report a superset of
    # the unit one.
    cargoExtraArgs = "--all-features --tests";
  };
}
// hoprStrategyPlatformPackages
