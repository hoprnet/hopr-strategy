{
  craneLib,
  cargo-nextest,
  libiconv,
  llvmPackages,
  openssl,
  pkg-config,
  sources,
  rev,
  ...
}:

let
  cargoExtraArgs = "-p hopr-strategy-integration-tests";
  commonArgs = {
    pname = "hopr-strategy-integration-tests";
    version = "0.1.0";
    src = sources.test;
    cargoToml = ./../../tests/integration/Cargo.toml;
    inherit cargoExtraArgs rev;
    CARGO_PROFILE = "test";
    strictDeps = true;
    nativeBuildInputs = [
      llvmPackages.bintools
      pkg-config
      libiconv
    ];
    buildInputs = [ openssl ];
  };

  # Compile all normal and dev dependencies separately so Cachix can restore
  # the expensive part of the integration-test build independently.
  cargoArtifacts = craneLib.buildDepsOnly (
    commonArgs
    // {
      src = sources.deps;
      # A single no-run test build prepares both normal and dev dependencies
      # in the same profile consumed by the final nextest archive.
      buildPhaseCargoCommand = "";
      cargoTestExtraArgs = "--no-run";
    }
  );
in
craneLib.mkCargoDerivation (
  commonArgs
  // {
    inherit cargoArtifacts;
    nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ cargo-nextest ];
    doCheck = true;
    doInstallCargoArtifacts = false;
    buildPhaseCargoCommand = ''
      cargo nextest --version
    '';
    checkPhaseCargoCommand = ''
      mkdir -p "$out"
      cargo nextest archive \
        --cargo-profile test \
        ${cargoExtraArgs} \
        --archive-format tar-zst \
        --archive-file "$out/integration-tests.tar.zst"
    '';
    installPhaseCommand = "true";
  }
)
