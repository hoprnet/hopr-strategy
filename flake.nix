# flake.nix - HOPR hopr-strategy Nix flake configuration
#
# This is the main entry point for the Nix flake. It uses the HOPR nix-lib
# for reusable Rust build functions and formatting configuration.
#
# Structure:
# - nix/packages/: Package definitions (hopr-strategy)
# - nix/checks.nix: CI/CD quality checks
# - nix-lib (external): Rust builders, treefmt, and utilities

{
  description = "HOPR hopr-strategy - Implementations of different HOPR strategies";

  # External dependencies - kept in main flake for Nix flake requirements
  #
  # Core Nix ecosystem dependencies:
  # - flake-parts: Modular flake framework for better organization
  # - nixpkgs: The main Nix package repository
  # - nix-lib: HOPR Nix library with reusable Rust build functions
  #
  # Development tools and quality assurance:
  # - pre-commit: Git hooks for code quality enforcement
  # - flake-root: Utilities for finding flake root directory
  #
  # Input optimization strategy:
  # nixpkgs, nixpkgs-unstable, rust-overlay and crane follow nix-lib, so every hoprnet flake on
  # the same nix-lib release shares one set of revisions; the other inputs follow nixpkgs.
  inputs = {
    # Core Nix ecosystem dependencies
    flake-parts.url = "github:hercules-ci/flake-parts";

    # HOPR Nix Library (provides flake-utils and reusable build functions)
    nix-lib.url = "github:hoprnet/nix-lib/v2.2.1";
    # nix-lib anchors the heavy pins (nixpkgs, nixpkgs-unstable, rust-overlay, crane) so every
    # hoprnet flake on the same nix-lib release shares them. To bump them, point nix-lib.url at
    # the new release tag, then run `nix flake update nix-lib`.
    nixpkgs.follows = "nix-lib/nixpkgs";
    nixpkgs-unstable.follows = "nix-lib/nixpkgs-unstable";

    # Rust build system
    crane.follows = "nix-lib/crane";
    rust-overlay.follows = "nix-lib/rust-overlay";

    # Development tools and quality assurance
    pre-commit.url = "github:cachix/git-hooks.nix";
    flake-root.url = "github:srid/flake-root";
    treefmt-nix.url = "github:numtide/treefmt-nix";

    # Input dependency optimization
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    pre-commit.inputs.nixpkgs.follows = "nixpkgs";
    nix-lib.inputs.treefmt-nix.follows = "treefmt-nix";
    nix-lib.inputs.flake-parts.follows = "flake-parts";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-unstable,
      flake-parts,
      nix-lib,
      crane,
      rust-overlay,
      pre-commit,
      ...
    }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      # Import flake modules for additional functionality
      imports = [
        inputs.nix-lib.flakeModules.default
        inputs.flake-root.flakeModule
      ];

      # Per-system configuration
      # Each system gets its own set of packages, shells, etc.
      perSystem =
        {
          config,
          lib,
          system,
          ...
        }:
        let
          # Git revision for version tracking
          rev = toString (self.shortRev or (self.dirtyShortRev or "dirty"));

          # Filesystem utilities for source filtering
          fs = lib.fileset;

          # Nixpkgs with rust-overlay
          overlays = [
            rust-overlay.overlays.default
          ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          pkgsUnstable = import nixpkgs-unstable { inherit system; };

          # Platform information
          buildPlatform = pkgs.stdenv.buildPlatform;

          # Import nix-lib for this system
          nixLib = nix-lib.lib.${system};

          # Crane library for Rust builds (for crate info extraction)
          craneLib = (crane.mkLib pkgs).overrideToolchain (p: p.rust-bin.stable.latest.default);

          # hopr-strategy crate information
          hoprStrategyCrateInfoOriginal = craneLib.crateNameFromCargoToml {
            cargoToml = ./Cargo.toml;
          };
          hoprStrategyCrateInfo = {
            pname = "hopr-strategy";
            # Normalize version to major.minor.patch for consistent caching
            version = pkgs.lib.strings.concatStringsSep "." (
              pkgs.lib.lists.take 3 (builtins.splitVersion hoprStrategyCrateInfoOriginal.version)
            );
          };

          # Create source trees for different build contexts using nix-lib
          sources = {
            main = nixLib.mkSrc {
              inherit fs;
              root = ./.;
              extraExtensions = [ "snap" ];
            };
            test = nixLib.mkTestSrc {
              inherit fs;
              root = ./.;
              extraExtensions = [ "snap" ];
            };
            deps = nixLib.mkDepsSrc {
              inherit fs;
              root = ./.;
            };
          };

          # Create all Rust builders for cross-compilation using nix-lib
          builders = nixLib.mkRustBuilders {
            rustToolchainFile = ./rust-toolchain.toml;
          };

          hoprStrategyPackages = import ./nix/packages/hopr-strategy.nix {
            inherit
              lib
              pkgs
              builders
              sources
              hoprStrategyCrateInfo
              rev
              nixLib
              ;
          };

          # Combine all packages
          packages = hoprStrategyPackages // {
            # Pre-commit hooks check
            pre-commit-check = pkgs.callPackage ./nix/packages/pre-commit-check.nix {
              inherit
                pre-commit
                system
                config
                ;
            };

            # Cacheable equivalent of `just quick`: formatting, Clippy,
            # cargo check, cargo-deny, rustdoc and doctests. linkFarm makes each validation an explicit input so
            # Cachix can restore their independent outputs.
            quick = pkgs.linkFarm "quick" [
              {
                name = "format";
                path = config.treefmt.build.check self;
              }
              {
                name = "clippy";
                path = hoprStrategyPackages.clippy;
              }
              {
                name = "check";
                path = hoprStrategyPackages.check;
              }
              {
                name = "deny";
                path = hoprStrategyPackages.deny;
              }
              {
                name = "doc";
                path = hoprStrategyPackages.doc;
              }
              {
                name = "test-doc";
                path = hoprStrategyPackages.test-doc;
              }
            ];
          };

          utilityApps = {
            update-github-labels = nixLib.mkUpdateGithubLabelsApp;
            audit = nixLib.mkAuditApp { };
            semver-checks = nixLib.mkSemverChecksApp { rustToolchain = stableToolchain; };
            check = nixLib.mkCheckApp { inherit system; };
            test = {
              type = "app";
              program = toString (
                pkgs.writeShellScript "test" ''
                  nix develop --command ${pkgs.just}/bin/just test
                ''
              );
            };
            nextest = {
              type = "app";
              program = toString (
                pkgs.writeShellScript "nextest" ''
                  export PATH="${pkgs.cargo-nextest}/bin:$PATH"
                  nix develop --command ${pkgs.just}/bin/just nextest
                ''
              );
            };
            test-integration = {
              type = "app";
              program = toString (
                pkgs.writeShellScript "test-integration" ''
                  nix build -L .#integration-tests
                ''
              );
            };
          };

          # Rust toolchains
          stableToolchain =
            (pkgs.pkgsBuildHost.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override
              {
                targets = [
                  (
                    if buildPlatform.config == "arm64-apple-darwin" then
                      "aarch64-apple-darwin"
                    else
                      buildPlatform.config
                  )
                ];
              };

          nightlyToolchain = (pkgs.pkgsBuildHost.rust-bin.nightly.latest.default).override {
            targets = [
              (
                if buildPlatform.config == "arm64-apple-darwin" then
                  "aarch64-apple-darwin"
                else
                  buildPlatform.config
              )
            ];
            extensions = [
              "rust-src"
              "rust-analyzer"
              "clippy"
              "rustfmt"
            ];
          };

          # Development shells using nix-lib
          shellArgs = {
            treefmtWrapper = config.treefmt.build.wrapper;
            treefmtPrograms = pkgs.lib.attrValues config.treefmt.build.programs;
            shellHook = ''
              # Runner-provided Nix binaries must not load libraries from this
              # shell's newer glibc closure.
              _hopr_ld_library_path="''${LD_LIBRARY_PATH-}"
              unset LD_LIBRARY_PATH

              echo "Running pre-commit checks..."
              _github_token="''${GITHUB_TOKEN:-''${GH_TOKEN:-$(gh auth token 2>/dev/null || true)}}"
              if [ -n "$_github_token" ]; then
                export GITHUB_TOKEN="$_github_token"
              fi
              unset _github_token
              ${packages.pre-commit-check.shellHook}

              if [ -n "$_hopr_ld_library_path" ]; then
                export LD_LIBRARY_PATH="$_hopr_ld_library_path"
              else
                unset LD_LIBRARY_PATH
              fi
              unset _hopr_ld_library_path
            '';
            extraPackages = with pkgs; [
              gh
              cargo-insta
              cargo-machete
              # From unstable: cargo-release 1.1.7 needs rustc 1.97, release-26.05 ships 1.95.
              pkgsUnstable.cargo-release
              cargo-shear
              yq
            ];
          };
          shells = {
            default = nixLib.mkDevShell (
              {
                rustToolchain = stableToolchain;
                shellName = "Development";
              }
              // shellArgs
            );

            experiment = nixLib.mkDevShell (
              {
                rustToolchain = nightlyToolchain;
                shellName = "Experimental Nightly";
              }
              // shellArgs
            );

            ci = nixLib.mkDevShell {
              rustToolchainFile = ./rust-toolchain.toml;
              shellName = "hopr-strategy CI";
              treefmtWrapper = config.treefmt.build.wrapper;
              treefmtPrograms = pkgs.lib.attrValues config.treefmt.build.programs;
              extraPackages = with pkgs; [
                cargo-machete
                pkgsUnstable.cargo-release
                cargo-shear
                zizmor
              ];
            };
            coverage = nixLib.mkDevShell {
              rustToolchainFile = ./rust-toolchain.toml;
              shellName = "Coverage";
              withLlvmTools = true;
            };
          };

          # Import checks
          checks = import ./nix/checks.nix {
            inherit packages;
          };
        in
        {
          # Configure treefmt using nix-lib options
          nix-lib.treefmt = {
            extraFormatters = {
              programs.nixfmt.package = pkgs.nixfmt;
              settings.formatter.shfmt.includes = [
                "*.sh"
                ".github/scripts/*.sh"
              ];
              settings.formatter.yamlfmt.includes = [
                ".github/labeler.yml"
                ".github/workflows/*.yaml"
              ];
              # Markdown formatter
              settings.formatter.deno = {
                command = pkgs.writeShellApplication {
                  name = "deno-fmt";
                  runtimeInputs = [ pkgs.deno ];
                  text = ''
                    deno fmt --config deno.json "$@"
                  '';
                };
                includes = [
                  "**/*.md"
                  "*.md"
                ];
              };
              # GitHub Actions workflow linter
              settings.formatter.actionlint = {
                command = pkgs.writeShellApplication {
                  name = "actionlint";
                  runtimeInputs = [ pkgs.actionlint ];
                  text = ''
                    actionlint "$@"
                  '';
                };
                includes = [ ".github/workflows/*.yaml" ];
              };
            };
          };

          # Export checks for CI
          inherit checks;

          # Export applications using nix-lib
          apps = utilityApps // {
            coverage-unit = {
              type = "app";
              program = toString (
                pkgs.writeShellScript "coverage-unit" ''
                  nix build -L .#coverage -o coverage.lcov
                ''
              );
            };
          };

          # Export packages
          packages = packages // {
            # Set default package
            default = packages.lib-hopr-strategy;
          };

          # Export development shells
          devShells = shells;

          # Formatter is automatically exported by nix-lib.flakeModules.default
        };

      # Supported systems for building
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
    };
}
