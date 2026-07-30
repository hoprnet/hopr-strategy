# ============================================================================
# Default Command
# ============================================================================

# Show available commands
default:
    @just --list

# ============================================================================
# Quick Workflows
# ============================================================================

# Quick check - format, clippy, and check
quick: fmt clippy check

# Development build and test cycle - format, check, and test
dev: fmt check test

# Watch for changes and run checks continuously
watch:
    cargo watch -x check -x test

# ============================================================================
# Build Commands
# ============================================================================

# Build in debug mode
build:
    cargo build --all-features

# Build in release mode with full optimizations
build-release:
    cargo build --all-features --release

# Check code without building binaries
check:
    cargo check --all-features

# Clean all build artifacts
clean:
    cargo clean

# ============================================================================
# Test Commands
# ============================================================================

# Run unit tests
test:
    ./.github/scripts/generate-metrics-docs.sh
    cargo test --workspace --exclude hopr-strategy-integration-tests --all-features --no-fail-fast

# Run unit tests in single thread mode with output (integration crate excluded).
test-debug:
    cargo test --workspace --exclude hopr-strategy-integration-tests --all-features -- --test-threads=1 --nocapture

# Run all unit tests using nextest (integration crate excluded).
nextest:
    cargo nextest run --workspace --exclude hopr-strategy-integration-tests --all-features

# Run strategy integration tests against a Blokli-Anvil docker stack.
# Requires docker running on the host + a pullable bloklid image (set BLOKLI_TEST_REMOTE_IMAGE).
test-integration:
    cargo test --manifest-path tests/integration/Cargo.toml -- --nocapture

# ============================================================================
# Code Quality
# ============================================================================

# Format all code with the treefmt wrapper provided by the dev shell
fmt:
    treefmt

# Run clippy lints with warnings as errors
clippy:
    cargo clippy --all-features -- -D warnings

# Run clippy on all targets
clippy-all:
    cargo clippy --all-features --all-targets -- -D warnings

# Automatically fix clippy warnings
clippy-fix:
    cargo clippy --all-features --fix --allow-dirty --allow-staged

# ============================================================================
# Documentation
# ============================================================================

# Generate and open documentation for this crate only
doc:
    cargo doc --all-features --no-deps --open

# Generate and open documentation including all dependencies
doc-all:
    cargo doc --all-features --open

# ============================================================================
# Dependency Management
# ============================================================================

# Update all dependencies to latest compatible versions
update:
    cargo update

# Show outdated dependencies that have newer versions available
outdated:
    cargo outdated
