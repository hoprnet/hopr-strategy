# checks.nix - CI/CD quality checks
#
# Defines automated checks that run in CI to ensure code quality.
# These checks can also be run locally for pre-push validation.

{
  packages,
}:

{
  # Rust linting checks
  hopr-strategy-clippy = packages.clippy;
  hopr-strategy-doc = packages.doc;
  hopr-strategy-deny = packages.deny;
  hopr-strategy-test-doc = packages.test-doc;

  # Repository hygiene checks
  pre-commit = packages.pre-commit-check;
}
