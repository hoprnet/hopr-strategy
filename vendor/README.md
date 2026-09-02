# Vendored Curvy crates

`curvy-prover` and `curvy-witness` are byte-identical copies of the `0.1.0-rc.3` releases
published on crates.io, with **one** change each: `thiserror = "=2.0.19"` relaxed to
`thiserror = "2.0.19"` in `Cargo.toml`, plus an empty `[workspace]` table so the copies do not
join the enclosing workspace.

## Why

The published crates pin `thiserror` to exactly 2.0.19. `hopr-api` 4.x and `hopr-chain-connector`
0.26 require `^2.0.20`. Cargo resolves a single `thiserror 2.x` for the whole graph, so with the
published crates the `strategy-pix-curvy` feature is unresolvable — not a compile error, a
dependency-resolution error before anything is built.

The crates are pulled in transitively through `curvy-sdk` (git) → `curvy-witnesscalc` →
`curvy-prover` → `curvy-witness`, and the `[patch.crates-io]` section in the root `Cargo.toml`
substitutes these copies for the registry versions.

## Consequences for consumers

Cargo only honours `[patch]` tables from the **root** workspace. A crate that depends on
`hopr-strategy` with `strategy-pix-curvy` therefore has to repeat the two patch lines, pointing at
this repository (Cargo locates the packages by name anywhere in the git checkout):

```toml
[patch.crates-io]
curvy-prover  = { git = "https://github.com/hoprnet/hopr-strategy", rev = "<the pinned rev>" }
curvy-witness = { git = "https://github.com/hoprnet/hopr-strategy", rev = "<the pinned rev>" }
```

## Removing this

Upstream (`0xCurvy/rs-core`) has an open dependabot branch bumping the pin. Once a release with a
compatible requirement (`=2.0.20` or, better, `"2"`) is on crates.io:

1. bump `curvy-core`/`curvy-sdk` to a matching release in the root `Cargo.toml`,
2. delete the `[patch.crates-io]` section and this directory,
3. drop the patch lines from consumers.
