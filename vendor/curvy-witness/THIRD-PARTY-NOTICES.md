# Third-party notices

The `curvy-core`, `curvy-witness`, `curvy-prover`, and `curvy-wasm` crates are
released under the MIT License (see `LICENSE`).

Portions of this software are ported or adapted from the projects listed below.
All are under permissive licenses. Each entry records the upstream project, its
license and copyright notice, and the files in this repository that derive from
it.

---

## @zk-kit/eddsa-poseidon - MIT

Copyright (c) 2024 Ethereum Foundation
<https://github.com/privacy-scaling-explorations/zk-kit>

- `crates/core/src/eddsa.rs` - port of the default (original BLAKE-512) EdDSA-Poseidon entry point
- `crates/core/src/blake512.rs` - port of `blake.ts`
- `crates/core/src/encoding.rs` - little-endian buffer/integer conventions (`leBufferToBigInt`, `leBigIntToBuffer`)

## @zk-kit/baby-jubjub 1.0.3 - MIT

Copyright (c) 2024 Ethereum Foundation
<https://github.com/privacy-scaling-explorations/zk-kit>

- `crates/core/src/babyjubjub.rs` - port of BabyJubjub point addition and scalar multiplication (EIP-2494)

## @zk-kit/imt - MIT

Copyright (c) 2024 Ethereum Foundation
<https://github.com/privacy-scaling-explorations/zk-kit>

- `crates/core/src/imt.rs` - port of the arity-2 incremental Merkle tree. The
  indexed and sharded engines in the same module are original work.

## blake-hash 2.0.0 - MIT

<https://github.com/cryptocoinjs/blake-hash>

The upstream project declares the MIT License in `package.json` and its README
but publishes no separate copyright notice.

- `crates/core/src/blake512.rs` - indirect: `@zk-kit/eddsa-poseidon`'s `blake.ts` was itself adapted from this package.

## poseidon-lite 0.2.1 - MIT

<https://github.com/vimwitch/poseidon-lite>

The upstream project declares the MIT License in `package.json` but publishes no
separate copyright notice.

- `crates/core/src/poseidon/mod.rs` - port of the unoptimized HadesHash permutation
- `crates/core/src/poseidon/constants.rs` and `crates/core/testdata/poseidon_constants.json` - round constants (`C`) and MDS matrices (`M`), transcribed verbatim

The Poseidon round constants and MDS matrices are parameters generated
deterministically (Grain LFSR) from the Poseidon specification for the BN254
scalar field.

## ark-circom 0.6.0 (circom-compat) - MIT OR Apache-2.0, used here under MIT

Copyright (c) 2021 Georgios Konstantopoulos
<https://github.com/arkworks-rs/circom-compat>

- `crates/prover/src/zkey.rs` - snarkjs `.zkey` parser, with the Wasmer-based witness calculator removed, unchecked bulk point deserialization behind a mandatory SHA-256 artifact digest, and parallel point conversion
- `crates/prover/src/qap.rs` - the snarkjs-compatible R1CS-to-QAP reduction
- `crates/prover/testdata/multiplier.zkey` - unmodified `test-vectors/test.zkey` fixture, used only by the prover integration test

---

## Note on circomlib, circomlibjs, and snarkjs (GPL-3.0)

No code from circomlib, circomlibjs, or snarkjs is included in this repository.

Those projects appear in source comments only as *compatibility targets*. The
Poseidon parameter sets, the EdDSA-Poseidon verification equation, the `.zkey`
and `.wtns` container layouts, and the snarkjs proof/public-signal JSON shapes
are formats and specifications that this code interoperates with. The
implementations here were ported from the permissively licensed projects listed
above, and the source comments record the points where behavior deliberately
diverges from circomlibjs.

`crates/prover/src/wtns.rs` and `crates/witness/src/lib.rs` are original
implementations written against the snarkjs `.wtns` container format and Curvy's
own `CVYWIT01` graph format respectively.

`crates/core/src/stealth.rs`, `cipher.rs`, `note.rs`, `witness.rs`,
`hash_utils.rs`, and `field.rs` are ports of Curvy's own Go and TypeScript
implementations.

---

## Runtime dependencies

The compiled crates link only against dependencies from crates.io under
MIT, Apache-2.0, BSD-3-Clause, Unicode-3.0, or Zlib terms. The exact set is
pinned in `Cargo.lock` and enforced on every CI run by `cargo deny` (see
`deny.toml`). Those dependencies are not redistributed in this repository and
retain their own licenses.
