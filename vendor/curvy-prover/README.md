# curvy-prover

Authenticated Curvy witness evaluation and self-verified arkworks Groth16
proving for existing snarkjs artifacts.

`CircuitProver` combines a deployment's `curvy-graph-v1` artifact and matching
`.zkey`. `Prover` can instead consume an existing snarkjs `.wtns` assignment.
This crate also publishes the `curvy-native-prover` executable and can be built
as the standalone prover WASM module.

## Install

```toml
[dependencies]
curvy-prover = "=0.1.0-rc.3"
```

## Prove from circuit input JSON

```rust,no_run
use curvy_prover::CircuitProver;

let zkey = std::fs::read("circuit.zkey")?;
let graph = std::fs::read("circuit.graph.bin")?;
let prover = CircuitProver::from_artifacts(
    &zkey,
    "0000000000000000000000000000000000000000000000000000000000000000",
    &graph,
    "0000000000000000000000000000000000000000000000000000000000000000",
)?;
let proof = prover.prove_json(r#"{"amount":"42"}"#)?;

println!("{}", proof.proof_json);
println!("{}", proof.public_signals_json);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Both artifact hashes are checked before their respective parsers run. Generated
proofs are verified internally before being returned.

## Features and execution targets

| Feature | Purpose |
|---|---|
| `std` | Native standard-library support; enabled by default |
| `parallel` | Rayon and arkworks parallel proving; enabled by default |
| `wasm` | Portable wasm-bindgen prover API |
| `wasm-threads` | Shared-memory browser prover with `initThreadPool(n)` |

The native executable accepts `CURVY_PROVER_NUM_THREADS=1..64` and defaults to
one thread. Library consumers can configure Rayon globally. Threaded WASM hosts
choose the worker count by awaiting the generated module's `initThreadPool(n)`.

See the [workspace guide](https://github.com/0xCurvy/rs-core#readme) for complete
commands, output directories, and threaded-browser requirements.
