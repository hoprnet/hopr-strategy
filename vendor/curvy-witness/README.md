# curvy-witness

Authenticated parser and evaluator for Curvy's offline-compiled
`curvy-graph-v1` Circom witness artifacts.

Use this crate when an integration needs the full BN254 witness assignment but
will perform proving elsewhere. Use `curvy-prover` when witness evaluation and
local Groth16 proving should be one operation.

## Install

```toml
[dependencies]
curvy-witness = "=0.1.0-rc.3"
```

## Evaluate a graph

```rust,no_run
use curvy_witness::WitnessGraph;

let graph_bytes = std::fs::read("circuit.graph.bin")?;
let graph = WitnessGraph::from_bytes(
    &graph_bytes,
    "0000000000000000000000000000000000000000000000000000000000000000",
)?;
let assignment = graph.calculate_json(r#"{"amount":"42"}"#)?;

assert_eq!(assignment.len(), graph.assignment_size());
# Ok::<(), Box<dyn std::error::Error>>(())
```

The expected SHA-256 is mandatory and is checked before graph parsing. For a
compressed artifact it authenticates the zstd frame bytes, before decoding.
Parsing also enforces graph/input size limits, canonical BN254 field values, valid
node references, and strict input names and shapes. The crate does not depend on
another Circom witness runtime.

## Accepted artifacts

A default build reads the `SIGNET01` and `CVYWIT01` envelopes at body version 1,
raw or zstd-compressed.

| feature | adds |
|---|---|
| `signet-v2` | the version-2 body encoding: varint distances and ZigZag output deltas. Not stable; no published artifact uses it. |
| `sage` | `sage::SageGraph`, a second evaluator over the same artifacts. |

See the [workspace guide](https://github.com/0xCurvy/rs-core#readme) for artifact
and build-target guidance.
