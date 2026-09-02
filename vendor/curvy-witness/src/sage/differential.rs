//! Randomised differential testing of SAGE against the default evaluator.
//!
//! SAGE's only unshared logic is slot allocation, and slot allocation depends on
//! *graph topology*, not on values. A bug there frees a slot one instruction too
//! early and yields a plausible-but-wrong assignment rather than an error - which
//! downstream is a proof of the wrong statement. Fixed test graphs cannot find that
//! class, because each one exercises exactly one liveness pattern.
//!
//! So this generates random valid graphs and compares full assignments four ways:
//! the default evaluator and SAGE, each over the v1 and v2 encodings of the same
//! logical graph. That also makes the v2 encoder/decoder a differential target for
//! free.

use ark_bn254::Fr;
use sha2::{Digest, Sha256};

use super::SageGraph;
use crate::{FIELD_BN254_FR, LEGACY_MAGIC, WitnessGraph, fnv1a};

/// Operations with no input-dependent error path, so a random graph always
/// evaluates. Division, modulus, shifts and `pow` are excluded deliberately: they
/// would fail or run long on random operands and would test shared arithmetic
/// rather than SAGE's allocator.
const SAFE_OPS: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 14, 19, 21, 22];

const V2_INPUT_TAG: u8 = 0x80;
const V2_CONSTANT_TAG: u8 = 0x81;
const V2_INVERSE_TAG: u8 = 0x82;

#[derive(Clone, Copy)]
enum Record {
    Input(u32),
    Constant(u64),
    Operation { tag: u8, left: usize, right: usize },
    Inverse(usize),
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*: deterministic, so a failure reproduces from its seed alone.
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

/// A random graph that every validation rule accepts.
///
/// Node 0 is the constant one and signal 0 points at it, because both evaluators
/// require the assignment to begin with one.
fn random_graph(rng: &mut Rng) -> (Vec<Record>, Vec<usize>, usize) {
    let input_buffer_len = 2 + rng.below(14);
    // Mostly small graphs so a long run covers many topologies, with a heavy tail so
    // deep chains and wide live sets both appear.
    let node_count = match rng.below(20) {
        0 => 2 + rng.below(4000),
        1..=4 => 2 + rng.below(600),
        _ => 2 + rng.below(120),
    };
    let mut records = Vec::with_capacity(node_count);
    records.push(Record::Constant(1));

    for index in 1..node_count {
        let record = match rng.below(10) {
            0..=1 => Record::Input(rng.below(input_buffer_len) as u32),
            2..=3 => Record::Constant(rng.next() % 4096),
            4 => Record::Inverse(rng.below(index)),
            _ => Record::Operation {
                tag: SAFE_OPS[rng.below(SAFE_OPS.len())],
                left: rng.below(index),
                // Bias towards reusing the immediately preceding node, which is what
                // makes long chains of short-lived values - the case slot recycling
                // is built for. Without the bias most graphs are shallow.
                right: if rng.below(2) == 0 {
                    index - 1
                } else {
                    rng.below(index)
                },
            },
        };
        records.push(record);
    }

    let signal_count = 1 + rng.below(node_count);
    let mut signals = vec![0_usize];
    for _ in 1..signal_count {
        signals.push(rng.below(node_count));
    }
    // Referencing the final node forces at least one value to stay live throughout.
    signals.push(node_count - 1);

    (records, signals, input_buffer_len)
}

#[allow(unused_variables)]
fn encode(version: u16, records: &[Record], signals: &[usize], input_buffer_len: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    // `CVYWIT01` is accepted in every feature combination.
    bytes.extend_from_slice(LEGACY_MAGIC);
    bytes.extend_from_slice(&version.to_le_bytes());
    bytes.extend_from_slice(&FIELD_BN254_FR.to_le_bytes());
    bytes.extend_from_slice(&64_u32.to_le_bytes());
    bytes.extend_from_slice(&[0_u8; 32]);
    bytes.extend_from_slice(&(records.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(signals.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&(input_buffer_len as u32).to_le_bytes());

    for (index, record) in records.iter().enumerate() {
        match *record {
            Record::Input(input) => {
                if version == 1 {
                    bytes.push(0);
                    bytes.extend_from_slice(&input.to_le_bytes());
                } else {
                    bytes.push(V2_INPUT_TAG);
                    push_varint(&mut bytes, u64::from(input));
                }
            }
            Record::Constant(value) => {
                bytes.push(if version == 1 { 1 } else { V2_CONSTANT_TAG });
                bytes.extend_from_slice(&field_bytes(value));
            }
            Record::Operation { tag, left, right } => {
                if version == 1 {
                    bytes.push(2);
                    bytes.push(tag);
                    bytes.extend_from_slice(&(left as u32).to_le_bytes());
                    bytes.extend_from_slice(&(right as u32).to_le_bytes());
                } else {
                    bytes.push(tag);
                    push_varint(&mut bytes, (index - left) as u64);
                    push_varint(&mut bytes, (index - right) as u64);
                }
            }
            Record::Inverse(source) => {
                if version == 1 {
                    bytes.push(3);
                    bytes.extend_from_slice(&(source as u32).to_le_bytes());
                } else {
                    bytes.push(V2_INVERSE_TAG);
                    push_varint(&mut bytes, (index - source) as u64);
                }
            }
        }
    }

    if version == 1 {
        for signal in signals {
            bytes.extend_from_slice(&(*signal as u32).to_le_bytes());
        }
    } else {
        let mut previous = 0_i64;
        for signal in signals {
            let signal = *signal as i64;
            let delta = signal - previous;
            push_varint(&mut bytes, ((delta << 1) ^ (delta >> 63)) as u64);
            previous = signal;
        }
    }

    bytes.extend_from_slice(&fnv1a("a").to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&((input_buffer_len - 1) as u32).to_le_bytes());
    bytes
}

fn push_varint(bytes: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        bytes.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    bytes.push(value as u8);
}

fn field_bytes(value: u64) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    bytes
}

fn input_json(rng: &mut Rng, input_buffer_len: usize) -> String {
    let values = (1..input_buffer_len)
        .map(|_| format!("\"{}\"", rng.next() % 100_000))
        .collect::<Vec<_>>();
    format!("{{\"a\":[{}]}}", values.join(","))
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn assignments(bytes: &[u8], input: &str) -> (Vec<Fr>, Vec<Fr>) {
    let sha = digest(bytes);
    let reference = WitnessGraph::from_bytes(bytes, &sha)
        .expect("default parser accepts the graph")
        .calculate_json(input)
        .expect("default evaluator");
    let candidate = SageGraph::from_bytes(bytes, &sha)
        .expect("SAGE compiles the graph")
        .calculate_json(input)
        .expect("SAGE evaluator");
    (reference, candidate)
}

/// Graphs per test. The default keeps `cargo test` quick; long soaks set
/// `SAGE_FUZZ_ITERATIONS` (a million takes a few minutes across all cores).
fn iterations(default: usize) -> usize {
    std::env::var("SAGE_FUZZ_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn shards() -> usize {
    std::env::var("SAGE_FUZZ_THREADS")
        .ok()
        .and_then(|value| value.parse().ok())
        .or_else(|| std::thread::available_parallelism().ok().map(Into::into))
        .unwrap_or(1)
        .max(1)
}

/// Run `total` iterations across threads, each shard deterministically seeded from
/// `base_seed` so any failure reproduces from its seed and index alone.
fn sharded<F, T>(total: usize, base_seed: u64, body: F) -> Vec<T>
where
    F: Fn(&mut Rng, usize) -> T + Sync,
    T: Send,
{
    let shards = shards().min(total.max(1));
    let per_shard = total.div_ceil(shards);
    std::thread::scope(|scope| {
        let handles = (0..shards)
            .map(|shard| {
                let body = &body;
                scope.spawn(move || {
                    let mut rng =
                        Rng(base_seed ^ ((shard as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15)));
                    let count = per_shard.min(total.saturating_sub(shard * per_shard));
                    (0..count)
                        .map(|_| body(&mut rng, shard))
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("fuzz shard panicked"))
            .collect()
    })
}

#[test]
fn sage_matches_the_default_evaluator_on_random_graphs() {
    let total = iterations(400);
    let outcomes = sharded(total, 0x5EED_1234_ABCD_0001, |rng, shard| {
        let (records, signals, input_buffer_len) = random_graph(rng);
        let input = input_json(rng, input_buffer_len);
        let v1 = encode(1, &records, &signals, input_buffer_len);
        let (reference_v1, sage_v1) = assignments(&v1, &input);
        assert_eq!(sage_v1, reference_v1, "shard {shard}: SAGE differs on v1");

        // Version 2 only exists behind `signet`, so it is only a differential
        // target when that feature is on.
        #[cfg(feature = "signet")]
        {
            let v2 = encode(2, &records, &signals, input_buffer_len);
            let (reference_v2, sage_v2) = assignments(&v2, &input);
            assert_eq!(sage_v2, reference_v2, "shard {shard}: SAGE differs on v2");
            assert_eq!(
                reference_v1, reference_v2,
                "shard {shard}: the two encodings differ"
            );
        }

        let slots = SageGraph::from_bytes(&v1, &digest(&v1))
            .expect("SAGE compiles the graph")
            .slot_count();
        (records.len(), slots)
    });

    // A run where nothing recycled would pass every assertion above while testing
    // none of what makes SAGE different.
    let recycled = outcomes
        .iter()
        .filter(|(nodes, slots)| slots < nodes)
        .count();
    let nodes: usize = outcomes.iter().map(|(nodes, _)| nodes).sum();
    let slots: usize = outcomes.iter().map(|(_, slots)| slots).sum();
    let largest = outcomes.iter().map(|(nodes, _)| *nodes).max().unwrap_or(0);
    println!(
        "graphs={total} recycled={recycled} nodes={nodes} slots={slots} \
         slot_ratio={:.4} largest_graph={largest}",
        slots as f64 / nodes as f64,
    );
    assert!(
        recycled * 4 > total * 3,
        "only {recycled}/{total} graphs exercised slot reuse; the generator has drifted"
    );
}

#[test]
fn sage_rejects_every_graph_the_default_parser_rejects() {
    let total = iterations(600);
    let accepted = sharded(total, 0xC0FF_EE00_1234_5678, |rng, shard| {
        let (records, signals, input_buffer_len) = random_graph(rng);
        #[cfg(feature = "signet")]
        let mut bytes = encode(2, &records, &signals, input_buffer_len);
        #[cfg(not(feature = "signet"))]
        let mut bytes = encode(1, &records, &signals, input_buffer_len);
        // Corrupt one byte anywhere past the header.
        let position = 64 + rng.below(bytes.len() - 64);
        bytes[position] ^= 1 << rng.below(8);
        let sha = digest(&bytes);

        // Whatever the default parser does with this, SAGE must agree - accepting a
        // graph the shipped evaluator rejects would be a strictly larger attack
        // surface behind the same authentication.
        let reference = WitnessGraph::from_bytes(&bytes, &sha);
        let candidate = SageGraph::from_bytes(&bytes, &sha);
        assert_eq!(
            reference.is_ok(),
            candidate.is_ok(),
            "shard {shard}: parsers disagree on a corrupted graph: default={:?} sage={:?}",
            reference.err(),
            candidate.err(),
        );

        // Most single-bit flips land in a constant or a varint payload and still
        // decode, so the majority of these reach evaluation. Those are the valuable
        // ones: mutation reaches topologies the generator would not choose, and
        // agreeing on *rejection* proves much less than agreeing on the assignment.
        let (Ok(reference), Ok(candidate)) = (reference, candidate) else {
            return 0;
        };
        let input = input_json(rng, input_buffer_len);
        match (
            reference.calculate_json(&input),
            candidate.calculate_json(&input),
        ) {
            (Ok(reference), Ok(candidate)) => {
                assert_eq!(
                    candidate, reference,
                    "shard {shard}: SAGE differs on a mutated graph"
                );
                1
            }
            (Err(_), Err(_)) => 1,
            (reference, candidate) => panic!(
                "shard {shard}: evaluators disagree on a mutated graph: \
                 default_ok={} sage_ok={}",
                reference.is_ok(),
                candidate.is_ok()
            ),
        }
    });

    // A run where corruption always killed the parse would prove much less than it
    // looks, so surface how many actually reached the evaluators.
    let survived: usize = accepted.iter().sum();
    println!("corrupted={total} reached_evaluation={survived}");
    assert!(
        survived * 4 > total,
        "only {survived}/{total} mutated graphs survived parsing"
    );
}
