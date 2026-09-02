//! SAGE - the Slot-Allocated Graph Evaluator.
//!
//! **Experimental.** Behind the `sage` feature; the API may change without a major
//! version. The default [`WitnessGraph`](crate::WitnessGraph) is the supported
//! evaluator.
//!
//! # Why it exists
//!
//! [`WitnessGraph`](crate::WitnessGraph) keeps one `Fr` per graph node for the
//! whole evaluation, because any later node may reference any earlier one. Most
//! nodes are dead almost immediately, so that array is mostly waste: pending(50)
//! has 7,442,816 nodes (227 MiB of values) but never needs more than 16,436 of
//! them live at once (0.50 MiB).
//!
//! SAGE compiles the graph once into fixed-width instructions with
//! liveness-allocated value slots, then reuses a slot as soon as its last reader
//! has run. Outputs are copied into the assignment the moment they are produced,
//! so an output does not pin a slot to the end.
//!
//! # What it does not change
//!
//! The wire format, the authentication, and the arithmetic are shared with the
//! default evaluator - this module adds a storage strategy, not a second graph
//! format or a second decoder. `read_node_record` is the only wire-format reader
//! in the crate, so the two cannot drift.
//!
//! # The saving is empirical, not a bound
//!
//! Slot count depends on graph topology, and nothing forces it below the node
//! count: a graph whose late instructions read its earliest nodes keeps everything
//! live, and `slots` approaches `node_count`. Constants trade back too - 16 bytes
//! of instruction plus 32 in the constant pool, against 40 in the default
//! `Vec<Node>`.
//!
//! So at the configured maxima the two are comparable (roughly 625 MiB here against
//! roughly 720 MiB for the default evaluator), and the large measured wins come
//! from what real circuits actually look like. **Do not treat this evaluator as
//! justification for raising any limit** - the budget behind [`crate::Limits`]
//! must continue to hold for the default evaluator on its own.
//!
//! # Measured
//!
//! Peak RSS and warm witness time, macOS release build, against the pinned
//! artifacts and their snarkjs reference witnesses:
//!
//! | profile | nodes | live slots | default evaluator | SAGE |
//! |---|---:|---:|---:|---:|
//! | pending(5,30) | 1,106,576 | 4,916 | ~96 MB | ~50 MB |
//! | pending(50,30) | 7,442,816 | 16,436 | ~638 MB | ~332 MB |

use ark_bn254::Fr;
use ark_ff::{Field, Zero};

#[cfg(feature = "signet")]
use crate::decompress_graph;
use crate::{
    Artifact, InputMapping, Limits, NodeRecord, Operation, WitnessError, authenticate,
    build_input_buffer, constant_from_bytes, preflight_body_size, read_header, read_input_mappings,
    read_node_record, read_output_references, reserved_vec,
};

/// One compiled instruction: three `u32` operand slots plus an opcode.
///
/// `left` means different things per kind - an input index, a constant index, or a
/// value slot - which is why [`SageGraph::calculate_json`] dispatches on `kind`
/// before it indexes anything.
#[derive(Debug, Clone, Copy)]
struct Instruction {
    left: u32,
    right: u32,
    destination: u32,
    kind: Kind,
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    Input,
    Constant,
    Inverse,
    Operation(Operation),
}

/// Copy a produced value into its final assignment position.
#[derive(Debug, Clone, Copy)]
struct OutputWrite {
    node: u32,
    signal: u32,
}

/// A graph compiled for slot-allocated evaluation.
///
/// Construction cost is one extra pass over the wire bytes to compute liveness;
/// after that the graph is immutable and evaluation allocates only the value slots
/// and the assignment.
pub struct SageGraph {
    limits: Limits,
    instructions: Vec<Instruction>,
    constants: Vec<Fr>,
    outputs: Vec<OutputWrite>,
    input_mapping: Vec<InputMapping>,
    input_buffer_len: usize,
    signal_count: usize,
    slots: usize,
    r1cs_sha256: [u8; 32],
}

impl SageGraph {
    /// Authenticate, decode, and compile an immutable graph artifact.
    ///
    /// Accepts exactly the artifacts [`WitnessGraph::from_bytes`](crate::WitnessGraph::from_bytes)
    /// accepts, and enforces the same limits.
    pub fn from_bytes(bytes: &[u8], expected_sha256: &str) -> Result<Self, WitnessError> {
        Self::from_bytes_with_limits(bytes, expected_sha256, Limits::default())
    }

    /// Authenticate, decode and compile under explicit ceilings.
    pub fn from_bytes_with_limits(
        bytes: &[u8],
        expected_sha256: &str,
        limits: Limits,
    ) -> Result<Self, WitnessError> {
        // Same authentication, same size caps, same compression support as the
        // default evaluator - sharing the helper is what stops the two drifting.
        match authenticate(bytes, expected_sha256, &limits)? {
            Artifact::Raw => compile(bytes, limits),
            #[cfg(feature = "signet")]
            Artifact::Zstd => compile(&decompress_graph(bytes, &limits)?, limits),
        }
    }

    /// Evaluate JSON circuit signals into the arkworks assignment.
    ///
    /// Produces the identical assignment to
    /// [`WitnessGraph::calculate_json`](crate::WitnessGraph::calculate_json).
    pub fn calculate_json(&self, input_json: &str) -> Result<Vec<Fr>, WitnessError> {
        let inputs = build_input_buffer(
            &self.input_mapping,
            self.input_buffer_len,
            input_json,
            &self.limits,
        )?;
        let mut values = reserved_vec("evaluation slots", self.slots)?;
        values.resize(self.slots, Fr::zero());
        let mut assignment = reserved_vec("witness assignment", self.signal_count)?;
        assignment.resize(self.signal_count, Fr::zero());
        let mut output_index = 0_usize;

        for (index, instruction) in self.instructions.iter().copied().enumerate() {
            // Dispatch first: `left` is only a value slot for the last two kinds.
            let value = match instruction.kind {
                Kind::Input => *slot(&inputs, instruction.left, "input")?,
                Kind::Constant => *slot(&self.constants, instruction.left, "constant")?,
                Kind::Inverse => slot(&values, instruction.left, "inverse source")?
                    .inverse()
                    .unwrap_or_else(Fr::zero),
                Kind::Operation(operation) => {
                    let left = *slot(&values, instruction.left, "left source")?;
                    let right = *slot(&values, instruction.right, "right source")?;
                    operation.evaluate(index, left, right)?
                }
            };
            *slot_mut(&mut values, instruction.destination, "destination")? = value;

            // Outputs are sorted by node, so every write for this node is contiguous.
            // Copying `value` rather than re-reading the slot is load-bearing: it is
            // what lets this node's slot be recycled on the very next instruction.
            while let Some(output) = self
                .outputs
                .get(output_index)
                .filter(|output| output.node as usize == index)
            {
                *slot_mut(&mut assignment, output.signal, "output signal")? = value;
                output_index += 1;
            }
        }

        // Every output must have been consumed. Unwritten signals would stay zero
        // and produce a silently wrong witness rather than a failure.
        if output_index != self.outputs.len() {
            return Err(WitnessError::CompiledIndex {
                what: "output write",
            });
        }
        if assignment.first().copied() != Some(Fr::from(1_u64)) {
            return Err(WitnessError::InvalidAssignmentOne);
        }
        Ok(assignment)
    }

    pub fn assignment_size(&self) -> usize {
        self.signal_count
    }

    pub fn r1cs_sha256(&self) -> [u8; 32] {
        self.r1cs_sha256
    }

    /// Live value slots this graph needs. Diagnostic: the ratio against the node
    /// count is the whole point of this evaluator.
    pub fn slot_count(&self) -> usize {
        self.slots
    }
}

fn compile(bytes: &[u8], limits: Limits) -> Result<SageGraph, WitnessError> {
    let (header, mut reader) = read_header(bytes, &limits)?;

    // Pass one: the last instruction that reads each node. A node nobody reads
    // keeps its own index, so its slot is released immediately after it is written.
    // Declared counts are checked against the bytes actually present before any
    // of them drives an allocation.
    preflight_body_size(&header, reader.len())?;
    let mut last_use = reserved_vec("node liveness", header.node_count)?;
    last_use.extend((0..header.node_count).map(|index| index as u32));
    for index in 0..header.node_count {
        let mut mark = |reference: usize| -> Result<(), WitnessError> {
            *at_mut(&mut last_use, reference, "node liveness")? = index as u32;
            Ok(())
        };
        match read_node_record(&mut reader, header.version, index, header.input_buffer_len)? {
            NodeRecord::Operation { left, right, .. } => {
                mark(left)?;
                mark(right)?;
            }
            NodeRecord::Inverse(source) => mark(source)?,
            NodeRecord::Input(_) | NodeRecord::Constant(_) => {}
        }
    }
    let node_section_end = reader.remaining_len();

    let signals = read_output_references(&mut reader, &header)?;
    let input_mapping = read_input_mappings(&mut reader, &header)?;
    if !reader.is_empty() {
        return Err(WitnessError::TrailingBytes);
    }

    let mut outputs = signals
        .iter()
        .enumerate()
        .map(|(signal, node)| {
            Ok(OutputWrite {
                node: index_u32(*node, "output reference")?,
                signal: index_u32(signal, "output signal")?,
            })
        })
        .collect::<Result<Vec<_>, WitnessError>>()?;
    outputs.sort_unstable_by_key(|output| (output.node, output.signal));
    drop(signals);

    // Pass two: assign slots, recycling one as soon as its last reader has run.
    let (_, mut reader) = read_header(bytes, &limits)?;
    let mut instructions = reserved_vec("instructions", header.node_count)?;
    let mut constants = Vec::new();
    let mut node_slots = reserved_vec("node slots", header.node_count)?;
    node_slots.resize(header.node_count, 0_u32);
    let mut free_slots = Vec::<u32>::new();
    // Which node currently owns each slot, so reuse can be checked rather than
    // merely argued. `slot_owner.len()` is the number of slots minted so far.
    let mut slot_owner = Vec::<u32>::new();

    for index in 0..header.node_count {
        let record = read_node_record(&mut reader, header.version, index, header.input_buffer_len)?;
        let (left, right, kind, first_release, second_release) = match record {
            NodeRecord::Operation {
                operation,
                left,
                right,
            } => (
                at(&node_slots, left, "left operand slot")?,
                at(&node_slots, right, "right operand slot")?,
                Kind::Operation(operation),
                Some(left),
                // A node used twice by one instruction must only be released once.
                (left != right).then_some(right),
            ),
            NodeRecord::Input(input) => {
                (index_u32(input, "input index")?, 0, Kind::Input, None, None)
            }
            NodeRecord::Constant(encoded) => {
                let constant_index = index_u32(constants.len(), "constant index")?;
                constants.push(constant_from_bytes(encoded, index)?);
                (constant_index, 0, Kind::Constant, None, None)
            }
            NodeRecord::Inverse(source) => (
                at(&node_slots, source, "inverse operand slot")?,
                0,
                Kind::Inverse,
                Some(source),
                None,
            ),
        };

        // Release operands before choosing a destination, so an instruction may
        // legitimately overwrite one of its own inputs - evaluation reads both
        // operands before it writes.
        for reference in [first_release, second_release].into_iter().flatten() {
            if at(&last_use, reference, "operand liveness")? as usize == index {
                free_slots.push(at(&node_slots, reference, "released slot")?);
            }
        }
        let destination = match free_slots.pop() {
            Some(slot) => {
                // The whole design rests on never handing out a slot whose previous
                // owner can still be read. Check it rather than trust it: this is the
                // one bug class that would yield a wrong witness instead of an error.
                let owner = at(&slot_owner, slot as usize, "recycled slot owner")?;
                if at(&last_use, owner as usize, "recycled slot liveness")? as usize > index {
                    return Err(WitnessError::Invariant(
                        "recycled a slot that is still live",
                    ));
                }
                *at_mut(&mut slot_owner, slot as usize, "recycled slot owner")? = index as u32;
                slot
            }
            None => {
                let slot = index_u32(slot_owner.len(), "slot count")?;
                slot_owner.push(index as u32);
                slot
            }
        };
        *at_mut(&mut node_slots, index, "destination slot")? = destination;
        instructions.push(Instruction {
            left,
            right,
            destination,
            kind,
        });
        if at(&last_use, index, "node liveness")? as usize == index {
            free_slots.push(destination);
        }
    }

    // The two passes must have decoded the node section identically; pass two reads
    // `node_slots` positions that pass one's liveness was computed from.
    if reader.remaining_len() != node_section_end {
        return Err(WitnessError::Invariant(
            "the two decode passes disagreed on the node section",
        ));
    }

    Ok(SageGraph {
        limits,
        instructions,
        constants,
        outputs,
        input_mapping,
        input_buffer_len: header.input_buffer_len,
        signal_count: header.signal_count,
        slots: slot_owner.len(),
        r1cs_sha256: header.r1cs_sha256,
    })
}

fn index_u32(value: usize, what: &'static str) -> Result<u32, WitnessError> {
    u32::try_from(value).map_err(|_| WitnessError::CompiledIndex { what })
}

/// Compile-time bounds check. Every reference the decoder returns is already known
/// to be prior and in range, so these never fire - going through them anyway means
/// panic-freedom is a property of this function rather than of an argument that
/// spans two others.
fn at<T: Copy>(values: &[T], index: usize, what: &'static str) -> Result<T, WitnessError> {
    values
        .get(index)
        .copied()
        .ok_or(WitnessError::CompiledIndex { what })
}

fn at_mut<'a, T>(
    values: &'a mut [T],
    index: usize,
    what: &'static str,
) -> Result<&'a mut T, WitnessError> {
    values
        .get_mut(index)
        .ok_or(WitnessError::CompiledIndex { what })
}

fn slot<'a, T>(values: &'a [T], index: u32, what: &'static str) -> Result<&'a T, WitnessError> {
    values
        .get(index as usize)
        .ok_or(WitnessError::CompiledIndex { what })
}

fn slot_mut<'a, T>(
    values: &'a mut [T],
    index: u32,
    what: &'static str,
) -> Result<&'a mut T, WitnessError> {
    values
        .get_mut(index as usize)
        .ok_or(WitnessError::CompiledIndex { what })
}

#[cfg(test)]
mod differential;

#[cfg(test)]
mod tests {
    use super::SageGraph;
    use crate::WitnessGraph;
    use ark_ff::PrimeField;
    use sha2::{Digest, Sha256};

    /// `a * a + 1`, written so nodes die at different points and slots get recycled.
    fn graph_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(crate::LEGACY_MAGIC);
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&crate::FIELD_BN254_FR.to_le_bytes());
        bytes.extend_from_slice(&64_u32.to_le_bytes());
        bytes.extend_from_slice(&[7_u8; 32]);
        bytes.extend_from_slice(&5_u32.to_le_bytes()); // nodes
        bytes.extend_from_slice(&2_u32.to_le_bytes()); // signals
        bytes.extend_from_slice(&1_u32.to_le_bytes()); // input mappings
        bytes.extend_from_slice(&2_u32.to_le_bytes()); // input buffer

        bytes.push(1); // node 0: constant one
        bytes.extend_from_slice(&field_bytes(1));
        bytes.push(0); // node 1: input a
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.push(2); // node 2: a * a
        bytes.push(0);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.push(1); // node 3: constant one
        bytes.extend_from_slice(&field_bytes(1));
        bytes.push(2); // node 4: (a * a) + 1
        bytes.push(2);
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());

        bytes.extend_from_slice(&0_u32.to_le_bytes()); // signal 0 -> node 0
        bytes.extend_from_slice(&4_u32.to_le_bytes()); // signal 1 -> node 4

        bytes.extend_from_slice(&crate::fnv1a("a").to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes
    }

    fn field_bytes(value: u64) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        bytes
    }

    fn digest(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// The contract that matters: same artifact, same input, same assignment.
    #[test]
    fn reproduces_the_default_evaluator() {
        let bytes = graph_bytes();
        let sha = digest(&bytes);
        let input = r#"{"a":"5"}"#;

        let reference = WitnessGraph::from_bytes(&bytes, &sha)
            .expect("default graph")
            .calculate_json(input)
            .expect("default assignment");
        let candidate = SageGraph::from_bytes(&bytes, &sha)
            .expect("SAGE graph")
            .calculate_json(input)
            .expect("SAGE assignment");

        assert_eq!(candidate, reference);
        assert_eq!(candidate[1].into_bigint().0[0], 26);
    }

    /// Five nodes, but never five live at once.
    #[test]
    fn recycles_slots_below_the_node_count() {
        let bytes = graph_bytes();
        let graph = SageGraph::from_bytes(&bytes, &digest(&bytes)).expect("SAGE graph");
        assert!(
            graph.slot_count() < graph.instructions.len(),
            "expected slot reuse, got {} slots for {} nodes",
            graph.slot_count(),
            graph.instructions.len()
        );
    }

    #[test]
    fn rejects_an_unauthenticated_artifact_before_compiling() {
        let error = SageGraph::from_bytes(b"not a graph", &"00".repeat(32))
            .err()
            .expect("hash must mismatch");
        assert!(matches!(error, crate::WitnessError::HashMismatch { .. }));
    }
}
