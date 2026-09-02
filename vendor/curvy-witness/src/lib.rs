#![doc = include_str!("../README.md")]
//!
//! ## Security model
//!
//! Graph bytes are deployment artifacts, not executable code. The parser hashes
//! the complete artifact before decoding and validates every size and reference.
//! Use this crate when an integration needs a full BN254 witness assignment but
//! performs proving elsewhere. [`curvy-prover`](https://docs.rs/curvy-prover)
//! builds on this evaluator when local Groth16 proving is required.
//!
//! ## Resource budget
//!
//! Ceilings are per-consumer, not global - see [`Limits`]. The default is
//! [`Limits::client`], which covers every published profile (largest: pending(5,30),
//! 1,106,576 nodes) and projects to roughly 280 MiB of structural memory at its
//! maxima. A batch prover that deliberately proves pending(50) opts into
//! [`Limits::batch_prover`] at the call site, taking 8,000,000 nodes and a ~799 MiB
//! projection with it.
//!
//! Every allocation derived from artifact-declared counts is fallible, so an
//! over-large graph is a typed error rather than an abort.
//!
//! ## Optional features
//!
//! A default build accepts the `CVYWIT01` and `SIGNET01` envelopes at version 1,
//! raw or zstd-compressed.
//!
//! - `signet-v2` - additionally accept the version-2 body encoding. Off by
//!   default: the encoding is not stable and no published artifact uses it.
//! - `sage` - add [`sage::SageGraph`], a second evaluator over the same artifacts.

#[cfg(feature = "sage")]
pub mod sage;

use std::cmp::Ordering;
use std::collections::HashSet;
use std::io::{Cursor, Read};

use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger, Field, PrimeField, Zero};
use num_bigint::BigUint;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

const LEGACY_MAGIC: &[u8; 8] = b"CVYWIT01";
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
/// Resource ceilings for one graph load.
///
/// These are per-consumer, not global: a browser client and a batch prover run the
/// same evaluator over very different circuits.
///
/// [`Limits::default`] is [`Limits::client`], which covers every published profile.
/// Anything larger is opt-in at the call site.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Limits {
    /// Raw artifact bytes.
    pub graph_bytes: usize,
    /// Compressed artifact bytes.
    pub compressed_graph_bytes: usize,
    /// Decoder window a zstd frame may request.
    pub zstd_window_bytes: u64,
    /// Circuit-input JSON.
    pub input_json_bytes: usize,
    pub nodes: usize,
    pub signals: usize,
    pub input_mappings: usize,
    pub input_values: usize,
}

impl Limits {
    /// Every profile published today, with headroom.
    ///
    /// The largest is pending(5,30) at 1,106,576 nodes and 11,978,841 bytes, so two
    /// million nodes and 64 MiB clear it comfortably. At these maxima the evaluator
    /// accounts for roughly 280 MiB of structural memory before allocator overhead:
    /// 76 MiB nodes + 61 MiB node values + 15 MiB signal indices + 61 MiB assignment
    /// + 61 MiB inputs + 64 MiB graph + 16 MiB input JSON.
    pub const fn client() -> Self {
        Self {
            graph_bytes: 64 * 1024 * 1024,
            compressed_graph_bytes: 32 * 1024 * 1024,
            zstd_window_bytes: 8 * 1024 * 1024,
            input_json_bytes: 16 * 1024 * 1024,
            nodes: 2_000_000,
            signals: 2_000_000,
            input_mappings: 4_096,
            input_values: 2_000_000,
        }
    }

    /// Wide enough for the pending(50) commitment profile: 7,442,816 nodes, and
    /// 80,771,417 bytes as version 1.
    ///
    /// Only for processes that deliberately prove that circuit - a batch prover or
    /// the artifact pipeline. At these maxima the evaluator accounts for roughly
    /// 799 MiB of structural memory, so a host running several concurrently needs to
    /// have budgeted for it. Handing these to a browser client would widen its DoS
    /// ceiling four-fold for a circuit it never loads.
    pub const fn batch_prover() -> Self {
        Self {
            graph_bytes: 96 * 1024 * 1024,
            nodes: 8_000_000,
            ..Self::client()
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::client()
    }
}

/// Stable SIGNET operation tags shared by graph producers and consumers.
///
/// These constants are the wire contract. New operations append a tag; existing
/// values must never be reordered or reused.
pub mod wire {
    /// SIGNET envelope revision 1. The independent `FORMAT_VERSION_*` field
    /// selects the graph-body encoding.
    pub const MAGIC: &[u8; 8] = b"SIGNET01";
    pub const FORMAT_VERSION_V1: u16 = 1;
    pub const FORMAT_VERSION_V2: u16 = 2;
    pub const FIELD_BN254_FR: u16 = 1;
    pub const HEADER_SIZE: u32 = 64;
    pub const V2_INPUT_TAG: u8 = 0x80;
    pub const V2_CONSTANT_TAG: u8 = 0x81;
    pub const V2_INVERSE_TAG: u8 = 0x82;

    pub const MUL: u8 = 0;
    pub const MONTGOMERY_MUL: u8 = 1;
    pub const ADD: u8 = 2;
    pub const SUB: u8 = 3;
    pub const EQ: u8 = 4;
    pub const NEQ: u8 = 5;
    pub const LT: u8 = 6;
    pub const GT: u8 = 7;
    pub const LEQ: u8 = 8;
    pub const GEQ: u8 = 9;
    pub const LOGICAL_OR: u8 = 10;
    pub const SHL: u8 = 11;
    pub const SHR: u8 = 12;
    pub const BIT_AND: u8 = 13;
    pub const NEG: u8 = 14;
    pub const INV: u8 = 15;
    pub const DIV: u8 = 16;
    pub const MOD: u8 = 17;
    pub const POW: u8 = 18;
    pub const LOGICAL_AND: u8 = 19;
    pub const INTEGER_DIV: u8 = 20;
    pub const BIT_XOR: u8 = 21;
    pub const BIT_OR: u8 = 22;

    pub const ALL_OPERATION_TAGS: [u8; 23] = [
        MUL,
        MONTGOMERY_MUL,
        ADD,
        SUB,
        EQ,
        NEQ,
        LT,
        GT,
        LEQ,
        GEQ,
        LOGICAL_OR,
        SHL,
        SHR,
        BIT_AND,
        NEG,
        INV,
        DIV,
        MOD,
        POW,
        LOGICAL_AND,
        INTEGER_DIV,
        BIT_XOR,
        BIT_OR,
    ];
}

use wire::MAGIC;
use wire::{FIELD_BN254_FR, FORMAT_VERSION_V1, HEADER_SIZE};
#[cfg(feature = "signet-v2")]
use wire::{FORMAT_VERSION_V2, V2_CONSTANT_TAG, V2_INPUT_TAG, V2_INVERSE_TAG};

#[derive(Debug, Error)]
pub enum WitnessError {
    #[error("expected graph SHA-256 must be exactly 64 hexadecimal characters")]
    InvalidExpectedHash,
    #[error("witness graph SHA-256 mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("witness graph exceeds the {maximum}-byte limit")]
    GraphTooLarge { maximum: usize },
    #[error("compressed witness graph exceeds the {maximum}-byte limit")]
    CompressedGraphTooLarge { maximum: usize },
    #[error("invalid zstd-compressed witness graph")]
    InvalidZstd,
    #[error("zstd witness graph requires a {requested}-byte window; maximum is {maximum}")]
    ZstdWindowTooLarge { requested: u64, maximum: u64 },
    #[error("zstd witness graph expands beyond the {maximum}-byte graph limit")]
    ZstdOutputTooLarge { maximum: usize },
    #[error("zstd witness graph contains a dictionary reference")]
    ZstdDictionaryUnsupported,
    #[error("zstd witness graph contains another frame or trailing bytes")]
    ZstdTrailingData,
    #[error("zstd witness graph checksum mismatch")]
    ZstdChecksumMismatch,
    #[error("witness input JSON exceeds the {maximum}-byte limit")]
    InputTooLarge { maximum: usize },
    #[error("witness graph is truncated")]
    Truncated,
    #[error("invalid witness graph magic")]
    InvalidMagic,
    #[error("unsupported witness graph format version {0}")]
    UnsupportedVersion(u16),
    #[error("unsupported witness graph field identifier {0}")]
    UnsupportedField(u16),
    #[error("invalid witness graph header size {0}")]
    InvalidHeaderSize(u32),
    #[error("witness graph {section} count {actual} exceeds limit {maximum}")]
    CountLimit {
        section: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("witness graph contains no nodes or signals")]
    EmptyGraph,
    #[error("invalid witness graph node tag {tag} at node {index}")]
    InvalidNodeTag { index: usize, tag: u8 },
    #[error("invalid witness graph operation tag {tag} at node {index}")]
    InvalidOperation { index: usize, tag: u8 },
    #[error("invalid variable-length integer in witness graph")]
    InvalidVarint,
    #[error("non-canonical variable-length integer in witness graph")]
    NonCanonicalVarint,
    #[error("node {index} has invalid backward-reference distance {distance}")]
    InvalidBackwardReference { index: usize, distance: u64 },
    #[error("node {index} references non-prior node {reference}")]
    ForwardReference { index: usize, reference: usize },
    #[error("node {index} references input {input}, but the input buffer has length {length}")]
    InputReference {
        index: usize,
        input: usize,
        length: usize,
    },
    #[error("constant at node {0} is not a canonical BN254 scalar")]
    NonCanonicalConstant(usize),
    #[error("witness output {index} references missing node {reference}")]
    OutputReference { index: usize, reference: usize },
    #[error("witness output delta at index {0} is out of range")]
    OutputDelta(usize),
    #[error("duplicate input hash {0:#018x} in witness graph")]
    DuplicateInputHash(u64),
    #[error("input mapping {index} range exceeds the graph input buffer")]
    InputMappingRange { index: usize },
    #[error("witness graph has trailing bytes")]
    TrailingBytes,
    #[error("unable to reserve memory for witness graph {section}")]
    AllocationFailed { section: &'static str },
    #[error("invalid witness input JSON: {0}")]
    InvalidInputJson(serde_json::Error),
    #[error("witness input must be a JSON object")]
    InputNotObject,
    #[error("unknown witness input signal {0:?}")]
    UnknownInput(String),
    #[error("two input names resolve to the same graph signal hash {0:#018x}")]
    InputHashCollision(u64),
    #[error("witness input {name:?} expects {expected} values, got {actual}")]
    InputLength {
        name: String,
        expected: usize,
        actual: usize,
    },
    #[error("witness input {name:?} contains an unsupported JSON value")]
    InvalidInputValue { name: String },
    #[error("witness input {name:?} contains invalid decimal field value {value:?}")]
    InvalidFieldValue { name: String, value: String },
    #[error("division or modulus by zero at graph node {0}")]
    DivisionByZero(usize),
    #[error("shift at graph node {0} is not in 0..256")]
    InvalidShift(usize),
    #[error("witness assignment must begin with the constant one")]
    InvalidAssignmentOne,
    #[error("compiled graph needs more value slots than a u32 can address")]
    SlotOverflow,
    #[error("compiled {what} index is out of bounds")]
    CompiledIndex { what: &'static str },
    /// A self-check inside SAGE's compiler failed. Reaching this means the
    /// compiler is wrong, not that the artifact is - it should be unreachable for
    /// every graph the parser accepts.
    #[error("SAGE compilation invariant violated: {0}")]
    Invariant(&'static str),
}

#[derive(Debug, Clone, Copy)]
enum Operation {
    Mul,
    MontgomeryMul,
    Add,
    Sub,
    Eq,
    Neq,
    Lt,
    Gt,
    Leq,
    Geq,
    LogicalOr,
    Shl,
    Shr,
    BitAnd,
    Neg,
    Inv,
    Div,
    Mod,
    Pow,
    LogicalAnd,
    IntegerDiv,
    BitXor,
    BitOr,
}

impl Operation {
    fn from_tag(tag: u8, index: usize) -> Result<Self, WitnessError> {
        let operation = match tag {
            wire::MUL => Self::Mul,
            wire::MONTGOMERY_MUL => Self::MontgomeryMul,
            wire::ADD => Self::Add,
            wire::SUB => Self::Sub,
            wire::EQ => Self::Eq,
            wire::NEQ => Self::Neq,
            wire::LT => Self::Lt,
            wire::GT => Self::Gt,
            wire::LEQ => Self::Leq,
            wire::GEQ => Self::Geq,
            wire::LOGICAL_OR => Self::LogicalOr,
            wire::SHL => Self::Shl,
            wire::SHR => Self::Shr,
            wire::BIT_AND => Self::BitAnd,
            wire::NEG => Self::Neg,
            wire::INV => Self::Inv,
            wire::DIV => Self::Div,
            wire::MOD => Self::Mod,
            wire::POW => Self::Pow,
            wire::LOGICAL_AND => Self::LogicalAnd,
            wire::INTEGER_DIV => Self::IntegerDiv,
            wire::BIT_XOR => Self::BitXor,
            wire::BIT_OR => Self::BitOr,
            _ => return Err(WitnessError::InvalidOperation { index, tag }),
        };
        Ok(operation)
    }

    fn evaluate(self, index: usize, left: Fr, right: Fr) -> Result<Fr, WitnessError> {
        let value = match self {
            Self::Mul | Self::MontgomeryMul => left * right,
            Self::Add => left + right,
            Self::Sub => left - right,
            Self::Eq => Fr::from(left == right),
            Self::Neq => Fr::from(left != right),
            Self::Lt => Fr::from(compare_balanced(left, right).is_lt()),
            Self::Gt => Fr::from(compare_balanced(left, right).is_gt()),
            Self::Leq => Fr::from(compare_balanced(left, right).is_le()),
            Self::Geq => Fr::from(compare_balanced(left, right).is_ge()),
            Self::LogicalOr => Fr::from(!left.is_zero() || !right.is_zero()),
            Self::LogicalAnd => Fr::from(!left.is_zero() && !right.is_zero()),
            Self::Neg => -left,
            Self::Inv => left.inverse().ok_or(WitnessError::DivisionByZero(index))?,
            Self::Div => left * right.inverse().ok_or(WitnessError::DivisionByZero(index))?,
            Self::Pow => left.pow(right.into_bigint().0),
            Self::Shl => shift(index, left, right, true)?,
            Self::Shr => shift(index, left, right, false)?,
            Self::BitAnd => bigint_to_field(left.into_bigint() & right.into_bigint()),
            Self::BitXor => bigint_to_field(left.into_bigint() ^ right.into_bigint()),
            Self::BitOr => bigint_to_field(left.into_bigint() | right.into_bigint()),
            Self::Mod | Self::IntegerDiv => {
                let left = field_to_biguint(left);
                let right = field_to_biguint(right);
                if right == BigUint::from(0_u8) {
                    return Err(WitnessError::DivisionByZero(index));
                }
                let value = if matches!(self, Self::Mod) {
                    left % right
                } else {
                    left / right
                };
                Fr::from_le_bytes_mod_order(&value.to_bytes_le())
            }
        };
        Ok(value)
    }
}

#[derive(Debug, Clone)]
enum Node {
    Input(usize),
    Constant(Fr),
    Operation(Operation, usize, usize),
    Inverse(usize),
}

/// One decoded node record, before the evaluator decides how to store it.
///
/// [`read_node_record`] is the single implementation of the wire format and its
/// validation rules.
#[derive(Debug, Clone, Copy)]
enum NodeRecord {
    Input(usize),
    /// Still encoded: canonicality is checked when a consumer materializes it.
    Constant([u8; 32]),
    Operation {
        operation: Operation,
        left: usize,
        right: usize,
    },
    Inverse(usize),
}

/// Authenticated header fields, already range-checked against the configured maxima.
#[derive(Debug, Clone, Copy)]
struct Header {
    version: FormatVersion,
    r1cs_sha256: [u8; 32],
    node_count: usize,
    signal_count: usize,
    input_mapping_count: usize,
    input_buffer_len: usize,
}

#[derive(Debug, Clone, Copy)]
struct InputMapping {
    hash: u64,
    signal_id: usize,
    signal_size: usize,
}

#[derive(Debug, Clone, Copy)]
enum FormatVersion {
    V1,
    #[cfg(feature = "signet-v2")]
    V2,
}

/// Parsed, reusable graph for one circuit revision.
pub struct WitnessGraph {
    limits: Limits,
    nodes: Vec<Node>,
    signals: Vec<usize>,
    input_mapping: Vec<InputMapping>,
    input_buffer_len: usize,
    r1cs_sha256: [u8; 32],
}

impl WitnessGraph {
    /// Authenticate and parse an immutable raw or zstd-compressed graph artifact.
    ///
    /// `expected_sha256` authenticates the bytes supplied to this method: the raw
    /// SIGNET bytes for an uncompressed artifact, or the zstd frame bytes for a
    /// compressed artifact. The expected digest must come from trusted protocol
    /// metadata; a digest supplied beside attacker-controlled bytes is not an
    /// authenticity boundary.
    pub fn from_bytes(bytes: &[u8], expected_sha256: &str) -> Result<Self, WitnessError> {
        Self::from_bytes_with_limits(bytes, expected_sha256, Limits::default())
    }

    /// Authenticate and parse under explicit ceilings.
    ///
    /// Use this to opt a batch prover into [`Limits::batch_prover`]; the plain
    /// [`from_bytes`](Self::from_bytes) keeps the conservative client budget.
    pub fn from_bytes_with_limits(
        bytes: &[u8],
        expected_sha256: &str,
        limits: Limits,
    ) -> Result<Self, WitnessError> {
        match authenticate(bytes, expected_sha256, &limits)? {
            Artifact::Raw => parse_graph(bytes, limits),
            Artifact::Zstd => parse_graph(&decompress_graph(bytes, &limits)?, limits),
        }
    }

    /// Evaluate JSON circuit signals directly into the arkworks assignment.
    pub fn calculate_json(&self, input_json: &str) -> Result<Vec<Fr>, WitnessError> {
        let inputs = self.parse_inputs(input_json)?;
        let mut values = reserved_vec("evaluation values", self.nodes.len())?;
        for (index, node) in self.nodes.iter().enumerate() {
            let value = match *node {
                Node::Input(input) => inputs[input],
                Node::Constant(value) => value,
                Node::Operation(operation, left, right) => {
                    operation.evaluate(index, values[left], values[right])?
                }
                Node::Inverse(source) => values[source].inverse().unwrap_or_else(Fr::zero),
            };
            values.push(value);
        }
        let mut assignment = reserved_vec("witness assignment", self.signals.len())?;
        assignment.extend(self.signals.iter().map(|index| values[*index]));
        if assignment.first().copied() != Some(Fr::from(1_u64)) {
            return Err(WitnessError::InvalidAssignmentOne);
        }
        Ok(assignment)
    }

    pub fn assignment_size(&self) -> usize {
        self.signals.len()
    }

    pub fn r1cs_sha256(&self) -> [u8; 32] {
        self.r1cs_sha256
    }

    fn parse_inputs(&self, input_json: &str) -> Result<Vec<Fr>, WitnessError> {
        build_input_buffer(
            &self.input_mapping,
            self.input_buffer_len,
            input_json,
            &self.limits,
        )
    }
}

/// What an authenticated artifact turned out to be.
enum Artifact {
    Raw,
    Zstd,
}

/// Size-cap and authenticate an artifact before any decoding happens.
///
/// Both evaluators go through this, so they cannot drift on how large an artifact
/// may be or on when its digest is checked.
fn authenticate(
    bytes: &[u8],
    expected_sha256: &str,
    limits: &Limits,
) -> Result<Artifact, WitnessError> {
    if is_zstd_artifact(bytes) {
        if bytes.len() > limits.compressed_graph_bytes {
            return Err(WitnessError::CompressedGraphTooLarge {
                maximum: limits.compressed_graph_bytes,
            });
        }
        verify_sha256(bytes, expected_sha256)?;
        return Ok(Artifact::Zstd);
    }
    if bytes.len() > limits.graph_bytes {
        return Err(WitnessError::GraphTooLarge {
            maximum: limits.graph_bytes,
        });
    }
    verify_sha256(bytes, expected_sha256)?;
    Ok(Artifact::Raw)
}

/// Only a real zstd frame counts. Skippable frames (`0x184d2a5*`) are legitimate
/// zstd, but our publication pipeline never emits them and honouring them would let
/// two distinct artifacts decode to one graph. Rejecting them keeps the
/// artifact-to-graph mapping injective and removes decoder surface.
fn is_zstd_artifact(bytes: &[u8]) -> bool {
    let Some(magic) = bytes
        .get(..4)
        .and_then(|value| <[u8; 4]>::try_from(value).ok())
        .map(u32::from_le_bytes)
    else {
        return false;
    };
    magic == u32::from_le_bytes(ZSTD_MAGIC)
}

/// Turn circuit-input JSON into the flat input buffer both evaluators consume.
fn build_input_buffer(
    input_mapping: &[InputMapping],
    input_buffer_len: usize,
    input_json: &str,
    limits: &Limits,
) -> Result<Vec<Fr>, WitnessError> {
    if input_json.len() > limits.input_json_bytes {
        return Err(WitnessError::InputTooLarge {
            maximum: limits.input_json_bytes,
        });
    }
    let value: Value = serde_json::from_str(input_json).map_err(WitnessError::InvalidInputJson)?;
    let object = value.as_object().ok_or(WitnessError::InputNotObject)?;
    // Circom graph evaluation leaves omitted input signals at zero.
    let mut inputs = reserved_vec("input values", input_buffer_len)?;
    inputs.resize(input_buffer_len, Fr::from(0_u64));
    inputs[0] = Fr::from(1_u64);
    let mut matched = reserved_vec("input mapping matches", input_mapping.len())?;
    matched.resize(input_mapping.len(), false);

    for (name, value) in object {
        let hash = fnv1a(name);
        let Some((mapping_index, mapping)) = input_mapping
            .iter()
            .enumerate()
            .find(|(_, mapping)| mapping.hash == hash)
        else {
            return Err(WitnessError::UnknownInput(name.clone()));
        };
        if matched[mapping_index] {
            return Err(WitnessError::InputHashCollision(hash));
        }
        let mut flattened = reserved_vec("flattened input", mapping.signal_size)?;
        flatten_input(name, value, mapping.signal_size, &mut flattened)?;
        if flattened.len() != mapping.signal_size {
            return Err(WitnessError::InputLength {
                name: name.clone(),
                expected: mapping.signal_size,
                actual: flattened.len(),
            });
        }
        let end = mapping.signal_id + mapping.signal_size;
        inputs[mapping.signal_id..end].copy_from_slice(&flattened);
        matched[mapping_index] = true;
    }

    Ok(inputs)
}

fn decompress_graph(bytes: &[u8], limits: &Limits) -> Result<Vec<u8>, WitnessError> {
    decompress_graph_with_limits(bytes, limits.graph_bytes, limits.zstd_window_bytes)
}

fn decompress_graph_with_limits(
    bytes: &[u8],
    maximum_output: usize,
    maximum_window: u64,
) -> Result<Vec<u8>, WitnessError> {
    use ruzstd::decoding::StreamingDecoder;
    use ruzstd::decoding::errors::FrameDecoderError;

    let source = Cursor::new(bytes);
    let mut decoder =
        StreamingDecoder::new_with_max_window_size(source, maximum_window).map_err(|error| {
            match error {
                FrameDecoderError::WindowSizeTooBig { requested, .. } => {
                    WitnessError::ZstdWindowTooLarge {
                        requested,
                        maximum: maximum_window,
                    }
                }
                FrameDecoderError::DictNotProvided { .. } => {
                    WitnessError::ZstdDictionaryUnsupported
                }
                _ => WitnessError::InvalidZstd,
            }
        })?;

    let declared_size = usize::try_from(decoder.decoder.content_size()).map_err(|_| {
        WitnessError::ZstdOutputTooLarge {
            maximum: maximum_output,
        }
    })?;
    if declared_size > maximum_output {
        return Err(WitnessError::ZstdOutputTooLarge {
            maximum: maximum_output,
        });
    }

    // Do not reserve the full declared size up front: a valid but hostile frame
    // may declare the entire 96 MiB budget and then fail immediately. Grow in
    // bounded chunks with fallible reservations instead.
    let mut decoded = reserved_vec("decompressed graph", declared_size.min(1024 * 1024))?;
    let mut chunk = [0_u8; 64 * 1024];
    const GROWTH_BYTES: usize = 4 * 1024 * 1024;
    loop {
        let count = decoder
            .read(&mut chunk)
            .map_err(|_| WitnessError::InvalidZstd)?;
        if count == 0 {
            break;
        }
        let required = decoded
            .len()
            .checked_add(count)
            .filter(|length| *length <= maximum_output)
            .ok_or(WitnessError::ZstdOutputTooLarge {
                maximum: maximum_output,
            })?;
        if declared_size != 0 && required > declared_size {
            return Err(WitnessError::InvalidZstd);
        }
        if required > decoded.capacity() {
            let rounded = required
                .checked_add(GROWTH_BYTES - 1)
                .map(|length| (length / GROWTH_BYTES) * GROWTH_BYTES)
                .unwrap_or(maximum_output);
            let target = if declared_size == 0 {
                rounded.min(maximum_output)
            } else {
                rounded.min(declared_size)
            };
            decoded
                .try_reserve_exact(target.saturating_sub(decoded.len()))
                .map_err(|_| WitnessError::AllocationFailed {
                    section: "decompressed graph",
                })?;
        }
        decoded.extend_from_slice(&chunk[..count]);
    }

    if declared_size != 0 && decoded.len() != declared_size {
        return Err(WitnessError::InvalidZstd);
    }
    // A frame that carries a checksum must match it. Frames without one are still
    // accepted because the artifact digest already authenticates the bytes.
    if let Some(expected) = decoder.decoder.get_checksum_from_data()
        && decoder.decoder.get_calculated_checksum() != Some(expected)
    {
        return Err(WitnessError::ZstdChecksumMismatch);
    }
    let (source, _) = decoder.into_parts();
    if source.position() != bytes.len() as u64 {
        return Err(WitnessError::ZstdTrailingData);
    }
    Ok(decoded)
}

fn reserved_vec<T>(section: &'static str, capacity: usize) -> Result<Vec<T>, WitnessError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| WitnessError::AllocationFailed { section })?;
    Ok(values)
}

fn parse_graph(bytes: &[u8], limits: Limits) -> Result<WitnessGraph, WitnessError> {
    let (header, mut reader) = read_header(bytes, &limits)?;
    preflight_body_size(&header, Reader::len(&reader))?;

    let mut nodes = reserved_vec("nodes", header.node_count)?;
    for index in 0..header.node_count {
        let record = read_node_record(&mut reader, header.version, index, header.input_buffer_len)?;
        nodes.push(match record {
            NodeRecord::Input(input) => Node::Input(input),
            NodeRecord::Constant(encoded) => Node::Constant(constant_from_bytes(encoded, index)?),
            NodeRecord::Operation {
                operation,
                left,
                right,
            } => Node::Operation(operation, left, right),
            NodeRecord::Inverse(source) => Node::Inverse(source),
        });
    }

    let signals = read_output_references(&mut reader, &header)?;
    let input_mapping = read_input_mappings(&mut reader, &header)?;
    if !reader.is_empty() {
        return Err(WitnessError::TrailingBytes);
    }

    Ok(WitnessGraph {
        limits,
        nodes,
        signals,
        input_mapping,
        input_buffer_len: header.input_buffer_len,
        r1cs_sha256: header.r1cs_sha256,
    })
}

/// Decode and range-check the fixed 64-byte header, returning a reader positioned
/// at the first node record.
fn read_header<'a>(bytes: &'a [u8], limits: &Limits) -> Result<(Header, Reader<'a>), WitnessError> {
    let mut reader = Reader::new(bytes);
    // Both envelopes are accepted at version 1: `CVYWIT01` is what earlier
    // artifacts carry, `SIGNET01` is what the pipeline emits now. Version 2 is the
    // denser body encoding and is not stable, so an unflagged build refuses it
    // rather than compiling a decoder path nothing exercises.
    let magic = reader.array::<8>()?;
    let recognised = magic == *LEGACY_MAGIC || magic == *MAGIC;
    if !recognised {
        return Err(WitnessError::InvalidMagic);
    }
    let version = match reader.u16()? {
        FORMAT_VERSION_V1 => FormatVersion::V1,
        #[cfg(feature = "signet-v2")]
        FORMAT_VERSION_V2 => FormatVersion::V2,
        version => return Err(WitnessError::UnsupportedVersion(version)),
    };
    let field = reader.u16()?;
    if field != FIELD_BN254_FR {
        return Err(WitnessError::UnsupportedField(field));
    }
    let header_size = reader.u32()?;
    if header_size != HEADER_SIZE {
        return Err(WitnessError::InvalidHeaderSize(header_size));
    }
    let r1cs_sha256 = reader.array::<32>()?;
    let node_count = checked_count("node", reader.u32()? as usize, limits.nodes)?;
    let signal_count = checked_count("signal", reader.u32()? as usize, limits.signals)?;
    let input_mapping_count = checked_count(
        "input mapping",
        reader.u32()? as usize,
        limits.input_mappings,
    )?;
    let input_buffer_len =
        checked_count("input value", reader.u32()? as usize, limits.input_values)?;
    if node_count == 0 || signal_count == 0 || input_buffer_len == 0 {
        return Err(WitnessError::EmptyGraph);
    }
    Ok((
        Header {
            version,
            r1cs_sha256,
            node_count,
            signal_count,
            input_mapping_count,
            input_buffer_len,
        },
        reader,
    ))
}

/// Reject impossible count/length combinations before reserving any count-sized
/// vectors. This is intentionally a lower bound: full record validation still
/// happens while decoding.
fn preflight_body_size(header: &Header, available: usize) -> Result<(), WitnessError> {
    let (minimum_node_bytes, minimum_signal_bytes) = match header.version {
        FormatVersion::V1 => (5_usize, 4_usize),
        #[cfg(feature = "signet-v2")]
        FormatVersion::V2 => (2_usize, 1_usize),
    };
    let minimum = header
        .node_count
        .checked_mul(minimum_node_bytes)
        .and_then(|size| {
            header
                .signal_count
                .checked_mul(minimum_signal_bytes)
                .and_then(|signals| size.checked_add(signals))
        })
        .and_then(|size| {
            header
                .input_mapping_count
                .checked_mul(16)
                .and_then(|mappings| size.checked_add(mappings))
        })
        .ok_or(WitnessError::Truncated)?;
    if available < minimum {
        return Err(WitnessError::Truncated);
    }
    Ok(())
}

fn read_output_references(
    reader: &mut Reader<'_>,
    header: &Header,
) -> Result<Vec<usize>, WitnessError> {
    let mut signals = reserved_vec("signal references", header.signal_count)?;
    match header.version {
        FormatVersion::V1 => {
            for index in 0..header.signal_count {
                let reference = reader.u32()? as usize;
                if reference >= header.node_count {
                    return Err(WitnessError::OutputReference { index, reference });
                }
                signals.push(reference);
            }
        }
        #[cfg(feature = "signet-v2")]
        FormatVersion::V2 => {
            let mut previous = 0_usize;
            for index in 0..header.signal_count {
                let reference = decode_output_delta(reader, previous, header.node_count, index)?;
                signals.push(reference);
                previous = reference;
            }
        }
    }
    Ok(signals)
}

fn read_input_mappings(
    reader: &mut Reader<'_>,
    header: &Header,
) -> Result<Vec<InputMapping>, WitnessError> {
    let mut input_mapping = reserved_vec("input mappings", header.input_mapping_count)?;
    let mut hashes = HashSet::new();
    hashes
        .try_reserve(header.input_mapping_count)
        .map_err(|_| WitnessError::AllocationFailed {
            section: "input mapping hashes",
        })?;
    for index in 0..header.input_mapping_count {
        let hash = reader.u64()?;
        let signal_id = reader.u32()? as usize;
        let signal_size = reader.u32()? as usize;
        if !hashes.insert(hash) {
            return Err(WitnessError::DuplicateInputHash(hash));
        }
        if signal_id == 0
            || signal_size == 0
            || signal_id
                .checked_add(signal_size)
                .is_none_or(|end| end > header.input_buffer_len)
        {
            return Err(WitnessError::InputMappingRange { index });
        }
        input_mapping.push(InputMapping {
            hash,
            signal_id,
            signal_size,
        });
    }
    Ok(input_mapping)
}

/// The single wire-format decoder. Every reference it returns is already known to
/// point at a prior node, and every input index is within the input buffer.
fn read_node_record(
    reader: &mut Reader<'_>,
    version: FormatVersion,
    index: usize,
    input_buffer_len: usize,
) -> Result<NodeRecord, WitnessError> {
    let tag = reader.u8()?;
    match version {
        FormatVersion::V1 => match tag {
            0 => checked_input(reader.u32()? as usize, index, input_buffer_len),
            1 => Ok(NodeRecord::Constant(reader.array::<32>()?)),
            2 => {
                let operation = Operation::from_tag(reader.u8()?, index)?;
                let left = reader.u32()? as usize;
                let right = reader.u32()? as usize;
                validate_reference(index, left)?;
                validate_reference(index, right)?;
                Ok(NodeRecord::Operation {
                    operation,
                    left,
                    right,
                })
            }
            3 => {
                let source = reader.u32()? as usize;
                validate_reference(index, source)?;
                Ok(NodeRecord::Inverse(source))
            }
            _ => Err(WitnessError::InvalidNodeTag { index, tag }),
        },
        #[cfg(feature = "signet-v2")]
        FormatVersion::V2 => match tag {
            V2_INPUT_TAG => checked_input(reader.var_u32()? as usize, index, input_buffer_len),
            V2_CONSTANT_TAG => Ok(NodeRecord::Constant(reader.array::<32>()?)),
            V2_INVERSE_TAG => Ok(NodeRecord::Inverse(decode_backward_reference(
                reader, index,
            )?)),
            0..=0x7f => {
                let operation = Operation::from_tag(tag, index)?;
                let left = decode_backward_reference(reader, index)?;
                let right = decode_backward_reference(reader, index)?;
                Ok(NodeRecord::Operation {
                    operation,
                    left,
                    right,
                })
            }
            _ => Err(WitnessError::InvalidNodeTag { index, tag }),
        },
    }
}

fn checked_input(input: usize, index: usize, length: usize) -> Result<NodeRecord, WitnessError> {
    if input >= length {
        return Err(WitnessError::InputReference {
            index,
            input,
            length,
        });
    }
    Ok(NodeRecord::Input(input))
}

fn constant_from_bytes(encoded: [u8; 32], index: usize) -> Result<Fr, WitnessError> {
    Fr::from_bigint(bigint_from_le_bytes(encoded)?).ok_or(WitnessError::NonCanonicalConstant(index))
}

#[cfg(feature = "signet-v2")]
fn decode_backward_reference(reader: &mut Reader<'_>, index: usize) -> Result<usize, WitnessError> {
    let distance = reader.var_u64()?;
    let distance_usize = usize::try_from(distance)
        .map_err(|_| WitnessError::InvalidBackwardReference { index, distance })?;
    if distance_usize == 0 || distance_usize > index {
        return Err(WitnessError::InvalidBackwardReference { index, distance });
    }
    Ok(index - distance_usize)
}

#[cfg(feature = "signet-v2")]
fn decode_output_delta(
    reader: &mut Reader<'_>,
    previous: usize,
    node_count: usize,
    index: usize,
) -> Result<usize, WitnessError> {
    let encoded = reader.var_u64()?;
    let magnitude = i128::from(encoded >> 1);
    let delta = if encoded & 1 == 0 {
        magnitude
    } else {
        -magnitude - 1
    };
    let reference = previous as i128 + delta;
    if reference < 0 || reference >= node_count as i128 {
        return Err(WitnessError::OutputDelta(index));
    }
    Ok(reference as usize)
}

fn checked_count(
    section: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<usize, WitnessError> {
    if actual > maximum {
        return Err(WitnessError::CountLimit {
            section,
            actual,
            maximum,
        });
    }
    Ok(actual)
}

fn validate_reference(index: usize, reference: usize) -> Result<(), WitnessError> {
    if reference >= index {
        return Err(WitnessError::ForwardReference { index, reference });
    }
    Ok(())
}

fn flatten_input(
    name: &str,
    value: &Value,
    limit: usize,
    output: &mut Vec<Fr>,
) -> Result<(), WitnessError> {
    if output.len() >= limit {
        return Err(WitnessError::InputLength {
            name: name.to_owned(),
            expected: limit,
            actual: output.len() + 1,
        });
    }
    match value {
        Value::String(value) => output.push(parse_field(name, value)?),
        Value::Number(value) => output.push(parse_field(name, &value.to_string())?),
        Value::Array(values) => {
            for value in values {
                flatten_input(name, value, limit, output)?;
            }
        }
        _ => {
            return Err(WitnessError::InvalidInputValue {
                name: name.to_owned(),
            });
        }
    }
    Ok(())
}

fn parse_field(name: &str, value: &str) -> Result<Fr, WitnessError> {
    let (negative, digits) = value
        .strip_prefix('-')
        .map_or((false, value), |digits| (true, digits));
    let integer = BigUint::parse_bytes(digits.as_bytes(), 10).ok_or_else(|| {
        WitnessError::InvalidFieldValue {
            name: name.to_owned(),
            value: value.to_owned(),
        }
    })?;
    let field = Fr::from_be_bytes_mod_order(&integer.to_bytes_be());
    Ok(if negative { -field } else { field })
}

fn compare_balanced(left: Fr, right: Fr) -> Ordering {
    let left_integer = left.into_bigint();
    let right_integer = right.into_bigint();
    let half = Fr::MODULUS >> 1_u32;
    match (left_integer > half, right_integer > half) {
        (false, true) => Ordering::Greater,
        (true, false) => Ordering::Less,
        (false, false) => left_integer.cmp(&right_integer),
        (true, true) => (-right).into_bigint().cmp(&(-left).into_bigint()),
    }
}

fn shift(index: usize, left: Fr, right: Fr, is_left: bool) -> Result<Fr, WitnessError> {
    let shift = right.into_bigint();
    if shift.0[1..].iter().any(|limb| *limb != 0) || shift.0[0] >= 256 {
        return Err(WitnessError::InvalidShift(index));
    }
    let shift = shift.0[0] as u32;
    let value = if is_left {
        let mut value = left.into_bigint() << shift;
        // Circom masks left shifts to 254 bits before reducing into BN254 Fr.
        value.0[3] &= (1_u64 << 62) - 1;
        value
    } else {
        left.into_bigint() >> shift
    };
    Ok(bigint_to_field(value))
}

fn bigint_to_field(value: BigInt<4>) -> Fr {
    Fr::from_le_bytes_mod_order(&value.to_bytes_le())
}

fn field_to_biguint(value: Fr) -> BigUint {
    BigUint::from_bytes_le(&value.into_bigint().to_bytes_le())
}

fn bigint_from_le_bytes(bytes: [u8; 32]) -> Result<BigInt<4>, WitnessError> {
    let mut limbs = [0_u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
        let encoded: [u8; 8] = chunk.try_into().map_err(|_| WitnessError::Truncated)?;
        *limb = u64::from_le_bytes(encoded);
    }
    Ok(BigInt(limbs))
}

fn fnv1a(value: &str) -> u64 {
    value.bytes().fold(0xCBF29CE484222325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001B3)
    })
}

fn verify_sha256(bytes: &[u8], expected_sha256: &str) -> Result<(), WitnessError> {
    if expected_sha256.len() != 64 || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(WitnessError::InvalidExpectedHash);
    }
    let expected = expected_sha256.to_ascii_lowercase();
    let actual = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual != expected {
        return Err(WitnessError::HashMismatch { expected, actual });
    }
    Ok(())
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    /// Undecoded bytes left. SAGE compares this across its two decode passes to
    /// prove they consumed the wire identically.
    #[cfg(feature = "sage")]
    fn remaining_len(&self) -> usize {
        self.remaining.len()
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], WitnessError> {
        if self.remaining.len() < length {
            return Err(WitnessError::Truncated);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WitnessError> {
        self.take(N)?
            .try_into()
            .map_err(|_| WitnessError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, WitnessError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, WitnessError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, WitnessError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, WitnessError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    #[cfg(feature = "signet-v2")]
    fn var_u32(&mut self) -> Result<u32, WitnessError> {
        u32::try_from(self.var_u64()?).map_err(|_| WitnessError::InvalidVarint)
    }

    #[cfg(feature = "signet-v2")]
    fn var_u64(&mut self) -> Result<u64, WitnessError> {
        let mut value = 0_u64;
        for index in 0..10 {
            let byte = self.u8()?;
            let payload = byte & 0x7f;
            if index == 9 && (byte & 0xfe) != 0 {
                return Err(WitnessError::InvalidVarint);
            }
            value |= u64::from(payload) << (index * 7);
            if byte & 0x80 == 0 {
                if index != 0 && payload == 0 {
                    return Err(WitnessError::NonCanonicalVarint);
                }
                return Ok(value);
            }
        }
        Err(WitnessError::InvalidVarint)
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn len(&self) -> usize {
        self.remaining.len()
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::PrimeField;
    use sha2::{Digest, Sha256};

    use super::{
        FIELD_BN254_FR, FORMAT_VERSION_V1, LEGACY_MAGIC, Limits, WitnessError, WitnessGraph, fnv1a,
    };
    #[cfg(feature = "signet-v2")]
    use super::{FORMAT_VERSION_V2, V2_CONSTANT_TAG, V2_INPUT_TAG, wire};
    use super::{MAGIC, ZSTD_MAGIC, decompress_graph_with_limits};
    use ruzstd::encoding::{CompressionLevel, compress_to_vec};

    fn graph_bytes(operation_reference: u32) -> Vec<u8> {
        v1_graph_bytes(LEGACY_MAGIC, operation_reference)
    }

    /// The combination the pipeline ships: `SIGNET01` envelope, version-1 body.
    fn signet_v1_graph_bytes(operation_reference: u32) -> Vec<u8> {
        v1_graph_bytes(MAGIC, operation_reference)
    }

    fn v1_graph_bytes(magic: &[u8; 8], operation_reference: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(magic);
        bytes.extend_from_slice(&FORMAT_VERSION_V1.to_le_bytes());
        bytes.extend_from_slice(&FIELD_BN254_FR.to_le_bytes());
        bytes.extend_from_slice(&64_u32.to_le_bytes());
        bytes.extend_from_slice(&[7_u8; 32]);
        bytes.extend_from_slice(&4_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u32.to_le_bytes());

        bytes.push(1);
        bytes.extend_from_slice(&field_bytes(1));
        bytes.push(0);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&field_bytes(2));
        bytes.push(2);
        bytes.push(2);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&operation_reference.to_le_bytes());

        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&fnv1a("a").to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes
    }

    #[cfg(feature = "signet-v2")]
    fn v2_graph_bytes_with_operation(operation_tag: u8, right_constant: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION_V2.to_le_bytes());
        bytes.extend_from_slice(&FIELD_BN254_FR.to_le_bytes());
        bytes.extend_from_slice(&64_u32.to_le_bytes());
        bytes.extend_from_slice(&[7_u8; 32]);
        bytes.extend_from_slice(&4_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u32.to_le_bytes());

        bytes.push(V2_CONSTANT_TAG);
        bytes.extend_from_slice(&field_bytes(1));
        bytes.push(V2_INPUT_TAG);
        push_var_u64(&mut bytes, 1);
        bytes.push(V2_CONSTANT_TAG);
        bytes.extend_from_slice(&field_bytes(right_constant));
        bytes.push(operation_tag);
        push_var_u64(&mut bytes, 2);
        push_var_u64(&mut bytes, 1);

        push_var_u64(&mut bytes, 0);
        push_var_u64(&mut bytes, 6);
        bytes.extend_from_slice(&fnv1a("a").to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes
    }

    #[cfg(feature = "signet-v2")]
    fn push_var_u64(bytes: &mut Vec<u8>, mut value: u64) {
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

    fn digest(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn evaluates_an_authenticated_graph() {
        let bytes = graph_bytes(2);
        let graph = WitnessGraph::from_bytes(&bytes, &digest(&bytes)).expect("graph must parse");
        let assignment = graph
            .calculate_json(r#"{"a":"5"}"#)
            .expect("input must evaluate");
        assert_eq!(assignment[0].into_bigint().0[0], 1);
        assert_eq!(assignment[1].into_bigint().0[0], 7);
    }

    #[test]
    fn accepts_legacy_cvywit_magic_during_signet_migration() {
        let mut bytes = graph_bytes(2);
        bytes[..8].copy_from_slice(LEGACY_MAGIC);
        let graph = WitnessGraph::from_bytes(&bytes, &digest(&bytes))
            .expect("legacy graph must remain readable");
        assert_eq!(graph.assignment_size(), 2);
    }

    /// The shipping combination, on a default build: `SIGNET01` at version 1,
    /// uncompressed. Neither the envelope nor the body encoding is behind a flag.
    #[test]
    fn evaluates_a_raw_signet_v1_graph() {
        let bytes = signet_v1_graph_bytes(2);
        assert_eq!(&bytes[..8], MAGIC.as_slice());
        let graph =
            WitnessGraph::from_bytes(&bytes, &digest(&bytes)).expect("signet v1 must parse");
        let assignment = graph
            .calculate_json(r#"{"a":"5"}"#)
            .expect("signet v1 must evaluate");
        assert_eq!(assignment[1].into_bigint().0[0], 7);
    }

    /// Version 2 stays gated: a default build must refuse it rather than
    /// mis-parsing a body encoding it does not implement.
    #[test]
    #[cfg(not(feature = "signet-v2"))]
    fn refuses_version_2_without_the_flag() {
        let mut bytes = signet_v1_graph_bytes(2);
        bytes[8..10].copy_from_slice(&2_u16.to_le_bytes());
        let error = WitnessGraph::from_bytes(&bytes, &digest(&bytes))
            .err()
            .expect("version 2 must be refused without the feature");
        assert!(matches!(error, WitnessError::UnsupportedVersion(2)));
    }

    #[cfg(feature = "signet-v2")]
    #[test]
    fn evaluates_v2_bitwise_xor_and_or_tags() {
        for (tag, expected) in [(wire::BIT_XOR, 6), (wire::BIT_OR, 7)] {
            let bytes = v2_graph_bytes_with_operation(tag, 3);
            let graph =
                WitnessGraph::from_bytes(&bytes, &digest(&bytes)).expect("v2 graph must parse");
            let assignment = graph
                .calculate_json(r#"{"a":"5"}"#)
                .expect("input must evaluate");
            assert_eq!(assignment[1].into_bigint().0[0], expected);
        }
    }

    #[cfg(feature = "signet-v2")]
    #[test]
    fn every_published_operation_tag_has_a_golden_v2_record() {
        assert_eq!(
            wire::ALL_OPERATION_TAGS,
            std::array::from_fn(|index| index as u8)
        );
        for tag in wire::ALL_OPERATION_TAGS {
            let bytes = v2_graph_bytes_with_operation(tag, 3);
            let graph = WitnessGraph::from_bytes(&bytes, &digest(&bytes))
                .unwrap_or_else(|error| panic!("operation tag {tag} must parse: {error}"));
            graph
                .calculate_json(r#"{"a":"5"}"#)
                .unwrap_or_else(|error| panic!("operation tag {tag} must evaluate: {error}"));
        }
    }

    #[test]
    fn automatically_decodes_an_authenticated_zstd_graph() {
        let bytes = signet_v1_graph_bytes(2);
        let compressed = compress_to_vec(bytes.as_slice(), CompressionLevel::Uncompressed);
        let graph = WitnessGraph::from_bytes(&compressed, &digest(&compressed))
            .expect("compressed graph must parse");
        let assignment = graph
            .calculate_json(r#"{"a":"5"}"#)
            .expect("compressed graph must evaluate");
        assert_eq!(assignment[1].into_bigint().0[0], 7);
    }

    #[test]
    fn authenticates_compressed_bytes_before_zstd_decoding() {
        let error = WitnessGraph::from_bytes(&ZSTD_MAGIC, &"00".repeat(32))
            .err()
            .expect("digest must mismatch before the invalid frame is decoded");
        assert!(matches!(error, WitnessError::HashMismatch { .. }));
    }

    #[test]
    fn rejects_zstd_output_past_the_decoded_limit() {
        let bytes = signet_v1_graph_bytes(2);
        let compressed = compress_to_vec(bytes.as_slice(), CompressionLevel::Uncompressed);
        let error = decompress_graph_with_limits(
            &compressed,
            bytes.len() - 1,
            Limits::default().zstd_window_bytes,
        )
        .expect_err("decoded output limit must be enforced while streaming");
        assert!(matches!(error, WitnessError::ZstdOutputTooLarge { .. }));
    }

    #[test]
    fn rejects_oversized_zstd_windows_before_decoding() {
        // Non-single-segment frame with a 16 MiB window descriptor. No block is
        // needed: the configured 8 MiB ceiling rejects the header first.
        let mut compressed = ZSTD_MAGIC.to_vec();
        compressed.extend_from_slice(&[0x00, 0x70]);
        let error = WitnessGraph::from_bytes(&compressed, &digest(&compressed))
            .err()
            .expect("oversized window must fail");
        assert!(matches!(
            error,
            WitnessError::ZstdWindowTooLarge {
                requested: 16_777_216,
                maximum,
            } if maximum == Limits::default().zstd_window_bytes
        ));
    }

    #[test]
    fn rejects_zstd_dictionaries_and_trailing_frames() {
        // Single-segment, one-byte dictionary id, one-byte content size.
        let mut dictionary_frame = ZSTD_MAGIC.to_vec();
        dictionary_frame.extend_from_slice(&[0x21, 0x01, 0x01]);
        let dictionary_error =
            WitnessGraph::from_bytes(&dictionary_frame, &digest(&dictionary_frame))
                .err()
                .expect("dictionary frame must fail");
        assert!(matches!(
            dictionary_error,
            WitnessError::ZstdDictionaryUnsupported
        ));

        let bytes = signet_v1_graph_bytes(2);
        let mut with_trailing = compress_to_vec(bytes.as_slice(), CompressionLevel::Uncompressed);
        with_trailing.extend_from_slice(&ZSTD_MAGIC);
        let trailing_error = WitnessGraph::from_bytes(&with_trailing, &digest(&with_trailing))
            .err()
            .expect("second frame must fail");
        assert!(matches!(trailing_error, WitnessError::ZstdTrailingData));
    }

    #[test]
    fn rejects_zstd_skippable_frames() {
        let skippable = [0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0];
        // A skippable frame is valid zstd but carries no graph, and honouring it
        // would let two distinct artifacts decode to the same graph. It is no longer
        // recognised as a compressed artifact at all, so it falls through to the
        // envelope check and fails there - earlier, and with a clearer error.
        let error = WitnessGraph::from_bytes(&skippable, &digest(&skippable))
            .err()
            .expect("skippable frame must not bypass the compression policy");
        assert!(matches!(error, WitnessError::InvalidMagic));
    }

    #[test]
    fn rejects_a_zstd_checksum_mismatch() {
        let bytes = signet_v1_graph_bytes(2);
        let mut compressed = compress_to_vec(bytes.as_slice(), CompressionLevel::Uncompressed);
        let checksum_byte = compressed.last_mut().expect("encoder must emit a checksum");
        *checksum_byte ^= 1;
        let error = WitnessGraph::from_bytes(&compressed, &digest(&compressed))
            .err()
            .expect("bad frame checksum must fail");
        assert!(matches!(error, WitnessError::ZstdChecksumMismatch));
    }

    /// The whole point of the seam: the same artifact is refused under the client
    /// budget and accepted under the batch-prover one. If these two ever agree, the
    /// limits have collapsed back into one global constant.
    #[test]
    fn limits_are_per_consumer() {
        assert!(Limits::batch_prover().nodes > Limits::client().nodes);
        assert!(Limits::batch_prover().graph_bytes > Limits::client().graph_bytes);

        let mut bytes = graph_bytes(2);
        let over_client = u32::try_from(Limits::client().nodes + 1).expect("fits u32");
        bytes[48..52].copy_from_slice(&over_client.to_le_bytes());
        let sha = digest(&bytes);

        let error = WitnessGraph::from_bytes(&bytes, &sha)
            .err()
            .expect("client budget must refuse it");
        assert!(matches!(
            error,
            WitnessError::CountLimit {
                section: "node",
                maximum,
                ..
            } if maximum == Limits::client().nodes
        ));

        // The batch prover gets past the count check and fails later, on the body
        // that is not actually there - which is the preflight doing its job.
        let error = WitnessGraph::from_bytes_with_limits(&bytes, &sha, Limits::batch_prover())
            .err()
            .expect("the stub body is still too short");
        assert!(matches!(error, WitnessError::Truncated), "{error}");
    }

    /// A published profile must load under the conservative default, or the default
    /// is wrong.
    #[test]
    fn the_client_budget_covers_every_published_profile() {
        let client = Limits::client();
        // pending(5,30), the largest published graph.
        assert!(client.nodes > 1_106_576);
        assert!(client.graph_bytes > 11_978_841);
        // pending(50,30) is deliberately out of reach without opting in.
        assert!(client.nodes < 7_442_816);
        assert!(Limits::batch_prover().nodes > 7_442_816);
    }

    #[test]
    fn rejects_impossible_body_size_before_node_allocation() {
        let mut bytes = graph_bytes(2);
        bytes.truncate(64);
        bytes[48..52].copy_from_slice(&(Limits::default().nodes as u32).to_le_bytes());
        bytes[52..56].copy_from_slice(&1_u32.to_le_bytes());
        bytes[56..60].copy_from_slice(&0_u32.to_le_bytes());
        bytes[60..64].copy_from_slice(&1_u32.to_le_bytes());
        let error = WitnessGraph::from_bytes(&bytes, &digest(&bytes))
            .err()
            .expect("impossible body must fail before reserving nodes");
        assert!(matches!(error, WitnessError::Truncated));
    }

    #[cfg(feature = "signet-v2")]
    #[test]
    fn rejects_non_canonical_v2_varints() {
        let mut bytes = v2_graph_bytes_with_operation(2, 2);
        let input_varint = 64 + 33 + 1;
        bytes.splice(input_varint..=input_varint, [0x81, 0x00]);
        let error = WitnessGraph::from_bytes(&bytes, &digest(&bytes))
            .err()
            .expect("overlong varint must fail");
        assert!(matches!(error, WitnessError::NonCanonicalVarint));
    }

    #[test]
    fn authenticates_before_parsing() {
        let error = WitnessGraph::from_bytes(b"not a graph", &"00".repeat(32))
            .err()
            .expect("digest must mismatch");
        assert!(matches!(error, WitnessError::HashMismatch { .. }));
    }

    #[test]
    fn rejects_forward_references_without_panicking() {
        let bytes = graph_bytes(3);
        let error = WitnessGraph::from_bytes(&bytes, &digest(&bytes))
            .err()
            .expect("self-reference must fail");
        assert!(matches!(
            error,
            WitnessError::ForwardReference {
                index: 3,
                reference: 3
            }
        ));
    }

    #[test]
    fn permits_omitted_zero_inputs_and_rejects_unknown_inputs() {
        let bytes = graph_bytes(2);
        let graph = WitnessGraph::from_bytes(&bytes, &digest(&bytes)).expect("graph must parse");
        graph
            .calculate_json("{}")
            .expect("omitted inputs remain zero");
        assert!(matches!(
            graph.calculate_json(r#"{"b":"5"}"#),
            Err(WitnessError::UnknownInput(name)) if name == "b"
        ));
    }
}
