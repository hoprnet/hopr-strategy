#![doc = include_str!("../README.md")]
//!
//! ## Security model
//!
//! The proving key parser is the committed `rs-core` implementation vendored
//! from `ark-circom` without its Wasmer witness calculator. Bulk query points are
//! constructed unchecked for fast startup, so every caller must provide a pinned
//! SHA-256 digest for the zkey before parsing is allowed.
//!
//! Native builds enable `std` and Rayon-backed `parallel` support by default.
//! Portable WASM uses the `wasm` feature; threaded browser builds use
//! `wasm-threads` and export `initThreadPool(n)` so the host selects the worker
//! count explicitly.

pub mod qap;
pub mod wtns;
pub mod zkey;

use std::io::Cursor;

use ark_bn254::{Bn254, Fq, Fq2, Fr};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, prepare_verifying_key};
use ark_relations::gr1cs::SynthesisError;
use ark_serialize::SerializationError;
use curvy_witness::{WitnessError, WitnessGraph};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use thiserror::Error;

use qap::CircomReduction;
use wtns::WtnsError;
use zkey::ZkeyMatrices;

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("expected zkey SHA-256 must be exactly 64 hexadecimal characters")]
    InvalidExpectedHash,
    #[error("zkey SHA-256 mismatch: expected {expected}, got {actual}")]
    ZkeyHashMismatch { expected: String, actual: String },
    #[error("invalid zkey: {0}")]
    InvalidZkey(SerializationError),
    #[error(transparent)]
    InvalidWitness(#[from] WtnsError),
    #[error(transparent)]
    InvalidWitnessGraph(#[from] WitnessError),
    #[error("witness assignment length mismatch: expected {expected}, got {actual}")]
    AssignmentLength { expected: usize, actual: usize },
    #[error("Groth16 proof generation failed: {0}")]
    ProofGeneration(SynthesisError),
    #[error("Groth16 verification failed: {0}")]
    Verification(SynthesisError),
    #[error("generated Groth16 proof did not verify")]
    SelfVerificationFailed,
}

/// Parsed, reusable proving key and constraint matrices for one circuit.
pub struct Prover {
    pk: ProvingKey<Bn254>,
    matrices: ZkeyMatrices<Fr>,
    pvk: PreparedVerifyingKey<Bn254>,
    assignment_size: usize,
}

impl Prover {
    /// Authenticate and parse one zkey. Hash verification happens before the
    /// unchecked point parser sees any artifact-controlled curve coordinates.
    pub fn from_zkey_bytes(bytes: &[u8], expected_sha256: &str) -> Result<Self, ProverError> {
        verify_sha256(bytes, expected_sha256)?;
        let mut cursor = Cursor::new(bytes);
        let (pk, matrices) = zkey::read_zkey(&mut cursor).map_err(ProverError::InvalidZkey)?;
        let pvk = prepare_verifying_key(&pk.vk);
        let assignment_size = pk.a_query.len();
        Ok(Self {
            pk,
            matrices,
            pvk,
            assignment_size,
        })
    }

    pub fn num_constraints(&self) -> usize {
        self.matrices.num_constraints
    }

    pub fn num_public(&self) -> usize {
        self.matrices.num_instance_variables.saturating_sub(1)
    }

    pub fn prove(&self, full_assignment: &[Fr]) -> Result<Proof<Bn254>, ProverError> {
        self.validate_assignment(full_assignment)?;
        let mut rng = ark_std::rand::rngs::OsRng;
        let r = Fr::rand(&mut rng);
        let s = Fr::rand(&mut rng);
        Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
            &self.pk,
            r,
            s,
            &self.matrices.matrices,
            self.matrices.num_instance_variables,
            self.matrices.num_constraints,
            full_assignment,
        )
        .map_err(ProverError::ProofGeneration)
    }

    pub fn public_inputs<'a>(&self, full_assignment: &'a [Fr]) -> Result<&'a [Fr], ProverError> {
        self.validate_assignment(full_assignment)?;
        Ok(&full_assignment[1..self.matrices.num_instance_variables])
    }

    pub fn verify(&self, proof: &Proof<Bn254>, public_inputs: &[Fr]) -> Result<bool, ProverError> {
        Groth16::<Bn254>::verify_proof(&self.pvk, proof, public_inputs)
            .map_err(ProverError::Verification)
    }

    /// Decode, prove, and self-verify one snarkjs witness before returning it.
    pub fn prove_wtns(&self, bytes: &[u8]) -> Result<ProofBundle, ProverError> {
        let assignment = wtns::read_wtns(bytes)?;
        self.prove_assignment(&assignment)
    }

    /// Prove and self-verify one direct arkworks witness assignment.
    pub fn prove_assignment(&self, assignment: &[Fr]) -> Result<ProofBundle, ProverError> {
        let proof = self.prove(assignment)?;
        let public_inputs = self.public_inputs(assignment)?;
        if !self.verify(&proof, public_inputs)? {
            return Err(ProverError::SelfVerificationFailed);
        }
        Ok(ProofBundle {
            proof_json: proof_to_snarkjs_json(&proof),
            public_signals_json: publics_to_json(public_inputs),
        })
    }

    fn validate_assignment(&self, full_assignment: &[Fr]) -> Result<(), ProverError> {
        self.validate_assignment_size(full_assignment.len())
    }

    fn validate_assignment_size(&self, actual: usize) -> Result<(), ProverError> {
        if actual != self.assignment_size {
            return Err(ProverError::AssignmentLength {
                expected: self.assignment_size,
                actual,
            });
        }
        Ok(())
    }
}

/// Authenticated witness graph and proving key for one immutable circuit bundle.
pub struct CircuitProver {
    prover: Prover,
    witness_graph: WitnessGraph,
}

impl CircuitProver {
    pub fn from_artifacts(
        zkey: &[u8],
        expected_zkey_sha256: &str,
        witness_graph: &[u8],
        expected_graph_sha256: &str,
    ) -> Result<Self, ProverError> {
        let prover = Prover::from_zkey_bytes(zkey, expected_zkey_sha256)?;
        let witness_graph = WitnessGraph::from_bytes(witness_graph, expected_graph_sha256)?;
        prover.validate_assignment_size(witness_graph.assignment_size())?;
        Ok(Self {
            prover,
            witness_graph,
        })
    }

    pub fn num_constraints(&self) -> usize {
        self.prover.num_constraints()
    }

    pub fn num_public(&self) -> usize {
        self.prover.num_public()
    }

    pub fn r1cs_sha256(&self) -> [u8; 32] {
        self.witness_graph.r1cs_sha256()
    }

    /// Evaluate authenticated `curvy-graph-v1` inputs without proving yet.
    ///
    /// This split is useful to native operators that report witness and proof
    /// timings separately. Most callers should use [`Self::prove_json`].
    pub fn calculate_witness_json(&self, input_json: &str) -> Result<Vec<Fr>, ProverError> {
        Ok(self.witness_graph.calculate_json(input_json)?)
    }

    /// Prove and self-verify an assignment produced by this circuit's graph.
    pub fn prove_assignment(&self, assignment: &[Fr]) -> Result<ProofBundle, ProverError> {
        self.prover.prove_assignment(assignment)
    }

    pub fn prove_json(&self, input_json: &str) -> Result<ProofBundle, ProverError> {
        let assignment = self.calculate_witness_json(input_json)?;
        self.prove_assignment(&assignment)
    }
}

pub struct ProofBundle {
    pub proof_json: String,
    pub public_signals_json: String,
}

fn verify_sha256(bytes: &[u8], expected_sha256: &str) -> Result<(), ProverError> {
    if expected_sha256.len() != 64 || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ProverError::InvalidExpectedHash);
    }
    let expected = expected_sha256.to_ascii_lowercase();
    let actual = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual != expected {
        return Err(ProverError::ZkeyHashMismatch { expected, actual });
    }
    Ok(())
}

fn fq_dec(value: &Fq) -> String {
    BigUint::from_bytes_be(&value.into_bigint().to_bytes_be()).to_str_radix(10)
}

fn fr_dec(value: &Fr) -> String {
    BigUint::from_bytes_be(&value.into_bigint().to_bytes_be()).to_str_radix(10)
}

fn fq2_json(value: &Fq2) -> String {
    format!("[\"{}\",\"{}\"]", fq_dec(&value.c0), fq_dec(&value.c1))
}

/// Serialize a proof with the same coordinate order and shape as snarkjs.
pub fn proof_to_snarkjs_json(proof: &Proof<Bn254>) -> String {
    format!(
        "{{\"pi_a\":[\"{}\",\"{}\",\"1\"],\"pi_b\":[{}, {},[\"1\",\"0\"]],\"pi_c\":[\"{}\",\"{}\",\"1\"],\"protocol\":\"groth16\",\"curve\":\"bn128\"}}",
        fq_dec(&proof.a.x),
        fq_dec(&proof.a.y),
        fq2_json(&proof.b.x),
        fq2_json(&proof.b.y),
        fq_dec(&proof.c.x),
        fq_dec(&proof.c.y),
    )
}

pub fn publics_to_json(publics: &[Fr]) -> String {
    let items = publics
        .iter()
        .map(|public| format!("\"{}\"", fr_dec(public)))
        .collect::<Vec<_>>();
    format!("[{}]", items.join(","))
}

#[cfg(feature = "wasm-threads")]
pub use wasm_bindgen_rayon::init_thread_pool;

#[cfg(feature = "wasm")]
mod wasm_api {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    pub struct WasmCircuitProver(crate::CircuitProver);

    #[wasm_bindgen]
    impl WasmCircuitProver {
        #[wasm_bindgen(constructor)]
        pub fn new(
            zkey: &[u8],
            expected_zkey_sha256: &str,
            witness_graph: &[u8],
            expected_graph_sha256: &str,
        ) -> Result<WasmCircuitProver, JsError> {
            crate::CircuitProver::from_artifacts(
                zkey,
                expected_zkey_sha256,
                witness_graph,
                expected_graph_sha256,
            )
            .map(WasmCircuitProver)
            .map_err(|error| JsError::new(&error.to_string()))
        }

        #[wasm_bindgen(getter, js_name = numConstraints)]
        pub fn num_constraints(&self) -> usize {
            self.0.num_constraints()
        }

        #[wasm_bindgen(getter, js_name = numPublic)]
        pub fn num_public(&self) -> usize {
            self.0.num_public()
        }

        /// Calculate, prove, and self-verify directly from circuit input JSON.
        pub fn prove(&self, input_json: &str) -> Result<String, JsError> {
            self.0
                .prove_json(input_json)
                .map(bundle_json)
                .map_err(|error| JsError::new(&error.to_string()))
        }
    }

    #[wasm_bindgen]
    pub struct WasmProver(crate::Prover);

    #[wasm_bindgen]
    impl WasmProver {
        #[wasm_bindgen(constructor)]
        pub fn new(zkey: &[u8], expected_sha256: &str) -> Result<WasmProver, JsError> {
            crate::Prover::from_zkey_bytes(zkey, expected_sha256)
                .map(WasmProver)
                .map_err(|error| JsError::new(&error.to_string()))
        }

        #[wasm_bindgen(getter, js_name = numConstraints)]
        pub fn num_constraints(&self) -> usize {
            self.0.num_constraints()
        }

        #[wasm_bindgen(getter, js_name = numPublic)]
        pub fn num_public(&self) -> usize {
            self.0.num_public()
        }

        /// Return `{"proof": ..., "publicSignals": [...]}` in snarkjs shape.
        pub fn prove(&self, wtns: &[u8]) -> Result<String, JsError> {
            self.0
                .prove_wtns(wtns)
                .map(bundle_json)
                .map_err(|error| JsError::new(&error.to_string()))
        }
    }

    fn bundle_json(bundle: crate::ProofBundle) -> String {
        format!(
            "{{\"proof\":{},\"publicSignals\":{}}}",
            bundle.proof_json, bundle.public_signals_json
        )
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::{Prover, ProverError, verify_sha256};

    #[test]
    fn rejects_an_untrusted_zkey_before_parsing() {
        let error = verify_sha256(b"not a zkey", &"00".repeat(32)).expect_err("hash must mismatch");
        assert!(matches!(error, ProverError::ZkeyHashMismatch { .. }));
    }

    #[test]
    fn rejects_a_malformed_expected_hash() {
        assert!(matches!(
            verify_sha256(b"anything", "not-a-digest"),
            Err(ProverError::InvalidExpectedHash)
        ));
    }

    #[test]
    fn rejects_malformed_zkey_after_its_digest_matches() {
        let bytes = b"not a zkey";
        let digest = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let error = Prover::from_zkey_bytes(bytes, &digest)
            .err()
            .expect("zkey parser must reject junk");
        assert!(matches!(error, ProverError::InvalidZkey(_)));
    }
}
