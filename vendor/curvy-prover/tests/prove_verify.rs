use ark_bn254::Fr;
use curvy_prover::{CircuitProver, ProverError};
use sha2::{Digest, Sha256};

const ZKEY: &[u8] = include_bytes!("../testdata/multiplier.zkey");
const ZKEY_SHA256: &str = "320819c1761ecd5edc2d0f6978889457ea402e28d984c42b29153d0f7e81b21f";

#[test]
fn proves_and_self_verifies_an_authenticated_graph() {
    let graph = multiplier_graph();
    let prover = CircuitProver::from_artifacts(ZKEY, ZKEY_SHA256, &graph, &digest(&graph))
        .expect("authenticated fixtures must parse");

    assert_eq!(prover.num_constraints(), 1);
    assert_eq!(prover.num_public(), 1);

    let assignment = prover
        .calculate_witness_json(r#"{"a":"3","b":"11"}"#)
        .expect("graph evaluation must succeed");
    assert_eq!(
        assignment,
        [Fr::from(1), Fr::from(33), Fr::from(3), Fr::from(11)]
    );

    let bundle = prover
        .prove_assignment(&assignment)
        .expect("valid witness must prove and self-verify");
    assert_eq!(bundle.public_signals_json, r#"["33"]"#);
    assert!(bundle.proof_json.contains(r#""protocol":"groth16""#));

    let mut invalid_assignment = assignment;
    invalid_assignment[1] += Fr::from(1);
    assert!(matches!(
        prover.prove_assignment(&invalid_assignment),
        Err(ProverError::SelfVerificationFailed)
    ));
}

fn multiplier_graph() -> Vec<u8> {
    let mut graph = Vec::new();

    graph.extend_from_slice(b"CVYWIT01");
    graph.extend_from_slice(&1_u16.to_le_bytes());
    graph.extend_from_slice(&1_u16.to_le_bytes());
    graph.extend_from_slice(&64_u32.to_le_bytes());
    graph.extend_from_slice(&[0_u8; 32]);
    graph.extend_from_slice(&4_u32.to_le_bytes());
    graph.extend_from_slice(&4_u32.to_le_bytes());
    graph.extend_from_slice(&2_u32.to_le_bytes());
    graph.extend_from_slice(&3_u32.to_le_bytes());

    for input in 0_u32..=2 {
        graph.push(0);
        graph.extend_from_slice(&input.to_le_bytes());
    }
    graph.push(2);
    graph.push(0);
    graph.extend_from_slice(&1_u32.to_le_bytes());
    graph.extend_from_slice(&2_u32.to_le_bytes());

    for signal in [0_u32, 3, 1, 2] {
        graph.extend_from_slice(&signal.to_le_bytes());
    }
    for (name, signal) in [("a", 1_u32), ("b", 2_u32)] {
        graph.extend_from_slice(&fnv1a(name).to_le_bytes());
        graph.extend_from_slice(&signal.to_le_bytes());
        graph.extend_from_slice(&1_u32.to_le_bytes());
    }

    graph
}

fn fnv1a(value: &str) -> u64 {
    value.bytes().fold(0xCBF29CE484222325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001B3)
    })
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
