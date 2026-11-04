//! I-95, ADR-015: the platform loads the shipped proposal definition only after the drift check passes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_journey::{LoadError, PROPOSAL_V1, load_proposal_v1};

/// I-95: the shipped definition loads, and it is the parsed `PROPOSAL_V1`.
#[test]
fn i95_load_proposal_v1_accepts_the_shipped_definition() {
    let def = load_proposal_v1().unwrap_or_else(|e| panic!("I-95: {e}"));
    assert_eq!(def.checksum(), &fstp_crypto::sha256(PROPOSAL_V1));
    assert_eq!(def.nodes().len(), 16, "I-95: one node per state");
}

/// I-95: a load error names each drift, so a refused start says why.
#[test]
fn i95_load_error_text_names_each_drift() {
    let drift = vec![fstp_journey::drift::Drift::EdgeMissing(
        "T-STAGE2-RANKED".to_owned(),
    )];
    let text = LoadError::Drift(drift).to_string();
    assert!(text.contains("T-STAGE2-RANKED"), "I-95: {text}");
}
