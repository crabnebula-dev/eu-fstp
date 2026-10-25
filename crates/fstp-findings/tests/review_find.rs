//! Reviewer reproducers for lane L-FIND-A (I-11, R-LA-02, P-21 NOTE 10).
//!
//! Each test fails against the code under review and passes once the
//! defect it names is fixed. Every value is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{CallId, ContentDigest, LlmConfigId, ProposalId, TextId, TextRef};
use fstp_findings::{
    Confidence, EvidenceRef, Finding, FindingId, FindingKind, FindingRecord, FindingStore,
    Severity, TraceRef, UntrustedText,
};
use fstp_json::{FromJson, parse};

fn evidence() -> EvidenceRef {
    EvidenceRef::Submission {
        text: TextRef::new(TextId::from_raw(1), ContentDigest::from_bytes([7; 32])),
        start: 0,
        end: 4,
    }
}

fn finding(id: u128, call: u128, config: u128, evidence: Vec<EvidenceRef>) -> Finding {
    Finding {
        id: FindingId::from_raw(id),
        call: CallId::from_raw(call),
        proposal: ProposalId::from_raw(1),
        config: LlmConfigId::from_raw(config),
        kind: FindingKind::Quality,
        criterion: None,
        severity: Severity::Minor,
        confidence: Confidence::FULL,
        statement: UntrustedText::new("synthetic statement".to_owned()),
        evidence,
        trace: TraceRef::from_raw(id),
    }
}

/// R-LA-02: every finding carries evidence pointers. A finding with an
/// empty evidence list must be refused by the store.
#[test]
fn review_r_la_02_finding_without_evidence_is_refused() {
    let mut store = FindingStore::genesis();
    let r = store.insert(LlmConfigId::from_raw(10), finding(1, 7, 10, Vec::new()));
    assert!(
        r.is_err(),
        "R-LA-02: a finding with no evidence pointer was stored"
    );
    assert_eq!(store, FindingStore::genesis());
}

/// I-11, P-21 NOTE 10: a replacement takes the next model on the pinned
/// list. A call that moved from config 10 to config 20 can never return
/// to config 10, so its findings never cycle between configurations.
#[test]
fn review_p21_replacement_never_returns_to_a_retired_config() {
    let mut store = FindingStore::genesis();
    let call = CallId::from_raw(7);
    store
        .insert(
            LlmConfigId::from_raw(10),
            finding(1, 7, 10, vec![evidence()]),
        )
        .unwrap();
    store
        .replace_call(
            call,
            LlmConfigId::from_raw(20),
            vec![finding(2, 7, 20, vec![evidence()])],
        )
        .unwrap();
    let back = store.replace_call(
        call,
        LlmConfigId::from_raw(10),
        vec![finding(3, 7, 10, vec![evidence()])],
    );
    assert!(
        back.is_err(),
        "P-21 NOTE 10: the call went back to the retired primary config"
    );
}

/// I-11, P-21 NOTE 10: a regeneration record must name which pinned
/// fallback model the replacement config uses. Without it, neither the
/// fold nor `decide_finding` in `fstp-engine` can check that the call took
/// the next model on the frozen list. A record that names no model must
/// therefore be refused by the decoder.
#[test]
fn review_p21_regenerated_record_without_model_is_refused() {
    let text = br#"{"record":"regenerated","call":"2","config_id":"11","findings":[]}"#;
    let v = parse(text).unwrap();
    assert!(
        FindingRecord::from_json(&v).is_err(),
        "P-21 NOTE 10: a regeneration that names no fallback model decoded"
    );
}
