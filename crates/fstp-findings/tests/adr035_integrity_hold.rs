//! ADR-035: the store's integrity hold (TH-01, I-10). A flagged
//! proposal is held until one release by the coordinator; a release
//! without a hold, or a second one, is refused and changes nothing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use fstp_domain::id::{AccountId, CallId, ProposalId};
use fstp_findings::{FindingRecord, FindingRefusal, FindingStore, IntegrityReason};

const CALL: CallId = CallId::from_raw(2);
const X: ProposalId = ProposalId::from_raw(5);
const Y: ProposalId = ProposalId::from_raw(6);
const COORD: AccountId = AccountId::from_raw(8);

fn held(p: ProposalId) -> FindingRecord {
    FindingRecord::IntegrityHeld {
        call: CALL,
        proposal: p,
        reasons: vec![IntegrityReason::ZeroWidth, IntegrityReason::Override],
    }
}

fn released(p: ProposalId) -> FindingRecord {
    FindingRecord::IntegrityReleased {
        call: CALL,
        proposal: p,
        by: COORD,
    }
}

/// ADR-035, TH-01, I-10: held until released, once, by the record of the
/// coordinator; other proposals are never held.
#[test]
fn adr035_th01_held_proposal_takes_no_ai_assessment_until_released() {
    let mut s = FindingStore::genesis();
    assert!(!s.held(X));
    assert_eq!(s.check_not_held(X), Ok(()));
    let before = s.clone();
    assert_eq!(
        s.apply(&released(X)),
        Err(FindingRefusal::NotHeld { proposal: X })
    );
    assert_eq!(s, before, "a refused release changes nothing");

    s.apply(&held(X)).unwrap();
    assert!(s.held(X));
    assert!(!s.held(Y));
    assert_eq!(
        s.check_not_held(X),
        Err(FindingRefusal::IntegrityHeld { proposal: X })
    );
    assert_eq!(
        s.integrity_of(X).map(|i| i.reasons.clone()),
        Some(vec![IntegrityReason::ZeroWidth, IntegrityReason::Override])
    );

    s.apply(&released(X)).unwrap();
    assert!(!s.held(X));
    assert_eq!(s.check_not_held(X), Ok(()));
    assert_eq!(s.integrity_of(X).and_then(|i| i.released_by), Some(COORD));
    let before = s.clone();
    assert_eq!(
        s.apply(&released(X)),
        Err(FindingRefusal::NotHeld { proposal: X }),
        "I-10: one release"
    );
    assert_eq!(s, before);
}

/// ADR-035, TH-26: both records round-trip through the codec with one
/// spelling, and a reason list out of order or empty is refused.
#[test]
fn adr035_integrity_records_round_trip_and_refuse_other_spellings() {
    use fstp_json::{FromJson, ToJson};
    for r in [held(X), released(X)] {
        let v = r.to_json();
        assert_eq!(FindingRecord::from_json(&v).unwrap(), r);
    }
    for bad in [
        r#"{"record":"integrity_held","call":"2","proposal":"5","reasons":[]}"#,
        r#"{"record":"integrity_held","call":"2","proposal":"5","reasons":["override","zero_width"]}"#,
        r#"{"record":"integrity_held","call":"2","proposal":"5","reasons":["override","override"]}"#,
        r#"{"record":"integrity_held","call":"2","proposal":"5","reasons":["other"]}"#,
        r#"{"record":"integrity_released","call":"2","proposal":"5"}"#,
    ] {
        let v = fstp_json::parse(bad.as_bytes()).unwrap();
        assert!(FindingRecord::from_json(&v).is_err(), "{bad}");
    }
}
