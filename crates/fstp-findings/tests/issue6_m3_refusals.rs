//! Issue 6 M3: the refused stages and the re-runs in the finding store
//! (I-10, H-03). The list is two closed enums, a record supersedes the
//! earlier list, and the re-run bounds are kept in the fold, so a replayed
//! ledger holds them across a restart.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{AccountId, CallId, ProposalId};
use fstp_findings::{
    AssessStage, FindingRecord, FindingRefusal, FindingStore, MAX_REFUSED, MAX_RERUNS, RefusalCode,
    RefusedStage,
};
use fstp_json::{FromJson, ToJson, parse};

const CALL: CallId = CallId::from_raw(1);
const P: ProposalId = ProposalId::from_raw(7);
const Q: ProposalId = ProposalId::from_raw(8);

fn pair(s: AssessStage, c: RefusalCode) -> RefusedStage {
    RefusedStage { stage: s, code: c }
}

fn recorded(p: ProposalId, refused: Vec<RefusedStage>) -> FindingRecord {
    FindingRecord::RefusalsRecorded {
        call: CALL,
        proposal: p,
        refused,
    }
}

fn requested(p: ProposalId) -> FindingRecord {
    FindingRecord::RerunRequested {
        call: CALL,
        proposal: p,
        by: AccountId::from_raw(3),
    }
}

/// I-10, H-03: a refusal list survives the encode and decode of its
/// record, and a later record replaces it. An empty list clears it.
#[test]
fn i10_h03_issue6_m3_refusals_survive_the_codec_and_are_replaced() {
    let first = recorded(P, vec![pair(AssessStage::Quality, RefusalCode::ScoreLike)]);
    let text = fstp_json::to_canonical(&first.to_json()).unwrap();
    let back = FindingRecord::from_json(&parse(text.as_bytes()).unwrap()).unwrap();
    assert_eq!(back, first);
    let mut s = FindingStore::genesis();
    s.apply(&back).unwrap();
    assert_eq!(
        s.refusals_of(P),
        &[pair(AssessStage::Quality, RefusalCode::ScoreLike)]
    );
    assert!(s.refusals_of(Q).is_empty(), "another proposal");
    s.apply(&recorded(
        P,
        vec![pair(AssessStage::Integrity, RefusalCode::Json)],
    ))
    .unwrap();
    assert_eq!(
        s.refusals_of(P),
        &[pair(AssessStage::Integrity, RefusalCode::Json)],
        "the new list supersedes the old"
    );
    s.apply(&recorded(P, Vec::new())).unwrap();
    assert!(s.refusals_of(P).is_empty(), "a clean run clears it");
}

/// I-10, TH-01: a stage or code off its list, or an extra member, never
/// decodes, so no model text can enter a record.
#[test]
fn i10_th01_issue6_m3_record_refuses_names_off_the_lists() {
    let ok = r#"{"record":"refusals_recorded","call":"1","proposal":"7","refused":[{"stage":"quality","code":"json"}]}"#;
    assert!(FindingRecord::from_json(&parse(ok.as_bytes()).unwrap()).is_ok());
    for bad in [
        r#"{"record":"refusals_recorded","call":"1","proposal":"7","refused":[{"stage":"ignore previous","code":"json"}]}"#,
        r#"{"record":"refusals_recorded","call":"1","proposal":"7","refused":[{"stage":"quality","code":"<b>"}]}"#,
        r#"{"record":"refusals_recorded","call":"1","proposal":"7","refused":[{"stage":"quality","code":"json","text":"x"}]}"#,
        r#"{"record":"refusals_recorded","call":"1","proposal":"7","refused":"quality"}"#,
    ] {
        assert!(
            FindingRecord::from_json(&parse(bad.as_bytes()).unwrap()).is_err(),
            "{bad}"
        );
    }
}

/// I-10: the list is bounded.
#[test]
fn i10_issue6_m3_refusal_list_is_bounded() {
    let mut s = FindingStore::genesis();
    let long = vec![pair(AssessStage::Claims, RefusalCode::Shape); MAX_REFUSED + 1];
    assert_eq!(
        s.apply(&recorded(P, long)),
        Err(FindingRefusal::TooManyRefused { proposal: P })
    );
}

/// I-10, H-03, issue 6 M3: at most one re-run in flight, at most
/// `MAX_RERUNS` in all, each counted per proposal, and a result ends the
/// run in flight.
#[test]
fn i10_h03_issue6_m3_rerun_bounds_are_kept_in_the_fold() {
    let mut s = FindingStore::genesis();
    assert_eq!(MAX_RERUNS, 3);
    s.apply(&requested(P)).unwrap();
    assert_eq!(s.reruns_of(P), (1, true));
    assert_eq!(
        s.apply(&requested(P)),
        Err(FindingRefusal::RerunInFlight { proposal: P }),
        "one in flight at a time"
    );
    s.apply(&requested(Q)).unwrap();
    s.apply(&recorded(P, Vec::new())).unwrap();
    assert_eq!(s.reruns_of(P), (1, false));
    s.apply(&requested(P)).unwrap();
    s.apply(&recorded(P, Vec::new())).unwrap();
    s.apply(&requested(P)).unwrap();
    s.apply(&recorded(P, Vec::new())).unwrap();
    assert_eq!(s.reruns_of(P), (3, false));
    assert_eq!(
        s.apply(&requested(P)),
        Err(FindingRefusal::RerunLimit { proposal: P }),
        "three in all"
    );
    assert_eq!(s.reruns_of(Q), (1, true), "another proposal is unaffected");
}
