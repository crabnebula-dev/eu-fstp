//! Issue 6 M3 follow-up: a re-run whose run dies is abandoned (I-10). The
//! cell records `RerunAbandoned` as the system, at its start for every
//! re-run in flight, or once a re-run has been in flight for
//! `RERUN_TIMEOUT_US`. The record frees the in-flight slot, and the re-run
//! still counts toward `MAX_RERUNS`. The fold keeps the request instant,
//! so a replayed ledger applies the same timeout rule.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{AccountId, CallId, ProposalId};
use fstp_domain::time::Timestamp;
use fstp_findings::{
    FindingRecord, FindingRefusal, FindingStore, MAX_RERUNS, RERUN_TIMEOUT_US, RerunEnd,
};
use fstp_json::{FromJson, ToJson, parse};

const CALL: CallId = CallId::from_raw(1);
const P: ProposalId = ProposalId::from_raw(7);
const Q: ProposalId = ProposalId::from_raw(8);
const T0: i64 = 1_800_000_000_000_000;

fn at(micros: i64) -> Timestamp {
    Timestamp::from_micros(T0.saturating_add(micros))
}

fn requested(p: ProposalId) -> FindingRecord {
    FindingRecord::RerunRequested {
        call: CALL,
        proposal: p,
        by: AccountId::from_raw(3),
    }
}

fn abandoned(p: ProposalId, reason: RerunEnd) -> FindingRecord {
    FindingRecord::RerunAbandoned {
        call: CALL,
        proposal: p,
        reason,
    }
}

/// I-10, issue 6 M3: the record survives its codec for both reasons, and
/// a reason off the list never decodes.
#[test]
fn i10_issue6_m3_rerun_abandoned_survives_the_codec() {
    for reason in RerunEnd::ALL {
        let r = abandoned(P, reason);
        let text = fstp_json::to_canonical(&r.to_json()).unwrap();
        let back = FindingRecord::from_json(&parse(text.as_bytes()).unwrap()).unwrap();
        assert_eq!(back, r);
    }
    let bad = r#"{"record":"rerun_abandoned","call":"1","proposal":"7","reason":"model said so"}"#;
    assert!(FindingRecord::from_json(&parse(bad.as_bytes()).unwrap()).is_err());
}

/// I-10, issue 6 M3: an abandoned re-run frees the in-flight slot and
/// still counts toward the three, so a proposal gets three re-runs in all
/// however many of them die.
#[test]
fn i10_issue6_m3_abandoned_rerun_frees_the_slot_and_counts_toward_three() {
    let mut s = FindingStore::genesis();
    s.apply_at(&requested(P), at(0)).unwrap();
    assert_eq!(s.rerun_in_flight(P), Some((CALL, at(0))));
    s.apply_at(&abandoned(P, RerunEnd::CellStart), at(1))
        .unwrap();
    assert_eq!(s.reruns_of(P), (1, false), "the slot is free");
    assert_eq!(s.rerun_in_flight(P), None);
    for k in 2..=MAX_RERUNS {
        let t = i64::from(k) * 10;
        s.apply_at(&requested(P), at(t)).unwrap();
        s.apply_at(&abandoned(P, RerunEnd::CellStart), at(t + 1))
            .unwrap();
    }
    assert_eq!(s.reruns_of(P), (MAX_RERUNS, false));
    assert_eq!(
        s.apply_at(&requested(P), at(100)),
        Err(FindingRefusal::RerunLimit { proposal: P }),
        "abandoned re-runs count toward the three"
    );
}

/// I-10, issue 6 M3: no re-run in flight, nothing to abandon. A second
/// abandon of the same run is refused, so each dead run is one record.
#[test]
fn i10_issue6_m3_only_a_rerun_in_flight_is_abandoned() {
    let mut s = FindingStore::genesis();
    assert_eq!(
        s.apply_at(&abandoned(P, RerunEnd::CellStart), at(0)),
        Err(FindingRefusal::NoRerunInFlight { proposal: P })
    );
    s.apply_at(&requested(P), at(0)).unwrap();
    s.apply_at(&abandoned(P, RerunEnd::CellStart), at(1))
        .unwrap();
    assert_eq!(
        s.apply_at(&abandoned(P, RerunEnd::CellStart), at(2)),
        Err(FindingRefusal::NoRerunInFlight { proposal: P })
    );
}

/// I-10, issue 6 M3: the timeout reason holds only once the re-run has
/// been in flight for `RERUN_TIMEOUT_US`. Another proposal's re-run is
/// unaffected.
#[test]
fn i10_issue6_m3_timeout_abandons_only_a_stale_rerun() {
    let mut s = FindingStore::genesis();
    s.apply_at(&requested(P), at(0)).unwrap();
    s.apply_at(&requested(Q), at(5)).unwrap();
    assert_eq!(
        s.apply_at(&abandoned(P, RerunEnd::Timeout), at(RERUN_TIMEOUT_US - 1)),
        Err(FindingRefusal::RerunNotStale { proposal: P }),
        "too early"
    );
    assert_eq!(
        s.reruns_of(P),
        (1, true),
        "a refused record changes nothing"
    );
    assert_eq!(s.stale_reruns(at(RERUN_TIMEOUT_US - 1)), Vec::new());
    assert_eq!(s.stale_reruns(at(RERUN_TIMEOUT_US)), vec![(P, CALL)]);
    s.apply_at(&abandoned(P, RerunEnd::Timeout), at(RERUN_TIMEOUT_US))
        .unwrap();
    assert_eq!(s.reruns_of(P), (1, false));
    assert_eq!(s.reruns_of(Q), (1, true));
    assert_eq!(s.in_flight_reruns(), vec![(Q, CALL)]);
}

/// I-10, issue 6 M3: a result that ends the run in flight clears its
/// instant, so a later timeout has nothing to abandon.
#[test]
fn i10_issue6_m3_a_result_leaves_nothing_to_abandon() {
    let mut s = FindingStore::genesis();
    s.apply_at(&requested(P), at(0)).unwrap();
    s.apply_at(
        &FindingRecord::RefusalsRecorded {
            call: CALL,
            proposal: P,
            refused: Vec::new(),
        },
        at(1),
    )
    .unwrap();
    assert!(s.stale_reruns(at(RERUN_TIMEOUT_US * 2)).is_empty());
    assert!(s.in_flight_reruns().is_empty());
}
