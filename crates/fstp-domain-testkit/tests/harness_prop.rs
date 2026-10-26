//! Self-tests of the fstp-prop adapters (`docs/handoff/m2-design.md` section 6.1).
//!
//! - Every state machine postcondition compares accept and refuse with an
//!   independent reference in both directions. This catches over-denial as
//!   well as over-permission.
//! - Every machine also checks `replay(ledger) == state` and that each read
//!   of the ledger extends the previous one (I-23).
//!
//! API this file is written against, in `fstp_domain_testkit::harness::prop`:
//! `two_way(context, reference_accepts, actual)`,
//! `two_way_exec(context, reference_accepts, driver_result)`,
//! `replay_matches(entries, state)` and `append_only(previous, current)`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_domain::engine::FoldError;
use fstp_domain::id::{ContentDigest, VaultEpoch};
use fstp_domain::oracle::QueryKind;
use fstp_domain::record::Record as CoreRecord;
use fstp_domain::refusal::Refusal;
use fstp_domain_testkit::harness::prop::{append_only, replay_matches, two_way, two_way_exec};
use fstp_engine::{ExecError, Record, replay};
use fstp_ledger::{Entry, MemStore, RecordStore, Seq, StoreError};

fn outcome(holds: bool) -> Record {
    Record::Core(CoreRecord::VaultOutcome {
        kind: QueryKind::IsVerified,
        digest: ContentDigest::from_bytes([5; 32]),
        holds,
        epoch: VaultEpoch::GENESIS,
    })
}

/// A ledger of three structural records in two batches.
fn ledger(first: bool) -> Vec<Entry<Record>> {
    let mut store = MemStore::<Record>::new();
    store
        .append(Seq::ZERO, 10, [1; 16], vec![outcome(first), outcome(true)])
        .expect("first batch");
    store
        .append(Seq::from_raw(2), 20, [2; 16], vec![outcome(false)])
        .expect("second batch");
    let mut out = Vec::new();
    store.read(Seq::ZERO, usize::MAX, &mut out).expect("read");
    out
}

// ---------------------------------------------------------------------------
// Two-way postconditions
// ---------------------------------------------------------------------------

/// Design 6.1: agreement with the reference passes in both directions.
#[test]
fn harness_two_way_passes_agreement_in_both_directions() {
    let accepted: Result<u8, Refusal> = Ok(1);
    let refused: Result<u8, Refusal> = Err(Refusal::not_implemented());
    assert_eq!(two_way("accept", true, &accepted), Ok(()));
    assert_eq!(two_way("refuse", false, &refused), Ok(()));
}

/// Design 6.1: an engine that accepts what the reference refuses fails the
/// postcondition (over-permission).
#[test]
fn harness_two_way_flags_over_permission() {
    let accepted: Result<u8, Refusal> = Ok(1);
    let r = two_way("over-permission", false, &accepted);
    let message = r.expect_err("over-permission passed");
    assert!(message.contains("over-permission"), "{message}");
}

/// Design 6.1: an engine that refuses what the reference accepts fails the
/// postcondition (over-denial). A stub that refuses everything fails here.
#[test]
fn harness_two_way_flags_over_denial() {
    let refused: Result<u8, Refusal> = Err(Refusal::not_implemented());
    let r = two_way("over-denial", true, &refused);
    let message = r.expect_err("over-denial passed");
    assert!(message.contains("over-denial"), "{message}");
}

// ---------------------------------------------------------------------------
// Replay and append-only (I-23)
// ---------------------------------------------------------------------------

/// I-23: a state that is the replay of the ledger passes.
#[test]
fn i23_replay_helper_accepts_the_replayed_state() {
    let entries = ledger(true);
    let state = replay(&entries).expect("replay");
    assert_eq!(replay_matches(&entries, &state), Ok(()));
}

/// I-23: a state that lags the ledger fails.
#[test]
fn i23_replay_helper_flags_a_diverging_state() {
    let entries = ledger(true);
    let stale = replay(&entries[..1]).expect("replay of a prefix");
    assert!(replay_matches(&entries, &stale).is_err());
}

/// I-23: a later read that extends the earlier one passes, including an
/// equal read and a read from an empty ledger.
#[test]
fn i23_append_only_helper_accepts_an_extension() {
    let entries = ledger(true);
    assert_eq!(append_only(&entries[..1], &entries), Ok(()));
    assert_eq!(append_only(&entries, &entries), Ok(()));
    assert_eq!(append_only(&[], &entries), Ok(()));
}

/// I-23: a later read that drops an entry or changes a past one fails.
#[test]
fn i23_append_only_helper_flags_a_truncated_or_changed_ledger() {
    let entries = ledger(true);
    let changed = ledger(false);
    assert!(append_only(&entries, &entries[..2]).is_err());
    assert!(append_only(&entries, &changed).is_err());
}

/// Design 6.1: over a driver result, an accept and an `ExecError::Refused`
/// are compared with the reference in both directions. Every other driver
/// error fails the check, whatever the reference says, so a fold error
/// (an I-23 defect) never passes as an expected refusal.
#[test]
fn harness_two_way_exec_counts_only_refused_as_a_refusal() {
    let accepted: Result<Seq, ExecError> = Ok(Seq::from_raw(1));
    let refused: Result<Seq, ExecError> = Err(ExecError::Refused(Refusal::not_implemented()));
    assert_eq!(two_way_exec("accept", true, &accepted), Ok(()));
    assert_eq!(two_way_exec("refuse", false, &refused), Ok(()));
    assert!(two_way_exec("over-permission", false, &accepted).is_err());
    assert!(two_way_exec("over-denial", true, &refused).is_err());
    for e in [
        ExecError::Fold(FoldError::TimeBackwards),
        ExecError::Store(StoreError::Unavailable),
        ExecError::Contended,
        ExecError::Duplicate {
            at: Seq::from_raw(1),
        },
        ExecError::ReservedCommandId,
    ] {
        for reference in [true, false] {
            let message = two_way_exec("other", reference, &Err(e)).expect_err("passed");
            assert!(
                message.contains("neither an accept nor a refusal"),
                "{message}"
            );
        }
    }
}
