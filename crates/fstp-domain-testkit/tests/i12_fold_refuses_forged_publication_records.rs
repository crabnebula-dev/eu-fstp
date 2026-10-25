//! I-12 by construction point 1 (design 2.4) at the fold.
//!
//! No command produces these records, so the command-driven suites never
//! reach the fold's structural checks. A decoded or forged ledger can. The
//! fold of `CallPublished` must refuse a record that names a superseded
//! version or skips a call sequence number. Otherwise a replayed ledger
//! could pin a call to a version that was not the head at publication.
//!
//! The fold of `PolicyVersionRecorded` also refuses a version in another
//! currency than its programme's. `Currency` has only EUR outside the
//! money crate's own unit tests, so no test here can build that record yet.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core::num::NonZeroU32;

use fstp_domain::FoldError;
use fstp_domain::id::{CallId, CallSeq, LlmConfigId, PolicyVersionId};
use fstp_domain::record::Record;
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::policy::{DRAFTER_1, P1, PM_A, PM_B, PM_C, PolicyWorld};
use fstp_ledger::Seq;
use fstp_money::Percent;

/// A world with call 1 approved and a later edit of P-02 that keeps the
/// approval, so the head is no longer the first version.
fn world() -> (PolicyWorld, PolicyVersionId, PolicyVersionId) {
    let mut w = PolicyWorld::new(false).unwrap_or_else(|e| panic!("{e}"));
    let first = w.head(P1).unwrap().id;
    assert!(w.draft(DRAFTER_1, 1, P1).unwrap().is_ok());
    assert!(w.approve(PM_B, 1).is_ok());
    let r = w
        .edit(PM_C, P1, |v| {
            v.frozen.p02 = Percent::from_bp(5_000).unwrap()
        })
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    let head = w.head(P1).unwrap().id;
    assert_ne!(first, head);
    (w, first, head)
}

/// A `CallPublished` of call 1 naming `policy` and sequence number `seq`.
fn published(policy: PolicyVersionId, seq: u32) -> Record {
    Record::CallPublished {
        call: CallId::from_raw(1),
        policy,
        seq: CallSeq::new(NonZeroU32::new(seq).unwrap()),
        config: LlmConfigId::from_raw(1),
        by: PM_A,
    }
}

/// Folds `record` onto a copy of the world's state after its last record.
fn fold(w: &PolicyWorld, record: &Record) -> Result<State, FoldError> {
    let mut state = w.state().clone();
    let at = Timestamp::from_micros(w.setup.now);
    fstp_domain::apply(&mut state, Seq::from_raw(u64::MAX), at, record).map(|()| state)
}

/// I-12: the well-formed record folds, so the refusals below come from the
/// field each forgery changes.
#[test]
fn i12_fold_accepts_a_publication_of_the_head_with_the_next_sequence() {
    let (w, _, head) = world();
    let r = fold(&w, &published(head, 1));
    assert!(r.is_ok(), "{r:?}");
}

/// I-12: a `CallPublished` that names a superseded version is inconsistent.
#[test]
fn i12_fold_refuses_a_publication_of_a_superseded_version() {
    let (w, first, _) = world();
    let r = fold(&w, &published(first, 1));
    assert_eq!(r.err(), Some(FoldError::Inconsistent));
}

/// I-12 with R-PC-02: a `CallPublished` that skips a call sequence number
/// is inconsistent.
#[test]
fn i12_fold_refuses_a_publication_that_skips_a_sequence_number() {
    let (w, _, head) = world();
    let r = fold(&w, &published(head, 2));
    assert_eq!(r.err(), Some(FoldError::Inconsistent));
}
