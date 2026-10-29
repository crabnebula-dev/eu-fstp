//! I-52, I-51, R-GA-01, D2e: one path to a published call (M4 design sections 3.4 and 3.10).
//!
//! `PublishCall` and `GuidePublished { call, version: 1, digest }` are one
//! ledger entry. The engine composes the publication only with a
//! recomputed clean validation report, so I-52 holds when the Guide is
//! generated. The engine fold refuses an entry holding `CallPublished`
//! without its `GuidePublished`.
//!
//! The fold test forges the ledger a broken writer would leave: the setup
//! from genesis drafts and approves call 1 through production commands,
//! and one more entry holds only a `CallPublished` of call 1. The record
//! itself is well formed, since the core fold accepts it on the same
//! state. So a refusal can only come from the missing Guide record.
//!
//! The composition tests run `fstp_engine::compose::publication` over
//! states with no creator records. No validation report of such a
//! programme is clean, so the composition must refuse with its own
//! reason, never with the stub's `NotImplemented`.
//!
//! Status: red. The fold folds the forged entry, and the W0 stub of
//! `compose::publication` refuses with `ComposeError::NotImplemented`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::FoldError;
use fstp_domain::id::{CallId, CallSeq, LlmConfigId, PolicyVersionId};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::run_on;
use fstp_domain_testkit::r#gen::roster::{P1, STAFF_PM, SodSetup, T0, call, sod_truth};
use fstp_domain_testkit::scenario::Scenario;
use fstp_engine::compose::{self, ComposeError};
use fstp_engine::{Engine, EngineState, OpenError, Record};
use fstp_ledger::{Entry, MemStore, RecordStore, Seq};

/// The command id of the forged entry. It is outside the driver's
/// reserved namespace.
const FORGED: [u8; 16] = *b"forged:publish:1";

/// A scenario from genesis with call 1 of P1 drafted and approved, and no
/// call published.
fn approved() -> Scenario {
    let setup = SodSetup::one(0, &[1]);
    let mut s = Scenario::new(sod_truth()).unwrap_or_else(|e| panic!("open: {e:?}"));
    for step in setup.steps().unwrap_or_else(|e| panic!("{e}")) {
        run_on(&mut s, &step, T0)
            .unwrap_or_else(|e| panic!("setup step {:?}: {e:?}", step.cmd.kind()));
    }
    s
}

/// The `CallPublished` a publication of call 1 at the head version would
/// hold: the first version of P1, the first call sequence number and the
/// configuration the M2 setup pins.
fn call_published() -> fstp_domain::Record {
    fstp_domain::Record::CallPublished {
        call: call(1),
        policy: PolicyVersionId::from_raw(P1.raw()),
        seq: CallSeq::FIRST,
        config: LlmConfigId::from_raw(1),
        by: STAFF_PM,
    }
}

fn read_all(store: &MemStore<Record>) -> Vec<Entry<Record>> {
    let mut out = Vec::new();
    store
        .read(Seq::ZERO, usize::MAX, &mut out)
        .unwrap_or_else(|e| panic!("store read: {e:?}"));
    out
}

/// The scenario's store with one more entry that holds only a
/// `CallPublished` of call 1, and the engine state before it.
fn forged() -> (MemStore<Record>, EngineState, Vec<Entry<Record>>) {
    let s = approved();
    let before = s.state().clone();
    let (engine, _) = s.into_parts();
    let (mut store, _, _) = engine.into_parts();
    let prefix = read_all(&store);
    let head = store.head();
    store
        .append(
            head,
            T0.micros(),
            FORGED,
            vec![Record::Core(call_published())],
        )
        .unwrap_or_else(|e| panic!("forged append: {e:?}"));
    (store, before, prefix)
}

/// Whether `e` is a refusal for the entry's content, not for its position
/// in time or sequence, and not a fold lane that has not landed.
fn content_refusal(e: FoldError) -> bool {
    !matches!(
        e,
        FoldError::TimeBackwards | FoldError::OutOfOrder | FoldError::NotImplemented
    )
}

/// I-52, R-GA-01, D2e: replay refuses a ledger with a `CallPublished`
/// entry that holds no `GuidePublished`. The prefix replays to the
/// scenario's state, and the core fold accepts the record on that state,
/// so the refusal comes from the missing Guide record.
#[test]
fn i52_fold_refuses_call_published_without_guide_published() {
    let (store, before, prefix) = forged();
    let replayed = fstp_engine::replay(&prefix).unwrap_or_else(|e| panic!("prefix: {e}"));
    assert_eq!(replayed, before, "I-23: the prefix replays to the state");
    let mut core = before.core.clone();
    let at = Timestamp::from_micros(T0.micros());
    assert_eq!(
        fstp_domain::apply(&mut core, Seq::from_raw(u64::MAX), at, &call_published()),
        Ok(()),
        "the forged record is well formed for the core fold"
    );
    let entries = read_all(&store);
    assert_eq!(entries.len(), prefix.len().saturating_add(1));
    match fstp_engine::replay(&entries) {
        Err(e) => assert!(
            content_refusal(e),
            "I-52: the refusal names the unpaired record, got {e:?}"
        ),
        Ok(_) => panic!("I-52: replay folded a CallPublished with no GuidePublished"),
    }
}

/// I-52, D2e: a driver opened over a store that holds the unpaired
/// `CallPublished` refuses to open, since opening replays the ledger.
#[test]
fn i52_open_refuses_store_with_call_published_without_guide_published() {
    let (store, _, _) = forged();
    match Engine::open(
        store,
        fstp_domain_testkit::vault::SyntheticVault::new(sod_truth()),
    ) {
        Err(OpenError::Fold(e)) => assert!(
            content_refusal(e),
            "I-52: the refusal names the unpaired record, got {e:?}"
        ),
        Err(e) => panic!("I-52: expected a fold refusal, got {e:?}"),
        Ok(_) => panic!("I-52: the driver opened a ledger with an unpaired CallPublished"),
    }
}

/// Whether the composition refused for a reason of its own.
fn refused_for_a_reason(r: &Result<fstp_engine::Command, ComposeError>) -> bool {
    matches!(r, Err(e) if !matches!(e, ComposeError::NotImplemented(_)))
}

/// I-52, D2e: an approved call of a programme with no creator records has
/// no clean validation report, so the publication is not composed.
#[test]
fn i52_compose_publication_refuses_without_clean_report() {
    let s = approved();
    let r = compose::publication(s.state(), call(1));
    assert!(
        refused_for_a_reason(&r),
        "I-52: publication composed without a clean report: {r:?}"
    );
}

/// I-52, D2e: no publication is composed for a call that does not exist,
/// neither in the empty state nor beside an approved call.
#[test]
fn i52_compose_publication_refuses_unknown_call() {
    let unknown = CallId::from_raw(9);
    let r = compose::publication(&EngineState::genesis(), unknown);
    assert!(refused_for_a_reason(&r), "I-52: genesis: {r:?}");
    let s = approved();
    let r = compose::publication(s.state(), unknown);
    assert!(refused_for_a_reason(&r), "I-52: unknown call: {r:?}");
}
