//! I-52, I-51, R-GA-01, D2e: the composed publication and the pairing rules of the fold (M4 design sections 3.4 and 3.10).
//!
//! NOT YET COMPILED. Cargo does not discover files in `tests/pending_d2e/`.
//! The refusal of a `CallPublished` entry with no Guide record runs today,
//! in `tests/i52_fold_refuses_call_published_without_guide_published.rs`.
//! This file holds the cases that need the Guide record itself. Move it to
//! `tests/` once these exist:
//!
//! - the `GuidePublished { call, version, digest }` record. The design does
//!   not say which envelope side holds it. [`guide_published`] and
//!   [`is_guide_published`] are the only places that name it;
//! - `fstp_domain_testkit::activation::activate` switched to the creator
//!   path (D8 step 2), so the programme has a clean report at publication;
//! - `fstp_engine::compose::publication` returning the command the engine
//!   executes as one entry.
//!
//! - `i52_publication_entry_pairs_call_published_with_guide_published`:
//!   the composed publication appends one `CallPublished` and one
//!   `GuidePublished` of version 1 for the call, under one command id.
//! - `i52_fold_refuses_guide_published_in_a_later_entry`: the Guide record
//!   must sit in the same entry. One entry later does not pair.
//! - `i52_fold_refuses_second_guide_published_for_a_call`: section 3.10.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Actor;
use fstp_domain::id::{CallId, CallSeq, ContentDigest, LlmConfigId, PolicyVersionId};
use fstp_domain_testkit::activation::activate;
use fstp_domain_testkit::r#gen::review::run_on;
use fstp_domain_testkit::r#gen::roster::{ADMIN_2, P1, STAFF_PM, SodSetup, T0, call, sod_truth};
use fstp_domain_testkit::scenario::Scenario;
use fstp_engine::compose;
use fstp_engine::{Record, replay};
use fstp_ledger::{Entry, MemStore, RecordStore, Seq};

/// The Guide record of `call`.
///
/// Seam: the design places `GuidePublished` in the publication entry but
/// names no envelope side. This reading puts it on the creator side.
fn guide_published(call: CallId, version: u32) -> Record {
    Record::Creator(fstp_creator::CreatorRecord::GuidePublished {
        call,
        version,
        digest: ContentDigest::from_bytes([0x52; 32]),
    })
}

/// Whether `r` is the Guide record of `call` at `version`.
fn is_guide_published(r: &Record, call: CallId, version: u32) -> bool {
    matches!(
        r,
        Record::Creator(fstp_creator::CreatorRecord::GuidePublished { call: c, version: v, .. })
            if *c == call && *v == version
    )
}

/// A `CallPublished` of call 1 at the head version, as the M2 publication
/// writes it, by `by`.
fn call_published(policy: PolicyVersionId) -> Record {
    Record::Core(fstp_domain::Record::CallPublished {
        call: call(1),
        policy,
        seq: CallSeq::FIRST,
        config: LlmConfigId::from_raw(1),
        by: STAFF_PM,
    })
}

/// P1 activated through the creator, with call 1 drafted and approved.
fn approved() -> Scenario {
    let mut s = Scenario::new(sod_truth()).unwrap_or_else(|e| panic!("open: {e:?}"));
    let steps = SodSetup::one(0, &[1])
        .steps()
        .unwrap_or_else(|e| panic!("{e}"));
    let (programme, rest): (Vec<_>, Vec<_>) = steps.into_iter().partition(|st| {
        matches!(
            st.cmd,
            fstp_domain::Command::CreateProgramme { .. } | fstp_domain::Command::GrantRole { .. }
        )
    });
    for st in &programme {
        run_on(&mut s, st, T0).unwrap_or_else(|e| panic!("{:?}: {e:?}", st.cmd.kind()));
    }
    activate(&mut s, P1, ADMIN_2).unwrap_or_else(|e| panic!("activate: {e:?}"));
    for st in &rest {
        run_on(&mut s, st, T0).unwrap_or_else(|e| panic!("{:?}: {e:?}", st.cmd.kind()));
    }
    s
}

fn read_all(store: &MemStore<Record>) -> Vec<Entry<Record>> {
    let mut out = Vec::new();
    store.read(Seq::ZERO, usize::MAX, &mut out).unwrap();
    out
}

/// I-52, R-GA-01, D2e: the composed publication is one entry with one
/// `CallPublished` of call 1 and one `GuidePublished` of version 1.
#[test]
fn i52_publication_entry_pairs_call_published_with_guide_published() {
    let mut s = approved();
    let before = s.entries().unwrap().len();
    let cmd = compose::publication(s.state(), call(1)).unwrap_or_else(|e| panic!("{e:?}"));
    let ctx = s.ctx(T0, Actor::Account(STAFF_PM));
    s.execute(cmd, ctx)
        .unwrap_or_else(|e| panic!("publication: {e:?}"));
    let entries = s.entries().unwrap();
    let added = &entries[before..];
    assert!(
        added.iter().all(|e| e.command == added[0].command),
        "R-GA-01: one entry"
    );
    let published = added
        .iter()
        .filter(|e| matches!(&e.record, Record::Core(fstp_domain::Record::CallPublished { call: c, .. }) if *c == call(1)))
        .count();
    let guides = added
        .iter()
        .filter(|e| is_guide_published(&e.record, call(1), 1))
        .count();
    assert_eq!((published, guides), (1, 1), "I-52: the pair, once each");
}

/// The ledger of [`approved`] with each batch appended as one entry.
fn forged(batches: Vec<Vec<Record>>) -> Vec<Entry<Record>> {
    let s = approved();
    let (engine, _) = s.into_parts();
    let (mut store, _, _) = engine.into_parts();
    for (n, batch) in batches.into_iter().enumerate() {
        let mut id = *b"forged:guide:000";
        id[15] = b'0'.saturating_add(u8::try_from(n).unwrap());
        let head = store.head();
        store.append(head, T0.micros(), id, batch).unwrap();
    }
    read_all(&store)
}

fn head_policy() -> PolicyVersionId {
    let s = approved();
    s.state().core.policy().head(P1).unwrap().id
}

/// I-52, R-GA-01, D2e: the fold accepts the pair in one entry.
#[test]
fn i52_fold_accepts_the_pair_in_one_entry() {
    let ledger = forged(vec![vec![
        call_published(head_policy()),
        guide_published(call(1), 1),
    ]]);
    assert!(replay(&ledger).is_ok(), "I-52: the paired entry folds");
}

/// I-52, R-GA-01, D2e: a `GuidePublished` one entry after its
/// `CallPublished` does not pair with it.
#[test]
fn i52_fold_refuses_guide_published_in_a_later_entry() {
    let ledger = forged(vec![
        vec![call_published(head_policy())],
        vec![guide_published(call(1), 1)],
    ]);
    assert!(replay(&ledger).is_err(), "I-52: the pair spans two entries");
}

/// I-52, section 3.10: the fold refuses a second `GuidePublished` for a call.
#[test]
fn i52_fold_refuses_second_guide_published_for_a_call() {
    let ledger = forged(vec![
        vec![call_published(head_policy()), guide_published(call(1), 1)],
        vec![guide_published(call(1), 1)],
    ]);
    assert!(replay(&ledger).is_err(), "I-52: a second Guide for call 1");
}
