//! I-06, SoD-09 and I-04: every vault answer a decision uses is recorded (overview NOTE 3 and NOTE 5, design 4.4).
//!
//! An accepted grant, draft or reaction holds one `VaultOutcome` per
//! question the step asked, with the answer's kind, bit and epoch. A
//! `VaultChanged` at the epoch already processed is refused, because the
//! application accepts answers only at the epoch it has processed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use fstp_domain::command::{Actor, Command, SystemCause};
use fstp_domain::id::{BindingId, ProposalId, VaultEpoch};
use fstp_domain::oracle::{Answers, Query, QueryKind};
use fstp_domain::record::Record;
use fstp_domain::refusal::RefusalReason;
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::roster::{
    A, B, Backend, C, Facts, Flags, P1, SodSetup, SodWorld, Step, T0, call, draft, grant, sod_truth,
};

/// One programme with P-12 = 1 and call 1 published.
fn world() -> SodWorld {
    let mut setup = SodSetup::one(1, &[1]);
    setup.published = vec![call(1)];
    SodWorld::from_setup(Backend::Production, sod_truth(), &setup)
        .unwrap_or_else(|e| panic!("setup: {e}"))
}

/// The answers as a multiset of kind, bit and epoch.
fn expected(answers: &Answers) -> BTreeMap<(QueryKind, bool, VaultEpoch), usize> {
    let mut out = BTreeMap::new();
    for (q, a) in answers.iter() {
        let n = out.entry((q.kind(), a.holds, a.epoch)).or_insert(0usize);
        *n = n.saturating_add(1);
    }
    out
}

/// The `VaultOutcome` records of `records` as the same multiset.
fn recorded(records: &[Record]) -> BTreeMap<(QueryKind, bool, VaultEpoch), usize> {
    let mut out = BTreeMap::new();
    for r in records {
        if let Record::VaultOutcome {
            kind, holds, epoch, ..
        } = r
        {
            let n = out.entry((*kind, *holds, *epoch)).or_insert(0usize);
            *n = n.saturating_add(1);
        }
    }
    out
}

/// Runs `step` and checks one `VaultOutcome` per question it asked.
fn check_step(w: &mut SodWorld, step: &Step, what: &str) {
    let (_, answers) = w
        .ask(step, Facts::Effective)
        .unwrap_or_else(|r| panic!("{what}: queries refused: {r}"));
    assert!(!answers.is_empty(), "{what} asks the vault");
    let records = w
        .exec(step, Facts::Effective)
        .unwrap_or_else(|e| panic!("{what}: harness: {e}"))
        .unwrap_or_else(|r| panic!("{what} refused: {r}"));
    assert_eq!(
        recorded(&records),
        expected(&answers),
        "{what}: one VaultOutcome per answer used: {records:?}"
    );
}

/// The `VaultChanged` that processes the vault's current epoch.
fn vault_changed(w: &SodWorld, epoch: VaultEpoch) -> Step {
    Step {
        actor: Actor::System(SystemCause::Vault),
        flags: Flags::NONE,
        cmd: Command::VaultChanged {
            epoch,
            changed: w.truth.changed_since(w.epoch()),
        },
    }
}

/// SoD-09, I-06: a Judging grant records its `IsVerified` and
/// `SameIdentityAsAny` answers.
#[test]
fn i06_sod09_grant_records_each_vault_answer() {
    let mut w = world();
    let step = grant(BindingId::from_raw(301), C, P1, Role::CommitteeMember, T0);
    check_step(&mut w, &step, "c's committee grant");
}

/// SoD-06, I-04, I-06: a draft records its `InExcludedClass` and
/// `SameIdentityAsAny` answers.
#[test]
fn i04_sod06_draft_records_each_vault_answer() {
    let mut w = world();
    let step = draft(
        B,
        ProposalId::from_raw(1),
        call(1),
        BindingId::from_raw(201),
        false,
    );
    check_step(&mut w, &step, "b's draft");
}

/// I-06, enforcement point 3: the reaction to b's verification records
/// its `ChangedSince` answer and every recheck answer.
#[test]
fn i06_reaction_records_each_vault_answer() {
    let mut w = world();
    let committee = grant(BindingId::from_raw(301), A, P1, Role::CommitteeMember, T0);
    w.exec(&committee, Facts::Effective)
        .unwrap()
        .unwrap_or_else(|r| panic!("a's committee grant refused: {r}"));
    let step = draft(
        B,
        ProposalId::from_raw(1),
        call(1),
        BindingId::from_raw(201),
        false,
    );
    w.exec(&step, Facts::Effective)
        .unwrap()
        .unwrap_or_else(|r| panic!("b's draft refused: {r}"));
    w.truth.verify(B);

    let reaction = vault_changed(&w, w.truth.epoch());
    let (_, answers) = w
        .ask(&reaction, Facts::Effective)
        .unwrap_or_else(|r| panic!("reaction queries refused: {r}"));
    assert!(
        answers
            .iter()
            .any(|(q, _)| matches!(q, Query::SameIdentityAsAny { .. })),
        "the reaction rechecks b's binding"
    );
    let records = w
        .sync(Facts::Effective)
        .unwrap_or_else(|e| panic!("reaction: harness: {e}"))
        .unwrap_or_else(|r| panic!("the reaction was refused: {r}"));
    assert_eq!(
        recorded(&records),
        expected(&answers),
        "the reaction records one VaultOutcome per answer used: {records:?}"
    );
}

/// I-06, overview NOTE 3: a `VaultChanged` at the epoch already processed
/// is refused before any question, and its decision is refused too.
#[test]
fn i06_vault_changed_at_the_processed_epoch_is_refused() {
    let w = world();
    let step = vault_changed(&w, w.epoch());
    let ctx = w.ctx(&step);
    match fstp_domain::queries(&w.state, &step.cmd, &ctx) {
        Ok(qs) => panic!("VaultChanged at the processed epoch asked {qs:?}"),
        Err(r) => assert_eq!(r.reason, RefusalReason::WrongState, "refused for {r}"),
    }
    let mut answers = Answers::new();
    let changed = Query::ChangedSince { epoch: w.epoch() };
    answers.insert(changed.clone(), w.truth.answer(&changed));
    match fstp_domain::decide(&w.state, &step.cmd, &ctx, &answers) {
        Ok(records) => panic!("VaultChanged at the processed epoch recorded {records:?}"),
        Err(r) => assert_eq!(r.reason, RefusalReason::WrongState, "refused for {r}"),
    }
}

/// I-06, enforcement point 3, overview NOTE 5: when b holds two Receiving
/// bindings with the same candidate set and P-13, the reaction asks each
/// question once and records each answer once.
#[test]
fn i06_reaction_records_a_shared_answer_once() {
    let mut setup = SodSetup::one(1, &[1, 2]);
    setup.published = vec![call(1), call(2)];
    let mut w = SodWorld::from_setup(Backend::Production, sod_truth(), &setup)
        .unwrap_or_else(|e| panic!("setup: {e}"));
    let committee = grant(BindingId::from_raw(301), A, P1, Role::CommitteeMember, T0);
    w.exec(&committee, Facts::Effective)
        .unwrap()
        .unwrap_or_else(|r| panic!("a's committee grant refused: {r}"));
    for (n, c) in [(1u128, 1u128), (2, 2)] {
        let step = draft(
            B,
            ProposalId::from_raw(n),
            call(c),
            BindingId::from_raw(200 + n),
            false,
        );
        w.exec(&step, Facts::Effective)
            .unwrap()
            .unwrap_or_else(|r| panic!("b's draft in call {c} refused: {r}"));
    }
    w.truth.verify(B);

    let reaction = vault_changed(&w, w.truth.epoch());
    let (_, answers) = w
        .ask(&reaction, Facts::Effective)
        .unwrap_or_else(|r| panic!("reaction queries refused: {r}"));
    let records = w
        .sync(Facts::Effective)
        .unwrap_or_else(|e| panic!("reaction: harness: {e}"))
        .unwrap_or_else(|r| panic!("the reaction was refused: {r}"));
    let voids = records
        .iter()
        .filter(|r| matches!(r, Record::BindingVoided(_)))
        .count();
    assert_eq!(voids, 2, "both of b's drafts are voided: {records:?}");
    assert_eq!(
        recorded(&records),
        expected(&answers),
        "the reaction records each shared answer once: {records:?}"
    );
}
