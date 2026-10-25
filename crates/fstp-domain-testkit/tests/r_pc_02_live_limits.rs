//! R-PC-02 NOTES with P-05 and P-13 NOTE 7, I-14 and I-50: live limits.
//!
//! - The published call records the P-05 and P-13 snapshot next to the
//!   frozen values, and a later live edit never changes it.
//! - Lowering P-05 asks the vault whether every recipient stays within
//!   the new cap, and a "no" refuses the edit (I-14, design 2.4, Q7 A).
//! - P-05 never exceeds P-58 (I-50).
//! - A published call enforces the stricter of its snapshot and the live
//!   value: the lower P-05 and every class of either P-13 (R-PC-02 NOTE 2).
//!   An unpublished call enforces the live values.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::command::Command;
use fstp_domain::id::{CallId, ClassId};
use fstp_domain::oracle::{Answers, Query, QueryKind};
use fstp_domain::record::Record;
use fstp_domain::refusal::RuleRef;
use fstp_domain_testkit::r#gen::policy::{
    DRAFTER_1, P1, PM_A, PM_B, PM_C, PolicyWorld, eur, next_version,
};
use fstp_domain_testkit::mc::policy_model::reads;
use fstp_engine::ExecError;

fn world() -> PolicyWorld {
    PolicyWorld::new(false).unwrap_or_else(|e| panic!("{e}"))
}

/// An `EditPolicy` by programme manager C that sets P-05 to `minor` cents.
fn p05_edit(w: &PolicyWorld, minor: i64) -> Command {
    let head = w.head(P1).unwrap();
    let mut v = next_version(&head, w.fresh_version());
    v.live.p05 = eur(minor).unwrap();
    Command::EditPolicy {
        base: head.id,
        version: Box::new(v),
    }
}

/// The vault's answers to `queries`, with every `AllRecipientsWithinCap` set to `within`.
fn answers(w: &PolicyWorld, queries: &[Query], within: bool) -> Answers {
    let mut out = Answers::new();
    for q in queries {
        let mut a = w.setup.scenario.truth().answer(q);
        if matches!(q, Query::AllRecipientsWithinCap { .. }) {
            a.holds = within;
        }
        out.insert(q.clone(), a);
    }
    out
}

/// R-PC-02 NOTE 2 with NOTE 7: the published call records P-05 and P-13 as
/// they were at publication. A live edit that lowers P-05 and adds a P-13
/// class changes the head and leaves the snapshot as it was.
#[test]
fn r_pc_02_live_edits_never_change_the_publication_snapshot() {
    let mut w = world();
    let head = w.head(P1).unwrap();
    assert!(w.draft(DRAFTER_1, 1, P1).unwrap().is_ok());
    assert!(w.approve(PM_B, 1).is_ok());
    assert!(w.publish(PM_A, 1).unwrap().is_ok());
    let r = w
        .edit(PM_C, P1, |v| {
            v.live.p05 = eur(1_000_000).unwrap();
            v.live.p13.0.insert(ClassId::from_raw(9));
        })
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    let f = reads::frozen_policy(w.state(), CallId::from_raw(1))
        .unwrap_or_else(|e| panic!("{e}"))
        .expect("published");
    assert_eq!((f.p05, &f.p13), (head.live.p05, &head.live.p13));
    let live = reads::head(w.state(), P1)
        .unwrap_or_else(|e| panic!("{e}"))
        .expect("head");
    assert_eq!(live.live.p05, eur(1_000_000).unwrap());
    assert!(live.live.p13.0.contains(&ClassId::from_raw(9)));
}

/// I-14 at the P-05 edit: lowering P-05 asks `AllRecipientsWithinCap` with the new cap.
#[test]
fn i14_lowering_p05_asks_whether_all_recipients_stay_within_cap() {
    let mut w = world();
    let cmd = p05_edit(&w, 1_000_000);
    let ctx = w.setup.ctx(PM_C, false);
    let qs = fstp_domain::queries(w.state(), &cmd, &ctx).unwrap_or_else(|r| panic!("{r}"));
    let cap = eur(1_000_000).unwrap();
    assert!(
        qs.iter()
            .any(|q| matches!(q, Query::AllRecipientsWithinCap { cap: c, .. } if *c == cap)),
        "{qs:?}"
    );
}

/// I-14 at the P-05 edit: when the vault answers that a recipient would
/// exceed the lowered cap, the edit is refused. When it answers that all
/// stay within, the edit records the new version.
#[test]
fn i14_lowering_p05_is_refused_when_a_recipient_would_exceed_it() {
    let mut w = world();
    let cmd = p05_edit(&w, 1_000_000);
    let ctx = w.setup.ctx(PM_C, false);
    let qs = fstp_domain::queries(w.state(), &cmd, &ctx).unwrap_or_else(|r| panic!("{r}"));
    let refused = fstp_domain::decide(w.state(), &cmd, &ctx, &answers(&w, &qs, false));
    assert!(
        matches!(refused, Err(r) if r.rule == RuleRef::I14),
        "{refused:?}"
    );
    let accepted = fstp_domain::decide(w.state(), &cmd, &ctx, &answers(&w, &qs, true))
        .unwrap_or_else(|r| panic!("{r}"));
    assert!(
        accepted
            .iter()
            .any(|r| matches!(r, Record::PolicyVersionRecorded { .. })),
        "{accepted:?}"
    );
}

/// I-50: an edit that sets P-05 above P-58 is refused, and one that sets it
/// equal to P-58 is accepted.
#[test]
fn i50_p05_above_p58_is_refused() {
    let mut w = world();
    let ceiling = w.head(P1).unwrap().live.p58.expect("P-58").amount().minor();
    let above = p05_edit(&w, ceiling.saturating_add(1));
    let r = w.setup.run(PM_C, false, above);
    assert!(
        matches!(r, Err(ExecError::Refused(x)) if x.rule == RuleRef::I50),
        "{r:?}"
    );
    let equal = p05_edit(&w, ceiling);
    let r = w.setup.run(PM_C, false, equal);
    assert!(r.is_ok(), "{r:?}");
}

/// Drafts call `call` and has it approved by programme manager B.
fn ready(w: &mut PolicyWorld, call: u128) {
    assert!(w.draft(DRAFTER_1, call, P1).unwrap().is_ok());
    assert!(w.approve(PM_B, call).is_ok());
}

fn p05_of(w: &PolicyWorld, call: u128) -> fstp_money::NonNegAmount {
    reads::effective_p05(w.state(), CallId::from_raw(call)).unwrap_or_else(|e| panic!("{e}"))
}

fn p13_of(w: &PolicyWorld, call: u128) -> BTreeSet<ClassId> {
    reads::effective_p13(w.state(), CallId::from_raw(call))
        .unwrap_or_else(|e| panic!("{e}"))
        .0
}

/// R-PC-02 NOTE 2 with NOTE 7: a live edit never loosens a published
/// call's cap. After P-05 is raised, the published call keeps its snapshot.
#[test]
fn r_pc_02_raised_p05_leaves_a_published_call_on_its_snapshot() {
    let mut w = world();
    let before = w.head(P1).unwrap().live.p05;
    ready(&mut w, 1);
    assert!(w.publish(PM_A, 1).unwrap().is_ok());
    let raised = eur(45_000_000).unwrap();
    let r = w.edit(PM_C, P1, |v| v.live.p05 = raised).unwrap();
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(p05_of(&w, 1), before);
}

/// R-PC-02 NOTE 2 with NOTE 7: a live edit may tighten a published call's
/// cap. After P-05 is lowered, the published call enforces the live value.
#[test]
fn r_pc_02_lowered_p05_tightens_a_published_call() {
    let mut w = world();
    ready(&mut w, 1);
    assert!(w.publish(PM_A, 1).unwrap().is_ok());
    let lowered = eur(1_000_000).unwrap();
    let r = w.edit(PM_C, P1, |v| v.live.p05 = lowered).unwrap();
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(p05_of(&w, 1), lowered);
}

/// R-PC-02 NOTE 2 with NOTE 7: after P-13 is replaced, a published call
/// enforces every class of its snapshot and of the live value.
#[test]
fn r_pc_02_replaced_p13_leaves_a_published_call_on_the_union() {
    let mut w = world();
    let snapshot = w.head(P1).unwrap().live.p13.0;
    ready(&mut w, 1);
    assert!(w.publish(PM_A, 1).unwrap().is_ok());
    let replaced: BTreeSet<ClassId> = [ClassId::from_raw(9)].into_iter().collect();
    assert!(snapshot.is_disjoint(&replaced));
    let r = w
        .edit(PM_C, P1, |v| v.live.p13.0 = replaced.clone())
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    let union: BTreeSet<ClassId> = snapshot.union(&replaced).copied().collect();
    assert_eq!(p13_of(&w, 1), union);
}

/// R-PC-02 NOTE 7: an unpublished call has no snapshot, so it enforces the
/// live P-05 and P-13, raised or replaced.
#[test]
fn r_pc_02_an_unpublished_call_enforces_the_live_limits() {
    let mut w = world();
    ready(&mut w, 1);
    let raised = eur(45_000_000).unwrap();
    let replaced: BTreeSet<ClassId> = [ClassId::from_raw(9)].into_iter().collect();
    let r = w
        .edit(PM_C, P1, |v| {
            v.live.p05 = raised;
            v.live.p13.0 = replaced.clone();
        })
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(p05_of(&w, 1), raised);
    assert_eq!(p13_of(&w, 1), replaced);
}

/// I-14 with design 4.4: an accepted lowering of P-05 records the vault's
/// answer. The batch holds exactly one `VaultOutcome` for
/// `AllRecipientsWithinCap`, with the answer's digest, `holds` true and the
/// state's epoch, ahead of the new version.
#[test]
fn i14_an_accepted_lowering_of_p05_records_the_vault_outcome() {
    let mut w = world();
    let cmd = p05_edit(&w, 1_000_000);
    let ctx = w.setup.ctx(PM_C, false);
    let qs = fstp_domain::queries(w.state(), &cmd, &ctx).unwrap_or_else(|r| panic!("{r}"));
    let given = answers(&w, &qs, true);
    let cap = qs
        .iter()
        .find(|q| matches!(q, Query::AllRecipientsWithinCap { .. }))
        .expect("the cap question");
    let answer = given.get(cap).expect("the cap answer");
    let batch =
        fstp_domain::decide(w.state(), &cmd, &ctx, &given).unwrap_or_else(|r| panic!("{r}"));
    let outcomes: Vec<usize> = batch
        .iter()
        .enumerate()
        .filter(|(_, r)| matches!(r, Record::VaultOutcome { .. }))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(outcomes.len(), 1, "{batch:?}");
    let at = outcomes[0];
    assert_eq!(
        batch[at],
        Record::VaultOutcome {
            kind: QueryKind::AllRecipientsWithinCap,
            digest: answer.digest,
            holds: true,
            epoch: w.state().epoch(),
        }
    );
    let version = batch
        .iter()
        .position(|r| matches!(r, Record::PolicyVersionRecorded { .. }))
        .expect("the new version");
    assert!(at < version, "{batch:?}");
}
