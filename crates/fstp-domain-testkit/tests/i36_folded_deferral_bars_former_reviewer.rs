//! I-36 with the stage rows folded: a former reviewer never takes a Receiving role in a later call while the reviewed proposal is undecided (design 2.7, decided 2026-10-25).
//!
//! The scenario runs production commands from genesis with P-12 = 0, so
//! SoD-05 alone would let a former committee member apply. The stage rows
//! of lane L-LIFE are folded through the structural fold, as the teeth
//! tests do, until that lane records them. The full chain through the
//! lifecycle commands is `i36_former_reviewer_never_receives_in_call_under_evaluation`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::Actor;
use fstp_domain::id::{AssignmentId, BindingId, ProposalId};
use fstp_domain::policy::ReadAccess;
use fstp_domain::record::{Record, Transitioned};
use fstp_domain::refusal::RuleRef;
use fstp_domain::rules::{Row, StateTag};
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, DraftSpec, L1, PR1, R1, R2, ReviewSetup, ReviewWorld, assign, handle,
    judge_binding, machine_judges, review_truth,
};
use fstp_domain_testkit::r#gen::roster::{Backend, SodSetup, Step, T0, call, draft, end, publish};

fn world() -> ReviewWorld {
    let mut base = SodSetup::one(0, &[1, 2]);
    base.published = vec![call(1)];
    let setup = ReviewSetup {
        base,
        p38: BTreeMap::new(),
        p10: ReadAccess::AssignedReviewersOnly,
        judges: machine_judges(),
        drafts: vec![DraftSpec {
            lead: L1,
            proposal: PR1,
            call: call(1),
            team: Vec::new(),
            minor: false,
            submit: true,
        }],
    };
    let mut w = ReviewWorld::from_setup(
        Backend::Production,
        review_truth(setup.accounts()),
        &setup,
        None,
    )
    .unwrap_or_else(|e| panic!("setup: {e}"));
    ok(
        &mut w,
        &assign(
            COORDINATOR,
            AssignmentId::from_raw(1),
            PR1,
            R1,
            AssignmentKind::Reviewer,
            Some(handle(1)),
        ),
    );
    ok(&mut w, &end(judge_binding(1), T0));
    ok(&mut w, &end(judge_binding(2), T0));
    ok(&mut w, &publish(call(2)));
    w
}

fn ok(w: &mut ReviewWorld, s: &Step) -> Vec<Record> {
    w.exec(s)
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("{:?} refused: {r}", s.cmd.kind()))
}

fn fold(w: &mut ReviewWorld, rows: &[(StateTag, StateTag, Row)]) {
    for (from, to, row) in rows {
        w.commit(&[Record::Transitioned(Transitioned {
            proposal: PR1,
            from: *from,
            to: *to,
            row: *row,
            actor: Actor::Account(COORDINATOR),
            decision: None,
        })])
        .unwrap_or_else(|e| panic!("fold {row:?}: {e}"));
    }
}

const TO_STAGE2: [(StateTag, StateTag, Row); 2] = [
    (
        StateTag::Submitted,
        StateTag::Stage1,
        Row::SubmittedToStage1,
    ),
    (StateTag::Stage1, StateTag::Stage2, Row::Stage1ToStage2),
];

fn apply(who: fstp_domain::id::AccountId, n: u128, c: u128) -> Step {
    draft(
        who,
        ProposalId::from_raw(n),
        call(c),
        BindingId::from_raw(n),
        false,
    )
}

/// I-36, decided 2026-10-25: while PR1 is in STAGE2 of call 1, it is
/// under evaluation in call 1 only, but it is undecided. So R1, who
/// reviewed it, is refused a draft in call 2 too, with P-12 = 0. This
/// closes the race with a later deferral of PR1 into call 2. R2, who never
/// reviewed PR1, drafts in call 2.
#[test]
fn i36_former_reviewer_may_not_apply_while_a_reviewed_proposal_is_undecided() {
    let mut w = world();
    fold(&mut w, &TO_STAGE2);
    let step = apply(R1, 9_302, 2);
    match w.exec(&step).unwrap_or_else(|e| panic!("harness: {e}")) {
        Err(r) => assert_eq!(r.rule, RuleRef::I36, "{r}"),
        Ok(records) => panic!("I-36: R1 drafted in call 2 while PR1 is undecided: {records:?}"),
    }
    let step = apply(R2, 9_303, 2);
    ok(&mut w, &step);
}

/// I-36, Q12: a DEFERRED proposal is under evaluation in the next call
/// too, so R1 is refused a draft in call 2 once PR1 is deferred. R2, who
/// never reviewed PR1, drafts in call 2.
#[test]
fn i36_deferred_proposal_bars_its_former_reviewer_in_the_next_call() {
    let mut w = world();
    fold(&mut w, &TO_STAGE2);
    fold(
        &mut w,
        &[(StateTag::Stage2, StateTag::Deferred, Row::Stage2ToDeferred)],
    );
    let step = apply(R1, 9_401, 2);
    match w.exec(&step).unwrap_or_else(|e| panic!("harness: {e}")) {
        Err(r) => assert_eq!(r.rule, RuleRef::I36, "{r}"),
        Ok(records) => panic!("I-36: R1 drafted in the next call of deferred PR1: {records:?}"),
    }
    let step = apply(R2, 9_402, 2);
    ok(&mut w, &step);
}
