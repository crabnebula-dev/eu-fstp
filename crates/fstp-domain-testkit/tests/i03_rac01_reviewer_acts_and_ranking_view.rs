//! I-03, R-AC-01 and the Conflict declarations section: reviewer acts in the stages, recusal and the ranking view (design 2.7 and 3.7).
//!
//! Every start state is built from genesis by production commands. The
//! stage rows of lane L-LIFE are folded through the structural fold, as
//! the teeth tests do, until that lane records them. Where a test needs a
//! vault answer that the reaction never saw, it calls `decide` with
//! answers it builds, as a havoc vault may give them at the current epoch.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::{AssignmentKind, cut_off_recusal_queries, recused_from_cut_off};
use fstp_domain::command::{Actor, Command, DeclarationSubject};
use fstp_domain::id::{AccountId, AssignmentId, CommandId, ProposalId};
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::record::{Record, Transitioned};
use fstp_domain::refusal::{Refusal, RuleRef};
use fstp_domain::rules::{Row, StateTag};
use fstp_domain::visibility::ranking_view;
use fstp_domain_testkit::r#gen::policy::text;
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, DraftSpec, L2, PR1, PR2, R1, R2, ReviewWorld, assign, declare, handle, read,
    review_truth,
};
use fstp_domain_testkit::r#gen::roster::{Backend, Flags, Step, call};
use fstp_domain_testkit::mc::conflict_model::conflict_setup;

const COMMAND: CommandId = CommandId::from_bytes(*b"test:i03:rac01!!");

fn world(two: bool) -> ReviewWorld {
    let mut setup = conflict_setup();
    if two {
        setup.drafts.push(DraftSpec {
            lead: L2,
            proposal: PR2,
            call: call(1),
            team: Vec::new(),
            minor: false,
            submit: true,
        });
    }
    ReviewWorld::from_setup(
        Backend::Production,
        review_truth(setup.accounts()),
        &setup,
        None,
    )
    .unwrap_or_else(|e| panic!("setup: {e}"))
}

fn ok(w: &mut ReviewWorld, s: &Step) -> Vec<Record> {
    w.exec(s)
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("{:?} refused: {r}", s.cmd))
}

fn go(w: &mut ReviewWorld, p: ProposalId, to: StateTag) {
    let path = [
        (
            StateTag::Submitted,
            StateTag::Stage1,
            Row::SubmittedToStage1,
        ),
        (StateTag::Stage1, StateTag::Stage2, Row::Stage1ToStage2),
        (StateTag::Stage2, StateTag::Ranked, Row::Stage2ToRanked),
        (
            StateTag::Ranked,
            StateTag::IrcReview,
            Row::RankedToIrcReview,
        ),
    ];
    for (from, next, row) in path {
        if w.view.proposals.get(&p).map(|l| l.state) != Some(from) {
            continue;
        }
        w.commit(&[Record::Transitioned(Transitioned {
            proposal: p,
            from,
            to: next,
            row,
            actor: Actor::Account(COORDINATOR),
            decision: None,
        })])
        .unwrap_or_else(|e| panic!("fold {row:?}: {e}"));
        if next == to {
            return;
        }
    }
}

/// R1 assigned to PR1, with no conflict declared, and PR1 in `to`.
fn active_reviewer(w: &mut ReviewWorld, to: StateTag) -> AssignmentId {
    let id = AssignmentId::from_raw(1);
    ok(
        w,
        &assign(
            COORDINATOR,
            id,
            PR1,
            R1,
            AssignmentKind::Reviewer,
            Some(handle(1)),
        ),
    );
    ok(
        w,
        &declare(R1, DeclarationSubject::Assignment(id), false, false),
    );
    go(w, PR1, to);
    id
}

/// Runs `step` on production with the world's answers, except that every
/// `HasConflict` question about `account` is answered `conflict`.
fn decide_with(
    w: &ReviewWorld,
    step: &Step,
    account: AccountId,
    conflict: bool,
) -> Result<Vec<Record>, Refusal> {
    let ctx = step.ctx(w.sod.now, COMMAND);
    let mut answers = Answers::new();
    for q in fstp_domain::queries(&w.sod.state, &step.cmd, &ctx)? {
        let mut a = w.answer(&q);
        if matches!(&q, Query::HasConflict { reviewer, .. } if *reviewer == account) {
            a.holds = conflict;
        }
        answers.insert(q, a);
    }
    fstp_domain::decide(&w.sod.state, &step.cmd, &ctx, &answers)
}

fn summary(assignment: AssignmentId) -> Step {
    Step::by(
        R1,
        Flags::NONE,
        Command::RecordRankingSummary {
            proposal: PR1,
            assignment,
            title: text(1),
            neutral_summary: text(2),
            rationale: text(3),
        },
    )
}

/// I-03, R-AC-01: an assigned reviewer reads in STAGE1 only after a fresh
/// `HasConflict` answer of false at the current epoch. An answer of true
/// that no reaction has seen still refuses the read under I-03.
#[test]
fn i03_reviewer_read_needs_a_fresh_no_conflict_answer() {
    let mut w = world(false);
    active_reviewer(&mut w, StateTag::Stage1);
    let step = read(R1, PR1);
    match decide_with(&w, &step, R1, true) {
        Err(r) => assert_eq!(r.rule, RuleRef::I03, "{r}"),
        Ok(records) => panic!("I-03: R1 read while the vault answers a conflict: {records:?}"),
    }
    let records = decide_with(&w, &step, R1, false).unwrap_or_else(|r| panic!("{r}"));
    assert!(
        records
            .iter()
            .any(|r| matches!(r, Record::ContentRead(c) if c.account == R1)),
        "{records:?}"
    );
}

/// I-03: a ranking summary is an assigned-reviewer act, so it needs the
/// same fresh `HasConflict` answer of false.
#[test]
fn i03_ranking_summary_needs_a_fresh_no_conflict_answer() {
    let mut w = world(false);
    let id = active_reviewer(&mut w, StateTag::Stage1);
    match decide_with(&w, &summary(id), R1, true) {
        Err(r) => assert_eq!(r.rule, RuleRef::I03, "{r}"),
        Ok(records) => {
            panic!("I-03: R1 wrote a summary while the vault answers a conflict: {records:?}")
        }
    }
    let records = ok(&mut w, &summary(id));
    assert!(
        records
            .iter()
            .any(|r| matches!(r, Record::RankingSummaryRecorded { .. })),
        "{records:?}"
    );
}

/// I-03: an assignment that is released, or whose proposal is still
/// SUBMITTED, opens no reviewer read and no summary, even with the vault
/// answering no conflict.
#[test]
fn i03_reviewer_acts_need_an_active_assignment_in_a_stage() {
    let mut w = world(false);
    let id = AssignmentId::from_raw(1);
    ok(
        &mut w,
        &assign(
            COORDINATOR,
            id,
            PR1,
            R1,
            AssignmentKind::Reviewer,
            Some(handle(1)),
        ),
    );
    go(&mut w, PR1, StateTag::Stage1);
    assert!(
        decide_with(&w, &read(R1, PR1), R1, false).is_err(),
        "R-CF-02: R1 read before declaring"
    );
    assert!(
        decide_with(&w, &summary(id), R1, false).is_err(),
        "R-CF-02: R1 wrote a summary before declaring"
    );
    ok(
        &mut w,
        &declare(R1, DeclarationSubject::Assignment(id), false, false),
    );
    ok(&mut w, &read(R1, PR1));
    ok(
        &mut w,
        &declare(R1, DeclarationSubject::Assignment(id), true, false),
    );
    assert!(
        decide_with(&w, &read(R1, PR1), R1, false).is_err(),
        "I-03: R1 read after declaring a conflict"
    );
    assert!(
        decide_with(&w, &summary(id), R1, false).is_err(),
        "I-03: R1 wrote a summary after declaring a conflict"
    );
}

fn recusal(w: &ReviewWorld, member: AccountId, conflict: bool) -> Result<bool, Refusal> {
    let mut answers = Answers::new();
    for q in cut_off_recusal_queries(&w.sod.state, member, call(1)) {
        let mut a = w.answer(&q);
        a.holds = conflict;
        answers.insert(q, a);
    }
    recused_from_cut_off(&w.sod.state, member, call(1), &answers)
}

/// I-03 and the Conflict declarations section: a committee member with a
/// conflict fact on a RANKED proposal of the call recuses from its cut-off
/// vote, and so does one the vault now finds conflicted. A member with
/// neither does not, and a missing answer refuses.
#[test]
fn i03_cut_off_recusal_follows_facts_and_fresh_answers() {
    let mut w = world(false);
    let id = active_reviewer(&mut w, StateTag::Stage1);
    ok(&mut w, &read(R1, PR1));
    ok(
        &mut w,
        &declare(R1, DeclarationSubject::Assignment(id), true, false),
    );
    assert_eq!(recusal(&w, R1, false), Ok(false), "PR1 is not RANKED yet");
    go(&mut w, PR1, StateTag::Ranked);
    assert_eq!(recusal(&w, R1, false), Ok(true), "R1 has a conflict fact");
    assert_eq!(recusal(&w, R2, false), Ok(false), "R2 has no conflict");
    assert_eq!(
        recusal(&w, R2, true),
        Ok(true),
        "the vault finds R2 conflicted"
    );
    assert!(
        recused_from_cut_off(&w.sod.state, R2, call(1), &Answers::new()).is_err(),
        "a missing answer refuses"
    );
}

/// R-AC-01, Committee ranking view, interim reading Q14: the view lists
/// the call's RANKED proposals with the assigned reviewers' summary, and
/// the remaining budget subtracts the requested totals of proposals in
/// IRC_REVIEW and later.
#[test]
fn r_ac_01_ranking_view_subtracts_committed_proposals() {
    let mut w = world(true);
    let id = active_reviewer(&mut w, StateTag::Stage1);
    ok(&mut w, &summary(id));
    go(&mut w, PR1, StateTag::Ranked);
    go(&mut w, PR2, StateTag::Ranked);
    let both = ranking_view(&w.sod.state, call(1)).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(both.len(), 2, "{both:?}");
    let (Some(one), Some(two)) = (
        both.iter().find(|r| r.proposal == PR1),
        both.iter().find(|r| r.proposal == PR2),
    ) else {
        panic!("{both:?}")
    };
    assert_eq!(one.title, Some(text(1)));
    assert_eq!(one.neutral_summary, Some(text(2)));
    assert_eq!(one.rationale, Some(text(3)));
    assert_eq!(two.title, None);
    w.commit(&[Record::Transitioned(Transitioned {
        proposal: PR2,
        from: StateTag::Ranked,
        to: StateTag::IrcReview,
        row: Row::RankedToIrcReview,
        actor: Actor::Account(COORDINATOR),
        decision: None,
    })])
    .unwrap_or_else(|e| panic!("fold: {e}"));
    let rows = ranking_view(&w.sod.state, call(1)).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(rows.len(), 1, "{rows:?}");
    let expected = one
        .remaining_budget
        .checked_sub(two.requested.amount())
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        rows.first().map(|r| r.remaining_budget),
        Some(expected),
        "PR2 in IRC_REVIEW counts against the call budget"
    );
}
