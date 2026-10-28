//! I-10 and I-03: who may mark a finding, through the reference driver.
//!
//! Sources: `SPEC/04-llm-assessment/assessment.md` (reviewers mark each
//! finding as agreed or disputed, and marks feed calibration),
//! `SPEC/02-domain/roles-and-sod.md` Conflict declarations (a declared or
//! detected conflict bars every assigned-reviewer act) and enforcement
//! point 2 (every action that changes state re-checks the binding).
//!
//! The scenario from genesis has PR1 in STAGE1 of call 1 with R1, R2 and
//! R3 assigned and declared, and one finding of call 1 on PR1. A mark is
//! recorded only for an assigned reviewer with an active assignment and no
//! conflict, while the vault epoch is processed. Every other mark is
//! refused with one refusal, so a refusal never tells whether a finding
//! id is taken. A mark appends only a finding record (I-10).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::Actor;
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain_testkit::r#gen::findings::{ASSESSOR, actor_ctx, finding_command_id};
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, L1, PR1, R1, R2, R3, run_on, tag, unassign, withdraw,
};
use fstp_domain_testkit::r#gen::roster::call;
use fstp_domain_testkit::mc::findings_model::{
    MARKED_FINDING, engine_command, exec_finding, mark_scenario, store_of,
};
use fstp_domain_testkit::mc::life_model::{T_EVAL, assignment_of};
use fstp_domain_testkit::scenario::Scenario;
use fstp_domain_testkit::vault::Relation;
use fstp_engine::ExecError;
use fstp_findings::{FindingCommand, FindingId, Mark};

fn start() -> Scenario {
    mark_scenario().unwrap_or_else(|e| panic!("mark scenario from genesis: {e}"))
}

fn mark_of(id: u128) -> FindingCommand {
    FindingCommand::Mark {
        finding: FindingId::from_raw(id),
        mark: Mark::Agreed,
    }
}

fn mark(s: &mut Scenario, actor: Actor, id: u128) -> Result<fstp_ledger::Seq, ExecError> {
    exec_finding(s, mark_of(id), actor, T_EVAL).unwrap_or_else(|e| panic!("{e}"))
}

/// The one refusal of a mark by an account that may not mark the finding.
const REFUSED: Refusal = Refusal::new(RuleRef::Actor, RefusalReason::WrongActor);

fn refused(r: &Result<fstp_ledger::Seq, ExecError>) -> Option<Refusal> {
    match r {
        Err(ExecError::Refused(x)) => Some(*x),
        _ => None,
    }
}

/// I-10, I-03: an assigned reviewer's mark is recorded as one finding
/// record, and the core is unchanged.
#[test]
fn i10_i03_assigned_reviewer_marks_a_finding() {
    let mut s = start();
    let core = s.state().core.clone();
    let before = s.entries().unwrap().len();
    let r = mark(&mut s, Actor::Account(R1), MARKED_FINDING);
    assert!(r.is_ok(), "R1's mark was {r:?}");
    let entries = s.entries().unwrap();
    let appended: Vec<_> = entries.get(before..).unwrap_or_default().to_vec();
    assert_eq!(appended.len(), 1, "a mark appends one entry");
    assert!(
        appended
            .iter()
            .all(|e| matches!(e.record, fstp_engine::Record::Finding(_))),
        "I-10: a mark appended {appended:?}"
    );
    assert_eq!(s.state().core, core, "I-10: a mark changed the core");
    let store = store_of(&s.state().findings).unwrap();
    let marks: Vec<_> = store
        .marks_of(FindingId::from_raw(MARKED_FINDING))
        .collect();
    assert_eq!(marks, vec![(R1, Mark::Agreed)]);
}

/// I-03: the lead, an unassigned coordinator and the System cannot mark.
#[test]
fn i10_i03_lead_coordinator_and_system_cannot_mark() {
    let mut s = start();
    for actor in [Actor::Account(L1), Actor::Account(COORDINATOR), ASSESSOR] {
        let r = mark(&mut s, actor, MARKED_FINDING);
        assert_eq!(refused(&r), Some(REFUSED), "{actor:?} marked: {r:?}");
    }
}

/// I-03: an unknown finding id gives the same refusal as a finding the
/// account may not mark, for a reviewer and for anyone else.
#[test]
fn i10_i03_unknown_finding_refusal_matches_an_unauthorised_mark() {
    let mut s = start();
    for actor in [Actor::Account(R1), Actor::Account(L1)] {
        let r = mark(&mut s, actor, 77);
        assert_eq!(
            refused(&r),
            Some(REFUSED),
            "{actor:?} on an unknown id: {r:?}"
        );
    }
}

/// I-03: a reviewer with a detected conflict cannot mark.
#[test]
fn i10_i03_conflicted_reviewer_cannot_mark() {
    let mut s = start();
    let ctx = s.ctx(
        T_EVAL,
        Actor::System(fstp_domain::command::SystemCause::Vault),
    );
    s.change_vault(|t| t.relate(tag(R2), tag(L1), Relation::CoWorker), ctx)
        .unwrap();
    let r = mark(&mut s, Actor::Account(R2), MARKED_FINDING);
    assert_eq!(refused(&r), Some(REFUSED), "conflicted R2 marked: {r:?}");
    let ok = mark(&mut s, Actor::Account(R1), MARKED_FINDING);
    assert!(ok.is_ok(), "R1 without a conflict was {ok:?}");
}

/// I-03, enforcement point 2: a reviewer whose assignment was released
/// cannot mark.
#[test]
fn i10_i03_released_assignment_cannot_mark() {
    let mut s = start();
    let id = assignment_of(R3, PR1, call(1), AssignmentKind::Reviewer);
    run_on(&mut s, &unassign(COORDINATOR, id), T_EVAL).unwrap();
    let r = mark(&mut s, Actor::Account(R3), MARKED_FINDING);
    assert_eq!(refused(&r), Some(REFUSED), "released R3 marked: {r:?}");
}

/// I-03, I-10: while the vault is ahead of the processed epoch, a mark is
/// refused with `StaleFacts` and nothing is appended. The finding command
/// does not process the vault change itself.
#[test]
fn i10_i03_mark_while_the_vault_is_ahead_is_stale() {
    let (mut engine, _) = start().into_parts();
    engine
        .oracle_mut()
        .truth_mut()
        .relate(tag(R1), tag(L1), Relation::CoWorker);
    let epoch = engine.state().epoch();
    let head = engine.head();
    let cmd = engine_command(mark_of(MARKED_FINDING)).unwrap();
    let r = engine.execute(
        cmd,
        actor_ctx(T_EVAL, Actor::Account(R1), finding_command_id(9)),
    );
    assert_eq!(
        refused(&r),
        Some(Refusal::new(
            RuleRef::StaleFacts,
            RefusalReason::AnswerStale
        )),
        "a mark with the vault ahead was {r:?}"
    );
    assert_eq!(engine.head(), head, "a refused mark appended entries");
    assert_eq!(
        engine.state().epoch(),
        epoch,
        "a mark processed the vault change"
    );
}

/// Folds a `Marked` record of `by` on `id` into a copy of `s`'s state at
/// its time floor, as a replayed log would.
fn fold_mark(
    s: &Scenario,
    by: fstp_domain::id::AccountId,
    id: u128,
) -> Result<(), fstp_domain::engine::FoldError> {
    let mut next = s.state().clone();
    let at = next.now_floor();
    let record = fstp_findings::FindingRecord::Marked {
        finding: FindingId::from_raw(id),
        by,
        mark: Mark::Disputed,
    };
    fstp_engine::apply(
        &mut next,
        fstp_ledger::Seq::from_raw(1),
        at,
        &fstp_engine::Record::Finding(record),
    )
}

/// I-03, I-10 at the fold: a replayed `Marked` record by the lead, by an
/// unassigned coordinator or by a released reviewer does not fold, since
/// the engine refuses each of those marks. An assigned reviewer's mark
/// folds.
#[test]
fn i10_i03_fold_refuses_a_mark_the_engine_would_refuse() {
    let mut s = start();
    let id = assignment_of(R3, PR1, call(1), AssignmentKind::Reviewer);
    run_on(&mut s, &unassign(COORDINATOR, id), T_EVAL).unwrap();
    for by in [L1, COORDINATOR, R3] {
        assert_eq!(
            fold_mark(&s, by, MARKED_FINDING),
            Err(fstp_domain::engine::FoldError::Inconsistent),
            "a forged mark by {by:?} folded"
        );
    }
    assert_eq!(fold_mark(&s, R1, MARKED_FINDING), Ok(()));
}

/// I-10, `SPEC/04-llm-assessment/assessment.md` (decided 2026-10-26):
/// marking stays open after the proposal reaches a terminal state, and a
/// mark never changes the proposal. The lead withdraws PR1, so it is
/// WITHDRAWN. R1's mark is then recorded as one finding record, and the
/// core is unchanged.
#[test]
fn i10_mark_after_a_terminal_state_is_recorded_and_changes_nothing() {
    let mut s = start();
    run_on(&mut s, &withdraw(L1, PR1), T_EVAL).unwrap();
    let withdrawn = s.entries().unwrap().iter().any(|e| {
        matches!(&e.record, fstp_engine::Record::Core(fstp_domain::record::Record::Transitioned(t))
            if t.proposal == PR1 && t.to == fstp_domain::rules::StateTag::Withdrawn)
    });
    assert!(withdrawn, "PR1 reached WITHDRAWN");
    let core = s.state().core.clone();
    let before = s.entries().unwrap().len();
    let r = mark(&mut s, Actor::Account(R1), MARKED_FINDING);
    assert!(r.is_ok(), "R1's mark after WITHDRAWN was {r:?}");
    let entries = s.entries().unwrap();
    let appended: Vec<_> = entries.get(before..).unwrap_or_default().to_vec();
    assert!(
        appended.len() == 1
            && appended
                .iter()
                .all(|e| matches!(e.record, fstp_engine::Record::Finding(_))),
        "I-10: a mark after WITHDRAWN appended {appended:?}"
    );
    assert_eq!(s.state().core, core, "I-10: a mark changed the core");
}
