//! Independent review of lane L-REV (step W4a): spec fidelity reproducers.
//!
//! Each test fails against the lane's current code and passes once the
//! named defect is fixed. They run production commands from genesis over
//! the synthetic vault of `gen::review`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, DeclarationSubject, SystemCause};
use fstp_domain::id::{AssignmentId, BindingId};
use fstp_domain::record::Record;
use fstp_domain::refusal::RuleRef;
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, L1, L2, LIST_1, PR1, PR2, R1, R2, R3, STRANGER, assign, declare, handle,
    machine_accounts, machine_setup, records_of, review_truth, run_records, scenario_from, tag,
};
use fstp_domain_testkit::r#gen::roster::{Step, T0, add_member};
use fstp_domain_testkit::scenario::Scenario;
use fstp_domain_testkit::vault::Relation;

fn start() -> Scenario {
    scenario_from(&machine_setup(), review_truth(machine_accounts()))
        .unwrap_or_else(|e| panic!("setup from genesis: {e}"))
}

fn ok(s: &mut Scenario, step: &Step) -> Vec<Record> {
    run_records(s, step, T0)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|r| panic!("{:?} refused: {r}", step.cmd))
}

fn vault(
    s: &mut Scenario,
    change: impl FnOnce(&mut fstp_domain_testkit::vault::GroundTruth),
) -> Vec<Record> {
    let before = records_of(s).unwrap().len();
    let ctx = s.ctx(T0, Actor::System(SystemCause::Vault));
    s.change_vault(change, ctx)
        .unwrap_or_else(|e| panic!("vault reaction: {e:?}"));
    records_of(s)
        .unwrap()
        .get(before..)
        .unwrap_or_default()
        .to_vec()
}

fn reviewer(
    n: u128,
    proposal: fstp_domain::id::ProposalId,
    who: fstp_domain::id::AccountId,
) -> Step {
    assign(
        COORDINATOR,
        AssignmentId::from_raw(n),
        proposal,
        who,
        AssignmentKind::Reviewer,
        Some(handle(n)),
    )
}

/// I-03, R-CF-02: an assigned reviewer who declared no conflict and later
/// finds one can still declare it. Under P-10 "assigned reviewers only"
/// the assignment is the reviewer's only declaration subject, so a refusal
/// leaves a known conflict unrecorded and the assignment active.
#[test]
fn review_active_reviewer_can_declare_a_later_conflict() {
    let mut s = start();
    let id = AssignmentId::from_raw(9_501);
    ok(&mut s, &reviewer(9_501, PR1, R3));
    ok(
        &mut s,
        &declare(R3, DeclarationSubject::Assignment(id), false, false),
    );
    let later = run_records(
        &mut s,
        &declare(R3, DeclarationSubject::Assignment(id), true, false),
        T0,
    )
    .unwrap();
    let proposal_level = run_records(
        &mut s,
        &declare(R3, DeclarationSubject::Proposal(PR1), true, false),
        T0,
    )
    .unwrap();
    assert!(
        later.is_ok() || proposal_level.is_ok(),
        "an active reviewer has no way to declare a conflict found later: \
         on the assignment {later:?}, on the proposal {proposal_level:?}"
    );
}

/// I-03, R-CF-02, enforcement point 1: a team member added after an
/// assignment who is related to the assignee makes the assignee conflicted.
/// The Receiving binding is a role binding, so the same batch records the
/// detected conflict and releases the assignment.
#[test]
fn review_team_member_added_after_assignment_is_checked_for_conflicts() {
    let mut s = start();
    let id = AssignmentId::from_raw(9_601);
    ok(&mut s, &reviewer(9_601, PR1, R3));
    ok(
        &mut s,
        &declare(R3, DeclarationSubject::Assignment(id), false, false),
    );
    // The relation is not with the current team, so no conflict yet.
    let reaction = vault(&mut s, |t| {
        t.relate(tag(R3), tag(STRANGER), Relation::Relative)
    });
    assert!(
        !reaction
            .iter()
            .any(|r| matches!(r, Record::ConflictDetected(_))),
        "no conflict before the team change: {reaction:?}"
    );
    let added = ok(
        &mut s,
        &add_member(L1, PR1, STRANGER, BindingId::from_raw(9_602), false),
    );
    assert!(
        added.iter().any(|r| matches!(
            r,
            Record::ConflictDetected(d) if d.account == R3 && d.proposal == PR1
        )),
        "R3 is now related to the team of PR1, yet the batch records no \
         detected conflict and keeps the assignment active: {added:?}"
    );
}

/// I-35, SoD-11, enforcement point 3: a team that declares an affiliation
/// on the proximity list of an assigned reviewer's organisation after the
/// assignment leaves the reviewer assigned to a proposal on that list.
/// The vault reaction must end that assignment, directly or by suspending
/// the binding it rests on.
#[test]
fn review_i35_affiliation_declared_after_assignment_ends_the_assignment() {
    let mut s = start();
    let id = AssignmentId::from_raw(9_701);
    ok(&mut s, &reviewer(9_701, PR2, R1));
    let reaction = vault(&mut s, |t| t.declare_affiliation(L2, LIST_1));
    let ended = reaction.iter().any(|r| match r {
        Record::AssignmentReleased(x) => x.assignment == id,
        _ => false,
    });
    assert!(
        ended,
        "R1 of O1 stays assigned to PR2 after its team declared an \
         affiliation on O1's list: {reaction:?}"
    );
}

/// I-34, SoD-10: the committee binding's organisation reaches `Assign`.
/// R1 and R2 both record O1, P-39 = 2, so the second is refused.
#[test]
fn review_i34_committee_organisation_reaches_assign() {
    let mut s = start();
    ok(&mut s, &reviewer(9_801, PR1, R1));
    match run_records(&mut s, &reviewer(9_802, PR1, R2), T0).unwrap() {
        Err(r) => assert_eq!(r.rule, RuleRef::I34),
        Ok(records) => panic!(
            "a second O1 reviewer was assigned below P-39 organisations, \
             because the roster drops the binding's organisation: {records:?}"
        ),
    }
}
