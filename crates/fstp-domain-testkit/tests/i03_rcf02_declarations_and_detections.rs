//! I-03 and R-CF-02 examples: declarations before reads, releases and permanent facts (design 2.7 and 6.2).
//!
//! Each test runs production commands from genesis through the reference
//! driver over a synthetic vault: one programme, two published calls, the
//! FSTP coordinator, four committee members, an IRC member and four
//! proposals. These examples pin the readings that the I-03 machine and
//! M-CONFLICT explore at random.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::{AssignmentKind, ReleaseCause};
use fstp_domain::command::{Actor, DeclarationSubject, SystemCause};
use fstp_domain::id::{AssignmentId, BindingId};
use fstp_domain::record::{
    AssignmentReleased, ConflictDeclared, ContentRead, Declared, OutboxEvent, Record,
};
use fstp_domain::refusal::Refusal;
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, L1, L3, PR1, PR2, PR3, R3, R4, STRANGER, assign, declare, handle,
    machine_accounts, machine_setup, read, records_of, review_truth, run_records, scenario_from,
    tag,
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

fn refused(s: &mut Scenario, step: &Step) -> Refusal {
    match run_records(s, step, T0).unwrap_or_else(|e| panic!("{e}")) {
        Err(r) => r,
        Ok(records) => panic!("{:?} accepted: {records:?}", step.cmd),
    }
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

/// R-CF-02 AC, I-03: the FSTP coordinator cannot read a submission for
/// the knock-out check before declaring conflicts on it.
#[test]
fn i03_rcf02_coordinator_declares_before_the_knock_out_read() {
    let mut s = start();
    refused(&mut s, &read(COORDINATOR, PR1));
    let declared = ok(
        &mut s,
        &declare(COORDINATOR, DeclarationSubject::Proposal(PR1), false, false),
    );
    assert!(
        declared.contains(&Record::ConflictDeclared(ConflictDeclared {
            subject: Declared::Proposal {
                proposal: PR1,
                account: COORDINATOR,
            },
            conflicted: false,
            notifiable: false,
        }))
    );
    let read_records = ok(&mut s, &read(COORDINATOR, PR1));
    assert!(read_records.contains(&Record::ContentRead(ContentRead {
        account: COORDINATOR,
        proposal: PR1,
    })));
}

/// I-03: a coordinator's declared conflict is permanent. Reads stay
/// refused, and a later no-conflict declaration is refused.
#[test]
fn i03_coordinator_conflict_is_permanent() {
    let mut s = start();
    ok(
        &mut s,
        &declare(COORDINATOR, DeclarationSubject::Proposal(PR2), true, false),
    );
    refused(&mut s, &read(COORDINATOR, PR2));
    refused(
        &mut s,
        &declare(COORDINATOR, DeclarationSubject::Proposal(PR2), false, false),
    );
    refused(&mut s, &read(COORDINATOR, PR2));
}

/// R-CF-02, I-03: a declared conflict releases the assignment in the same
/// batch, the reviewer is never assigned to that proposal again, and
/// another reviewer takes the place.
#[test]
fn i03_rcf02_declared_conflict_releases_and_bars_reassignment() {
    let mut s = start();
    let id = AssignmentId::from_raw(9_101);
    ok(&mut s, &reviewer(9_101, PR1, R3));
    let batch = ok(
        &mut s,
        &declare(R3, DeclarationSubject::Assignment(id), true, true),
    );
    assert!(batch.contains(&Record::ConflictDeclared(ConflictDeclared {
        subject: Declared::Assignment(id),
        conflicted: true,
        notifiable: true,
    })));
    assert!(
        batch.contains(&Record::AssignmentReleased(AssignmentReleased {
            assignment: id,
            cause: ReleaseCause::DeclaredConflict,
        }))
    );
    refused(&mut s, &reviewer(9_102, PR1, R3));
    ok(&mut s, &reviewer(9_103, PR1, R4));
}

/// I-03: a relation the vault reveals mid-run bars the cleared
/// coordinator's read. The reaction records the detected conflict, so the
/// read stays refused after the relation ends.
#[test]
fn i03_detected_conflict_outlives_the_relation() {
    let mut s = start();
    ok(
        &mut s,
        &declare(COORDINATOR, DeclarationSubject::Proposal(PR3), false, false),
    );
    ok(&mut s, &read(COORDINATOR, PR3));
    let reaction = vault(&mut s, |t| {
        t.relate(tag(COORDINATOR), tag(L3), Relation::Relative)
    });
    assert!(
        reaction.iter().any(|r| matches!(
            r,
            Record::ConflictDetected(d) if d.account == COORDINATOR && d.proposal == PR3
        )),
        "the reaction records the detected conflict: {reaction:?}"
    );
    refused(&mut s, &read(COORDINATOR, PR3));
    vault(&mut s, |t| {
        t.unrelate(tag(COORDINATOR), tag(L3), Relation::Relative)
    });
    refused(&mut s, &read(COORDINATOR, PR3));
}

/// I-03, R-CF-02: when the vault finds an assigned reviewer related to the
/// team, the reaction records the detected conflict and releases the
/// assignment in the same batch.
#[test]
fn i03_detected_conflict_releases_the_assignment() {
    let mut s = start();
    let id = AssignmentId::from_raw(9_201);
    ok(&mut s, &reviewer(9_201, PR3, R4));
    ok(
        &mut s,
        &declare(R4, DeclarationSubject::Assignment(id), false, false),
    );
    let reaction = vault(&mut s, |t| t.relate(tag(L3), tag(R4), Relation::Mentoring));
    assert!(
        reaction.iter().any(|r| matches!(
            r,
            Record::ConflictDetected(d) if d.account == R4 && d.proposal == PR3
        )),
        "the reaction records the detected conflict: {reaction:?}"
    );
    assert!(
        reaction.contains(&Record::AssignmentReleased(AssignmentReleased {
            assignment: id,
            cause: ReleaseCause::DetectedConflict,
        })),
        "the reaction releases the assignment: {reaction:?}"
    );
    refused(&mut s, &reviewer(9_202, PR3, R4));
}

/// R-AC-01, P-10 (test-author reading): an assigned reviewer does not read
/// in SUBMITTED, even after declaring no conflict, because P-10 opens
/// reads in stages 1 and 2.
#[test]
fn i03_rac01_assignee_does_not_read_in_submitted() {
    let mut s = start();
    let id = AssignmentId::from_raw(9_301);
    ok(&mut s, &reviewer(9_301, PR1, R3));
    refused(&mut s, &read(R3, PR1));
    ok(
        &mut s,
        &declare(R3, DeclarationSubject::Assignment(id), false, false),
    );
    refused(&mut s, &read(R3, PR1));
}

/// R-CF-04 and Identity discovery: when the vault verifies the lead of
/// PR3 with the identity of R4, who is assigned to PR3, the reaction voids
/// the lead's binding under I-06 and records a notifiable conflict for R4
/// with its notification draft. A later detection through a relation of
/// another reviewer on another proposal is not notifiable.
#[test]
fn i03_rcf04_identity_discovery_flags_only_the_matching_reviewer() {
    let mut s = start();
    let id = AssignmentId::from_raw(9_401);
    ok(&mut s, &reviewer(9_401, PR3, R4));
    ok(
        &mut s,
        &declare(R4, DeclarationSubject::Assignment(id), false, false),
    );
    ok(&mut s, &reviewer(9_402, PR1, R3));
    let reaction = vault(&mut s, |t| {
        t.set_identity(L3, tag(R4));
        t.verify(L3);
    });
    assert!(
        reaction.iter().any(
            |r| matches!(r, Record::BindingVoided(v) if v.rule == fstp_domain::refusal::RuleRef::I06)
        ),
        "the discovery voids the lead's binding: {reaction:?}"
    );
    assert!(
        reaction.iter().any(|r| matches!(
            r,
            Record::ConflictDetected(d) if d.account == R4 && d.proposal == PR3 && d.notifiable
        )),
        "R-CF-04: R4 gets a notifiable conflict: {reaction:?}"
    );
    assert!(
        reaction.contains(&Record::OutboxEnqueued(OutboxEvent::NotifiableConflict {
            proposal: PR3
        })),
        "R-CF-04: the coordinator gets a notification draft: {reaction:?}"
    );
    assert!(
        !reaction
            .iter()
            .any(|r| matches!(r, Record::ConflictDetected(d) if d.account == R3)),
        "R3 is not related to the discovery: {reaction:?}"
    );
    let later = vault(&mut s, |t| t.relate(tag(R3), tag(L1), Relation::CoWorker));
    assert!(
        later.iter().any(|r| matches!(
            r,
            Record::ConflictDetected(d) if d.account == R3 && d.proposal == PR1 && !d.notifiable
        )),
        "a detection through a relation is not notifiable: {later:?}"
    );
}

/// I-03, R-CF-02 and enforcement point 1: a team member added after an
/// assignment who is related to the assignee makes the assignee
/// conflicted. The batch that grants the Receiving binding records the
/// detected conflict and releases the assignment.
#[test]
fn i03_rcf02_new_team_member_is_checked_against_the_assignees() {
    let mut s = start();
    let id = AssignmentId::from_raw(9_501);
    ok(&mut s, &reviewer(9_501, PR1, R3));
    ok(
        &mut s,
        &declare(R3, DeclarationSubject::Assignment(id), false, false),
    );
    vault(&mut s, |t| {
        t.relate(tag(R3), tag(STRANGER), Relation::Relative)
    });
    let added = ok(
        &mut s,
        &add_member(L1, PR1, STRANGER, BindingId::from_raw(9_502), false),
    );
    assert!(
        added.iter().any(|r| matches!(
            r,
            Record::ConflictDetected(d) if d.account == R3 && d.proposal == PR1 && !d.notifiable
        )),
        "{added:?}"
    );
    assert!(
        added.contains(&Record::AssignmentReleased(AssignmentReleased {
            assignment: id,
            cause: ReleaseCause::DetectedConflict,
        })),
        "{added:?}"
    );
    refused(&mut s, &reviewer(9_503, PR1, R3));
}
