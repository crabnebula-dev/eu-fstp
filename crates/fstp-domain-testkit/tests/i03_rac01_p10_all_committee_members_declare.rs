//! I-03, R-CF-02 and R-AC-01 under P-10 "all committee members" (Conflict declarations, design 2.7 and 3.7).
//!
//! Under P-10 "all committee members" every committee member declares per
//! proposal before reading, and a member without an assignment reads after
//! declaring no conflict. A conflicted proposal-level declaration releases
//! the declarer's assignments on that proposal in the same batch. Every
//! start state is built from genesis by production commands, with the
//! stage rows folded through the structural fold until lane L-LIFE
//! records them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::{AssignmentKind, ReleaseCause};
use fstp_domain::command::{Actor, DeclarationSubject};
use fstp_domain::id::AssignmentId;
use fstp_domain::policy::ReadAccess;
use fstp_domain::record::{AssignmentReleased, Record, Transitioned};
use fstp_domain::refusal::Refusal;
use fstp_domain::rules::{Row, StateTag};
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, PR1, R1, R2, ReviewWorld, assign, declare, handle, read, review_truth,
};
use fstp_domain_testkit::r#gen::roster::{Backend, Step};
use fstp_domain_testkit::mc::conflict_model::conflict_setup;

fn world(p10: ReadAccess) -> ReviewWorld {
    let mut setup = conflict_setup();
    setup.p10 = p10;
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

fn refused(w: &mut ReviewWorld, s: &Step) -> Refusal {
    match w.exec(s).unwrap_or_else(|e| panic!("harness: {e}")) {
        Err(r) => r,
        Ok(records) => panic!("{:?} accepted: {records:?}", s.cmd),
    }
}

fn stage1(w: &mut ReviewWorld) {
    w.commit(&[Record::Transitioned(Transitioned {
        proposal: PR1,
        from: StateTag::Submitted,
        to: StateTag::Stage1,
        row: Row::SubmittedToStage1,
        actor: Actor::Account(COORDINATOR),
        decision: None,
    })])
    .unwrap_or_else(|e| panic!("fold: {e}"));
}

/// R-AC-01, P-10: under "all committee members" an unassigned committee
/// member reads in STAGE1 after declaring no conflict on the proposal,
/// and not before.
#[test]
fn r_ac_01_all_committee_members_read_after_declaring() {
    let mut w = world(ReadAccess::AllCommitteeMembers);
    stage1(&mut w);
    refused(&mut w, &read(R2, PR1));
    ok(
        &mut w,
        &declare(R2, DeclarationSubject::Proposal(PR1), false, false),
    );
    let records = ok(&mut w, &read(R2, PR1));
    assert!(
        records
            .iter()
            .any(|r| matches!(r, Record::ContentRead(c) if c.account == R2)),
        "{records:?}"
    );
}

/// R-AC-01, P-10: under "assigned reviewers only" an unassigned committee
/// member neither declares at proposal level nor reads.
#[test]
fn r_ac_01_assigned_reviewers_only_keeps_unassigned_members_out() {
    let mut w = world(ReadAccess::AssignedReviewersOnly);
    stage1(&mut w);
    refused(
        &mut w,
        &declare(R2, DeclarationSubject::Proposal(PR1), false, false),
    );
    refused(&mut w, &read(R2, PR1));
}

/// I-03, R-CF-02: a conflicted proposal-level declaration by an assigned
/// committee member releases the assignment in the same batch, and the
/// member reads no more.
#[test]
fn i03_rcf02_proposal_level_conflict_releases_the_assignment() {
    let mut w = world(ReadAccess::AllCommitteeMembers);
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
    ok(
        &mut w,
        &declare(R1, DeclarationSubject::Assignment(id), false, false),
    );
    stage1(&mut w);
    ok(&mut w, &read(R1, PR1));
    let batch = ok(
        &mut w,
        &declare(R1, DeclarationSubject::Proposal(PR1), true, false),
    );
    assert!(
        batch.contains(&Record::AssignmentReleased(AssignmentReleased {
            assignment: id,
            cause: ReleaseCause::DeclaredConflict,
        })),
        "{batch:?}"
    );
    refused(&mut w, &read(R1, PR1));
}
