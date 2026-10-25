//! Review reproducers for lane L-REV, step W4a (test strength and API lens).
//!
//! Each test fails against the lane's current code and passes once the
//! named defect is fixed. Every start state is built from genesis by
//! production commands. Where a state needs a lifecycle row that lane
//! L-LIFE has not written yet, the test folds the `Transitioned` record
//! through the structural fold, as the teeth tests do.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::{AssignmentKind, ReleaseCause};
use fstp_domain::command::{Actor, DeclarationSubject};
use fstp_domain::id::{AccountId, AssignmentId, BindingId, ProposalId};
use fstp_domain::record::{AssignmentReleased, Record, Transitioned};
use fstp_domain::roles::Role;
use fstp_domain::rules::{Row, StateTag};
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, DraftSpec, L1, L2, O1, PR1, PR2, R1, ReviewSetup, ReviewWorld, assign, declare,
    handle, judge_binding, milestone_of, plan_of, read, record_plan, review_truth, submit, tag,
};
use fstp_domain_testkit::r#gen::roster::{
    Backend, P1, P2, SodSetup, Step, T0, call, draft, end, grant,
};
use fstp_domain_testkit::mc::conflict_model::conflict_setup;

fn ok(w: &mut ReviewWorld, s: &Step) -> Vec<Record> {
    w.exec(s)
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("{:?} refused: {r}", s.cmd))
}

fn go(w: &mut ReviewWorld, p: ProposalId, rows: &[(StateTag, StateTag, Row)]) {
    for (from, to, row) in rows {
        w.commit(&[Record::Transitioned(Transitioned {
            proposal: p,
            from: *from,
            to: *to,
            row: *row,
            actor: Actor::Account(COORDINATOR),
            decision: None,
        })])
        .unwrap_or_else(|e| panic!("fold {row:?}: {e}"));
    }
}

fn reviewer(n: u128, proposal: ProposalId, who: AccountId) -> Step {
    assign(
        COORDINATOR,
        AssignmentId::from_raw(n),
        proposal,
        who,
        AssignmentKind::Reviewer,
        Some(handle(n)),
    )
}

/// I-02, SoD-02 and `SPEC/02-domain/roles-and-sod.md` NOTE 3: I-02 holds
/// within one programme. An account that is a committee member in P1 and
/// an IRC member in P2 breaks no rule, so its unreleased reviewer
/// assignment in P1 must not bar an IRC assignment in P2.
///
/// `plan_assign` scans `unreleased_of(reviewer)` across every programme,
/// and refuses with I-02. The reference `assign_verdict` makes the same
/// cross-programme scan, so the two-way machines cannot see it.
#[test]
fn review_i02_assignment_bar_is_per_programme() {
    let mut base = SodSetup::one(1, &[1]);
    base.programmes = vec![P1, P2];
    base.calls = vec![(P1, call(1)), (P2, call(2))];
    base.published = vec![call(1), call(2)];
    let setup = ReviewSetup {
        base,
        p38: Default::default(),
        p10: fstp_domain::policy::ReadAccess::AssignedReviewersOnly,
        judges: vec![
            (COORDINATOR, Role::FstpCoordinator, None),
            (R1, Role::CommitteeMember, Some(O1)),
        ],
        drafts: vec![DraftSpec {
            lead: L1,
            proposal: PR1,
            call: call(1),
            team: Vec::new(),
            minor: false,
            submit: true,
        }],
    };
    let mut accounts = setup.accounts();
    accounts.insert(L2);
    let mut w = ReviewWorld::from_setup(Backend::Production, review_truth(accounts), &setup, None)
        .unwrap_or_else(|e| panic!("setup: {e}"));
    ok(
        &mut w,
        &grant(
            BindingId::from_raw(260),
            COORDINATOR,
            P2,
            Role::FstpCoordinator,
            T0,
        ),
    );
    ok(
        &mut w,
        &grant(BindingId::from_raw(261), R1, P2, Role::IrcMember, T0),
    );
    ok(
        &mut w,
        &draft(L2, PR2, call(2), BindingId::from_raw(262), false),
    );
    ok(
        &mut w,
        &record_plan(L2, plan_of(PR2), PR2, &[milestone_of(PR2)]).unwrap(),
    );
    ok(&mut w, &submit(L2, PR2, plan_of(PR2), false));
    ok(&mut w, &reviewer(1, PR1, R1));
    go(
        &mut w,
        PR2,
        &[
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
        ],
    );
    let irc = assign(
        COORDINATOR,
        AssignmentId::from_raw(50),
        PR2,
        R1,
        AssignmentKind::Irc,
        Some(handle(50)),
    );
    match w.exec(&irc).unwrap_or_else(|e| panic!("harness: {e}")) {
        Ok(records) => assert!(
            records.iter().any(|r| matches!(r, Record::Assigned(_))),
            "{records:?}"
        ),
        Err(r) => panic!(
            "I-02 is per programme: R1's reviewer assignment in P1 must not bar its IRC \
             assignment in P2, but Assign refused with {r:?}"
        ),
    }
}

/// R-CF-02, I-03 and design 2.7 ("Declaring a conflict releases the
/// assignment in the same batch"): a reviewer who declared no conflict and
/// later learns of one must be able to declare it. The declaration makes
/// the conflict fact permanent and releases the assignment.
///
/// `check_declare` admits a declaration on an assignment only while it
/// awaits the first declaration, and under P-10 "assigned reviewers only"
/// a committee member cannot declare at proposal level either. So the
/// reviewer has no way to record the conflict, keeps an active assignment,
/// and keeps reading.
#[test]
fn review_rcf02_active_reviewer_can_declare_a_later_conflict() {
    let setup = conflict_setup();
    let mut w = ReviewWorld::from_setup(
        Backend::Production,
        review_truth(setup.accounts()),
        &setup,
        None,
    )
    .unwrap_or_else(|e| panic!("setup: {e}"));
    let id = AssignmentId::from_raw(1);
    ok(&mut w, &reviewer(1, PR1, R1));
    ok(
        &mut w,
        &declare(R1, DeclarationSubject::Assignment(id), false, false),
    );
    go(
        &mut w,
        PR1,
        &[(
            StateTag::Submitted,
            StateTag::Stage1,
            Row::SubmittedToStage1,
        )],
    );
    ok(&mut w, &read(R1, PR1));
    let assignment = w.exec(&declare(
        R1,
        DeclarationSubject::Assignment(id),
        true,
        false,
    ));
    let proposal = w.exec(&declare(R1, DeclarationSubject::Proposal(PR1), true, false));
    let released = [&assignment, &proposal].iter().any(|r| {
        matches!(r, Ok(Ok(records)) if records.contains(&Record::AssignmentReleased(
            AssignmentReleased { assignment: id, cause: ReleaseCause::DeclaredConflict },
        )))
    });
    assert!(
        released,
        "R-CF-02: R1 learns of a conflict after declaring none and cannot declare it. \
         On the assignment: {assignment:?}. On the proposal: {proposal:?}"
    );
    assert!(
        matches!(w.exec(&read(R1, PR1)), Ok(Err(_))),
        "I-03: R1 reads after declaring a conflict"
    );
}

/// R-CF-04 and `SPEC/02-domain/roles-and-sod.md` Identity discovery:
/// "Scores already given by a matching Judging account get a notifiable
/// conflict." The discovery must reach every account that reviewed the
/// proposal, whether or not its assignment is still unreleased.
///
/// Story: R1 is assigned to PR1, declares no conflict and reads it in
/// STAGE1. R1's committee binding then ends, which releases the
/// assignment. The vault later verifies L1, the lead, with R1's identity.
/// The roles lane voids L1's binding under I-06. `reaction` rechecks only
/// `tracked_pairs`, the unreleased assignments and clearances, so it
/// records no `ConflictDetected` for R1 on PR1 and enqueues no
/// notification. The R-CF-04 fact is lost.
#[test]
fn review_rcf04_discovery_flags_a_released_reviewer() {
    let setup = conflict_setup();
    let mut accounts = setup.accounts();
    accounts.remove(&L1);
    let mut w = ReviewWorld::from_setup(Backend::Production, review_truth(accounts), &setup, None)
        .unwrap_or_else(|e| panic!("setup: {e}"));
    let id = AssignmentId::from_raw(1);
    ok(&mut w, &reviewer(1, PR1, R1));
    ok(
        &mut w,
        &declare(R1, DeclarationSubject::Assignment(id), false, false),
    );
    go(
        &mut w,
        PR1,
        &[(
            StateTag::Submitted,
            StateTag::Stage1,
            Row::SubmittedToStage1,
        )],
    );
    ok(&mut w, &read(R1, PR1));
    let ended = ok(&mut w, &end(judge_binding(1), T0));
    assert!(
        ended.contains(&Record::AssignmentReleased(AssignmentReleased {
            assignment: id,
            cause: ReleaseCause::BindingEnded,
        })),
        "setup: ending R1's committee binding releases the assignment: {ended:?}"
    );
    w.sod.truth.set_identity(L1, tag(R1));
    w.sod.truth.verify(L1);
    let reaction = w
        .sync()
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("the reaction was refused: {r}"));
    assert!(
        reaction
            .iter()
            .any(|r| matches!(r, Record::BindingVoided(v) if v.rule == fstp_domain::refusal::RuleRef::I06)),
        "setup: the discovery voids L1's binding under I-06: {reaction:?}"
    );
    assert!(
        reaction.iter().any(|r| matches!(
            r,
            Record::ConflictDetected(d) if d.account == R1 && d.proposal == PR1 && d.notifiable
        )),
        "R-CF-04: R1 reviewed PR1 and shares L1's verified identity, but the reaction \
         records no notifiable conflict: {reaction:?}"
    );
}
