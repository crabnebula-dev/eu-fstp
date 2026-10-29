//! I-34, SoD-10, R-NG-03: the amount determination needs active reviewers of at least P-39 organisations (decided 2026-10-28).
//!
//! `SPEC/02-domain/roles-and-sod.md`, Reviewer assignment NOTE: SoD-10 and
//! I-34 hold at every step where the assigned reviewers decide, the
//! amount determination in NEGOTIATION included. The organisations are
//! read from each active reviewer assignee's committee binding. The money
//! reference mirrors the check with the committee organisation data of
//! the review reference.
//!
//! Every story starts from genesis by production commands. R1 (O1), R2
//! (O2) and R3 (O3) are assigned to every proposal, and P-39 = 2. Every
//! step is compared with the references in both directions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{MoneySetup, MoneyStory, PA, amount_decision, determine};
use fstp_domain_testkit::r#gen::review::{COORDINATOR, R1, R2, R3, plan_of, unassign};
use fstp_domain_testkit::r#gen::roster::{Backend, call};
use fstp_domain_testkit::mc::life_model::assignment_of;

/// The story: three reviewers of three organisations on every proposal.
fn story(b: Backend) -> MoneyStory {
    let mut setup = MoneySetup::sybil([400, 200, 100]);
    setup.reviewers = vec![R1, R2, R3];
    MoneyStory::new(&setup, b)
        .unwrap_or_else(|e| panic!("three proposals to NEGOTIATION from genesis: {e}"))
}

/// The coordinator releases R2's reviewer assignment on PA. R1 (O1) and R3
/// (O3) still span two organisations, so R1 determines a's amount. The
/// coordinator then releases R3. R1 alone spans one organisation, below
/// P-39 = 2, so a new determination is refused under I-34.
fn determination_needs_p39(b: Backend) {
    let mut s = story(b);
    let r2 = assignment_of(R2, PA, call(1), AssignmentKind::Reviewer);
    s.run(&unassign(COORDINATOR, r2))
        .unwrap_or_else(|e| panic!("the release of R2 in NEGOTIATION: {e}"));
    s.determine(PA, 1, &[]).unwrap_or_else(|e| {
        panic!("I-34: R1 (O1) and R3 (O3) span P-39 = 2, so R1 determines 4.00: {e}")
    });
    let r3 = assignment_of(R3, PA, call(1), AssignmentKind::Reviewer);
    s.run(&unassign(COORDINATOR, r3))
        .unwrap_or_else(|e| panic!("the release of R3 in NEGOTIATION: {e}"));
    let again = determine(R1, PA, amount_decision(PA, 2), plan_of(PA), &[]).unwrap();
    s.refused(&again).unwrap_or_else(|e| {
        panic!(
            "I-34, SoD-10 (decided 2026-10-28): R1 alone spans one organisation, below \
             P-39 = 2, so the amount determination is refused: {e}"
        )
    });
    assert_eq!(s.state(PA), Some(StateTag::Negotiation));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// I-34, SoD-10, R-NG-03: the amount determination re-checks P-39 over
/// the active reviewer assignees.
#[test]
fn i34_amount_determination_needs_p39_organisations() {
    determination_needs_p39(Backend::Production);
}

/// I-34, SoD-10, R-NG-03: the same story on the references alone.
#[test]
fn i34_amount_determination_needs_p39_organisations_on_the_reference() {
    determination_needs_p39(Backend::Reference);
}

/// With every reviewer but R1 released before any determination, the
/// first determination is refused too.
fn first_determination_needs_p39(b: Backend) {
    let mut s = story(b);
    for r in [R2, R3] {
        let a = assignment_of(r, PA, call(1), AssignmentKind::Reviewer);
        s.run(&unassign(COORDINATOR, a))
            .unwrap_or_else(|e| panic!("the release of {r:?} in NEGOTIATION: {e}"));
    }
    let first = determine(R1, PA, amount_decision(PA, 1), plan_of(PA), &[]).unwrap();
    s.refused(&first).unwrap_or_else(|e| {
        panic!("I-34, SoD-10: R1 alone spans one organisation, so no amount is determined: {e}")
    });
    assert_eq!(s.world.money.counted(PA), 0, "I-14: nothing is reserved");
}

/// I-34, SoD-10, R-NG-03: the first determination needs P-39 organisations too.
#[test]
fn i34_first_amount_determination_needs_p39_organisations() {
    first_determination_needs_p39(Backend::Production);
}

/// I-34, SoD-10, R-NG-03: the same story on the references alone.
#[test]
fn i34_first_amount_determination_needs_p39_organisations_on_the_reference() {
    first_determination_needs_p39(Backend::Reference);
}

/// R2 and R3 are released before any determination, so R1 alone cannot
/// determine the amount. The coordinator assigns R2 (O2) again in
/// NEGOTIATION, R2 declares no conflict, and R1's determination is then
/// accepted. So the I-34 refusal leaves the proposal a way forward (W7 fix
/// round 1 reading, R-CF-02 and R-NG-03).
fn reassignment_restores_p39(b: Backend) {
    use fstp_domain::command::DeclarationSubject;
    use fstp_domain::id::AssignmentId;
    use fstp_domain_testkit::r#gen::review::{assign, declare, handle};
    let mut s = story(b);
    for r in [R2, R3] {
        let a = assignment_of(r, PA, call(1), AssignmentKind::Reviewer);
        s.run(&unassign(COORDINATOR, a))
            .unwrap_or_else(|e| panic!("the release of {r:?} in NEGOTIATION: {e}"));
    }
    let fresh = AssignmentId::from_raw(987_654);
    s.run(&assign(
        COORDINATOR,
        fresh,
        PA,
        R2,
        AssignmentKind::Reviewer,
        Some(handle(fresh.raw())),
    ))
    .unwrap_or_else(|e| panic!("R-CF-02: R2 is assigned again in NEGOTIATION: {e}"));
    s.run(&declare(
        R2,
        DeclarationSubject::Assignment(fresh),
        false,
        false,
    ))
    .unwrap_or_else(|e| panic!("R2 declares no conflict: {e}"));
    s.determine(PA, 1, &[]).unwrap_or_else(|e| {
        panic!("I-34: R1 (O1) and R2 (O2) span P-39 = 2 again, so R1 determines: {e}")
    });
    assert_eq!(s.state(PA), Some(StateTag::Negotiation));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// I-34, SoD-10, R-NG-03, R-CF-02: a reviewer assigned in NEGOTIATION
/// restores P-39 organisations for the amount determination.
#[test]
fn i34_reviewer_assigned_in_negotiation_restores_p39_organisations() {
    reassignment_restores_p39(Backend::Production);
}

/// I-34, SoD-10, R-NG-03, R-CF-02: the same story on the references alone.
#[test]
fn i34_reviewer_assigned_in_negotiation_restores_p39_organisations_on_the_reference() {
    reassignment_restores_p39(Backend::Reference);
}
