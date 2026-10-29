//! Reviewer reproducer for I-34 at the amount determination (R-NG-03,
//! SoD-10, decided 2026-10-28).
//!
//! I-34 now refuses `DetermineAmount` while the active reviewers of the
//! proposal span fewer than P-39 organisations. Reviewer assignment is
//! closed in NEGOTIATION, and NOTE 9 names no decline ground for it. So
//! once reviewers are released in NEGOTIATION before any amount is set,
//! the proposal can never reach GRANTED or DECLINED by any command.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::Actor;
use fstp_domain::id::AssignmentId;
use fstp_domain_testkit::r#gen::money::{
    MoneySetup, MoneyStory, PA, amount_decision, decline_negotiation, determine,
};
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, R1, R2, R3, assign, handle, plan_of, unassign,
};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, call};
use fstp_domain_testkit::mc::life_model::assignment_of;

/// The production outcome of `step` alone.
fn prod(
    s: &MoneyStory,
    step: &fstp_domain_testkit::r#gen::roster::Step,
) -> Result<Vec<fstp_domain::record::Record>, fstp_domain::refusal::Refusal> {
    s.world
        .life
        .rev
        .production_outcome(step)
        .unwrap_or_else(|| panic!("production backend"))
}

/// R1 (O1), R2 (O2) and R3 (O3) review PA, and P-39 = 2. In NEGOTIATION,
/// before any amount is determined, R2 and R3 are released. R1 alone
/// cannot determine the amount under I-34. The proposal must keep a way
/// forward: either a reviewer of another organisation can be assigned
/// again, or the programme manager can decline it with a recorded reason.
#[test]
fn review_w7fid_i34_determination_refusal_leaves_a_way_forward() {
    let mut setup = MoneySetup::sybil([400, 200, 100]);
    setup.reviewers = vec![R1, R2, R3];
    let mut s = MoneyStory::new(&setup, Backend::Production)
        .unwrap_or_else(|e| panic!("three proposals to NEGOTIATION: {e}"));
    for r in [R2, R3] {
        let a = assignment_of(r, PA, call(1), AssignmentKind::Reviewer);
        s.run(&unassign(COORDINATOR, a))
            .unwrap_or_else(|e| panic!("the release of {r:?} in NEGOTIATION: {e}"));
    }
    let first = determine(R1, PA, amount_decision(PA, 1), plan_of(PA), &[]).unwrap();
    assert!(
        prod(&s, &first).is_err(),
        "baseline: I-34 refuses R1's determination alone"
    );
    let fresh = AssignmentId::from_raw(987_654);
    let reassigned = [None, Some(handle(987_654))].into_iter().any(|h| {
        prod(
            &s,
            &assign(COORDINATOR, fresh, PA, R2, AssignmentKind::Reviewer, h),
        )
        .is_ok()
    });
    let declined = prod(&s, &decline_negotiation(Actor::Account(STAFF_PM), PA)).is_ok();
    assert!(
        reassigned || declined,
        "I-34 at the determination (decided 2026-10-28): PA can neither get a reviewer of another organisation nor be declined, so it can never leave NEGOTIATION except by withdrawal"
    );
}
