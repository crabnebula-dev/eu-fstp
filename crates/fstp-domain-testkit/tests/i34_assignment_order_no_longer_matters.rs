//! I-34, SoD-10: an `Assign` is refused only once P-39 organisations are out of reach (W7 fix).
//!
//! Admission, the stage 1 close, the stage 2 ranking and the amount
//! determination check I-34 over the reviewers themselves (decided
//! 2026-10-28). So the assignment rule no longer needs each reviewer to
//! bring a new organisation while the proposal spans fewer than P-39. It
//! refuses only an assignment after which P-39 organisations cannot be
//! reached, even with every other committee member of the programme. The
//! order in which the coordinator assigns reviewers then no longer
//! matters.
//!
//! Every story starts from genesis by production commands, P-39 = 2, and
//! every step is compared with the references in both directions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::id::{AccountId, OrganisationId};
use fstp_domain::roles::Role;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::review::{L1, O1, PR1, R1, R2, R3};
use fstp_domain_testkit::r#gen::roster::{Backend, call};
use fstp_domain_testkit::mc::life_model::{
    Story, admit, assign_declared, life_judges, story_setup,
};
use fstp_domain_testkit::reference::review::check_i34_assign;

/// The life judges with R3 moved to O1: R1 and R3 of O1, R2 of O2.
fn judges_r3_in_o1() -> Vec<(AccountId, Role, Option<OrganisationId>)> {
    let mut judges = life_judges();
    for j in &mut judges {
        if j.0 == R3 {
            j.2 = Some(O1);
        }
    }
    judges
}

/// The life judges with every committee member in O1.
fn judges_all_in_o1() -> Vec<(AccountId, Role, Option<OrganisationId>)> {
    let mut judges = life_judges();
    for j in &mut judges {
        if j.1 == Role::CommitteeMember {
            j.2 = Some(O1);
        }
    }
    judges
}

/// R1 and R3 of O1 are assigned first, then R2 of O2. Each assignment
/// leaves O2 in reach, so each is accepted, and the admission over O1 and
/// O2 is accepted.
fn same_organisation_first(b: Backend) {
    let setup = story_setup(vec![(L1, PR1, false)], judges_r3_in_o1());
    let mut s = Story::new(&setup, b, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.checked(L1, PR1, &[R1, R3, R2]).unwrap_or_else(|e| {
        panic!("I-34 (W7 fix): R1 and R3 of O1, then R2 of O2, are assigned in that order: {e}")
    });
    s.run(&admit(PR1))
        .unwrap_or_else(|e| panic!("I-34: the admission over O1 and O2: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Stage1));
}

/// I-34, SoD-10 (W7 fix): two reviewers of one organisation may be
/// assigned before one of another, while that one is still in reach.
#[test]
fn i34_assignment_order_no_longer_matters() {
    same_organisation_first(Backend::Production);
}

/// I-34, SoD-10 (W7 fix): the same story on the references alone.
#[test]
fn i34_assignment_order_no_longer_matters_on_the_reference() {
    same_organisation_first(Backend::Reference);
}

/// R1 and R3 of O1 are assigned, and R2 of O2 is not. The admission is
/// refused under I-34, since the reviewers span one organisation. The
/// assignment rule left O2 in reach, and the admission holds I-34.
fn admission_still_holds_i34(b: Backend) {
    let setup = story_setup(vec![(L1, PR1, false)], judges_r3_in_o1());
    let mut s = Story::new(&setup, b, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.checked(L1, PR1, &[R1, R3])
        .unwrap_or_else(|e| panic!("R1 and R3 of O1 are assigned: {e}"));
    let out = s
        .attempt(&admit(PR1))
        .unwrap_or_else(|e| panic!("the admission over one organisation: {e}"));
    assert!(
        out.is_none(),
        "I-34: the admission over reviewers of one organisation is refused: {out:?}"
    );
    assert_eq!(s.state(PR1), Some(StateTag::Submitted));
}

/// I-34, SoD-10: the admission refuses reviewers of fewer than P-39
/// organisations, whatever the assignment rule let through.
#[test]
fn i34_admission_refuses_reviewers_of_one_organisation() {
    admission_still_holds_i34(Backend::Production);
}

/// I-34, SoD-10: the same story on the references alone.
#[test]
fn i34_admission_refuses_reviewers_of_one_organisation_on_the_reference() {
    admission_still_holds_i34(Backend::Reference);
}

/// Every committee member of the programme is in O1. P-39 = 2 can never
/// be reached, so the first assignment is refused under I-34.
fn out_of_reach(b: Backend) {
    let setup = story_setup(vec![(L1, PR1, false)], judges_all_in_o1());
    let mut s = Story::new(&setup, b, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.submit(L1, PR1)
        .unwrap_or_else(|e| panic!("PR1 is submitted: {e}"));
    s.at(fstp_domain_testkit::mc::life_model::T_EVAL);
    let steps = assign_declared(R1, PR1, call(1), AssignmentKind::Reviewer);
    let first = steps.first().unwrap_or_else(|| panic!("no assign step"));
    let out = s
        .attempt(first)
        .unwrap_or_else(|e| panic!("the assignment of R1: {e}"));
    assert!(
        out.is_none(),
        "I-34 (W7 fix): every committee member is in O1, so P-39 = 2 is out of reach and \
         the assignment is refused: {out:?}"
    );
}

/// I-34, SoD-10 (W7 fix): an assignment after which P-39 organisations are
/// out of reach is refused.
#[test]
fn i34_assignment_is_refused_once_p39_is_out_of_reach() {
    out_of_reach(Backend::Production);
}

/// I-34, SoD-10 (W7 fix): the same story on the references alone.
#[test]
fn i34_assignment_is_refused_once_p39_is_out_of_reach_on_the_reference() {
    out_of_reach(Backend::Reference);
}

/// I-34 teeth (design 6.1, W7 fix): the predicate of an accepted `Assign`
/// catches an assignment after which P-39 organisations are out of reach.
/// With every committee member in O1, an accepted assignment of R1 breaks
/// it. With R2 of O2 in the programme, the same assignment does not.
#[test]
fn i34_teeth_assignment_out_of_reach_is_caught() {
    let t = fstp_domain_testkit::mc::life_model::T_EVAL;
    for (judges, broken) in [(judges_all_in_o1(), true), (judges_r3_in_o1(), false)] {
        let setup = story_setup(vec![(L1, PR1, false)], judges);
        let mut s =
            Story::new(&setup, Backend::Reference, |_| {}).unwrap_or_else(|e| panic!("{e}"));
        s.submit(L1, PR1)
            .unwrap_or_else(|e| panic!("PR1 is submitted: {e}"));
        let rev = &s.world.rev;
        let out = check_i34_assign(&rev.sod.view, &rev.view, PR1, R1, t);
        assert_eq!(
            out.is_err(),
            broken,
            "I-34: the predicate on R1's assignment with P-39 out of reach = {broken}: {out:?}"
        );
    }
}
