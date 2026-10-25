//! I-02, assignment half, with SoD-02 (design 2.6, 2.7 and 6.2).
//!
//! The assigned reviewer is an assignment over a committee member binding
//! and counts as a Judging role for I-02. The machine grants and ends the
//! committee member and IRC member bindings of one account and assigns
//! and releases its assignments. Every command is compared with the
//! references in both directions, and an `EndRole` must release the
//! assignments that rest on the ended binding in the same batch. The
//! invariant: no account holds an IRC binding or IRC assignment beside
//! another Judging binding or a reviewer assignment, and every unreleased
//! assignment rests on a held binding of its role.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::{AssignmentKind, ReleaseCause};
use fstp_domain::id::{AssignmentId, BindingId, OrganisationId};
use fstp_domain::record::{AssignmentReleased, Record};
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, IRC, PR1, RevFocus, ReviewMachine, SWITCHER, assign, declare, handle,
    machine_accounts, machine_setup, review_truth, run_records, scenario_from,
};
use fstp_domain_testkit::r#gen::roster::{Backend, P1, T0, end, grant};
use fstp_prop::{Config, check_machine_with, run_machine};

/// I-02, SoD-02: an IRC member holds no other Judging assignment, and the reverse.
#[test]
fn i02_assignment_irc_member_holds_no_other_judging_assignment() {
    let machine = ReviewMachine::new(RevFocus::I02);
    check_machine_with(
        "i02_assignment_irc_member_holds_no_other_judging_assignment",
        Config::default().with_cases(RevFocus::I02.cases),
        &machine,
    );
}

/// I-02: the same machine with the references as its own engine passes.
#[test]
fn i02_assignment_machine_agrees_with_its_reference() {
    let machine = ReviewMachine::with_backend(RevFocus::I02, Backend::Reference);
    let outcome = run_machine(
        "i02_assignment_machine_agrees_with_its_reference",
        Config::default().with_cases(RevFocus::I02.cases),
        &machine,
    );
    if let Some(f) = outcome.failure() {
        panic!("the reference-backed machine failed: {}", f.message);
    }
}

/// I-02, SoD-02 NOTE 4: ending a committee binding releases its reviewer
/// assignment in the same batch, so the account may then hold an IRC
/// binding with no reviewer assignment left. An IRC member is never
/// assigned as a reviewer.
#[test]
fn i02_assignment_end_of_committee_binding_releases_the_assignment() {
    let mut s = scenario_from(&machine_setup(), review_truth(machine_accounts()))
        .unwrap_or_else(|e| panic!("setup from genesis: {e}"));
    let committee = BindingId::from_raw(5_001);
    let mut g = grant(committee, SWITCHER, P1, Role::CommitteeMember, T0);
    if let fstp_domain::command::Command::GrantRole { organisation, .. } = &mut g.cmd {
        *organisation = Some(OrganisationId::from_raw(3));
    }
    assert!(
        run_records(&mut s, &g, T0).unwrap().is_ok(),
        "committee grant"
    );
    let id = AssignmentId::from_raw(5_101);
    let a = assign(
        COORDINATOR,
        id,
        PR1,
        SWITCHER,
        AssignmentKind::Reviewer,
        Some(handle(5_101)),
    );
    assert!(
        run_records(&mut s, &a, T0).unwrap().is_ok(),
        "reviewer assignment"
    );
    let d = declare(
        SWITCHER,
        fstp_domain::command::DeclarationSubject::Assignment(id),
        false,
        false,
    );
    assert!(
        run_records(&mut s, &d, T0).unwrap().is_ok(),
        "no-conflict declaration"
    );
    let ended = run_records(&mut s, &end(committee, T0), T0)
        .unwrap()
        .unwrap_or_else(|r| panic!("EndRole refused: {r}"));
    let release = Record::AssignmentReleased(AssignmentReleased {
        assignment: id,
        cause: ReleaseCause::BindingEnded,
    });
    assert!(
        ended.contains(&release),
        "I-02: the end of the committee binding releases the assignment in the same batch: {ended:?}"
    );
    let irc = grant(
        BindingId::from_raw(5_002),
        SWITCHER,
        P1,
        Role::IrcMember,
        T0,
    );
    assert!(
        run_records(&mut s, &irc, T0).unwrap().is_ok(),
        "SoD-02 NOTE 4: a past committee binding never bars an IRC binding"
    );
    let again = assign(
        COORDINATOR,
        AssignmentId::from_raw(5_102),
        PR1,
        SWITCHER,
        AssignmentKind::Reviewer,
        Some(handle(5_102)),
    );
    assert!(
        run_records(&mut s, &again, T0).unwrap().is_err(),
        "I-02: an IRC member is never assigned as a reviewer"
    );
    let irc_as_reviewer = assign(
        COORDINATOR,
        AssignmentId::from_raw(5_103),
        PR1,
        IRC,
        AssignmentKind::Reviewer,
        Some(handle(5_103)),
    );
    assert!(
        run_records(&mut s, &irc_as_reviewer, T0).unwrap().is_err(),
        "I-02: an IRC member is never assigned as a reviewer"
    );
}
