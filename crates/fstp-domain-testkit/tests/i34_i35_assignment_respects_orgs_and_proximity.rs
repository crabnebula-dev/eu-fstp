//! I-34 and I-35 with SoD-10 and SoD-11, machine over assignment runs (design 2.7 and 6.2).
//!
//! The test plan row: random assignment runs over generated organisations
//! and proximity lists never violate distinctness or proximity. The
//! committee bindings record organisations O1, O1, O2 and O3, P-39 = 2,
//! and P-38 gives O1 a proximity list. Applicants declare affiliations on
//! that list mid-run, through the vault. Every `Assign` is compared with
//! the reference in both directions. After every accepted reviewer
//! assignment, a proposal below P-39 organisations gained a new one
//! (I-34), and no reviewer of O1 serves a team that declares an
//! affiliation on O1's list (I-35).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::{AssignmentKind, ReleaseCause};
use fstp_domain::id::{AssignmentId, PolicyVersionId};
use fstp_domain::policy::ProximityLists;
use fstp_domain::record::{AssignmentReleased, Record};
use fstp_domain::refusal::RuleRef;
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, L1, L2, LIST_1, O1, PR1, PR2, R1, R2, R3, RevFocus, ReviewMachine, ReviewWorld,
    assign, handle, machine_accounts, machine_setup, records_of, review_truth, run_records,
    scenario_from,
};
use fstp_domain_testkit::r#gen::roster::{Backend, P1, T0, edit_policy};
use fstp_prop::{Config, check_machine_with, run_machine};

/// I-34, I-35, SoD-10, SoD-11: assignment runs respect distinct
/// organisations and proximity lists.
#[test]
fn i34_i35_assignment_respects_orgs_and_proximity() {
    let machine = ReviewMachine::new(RevFocus::I34_I35);
    check_machine_with(
        "i34_i35_assignment_respects_orgs_and_proximity",
        Config::default().with_cases(RevFocus::I34_I35.cases),
        &machine,
    );
}

/// I-34, I-35: the same machine with the references as its own engine passes.
#[test]
fn i34_i35_machine_agrees_with_its_reference() {
    let machine = ReviewMachine::with_backend(RevFocus::I34_I35, Backend::Reference);
    let outcome = run_machine(
        "i34_i35_machine_agrees_with_its_reference",
        Config::default().with_cases(RevFocus::I34_I35.cases),
        &machine,
    );
    if let Some(f) = outcome.failure() {
        panic!("the reference-backed machine failed: {}", f.message);
    }
}

fn reviewer(
    n: u128,
    proposal: fstp_domain::id::ProposalId,
    who: fstp_domain::id::AccountId,
) -> fstp_domain_testkit::r#gen::roster::Step {
    assign(
        COORDINATOR,
        AssignmentId::from_raw(n),
        proposal,
        who,
        AssignmentKind::Reviewer,
        Some(handle(n)),
    )
}

/// I-34, SoD-10: below P-39 = 2 organisations, a second reviewer of the
/// same organisation is refused under I-34, and one of another is accepted.
#[test]
fn i34_second_reviewer_of_the_same_organisation_is_refused_below_p39() {
    let mut s = scenario_from(&machine_setup(), review_truth(machine_accounts()))
        .unwrap_or_else(|e| panic!("setup from genesis: {e}"));
    let first = run_records(&mut s, &reviewer(9_001, PR1, R1), T0).unwrap();
    assert!(first.is_ok(), "R1 of O1 is assigned: {first:?}");
    let same = run_records(&mut s, &reviewer(9_002, PR1, R2), T0).unwrap();
    match same {
        Err(r) => assert_eq!(r.rule, RuleRef::I34, "R2 of O1 is refused under I-34"),
        Ok(records) => panic!("R2 of O1 was assigned below P-39: {records:?}"),
    }
    let other = run_records(&mut s, &reviewer(9_003, PR1, R3), T0).unwrap();
    assert!(other.is_ok(), "R3 of O2 is assigned: {other:?}");
}

/// I-35, SoD-11: once a team member declares an affiliation on the
/// proximity list of O1, a reviewer of O1 is refused under I-35, and a
/// reviewer of O2 is still assigned.
#[test]
fn i35_reviewer_of_a_listed_organisation_is_refused() {
    let mut s = scenario_from(&machine_setup(), review_truth(machine_accounts()))
        .unwrap_or_else(|e| panic!("setup from genesis: {e}"));
    let ctx = s.ctx(
        T0,
        fstp_domain::command::Actor::System(fstp_domain::command::SystemCause::Vault),
    );
    s.change_vault(|t| t.declare_affiliation(L2, LIST_1), ctx)
        .unwrap_or_else(|e| panic!("vault reaction: {e:?}"));
    match run_records(&mut s, &reviewer(9_011, PR2, R1), T0).unwrap() {
        Err(r) => assert_eq!(r.rule, RuleRef::I35, "R1 of O1 is refused under I-35"),
        Ok(records) => panic!("R1 of O1 was assigned to a proposal on its list: {records:?}"),
    }
    let other = run_records(&mut s, &reviewer(9_012, PR2, R3), T0).unwrap();
    assert!(other.is_ok(), "R3 of O2 is assigned: {other:?}");
}

/// I-35, SoD-11, enforcement point 3: a team affiliation on the list of
/// O1, declared after R1 of O1 was assigned, ends that assignment in the
/// vault reaction. The assignment of R3 of O2 stays.
#[test]
fn i35_affiliation_declared_after_assignment_releases_it() {
    let mut s = scenario_from(&machine_setup(), review_truth(machine_accounts()))
        .unwrap_or_else(|e| panic!("setup from genesis: {e}"));
    run_records(&mut s, &reviewer(9_021, PR2, R1), T0)
        .unwrap()
        .unwrap_or_else(|r| panic!("R1 of O1 is assigned: {r}"));
    run_records(&mut s, &reviewer(9_022, PR2, R3), T0)
        .unwrap()
        .unwrap_or_else(|r| panic!("R3 of O2 is assigned: {r}"));
    let before = records_of(&s).unwrap().len();
    let ctx = s.ctx(
        T0,
        fstp_domain::command::Actor::System(fstp_domain::command::SystemCause::Vault),
    );
    s.change_vault(|t| t.declare_affiliation(L2, LIST_1), ctx)
        .unwrap_or_else(|e| panic!("vault reaction: {e:?}"));
    let reaction = records_of(&s).unwrap().split_off(before);
    let released = |n: u128| {
        reaction.iter().any(
            |r| matches!(r, Record::AssignmentReleased(x) if x.assignment == AssignmentId::from_raw(n)),
        )
    };
    assert!(
        released(9_021),
        "I-35: R1 of O1 stays assigned: {reaction:?}"
    );
    assert!(!released(9_022), "R3 of O2 is released: {reaction:?}");
}

/// I-35, SoD-11, enforcement point 3: an `EditPolicy` that gives O1 a
/// proximity list on which the team already declares an affiliation ends
/// the assignment of R1 of O1 in the same batch.
#[test]
fn i35_p38_edit_releases_a_reviewer_now_on_the_list() {
    let setup = fstp_domain_testkit::mc::conflict_model::conflict_setup();
    let mut truth = review_truth(setup.accounts());
    truth.declare_affiliation(L1, LIST_1);
    let mut w = ReviewWorld::from_setup(Backend::Production, truth, &setup, None)
        .unwrap_or_else(|e| panic!("setup: {e}"));
    let id = AssignmentId::from_raw(9_031);
    w.exec(&reviewer(9_031, PR1, R1))
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("R1 of O1 is assigned while O1 has no list: {r}"));
    let head = setup
        .base
        .version(P1)
        .unwrap_or_else(|e| panic!("head: {e}"));
    let edit = edit_policy(&head, PolicyVersionId::from_raw(2), |v| {
        v.live.p38 = ProximityLists([(O1, LIST_1)].into_iter().collect());
    });
    let batch = w
        .exec(&edit)
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("the P-38 edit was refused: {r}"));
    assert!(
        batch.contains(&Record::AssignmentReleased(AssignmentReleased {
            assignment: id,
            cause: ReleaseCause::DetectedConflict,
        })),
        "I-35: R1 of O1 stays assigned after O1's list names L1's affiliation: {batch:?}"
    );
}
