//! R-IR-04, Q18: an amendment that no P-14 exemption covers goes through IRC review, with `AssignmentKind::Amendment` assignments (design 2.7 and 2.11).
//!
//! `SPEC/02-domain/state-machine.md`, Amendments: an amendment bypasses
//! IRC_REVIEW only when an exemption in P-14 applies, and the programme
//! manager decides whether one applies. `SPEC/02-domain/contracts.md`,
//! Rules: an amendment is a new version signed by all parties, and IRC
//! review follows P-14. R-IR-04: amendments meeting P-14 skip IRC review.
//!
//! Readings checked here, recorded in the money reference:
//!
//! - The programme manager routes the amendment, once, through an
//!   exemption or IRC review (P-14).
//! - For an IRC route, the FSTP coordinator assigns IRC members to the
//!   grant with `AssignmentKind::Amendment` naming the amendment. Each
//!   assignee declares no conflict and records one `RecordIrcReview`. The
//!   proposal state never changes, so no batch holds a transition (Q18).
//! - Activation needs at least P-15 active amendment assignments, every one
//!   validated, none awaiting its declaration, and no concern (R-IR-01
//!   read for amendments). Test-author choice: a concern ends the review,
//!   and the amendment cannot be activated.
//!
//! The story starts from genesis by production commands: lead a granted
//! 3.00, P-15 = 2, with IRC members IRC and IRC2. Every step is compared
//! with the money reference in both directions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::amendment::AmendmentRoute;
use fstp_domain::assignment::AssignmentKind;
use fstp_domain::id::{AmendmentId, ContractId, PlanVersionId};
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::record::Record;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    LA, MoneySetup, MoneyStory, PA, PB, activate_amendment, amendment_assignment,
    assign_amendment_declared, milestone_n, money_plan, propose_amendment, route_amendment,
    start_execution,
};
use fstp_domain_testkit::r#gen::review::{COORDINATOR, IRC, R1, assign, handle, plan_of};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, T0};
use fstp_domain_testkit::mc::life_model::{IRC2, irc_review};

const AMENDED: PlanVersionId = PlanVersionId::from_raw(4_701);
const AMENDMENT: AmendmentId = AmendmentId::from_raw(701);
const CONTRACT: ContractId = ContractId::from_raw(54_701);

/// PA granted 3.00 in GRANTED, with an amendment plan of 2.00 proposed by
/// the lead and not yet routed.
fn proposed(b: Backend) -> MoneyStory {
    let mut s = MoneyStory::new(&MoneySetup::sybil([300, 300, 200]), b)
        .unwrap_or_else(|e| panic!("three proposals to NEGOTIATION from genesis: {e}"));
    s.grant(PA)
        .unwrap_or_else(|e| panic!("a granted 3.00: {e}"));
    s.run(
        &money_plan(
            LA,
            PA,
            AMENDED,
            PlanOrigin::Amendment,
            Some(plan_of(PA)),
            &[(milestone_n(PA, 20), 200, T0)],
        )
        .unwrap(),
    )
    .unwrap_or_else(|e| panic!("Q18: the lead records the amendment plan: {e}"));
    s.run(&propose_amendment(LA, AMENDMENT, PA, AMENDED))
        .unwrap_or_else(|e| panic!("{e}"));
    s
}

fn activation_refused(s: &mut MoneyStory, why: &str) {
    s.refused(&activate_amendment(AMENDMENT, CONTRACT))
        .unwrap_or_else(|e| panic!("R-IR-04: {why}: {e}"));
}

fn no_transition(records: &[Record], what: &str) {
    assert!(
        !records.iter().any(|r| matches!(r, Record::Transitioned(_))),
        "Q18: {what} changes no proposal state: {records:?}"
    );
}

/// The programme manager decides the P-14 route, once.
fn p14_route_is_the_programme_managers(b: Backend) {
    let mut s = proposed(b);
    for outsider in [COORDINATOR, LA, R1, IRC] {
        s.refused(&route_amendment(
            outsider,
            AMENDMENT,
            AmendmentRoute::Exempt,
        ))
        .unwrap_or_else(|e| panic!("P-14: {outsider:?} does not decide the exemption: {e}"));
    }
    s.run(&route_amendment(STAFF_PM, AMENDMENT, AmendmentRoute::Irc))
        .unwrap_or_else(|e| panic!("P-14: the programme manager routes to IRC review: {e}"));
    s.refused(&route_amendment(
        STAFF_PM,
        AMENDMENT,
        AmendmentRoute::Exempt,
    ))
    .unwrap_or_else(|e| panic!("P-14: the route is decided once: {e}"));
    activation_refused(&mut s, "an IRC route activates only after its IRC review");
    assert_eq!(s.state(PA), Some(StateTag::Granted));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// An IRC-routed amendment activates once P-15 IRC members validated it.
fn irc_validation_activates_the_amendment(b: Backend) {
    let mut s = proposed(b);
    s.run(&route_amendment(STAFF_PM, AMENDMENT, AmendmentRoute::Irc))
        .unwrap_or_else(|e| panic!("{e}"));
    activation_refused(&mut s, "no IRC member is assigned yet");
    for st in assign_amendment_declared(IRC, PA, AMENDMENT) {
        let r = s
            .run(&st)
            .unwrap_or_else(|e| panic!("R-IR-04: IRC is assigned to the amendment: {e}"));
        no_transition(&r, "an amendment assignment");
    }
    activation_refused(&mut s, "no IRC member validated yet");
    let r = s
        .run(&irc_review(IRC, amendment_assignment(IRC, AMENDMENT), true))
        .unwrap_or_else(|e| panic!("R-IR-04: IRC validates the amendment: {e}"));
    no_transition(&r, "an amendment validation");
    s.refused(&irc_review(IRC, amendment_assignment(IRC, AMENDMENT), true))
        .unwrap_or_else(|e| panic!("R-IR-01: the review is recorded once: {e}"));
    activation_refused(&mut s, "one validation lies below P-15 = 2");
    for st in assign_amendment_declared(IRC2, PA, AMENDMENT) {
        s.run(&st).unwrap_or_else(|e| panic!("{e}"));
    }
    activation_refused(&mut s, "IRC2 has not validated yet");
    s.refused(&irc_review(
        IRC,
        amendment_assignment(IRC2, AMENDMENT),
        true,
    ))
    .unwrap_or_else(|e| panic!("I-03: only the assignee records its review: {e}"));
    let r = s
        .run(&irc_review(
            IRC2,
            amendment_assignment(IRC2, AMENDMENT),
            true,
        ))
        .unwrap_or_else(|e| panic!("{e}"));
    no_transition(&r, "an amendment validation");
    assert_eq!(s.state(PA), Some(StateTag::Granted));
    s.run(&activate_amendment(AMENDMENT, CONTRACT))
        .unwrap_or_else(|e| panic!("R-IR-04: every IRC member validated, so it activates: {e}"));
    assert_eq!(
        s.state(PA),
        Some(StateTag::Granted),
        "Q18: activation leaves GRANTED"
    );
    assert_eq!(
        s.world.money.counted(PA),
        200,
        "I-14: the amended total counts"
    );
    s.run(&start_execution(PA))
        .unwrap_or_else(|e| panic!("NOTE 11: execution starts on the amended plan: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// Amendment assignments need an IRC-routed amendment of the same grant,
/// an IRC member as assignee and the FSTP coordinator as actor.
fn amendment_assignments_need_an_irc_route(b: Backend) {
    let mut s = proposed(b);
    let id = amendment_assignment(IRC, AMENDMENT);
    let irc = |actor, proposal, member| {
        assign(
            actor,
            id,
            proposal,
            member,
            AssignmentKind::Amendment(AMENDMENT),
            Some(handle(id.raw())),
        )
    };
    s.refused(&irc(COORDINATOR, PA, IRC))
        .unwrap_or_else(|e| panic!("R-IR-04: an unrouted amendment has no IRC review: {e}"));
    s.run(&route_amendment(
        STAFF_PM,
        AMENDMENT,
        AmendmentRoute::Exempt,
    ))
    .unwrap_or_else(|e| panic!("{e}"));
    s.refused(&irc(COORDINATOR, PA, IRC)).unwrap_or_else(|e| {
        panic!("R-IR-04: an exempt amendment skips IRC review, so nobody is assigned: {e}")
    });
    s.run(&activate_amendment(AMENDMENT, CONTRACT))
        .unwrap_or_else(|e| panic!("R-IR-04: the exempt amendment activates at once: {e}"));

    let mut t = proposed(b);
    t.run(&route_amendment(STAFF_PM, AMENDMENT, AmendmentRoute::Irc))
        .unwrap_or_else(|e| panic!("{e}"));
    t.refused(&irc(COORDINATOR, PB, IRC))
        .unwrap_or_else(|e| panic!("the amendment belongs to PA, not PB: {e}"));
    t.refused(&irc(COORDINATOR, PA, R1))
        .unwrap_or_else(|e| panic!("R-IR-04: R1 holds no IRC member binding: {e}"));
    t.refused(&irc(STAFF_PM, PA, IRC))
        .unwrap_or_else(|e| panic!("the FSTP coordinator assigns IRC members: {e}"));
    t.run(&irc(COORDINATOR, PA, IRC))
        .unwrap_or_else(|e| panic!("R-IR-04: IRC is assigned to the amendment: {e}"));
    activation_refused(&mut t, "IRC still awaits its declaration");
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
    t.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// A concern on an amendment leaves the grant in its state, takes no
/// later validation and blocks activation (test-author choice).
fn a_concern_blocks_the_amendment(b: Backend) {
    let mut s = proposed(b);
    s.run(&route_amendment(STAFF_PM, AMENDMENT, AmendmentRoute::Irc))
        .unwrap_or_else(|e| panic!("{e}"));
    for m in [IRC, IRC2] {
        for st in assign_amendment_declared(m, PA, AMENDMENT) {
            s.run(&st).unwrap_or_else(|e| panic!("{e}"));
        }
    }
    let r = s
        .run(&irc_review(
            IRC,
            amendment_assignment(IRC, AMENDMENT),
            false,
        ))
        .unwrap_or_else(|e| panic!("R-IR-04: IRC raises a concern on the amendment: {e}"));
    no_transition(&r, "an amendment concern");
    assert_eq!(
        s.state(PA),
        Some(StateTag::Granted),
        "Q18: a concern on an amendment never defers or declines the grant"
    );
    s.refused(&irc_review(
        IRC2,
        amendment_assignment(IRC2, AMENDMENT),
        true,
    ))
    .unwrap_or_else(|e| panic!("no validation counts once a concern is raised: {e}"));
    activation_refused(&mut s, "a concern blocks activation");
    assert_eq!(s.world.money.counted(PA), 300, "I-14: the grant keeps 3.00");
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// R-IR-04, P-14: the programme manager decides the route, once, and an
/// IRC route does not activate before its review.
#[test]
fn r_ir_04_p14_route_is_decided_by_the_programme_manager() {
    p14_route_is_the_programme_managers(Backend::Production);
}

/// R-IR-04, R-IR-01: an IRC-routed amendment activates once at least P-15
/// IRC members assigned to it validated it, and the grant keeps its state.
#[test]
fn r_ir_04_irc_routed_amendment_activates_after_p15_validations() {
    irc_validation_activates_the_amendment(Backend::Production);
}

/// R-IR-04, I-02, I-03: amendment assignments need an IRC-routed amendment
/// of the grant, an IRC member and the FSTP coordinator.
#[test]
fn r_ir_04_amendment_assignments_need_an_irc_routed_amendment() {
    amendment_assignments_need_an_irc_route(Backend::Production);
}

/// R-IR-04, Q18: a concern blocks the amendment and leaves the grant's state.
#[test]
fn r_ir_04_concern_blocks_the_amendment_and_keeps_the_state() {
    a_concern_blocks_the_amendment(Backend::Production);
}

/// R-IR-04: the IRC route stories pass on the references alone.
#[test]
fn r_ir_04_amendment_irc_route_stories_pass_on_the_reference() {
    p14_route_is_the_programme_managers(Backend::Reference);
    irc_validation_activates_the_amendment(Backend::Reference);
    amendment_assignments_need_an_irc_route(Backend::Reference);
    a_concern_blocks_the_amendment(Backend::Reference);
}
