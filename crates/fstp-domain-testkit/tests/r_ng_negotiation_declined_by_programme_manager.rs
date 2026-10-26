//! NOTE 9 and NOTE 13: NEGOTIATION to DECLINED is recorded by the programme manager with a computed reason (decided 2026-10-25, Q6 A, O-49).
//!
//! Three proposals reach NEGOTIATION from genesis by production commands
//! under P-04 = [2.00, 4.00] and P-05 = 6.00: lead a with 4.00, lead b,
//! the Sybil of a, with 3.00, and lead c with 1.00. Lead c's plan lies
//! below the P-04 minimum, so no amount can keep I-13. Only the programme
//! manager records the decline, never the System, the lead or a reviewer.
//! A proposal with no listed failure cannot be declined: with b at 2.00,
//! a's 4.00 still leaves b's whole plan within the cap. The cap failure
//! appears once a holds 4.00 and P-05 is lowered to 4.00. It also appears
//! for b's 3.00 under P-05 = 6.00, although the P-04 minimum fits. In M2 a
//! deduction is refused, so the plan total is the only amount b can reach.
//! DECLINED is terminal, and the decline releases the open reservation.
//!
//! Identity discovery can also leave an open reservation above the cap.
//! Under P-04 = [3.00, 4.00], leads a and b each reserve 4.00 while b is
//! unverified, so the vault groups b alone. Once the vault verifies b,
//! neither can be granted. The completing grant fact is refused, and the
//! programme manager records the decline for no amount within the cap.
//! The decline releases the reservation, and the other grant then passes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::{Actor, SystemCause};
use fstp_domain::decision::NegotiationFailure;
use fstp_domain::id::PolicyVersionId;
use fstp_domain::record::Record;
use fstp_domain::rules::{Row, StateTag};
use fstp_domain_testkit::r#gen::money::{
    LA, LB, LC, MoneySetup, MoneyStory, PA, PB, PC, accept_grant, approve_grant,
    contract_effective, decline_negotiation, edit_p05,
};
use fstp_domain_testkit::r#gen::review::{R1, withdraw};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM};

fn story(b: Backend) -> MoneyStory {
    MoneyStory::new(&MoneySetup::sybil([400, 300, 100]), b)
        .unwrap_or_else(|e| panic!("three proposals to NEGOTIATION from genesis: {e}"))
}

fn reason(recs: &[Record]) -> Option<NegotiationFailure> {
    recs.iter().find_map(|r| match r {
        Record::NegotiationDeclined { reason, .. } => Some(*reason),
        _ => None,
    })
}

fn only_the_programme_manager(b: Backend) {
    let mut s = story(b);
    for actor in [
        Actor::System(SystemCause::Timeline),
        Actor::Account(LC),
        Actor::Account(R1),
    ] {
        s.refused(&decline_negotiation(actor, PC))
            .unwrap_or_else(|e| panic!("NOTE 13: {actor:?} must not record the decline: {e}"));
    }
    let recs = s
        .run(&decline_negotiation(Actor::Account(STAFF_PM), PC))
        .unwrap_or_else(|e| panic!("NOTE 9: the programme manager records the decline: {e}"));
    assert_eq!(reason(&recs), Some(NegotiationFailure::NoAmountWithinRange));
    let t = recs.iter().find_map(|r| match r {
        Record::Transitioned(t) => Some(*t),
        _ => None,
    });
    let t = t.unwrap_or_else(|| panic!("R-AU-01: the batch records the transition: {recs:?}"));
    assert_eq!(
        (t.from, t.to, t.row),
        (
            StateTag::Negotiation,
            StateTag::Declined,
            Row::NegotiationToDeclined
        )
    );
    assert_eq!(
        t.actor,
        Actor::Account(STAFF_PM),
        "R-LA-03: a named human records it"
    );
    s.refused(&withdraw(LC, PC))
        .unwrap_or_else(|e| panic!("NOTE 10: DECLINED is terminal: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

fn no_failure_no_decline(b: Backend) {
    let mut s = MoneyStory::new(&MoneySetup::sybil([400, 200, 100]), b)
        .unwrap_or_else(|e| panic!("three proposals to NEGOTIATION from genesis: {e}"));
    s.refused(&decline_negotiation(Actor::Account(STAFF_PM), PA))
        .unwrap_or_else(|e| {
            panic!("NOTE 9: a's 4.00 lies within P-04 and the cap, so no failure holds: {e}")
        });
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    s.refused(&decline_negotiation(Actor::Account(STAFF_PM), PA))
        .unwrap_or_else(|e| panic!("NOTE 9: a's reservation stands, so no failure holds: {e}"));
    s.refused(&decline_negotiation(Actor::Account(STAFF_PM), PB))
        .unwrap_or_else(|e| panic!("NOTE 9: b's headroom 2.00 still allows its plan 2.00: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

fn plan_total_breaks_the_cap(b: Backend) {
    let mut s = story(b);
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    let recs = s
        .run(&decline_negotiation(Actor::Account(STAFF_PM), PB))
        .unwrap_or_else(|e| {
            panic!("NOTE 9: b can reach only its plan 3.00, above the headroom 2.00: {e}")
        });
    assert_eq!(reason(&recs), Some(NegotiationFailure::NoAmountWithinCap));
    assert_eq!(s.state(PB), Some(StateTag::Declined));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

fn cap_failure(b: Backend) {
    let mut s = story(b);
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    let head = s.world.head.clone().unwrap();
    s.run(&edit_p05(&head, PolicyVersionId::from_raw(902), 400).unwrap())
        .unwrap_or_else(|e| panic!("I-14: P-05 4.00 keeps a's 4.00 within the cap: {e}"));
    let recs = s
        .run(&decline_negotiation(Actor::Account(STAFF_PM), PB))
        .unwrap_or_else(|e| panic!("NOTE 9: no amount can keep I-14 for b: {e}"));
    assert_eq!(reason(&recs), Some(NegotiationFailure::NoAmountWithinCap));
    s.refused(&decline_negotiation(Actor::Account(STAFF_PM), PA))
        .unwrap_or_else(|e| panic!("NOTE 9: a's reservation stands, so a cannot be declined: {e}"));
    s.run(&withdraw(LA, PA))
        .unwrap_or_else(|e| panic!("a withdraws: {e}"));
    assert_eq!(
        s.world.money.counted(PA),
        0,
        "the withdrawal releases a's reservation"
    );
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

fn discovery_leaves_no_headroom(b: Backend) {
    let mut setup = MoneySetup::sybil([400, 400, 100]);
    setup.drafts.truncate(2);
    setup.p04 = (300, 400);
    setup.unverified = vec![LB];
    let mut s = MoneyStory::new(&setup, b)
        .unwrap_or_else(|e| panic!("two proposals to NEGOTIATION from genesis: {e}"));
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    s.determine(PB, 1, &[])
        .unwrap_or_else(|e| panic!("b, unverified and so grouped alone, reserves 4.00: {e}"));
    s.world
        .vault(|t| t.verify(LB))
        .unwrap_or_else(|e| panic!("the vault verifies b: {e}"));
    s.invariants().unwrap_or_else(|e| {
        panic!("I-14: reservations checked when they opened are no breach: {e}")
    });
    s.run(&accept_grant(LB, PB))
        .unwrap_or_else(|e| panic!("b accepts: {e}"));
    s.run(&approve_grant(STAFF_PM, PB))
        .unwrap_or_else(|e| panic!("the programme manager approves: {e}"));
    s.refused(&contract_effective(PB)).unwrap_or_else(|e| {
        panic!("I-14: a's 4.00 plus b's 4.00 exceeds 6.00, so GRANTED is disabled: {e}")
    });
    let recs = s
        .run(&decline_negotiation(Actor::Account(STAFF_PM), PB))
        .unwrap_or_else(|e| panic!("NOTE 9: b's headroom 2.00 lies below its 4.00: {e}"));
    assert_eq!(reason(&recs), Some(NegotiationFailure::NoAmountWithinCap));
    assert!(
        recs.iter()
            .any(|r| matches!(r, Record::CapReleased { proposal, .. } if *proposal == PB)),
        "the decline releases b's reservation: {recs:?}"
    );
    s.grant_facts(PA)
        .unwrap_or_else(|e| panic!("a is granted once b's reservation is released: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Granted));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// NOTE 9, NOTE 13, O-49: only the programme manager records NEGOTIATION
/// to DECLINED, with the computed reason, and DECLINED is terminal.
#[test]
fn r_ng_negotiation_declined_only_by_the_programme_manager() {
    only_the_programme_manager(Backend::Production);
}

/// NOTE 9: a negotiation with no listed failure cannot be declined.
#[test]
fn r_ng_negotiation_without_failure_is_not_declined() {
    no_failure_no_decline(Backend::Production);
}

/// NOTE 9, I-14: no amount within the cap is a decline reason.
#[test]
fn r_ng_negotiation_declined_when_no_amount_fits_the_cap() {
    cap_failure(Backend::Production);
}

/// NOTE 9, I-14, R-NG-03: a plan total above the cap headroom is a decline
/// reason even when the P-04 minimum fits, since a deduction is refused in M2.
#[test]
fn r_ng_negotiation_declined_when_only_the_plan_total_breaks_the_cap() {
    plan_total_breaks_the_cap(Backend::Production);
}

/// NOTE 9, I-14, Identity discovery: a verification that leaves an open
/// reservation above the cap lets the programme manager decline.
#[test]
fn r_ng_negotiation_declined_when_discovery_leaves_no_cap_headroom() {
    discovery_leaves_no_headroom(Backend::Production);
}

/// NOTE 9: the stories pass on the references alone.
#[test]
fn r_ng_negotiation_decline_stories_pass_on_the_reference() {
    only_the_programme_manager(Backend::Reference);
    no_failure_no_decline(Backend::Reference);
    cap_failure(Backend::Reference);
    plan_total_breaks_the_cap(Backend::Reference);
    discovery_leaves_no_headroom(Backend::Reference);
}
