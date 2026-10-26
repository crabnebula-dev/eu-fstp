//! NOTE 9, I-13, I-14, R-NG-03: NEGOTIATION to DECLINED on amount grounds needs that no amount within P-04 fits the recipient's remaining room under P-05 (decided 2026-10-26).
//!
//! `SPEC/02-domain/state-machine.md` NOTE 9: for I-13 and I-14, "cannot
//! reach" GRANTED means that no amount within P-04 fits the recipient's
//! remaining room under P-05, so even the P-04 minimum does not fit. A
//! plan total above the cap is no ground for declining while a smaller
//! negotiated plan could still fit, and the lead may propose one. The
//! lead proposes plan content and the assigned reviewers set the amount,
//! with a deduction carried by the negotiated plan (R-NG-03, design 2.11).
//! The remaining room reads the stricter of the publication snapshot and
//! the live P-05 (`SPEC/02-domain/contracts.md`, P-05 NOTE 7).
//!
//! Once the lead accepted or the programme manager approved, a new
//! determination is refused, so the determined amount is locked. The
//! locked amount then decides. The programme manager records the decline
//! with its computed reason (NOTE 13, R-LA-03).
//!
//! Every story starts from genesis by production commands, with lead a,
//! lead b of the same verified identity, and lead c, under P-04 = [2.00,
//! 4.00]. Every step is compared with the money reference in both
//! directions. Each `_on_the_reference` twin runs the same story on the
//! references alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::{Actor, SystemCause};
use fstp_domain::decision::NegotiationFailure;
use fstp_domain::id::{AccountId, PlanVersionId, PolicyVersionId, ProposalId};
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::record::Record;
use fstp_domain::rules::{Row, StateTag};
use fstp_domain_testkit::r#gen::money::{
    LA, LB, LC, MoneySetup, MoneyStory, PA, PB, accept_grant, amount_decision, approve_grant,
    contract_effective, decline_negotiation, determine, edit_p05, milestone_n, money_plan,
};
use fstp_domain_testkit::r#gen::review::{R1, plan_of};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, Step, T0};

fn story_of(setup: &MoneySetup, b: Backend) -> MoneyStory {
    MoneyStory::new(setup, b)
        .unwrap_or_else(|e| panic!("three proposals to NEGOTIATION from genesis: {e}"))
}

fn reason(recs: &[Record]) -> Option<NegotiationFailure> {
    recs.iter().find_map(|r| match r {
        Record::NegotiationDeclined { reason, .. } => Some(*reason),
        _ => None,
    })
}

/// The lead's negotiated plan of `proposal` with one milestone of `cents`,
/// superseding the submitted plan.
fn negotiated_plan(lead: AccountId, proposal: ProposalId, cents: i64) -> (PlanVersionId, Step) {
    let plan = PlanVersionId::from_raw(4_900u128.saturating_add(proposal.raw()));
    let step = money_plan(
        lead,
        proposal,
        plan,
        PlanOrigin::Negotiated,
        Some(plan_of(proposal)),
        &[(milestone_n(proposal, 60), cents, T0)],
    )
    .unwrap_or_else(|e| panic!("{e}"));
    (plan, step)
}

/// Checks that `recs` decline `proposal` for no amount within the cap,
/// recorded by the programme manager on row NEGOTIATION to DECLINED.
fn declined_for_the_cap(s: &MoneyStory, recs: &[Record], proposal: ProposalId) {
    assert_eq!(reason(recs), Some(NegotiationFailure::NoAmountWithinCap));
    let t = recs.iter().find_map(|r| match r {
        Record::Transitioned(t) if t.proposal == proposal => Some(*t),
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
        "NOTE 13, R-LA-03: the programme manager records the decline"
    );
    assert_eq!(s.state(proposal), Some(StateTag::Declined));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// (a) a holds 4.00 under P-05 = 6.00, so b's room is 2.00. b's plan total
/// 3.00 lies above it, and a determination at 3.00 is refused under I-14.
/// The P-04 minimum 2.00 fits, so no amount failure holds and the decline
/// is refused, although no negotiated plan is recorded yet. The lead then
/// records a negotiated plan of 2.00, R1 deducts 1.00 naming it, and the
/// grant proceeds to GRANTED with a's 4.00 and b's 2.00 at exactly P-05.
fn p04_minimum_fits_the_room(b: Backend) {
    let mut s = story_of(&MoneySetup::sybil([400, 300, 100]), b);
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    let full = determine(R1, PB, amount_decision(PB, 1), plan_of(PB), &[]).unwrap();
    s.refused(&full)
        .unwrap_or_else(|e| panic!("I-14: b's 3.00 on top of a's 4.00 exceeds 6.00: {e}"));
    s.refused(&decline_negotiation(Actor::Account(STAFF_PM), PB))
        .unwrap_or_else(|e| {
            panic!(
                "NOTE 9 (decided 2026-10-26): b's plan 3.00 breaks the cap, but the P-04 \
                 minimum 2.00 fits the room 2.00, so the decline is refused: {e}"
            )
        });
    assert_eq!(s.state(PB), Some(StateTag::Negotiation));
    let (plan, step) = negotiated_plan(LB, PB, 200);
    s.run(&step)
        .unwrap_or_else(|e| panic!("R-NG-03: the lead records a negotiated plan of 2.00: {e}"));
    let cut = determine(R1, PB, amount_decision(PB, 2), plan, &[100]).unwrap();
    s.run(&cut).unwrap_or_else(|e| {
        panic!("R-NG-03, I-13, I-14: R1 deducts 1.00 and reserves 2.00 for b: {e}")
    });
    s.refused(&decline_negotiation(Actor::Account(STAFF_PM), PB))
        .unwrap_or_else(|e| panic!("NOTE 9: b's reservation 2.00 fits, so no failure holds: {e}"));
    s.grant_facts(PB)
        .unwrap_or_else(|e| panic!("b is granted 2.00 on the negotiated plan: {e}"));
    assert_eq!(s.state(PB), Some(StateTag::Granted));
    assert_eq!(s.world.money.counted(PB), 200);
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// (a) for I-13: a's plan total 5.00 lies above the P-04 maximum 4.00, and
/// no negotiated plan is recorded yet. An amount within P-04 can still
/// exist, since the P-04 minimum 2.00 lies below the plan total, so the
/// decline is refused. The lead records a negotiated plan of 4.00, R1
/// deducts 1.00 naming it, and the grant proceeds to GRANTED.
fn plan_total_above_the_p04_maximum(b: Backend) {
    let mut s = story_of(&MoneySetup::sybil([500, 200, 100]), b);
    let full = determine(R1, PA, amount_decision(PA, 1), plan_of(PA), &[]).unwrap();
    s.refused(&full)
        .unwrap_or_else(|e| panic!("I-13: 5.00 lies above the P-04 maximum 4.00: {e}"));
    s.refused(&decline_negotiation(Actor::Account(STAFF_PM), PA))
        .unwrap_or_else(|e| {
            panic!(
                "NOTE 9 (decided 2026-10-26): a smaller negotiated plan within P-04 can still \
                 be proposed, so the decline is refused: {e}"
            )
        });
    let (plan, step) = negotiated_plan(LA, PA, 400);
    s.run(&step)
        .unwrap_or_else(|e| panic!("R-NG-03: the lead records a negotiated plan of 4.00: {e}"));
    let cut = determine(R1, PA, amount_decision(PA, 2), plan, &[100]).unwrap();
    s.run(&cut)
        .unwrap_or_else(|e| panic!("R-NG-03, I-13: R1 deducts 1.00 and reserves 4.00: {e}"));
    s.grant_facts(PA)
        .unwrap_or_else(|e| panic!("a is granted 4.00 on the negotiated plan: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Granted));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// (b) P-05 = 5.00 at publication. a holds 4.00, so b's room is 1.00 and
/// even the P-04 minimum 2.00 does not fit. Only the programme manager
/// records the decline, for no amount within the cap.
fn p04_minimum_above_the_snapshot_room(b: Backend) {
    let mut setup = MoneySetup::sybil([400, 300, 100]);
    setup.p05 = 500;
    let mut s = story_of(&setup, b);
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00 within P-05 5.00: {e}"));
    for actor in [
        Actor::System(SystemCause::Timeline),
        Actor::Account(LB),
        Actor::Account(R1),
        Actor::Account(LC),
    ] {
        s.refused(&decline_negotiation(actor, PB))
            .unwrap_or_else(|e| panic!("NOTE 13: {actor:?} must not record the decline: {e}"));
    }
    let recs = s
        .run(&decline_negotiation(Actor::Account(STAFF_PM), PB))
        .unwrap_or_else(|e| {
            panic!("NOTE 9: the P-04 minimum 2.00 lies above b's room 1.00, so b is declined: {e}")
        });
    declined_for_the_cap(&s, &recs, PB);
}

/// (b) with the live value: P-05 = 6.00 at publication, then lowered to
/// 5.00 while a holds 4.00. The snapshot leaves b a room of 2.00, which
/// the P-04 minimum fits. The live value leaves 1.00, which it does not.
/// The stricter value applies (P-05 NOTE 7), so b is declined.
fn p04_minimum_above_the_live_room(b: Backend) {
    let mut s = story_of(&MoneySetup::sybil([400, 300, 100]), b);
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    s.refused(&decline_negotiation(Actor::Account(STAFF_PM), PB))
        .unwrap_or_else(|e| panic!("NOTE 9: under P-05 6.00 the P-04 minimum fits: {e}"));
    let head = s.world.head.clone().unwrap();
    s.run(&edit_p05(&head, PolicyVersionId::from_raw(903), 500).unwrap())
        .unwrap_or_else(|e| panic!("I-14: P-05 5.00 keeps a's 4.00 within the cap: {e}"));
    let recs = s
        .run(&decline_negotiation(Actor::Account(STAFF_PM), PB))
        .unwrap_or_else(|e| {
            panic!("NOTE 9: under the live P-05 5.00 b's room is 1.00, below the P-04 minimum: {e}")
        });
    declined_for_the_cap(&s, &recs, PB);
}

/// (c) b starts unverified, so the vault groups b alone. a reserves 4.00
/// and b reserves 3.00. The vault then verifies b, which leaves b a room
/// of 2.00 (Identity discovery). While b's amount is open, the P-04
/// minimum fits, so the decline is refused. After b's acceptance and the
/// programme manager's approval the amount 3.00 is locked: a new
/// determination is refused, the contract fact is refused under I-14, and
/// the decline is recorded for no amount within the cap. It releases b's
/// reservation, and a is then granted.
fn locked_amount_decides(b: Backend) {
    let mut setup = MoneySetup::sybil([400, 300, 100]);
    setup.unverified = vec![LB];
    let mut s = story_of(&setup, b);
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    s.determine(PB, 1, &[])
        .unwrap_or_else(|e| panic!("b, unverified and so grouped alone, reserves 3.00: {e}"));
    s.world
        .vault(|t| t.verify(LB))
        .unwrap_or_else(|e| panic!("the vault verifies b: {e}"));
    s.refused(&decline_negotiation(Actor::Account(STAFF_PM), PB))
        .unwrap_or_else(|e| {
            panic!(
                "NOTE 9 (decided 2026-10-26): b's amount is still open and the P-04 minimum \
                 2.00 fits the room 2.00, so the decline is refused: {e}"
            )
        });
    s.run(&accept_grant(LB, PB))
        .unwrap_or_else(|e| panic!("b accepts 3.00: {e}"));
    s.run(&approve_grant(STAFF_PM, PB))
        .unwrap_or_else(|e| panic!("the programme manager approves 3.00: {e}"));
    let again = determine(R1, PB, amount_decision(PB, 2), plan_of(PB), &[]).unwrap();
    s.refused(&again)
        .unwrap_or_else(|e| panic!("R-NG-03: the accepted amount is locked: {e}"));
    s.refused(&contract_effective(PB)).unwrap_or_else(|e| {
        panic!("I-14: a's 4.00 plus b's locked 3.00 exceeds 6.00, so GRANTED is disabled: {e}")
    });
    let recs = s
        .run(&decline_negotiation(Actor::Account(STAFF_PM), PB))
        .unwrap_or_else(|e| {
            panic!("NOTE 9: the locked amount 3.00 lies above b's room 2.00, so b is declined: {e}")
        });
    assert!(
        recs.iter()
            .any(|r| matches!(r, Record::CapReleased { proposal, .. } if *proposal == PB)),
        "the decline releases b's reservation: {recs:?}"
    );
    declined_for_the_cap(&s, &recs, PB);
    s.grant_facts(PA)
        .unwrap_or_else(|e| panic!("a is granted once b's reservation is released: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Granted));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// (b) with a zero P-04 minimum: P-04 = [0.00, 4.00] and P-05 = 4.00. a
/// holds 4.00, so b's room is 0.00. A grant is never zero, since the
/// agreed plan total equals the granted amount and every milestone amount
/// is positive (R-NG-03, design 2.11). So no grant amount within P-04
/// fits, a determination of b is refused under I-14, and the programme
/// manager records the decline for no amount within the cap.
fn zero_p04_minimum_with_no_room_left(b: Backend) {
    let mut setup = MoneySetup::sybil([400, 300, 100]);
    setup.p04 = (0, 400);
    setup.p05 = 400;
    let mut s = story_of(&setup, b);
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00 within P-05 4.00: {e}"));
    let full = determine(R1, PB, amount_decision(PB, 1), plan_of(PB), &[]).unwrap();
    s.refused(&full)
        .unwrap_or_else(|e| panic!("I-14: any amount for b exceeds the room 0.00: {e}"));
    let recs = s
        .run(&decline_negotiation(Actor::Account(STAFF_PM), PB))
        .unwrap_or_else(|e| {
            panic!(
                "NOTE 9: the smallest grant amount 0.01 lies above b's room 0.00, so b is \
                 declined: {e}"
            )
        });
    declined_for_the_cap(&s, &recs, PB);
}

/// NOTE 9, NOTE 13, I-14, R-NG-03: with a zero P-04 minimum the smallest
/// grant amount is one minor unit, so no room left is a decline reason.
#[test]
fn r_ng_decline_when_no_room_is_left_under_a_zero_p04_minimum() {
    zero_p04_minimum_with_no_room_left(Backend::Production);
}

/// NOTE 9, NOTE 13, I-14, R-NG-03: the same story on the references alone.
#[test]
fn r_ng_decline_when_no_room_is_left_under_a_zero_p04_minimum_on_the_reference() {
    zero_p04_minimum_with_no_room_left(Backend::Reference);
}

/// NOTE 9 (decided 2026-10-26), I-14, R-NG-03: a plan total above the room
/// is no decline reason while the P-04 minimum fits. The lead records a
/// smaller negotiated plan and the grant proceeds.
#[test]
fn r_ng_decline_refused_while_the_p04_minimum_fits_the_room() {
    p04_minimum_fits_the_room(Backend::Production);
}

/// NOTE 9 (decided 2026-10-26), I-14, R-NG-03: the same story on the references alone.
#[test]
fn r_ng_decline_refused_while_the_p04_minimum_fits_the_room_on_the_reference() {
    p04_minimum_fits_the_room(Backend::Reference);
}

/// NOTE 9 (decided 2026-10-26), I-13, R-NG-03: a plan total above the P-04
/// maximum is no decline reason while a negotiated plan within P-04 can
/// still be proposed.
#[test]
fn r_ng_decline_refused_for_a_plan_total_above_the_p04_maximum() {
    plan_total_above_the_p04_maximum(Backend::Production);
}

/// NOTE 9 (decided 2026-10-26), I-13, R-NG-03: the same story on the references alone.
#[test]
fn r_ng_decline_refused_for_a_plan_total_above_the_p04_maximum_on_the_reference() {
    plan_total_above_the_p04_maximum(Backend::Reference);
}

/// NOTE 9, NOTE 13, I-14, R-LA-03: the P-04 minimum above the room under
/// the P-05 snapshot is a decline reason, recorded by the programme manager.
#[test]
fn r_ng_decline_when_the_p04_minimum_exceeds_the_snapshot_room() {
    p04_minimum_above_the_snapshot_room(Backend::Production);
}

/// NOTE 9, NOTE 13, I-14, R-LA-03: the same story on the references alone.
#[test]
fn r_ng_decline_when_the_p04_minimum_exceeds_the_snapshot_room_on_the_reference() {
    p04_minimum_above_the_snapshot_room(Backend::Reference);
}

/// NOTE 9, I-14, P-05 NOTE 7: the room reads the stricter of the snapshot
/// and the live P-05.
#[test]
fn r_ng_decline_when_the_p04_minimum_exceeds_the_live_room() {
    p04_minimum_above_the_live_room(Backend::Production);
}

/// NOTE 9, I-14, P-05 NOTE 7: the same story on the references alone.
#[test]
fn r_ng_decline_when_the_p04_minimum_exceeds_the_live_room_on_the_reference() {
    p04_minimum_above_the_live_room(Backend::Reference);
}

/// NOTE 9, I-14, R-NG-03, Identity discovery: after acceptance and
/// approval the locked amount decides the decline.
#[test]
fn r_ng_decline_after_acceptance_and_approval_reads_the_locked_amount() {
    locked_amount_decides(Backend::Production);
}

/// NOTE 9, I-14, R-NG-03, Identity discovery: the same story on the references alone.
#[test]
fn r_ng_decline_after_acceptance_and_approval_reads_the_locked_amount_on_the_reference() {
    locked_amount_decides(Backend::Reference);
}
