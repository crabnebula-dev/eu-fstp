//! R-NG-03, NOTE 9, I-13, I-14: the grant amount is never locked (decided 2026-10-28).
//!
//! `SPEC/02-domain/state-machine.md` NOTE 9: acceptance or approval does
//! not stop the assigned reviewers from determining a new amount. The new
//! amount supersedes the earlier one, and the applicant and programme
//! manager then accept and approve again. The reservation moves to the new
//! amount in the same batch: the old one is released before the new one is
//! reserved, so the two are never counted together (I-14, design 2.11).
//!
//! Every story starts from genesis by production commands, with lead a,
//! lead b of the same verified identity, and lead c, under P-04 = [2.00,
//! 4.00] and P-05 = 6.00. Every step is compared with the money reference
//! in both directions. Each `_on_the_reference` twin runs the same story on
//! the references alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{AccountId, PlanVersionId, ProposalId};
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::record::Record;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    LA, LB, MoneySetup, MoneyStory, PA, PB, accept_decision, accept_decision_n, accept_grant,
    accept_grant_as, amount_decision, approve_decision, approve_decision_n, approve_grant,
    approve_grant_as, contract_effective, determine, milestone_n, money_plan,
};
use fstp_domain_testkit::r#gen::review::{R1, plan_of};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, Step, T0};

fn story_of(setup: &MoneySetup, b: Backend) -> MoneyStory {
    MoneyStory::new(setup, b)
        .unwrap_or_else(|e| panic!("three proposals to NEGOTIATION from genesis: {e}"))
}

/// The lead's negotiated plan of `proposal` with one milestone of `cents`,
/// superseding the submitted plan.
fn negotiated_plan(lead: AccountId, proposal: ProposalId, cents: i64) -> (PlanVersionId, Step) {
    let plan = PlanVersionId::from_raw(4_950u128.saturating_add(proposal.raw()));
    let step = money_plan(
        lead,
        proposal,
        plan,
        PlanOrigin::Negotiated,
        Some(plan_of(proposal)),
        &[(milestone_n(proposal, 61), cents, T0)],
    )
    .unwrap_or_else(|e| panic!("{e}"));
    (plan, step)
}

/// The positions of the release and the reservation of `proposal` in `recs`.
fn moved(recs: &[Record], proposal: ProposalId) -> (Option<usize>, Option<usize>) {
    let released = recs
        .iter()
        .position(|r| matches!(r, Record::CapReleased { proposal: p, .. } if *p == proposal));
    let reserved = recs
        .iter()
        .position(|r| matches!(r, Record::CapReserved { proposal: p, .. } if *p == proposal));
    (released, reserved)
}

/// a reserves 4.00, and the lead and the programme manager accept and
/// approve it. R1 then determines 3.00 on a negotiated plan of 3.00 with
/// a deduction of 1.00. The batch releases 4.00 before it reserves 3.00,
/// and only 3.00 counts. The contract fact does not grant a, since the
/// acceptance and the approval of 4.00 no longer count. Once both are
/// given again, a is granted 3.00.
fn supersede(b: Backend) {
    let mut s = story_of(&MoneySetup::sybil([400, 200, 100]), b);
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    s.run(&accept_grant(LA, PA))
        .unwrap_or_else(|e| panic!("a accepts 4.00: {e}"));
    s.run(&approve_grant(STAFF_PM, PA))
        .unwrap_or_else(|e| panic!("the programme manager approves 4.00: {e}"));
    let (plan, step) = negotiated_plan(LA, PA, 300);
    s.run(&step)
        .unwrap_or_else(|e| panic!("R-NG-03: a records a negotiated plan of 3.00: {e}"));
    let again = determine(R1, PA, amount_decision(PA, 2), plan, &[100]).unwrap();
    let recs = s.run(&again).unwrap_or_else(|e| {
        panic!("NOTE 9 (decided 2026-10-28): R1 determines 3.00 after acceptance and approval: {e}")
    });
    match moved(&recs, PA) {
        (Some(x), Some(y)) => assert!(x < y, "I-14: release before reserve: {recs:?}"),
        _ => panic!("I-14: the batch moves a's reservation to 3.00: {recs:?}"),
    }
    assert_eq!(s.world.money.counted(PA), 300, "I-14: only 3.00 counts");
    s.run(&contract_effective(PA))
        .unwrap_or_else(|e| panic!("the contract fact is recorded: {e}"));
    assert_eq!(
        s.state(PA),
        Some(StateTag::Negotiation),
        "NOTE 9: the acceptance and the approval of 4.00 no longer count"
    );
    s.run(&accept_grant_as(
        LA,
        PA,
        accept_decision_n(PA, 2),
        amount_decision(PA, 2),
    ))
    .unwrap_or_else(|e| panic!("a accepts 3.00: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Negotiation));
    s.run(&approve_grant_as(
        STAFF_PM,
        PA,
        approve_decision_n(PA, 2),
        amount_decision(PA, 2),
    ))
    .unwrap_or_else(|e| panic!("the programme manager approves 3.00: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Granted));
    assert_eq!(
        s.world.money.proposals.get(&PA).and_then(|q| q.granted),
        Some(300)
    );
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// R-NG-03, NOTE 9, I-14: a new amount after acceptance and approval
/// supersedes the old one and moves the reservation in the same batch.
#[test]
fn r_ng_03_new_amount_after_acceptance_and_approval_supersedes_the_old_one() {
    supersede(Backend::Production);
}

/// R-NG-03, NOTE 9, I-14: the same story on the references alone.
#[test]
fn r_ng_03_new_amount_after_acceptance_and_approval_supersedes_the_old_one_on_the_reference() {
    supersede(Backend::Reference);
}

/// a reserves 4.00 and b reserves 2.00, so the pair holds exactly P-05.
/// b accepts 2.00. R1 then determines b's full plan of 3.00, which does not
/// fit the room 2.00, so it is refused under I-14. A refused determination
/// changes nothing: b's acceptance of 2.00 still counts, and the approval
/// and the contract fact grant b 2.00.
fn refused_new_amount(b: Backend) {
    let mut s = story_of(&MoneySetup::sybil([400, 300, 100]), b);
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    let (plan, step) = negotiated_plan(LB, PB, 200);
    s.run(&step)
        .unwrap_or_else(|e| panic!("b records a negotiated plan of 2.00: {e}"));
    let first = determine(R1, PB, amount_decision(PB, 1), plan, &[100]).unwrap();
    s.run(&first)
        .unwrap_or_else(|e| panic!("R1 reserves 2.00 for b: {e}"));
    s.run(&accept_grant(LB, PB))
        .unwrap_or_else(|e| panic!("b accepts 2.00: {e}"));
    let full = determine(R1, PB, amount_decision(PB, 2), plan_of(PB), &[]).unwrap();
    s.refused(&full).unwrap_or_else(|e| {
        panic!("I-14: b's 3.00 beside a's 4.00 exceeds 6.00, so the new amount is refused: {e}")
    });
    assert_eq!(s.world.money.counted(PB), 200);
    s.run(&approve_grant(STAFF_PM, PB))
        .unwrap_or_else(|e| panic!("the programme manager approves 2.00: {e}"));
    s.run(&contract_effective(PB))
        .unwrap_or_else(|e| panic!("the contract fact completes the facts for 2.00: {e}"));
    assert_eq!(s.state(PB), Some(StateTag::Granted));
    assert_eq!(
        s.world.money.proposals.get(&PB).and_then(|q| q.granted),
        Some(200)
    );
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// R-NG-03, NOTE 9, I-14: a refused new amount leaves the accepted amount
/// and its acceptance in place.
#[test]
fn r_ng_03_refused_new_amount_keeps_the_accepted_amount() {
    refused_new_amount(Backend::Production);
}

/// R-NG-03, NOTE 9, I-14: the same story on the references alone.
#[test]
fn r_ng_03_refused_new_amount_keeps_the_accepted_amount_on_the_reference() {
    refused_new_amount(Backend::Reference);
}

/// a reserves 4.00 and accepts it. R1 determines 4.00 again on the same
/// plan, under a new decision. The new determination supersedes the old
/// one, so the acceptance is given again, under a fresh decision id. The
/// old id is spent, so an acceptance under it is refused.
fn reacceptance_needs_a_fresh_id(b: Backend) {
    let mut s = story_of(&MoneySetup::sybil([400, 200, 100]), b);
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    s.run(&accept_grant(LA, PA))
        .unwrap_or_else(|e| panic!("a accepts 4.00: {e}"));
    let again = determine(R1, PA, amount_decision(PA, 2), plan_of(PA), &[]).unwrap();
    let recs = s.run(&again).unwrap_or_else(|e| {
        panic!("NOTE 9 (decided 2026-10-28): a new determination after acceptance: {e}")
    });
    match moved(&recs, PA) {
        (Some(x), Some(y)) => assert!(x < y, "I-14: release before reserve: {recs:?}"),
        _ => panic!("I-14: the batch moves a's reservation: {recs:?}"),
    }
    assert_eq!(s.world.money.counted(PA), 400, "I-14: 4.00 counts once");
    let reused = accept_grant_as(LA, PA, accept_decision(PA), amount_decision(PA, 2));
    s.refused(&reused)
        .unwrap_or_else(|e| panic!("the spent acceptance id is refused: {e}"));
    s.run(&accept_grant_as(
        LA,
        PA,
        accept_decision_n(PA, 2),
        amount_decision(PA, 2),
    ))
    .unwrap_or_else(|e| panic!("NOTE 9: a accepts the new determination: {e}"));
    // Q-W7-7 (decided 2026-10-28): the approval names the current
    // determination.
    s.run(&approve_grant_as(
        STAFF_PM,
        PA,
        approve_decision(PA),
        amount_decision(PA, 2),
    ))
    .unwrap_or_else(|e| panic!("the programme manager approves: {e}"));
    s.run(&contract_effective(PA))
        .unwrap_or_else(|e| panic!("the contract fact grants a: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Granted));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// R-NG-03, NOTE 9: a new determination needs a new acceptance under a
/// fresh decision id.
#[test]
fn r_ng_03_new_determination_needs_a_new_acceptance() {
    reacceptance_needs_a_fresh_id(Backend::Production);
}

/// R-NG-03, NOTE 9: the same story on the references alone.
#[test]
fn r_ng_03_new_determination_needs_a_new_acceptance_on_the_reference() {
    reacceptance_needs_a_fresh_id(Backend::Reference);
}
