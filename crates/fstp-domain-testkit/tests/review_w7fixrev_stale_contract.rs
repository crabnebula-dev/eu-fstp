//! Review reproducer for close-out round 2 (Q-W7-4, decided 2026-10-28).
//!
//! Daniel's answer: a new amount determination clears any contract fact
//! recorded for the earlier amount, so the contract always matches the
//! current amount. NEGOTIATION to GRANTED then needs the contract fact for
//! the current determination. A contract signed for the earlier amount is
//! immutable (`contracts.md` Rules), so its EFFECTIVE fact is never a fact
//! for the new amount.
//!
//! Production clears the fact but forgets which contract it named. A
//! redelivered EFFECTIVE fact for the contract of the earlier amount is
//! then recorded again, and it grants the new amount on the old contract.
//! The contract port of M5 may deliver a fact more than once. Before the
//! new determination such a repeat is refused as a repeated fact.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{PlanVersionId, ProposalId};
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    LA, MoneySetup, MoneyStory, PA, accept_decision_n, accept_grant, accept_grant_as,
    amount_decision, approve_decision, approve_grant_as, contract_effective, determine,
    milestone_n, money_plan,
};
use fstp_domain_testkit::r#gen::review::{R1, plan_of};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, T0};

/// R1 determines a's second amount, 3.00, on a negotiated plan of 3.00
/// with a deduction of 1.00 (R-NG-03, design 2.11).
fn redetermine(s: &mut MoneyStory, proposal: ProposalId) {
    let plan = PlanVersionId::from_raw(4_980u128.saturating_add(proposal.raw()));
    let negotiated = money_plan(
        LA,
        proposal,
        plan,
        PlanOrigin::Negotiated,
        Some(plan_of(proposal)),
        &[(milestone_n(proposal, 64), 300, T0)],
    )
    .unwrap_or_else(|e| panic!("{e}"));
    s.run(&negotiated)
        .unwrap_or_else(|e| panic!("R-NG-03: a records a negotiated plan of 3.00: {e}"));
    let again = determine(R1, proposal, amount_decision(proposal, 2), plan, &[100])
        .unwrap_or_else(|e| panic!("{e}"));
    s.run(&again)
        .unwrap_or_else(|e| panic!("NOTE 9: R1 determines a new amount of 3.00: {e}"));
}

/// R-NG-03, NOTE 9 (Q-W7-4, decided 2026-10-28): after a new amount, a
/// redelivered EFFECTIVE fact for the contract of the superseded amount is
/// refused, so a is never granted 3.00 on the contract signed for 4.00.
#[test]
fn review_w7fixrev_stale_contract_fact_after_new_amount_is_refused() {
    let mut s = MoneyStory::new(&MoneySetup::sybil([400, 200, 100]), Backend::Production)
        .unwrap_or_else(|e| panic!("three proposals to NEGOTIATION from genesis: {e}"));
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    s.run(&contract_effective(PA))
        .unwrap_or_else(|e| panic!("the contract of 4.00 is EFFECTIVE: {e}"));
    s.refused(&contract_effective(PA)).unwrap_or_else(|e| {
        panic!("a repeated contract fact is refused before the new amount: {e}")
    });
    s.run(&accept_grant(LA, PA))
        .unwrap_or_else(|e| panic!("a accepts 4.00: {e}"));
    redetermine(&mut s, PA);
    let second = amount_decision(PA, 2);
    s.run(&accept_grant_as(LA, PA, accept_decision_n(PA, 2), second))
        .unwrap_or_else(|e| panic!("a accepts 3.00: {e}"));
    s.run(&approve_grant_as(
        STAFF_PM,
        PA,
        approve_decision(PA),
        second,
    ))
    .unwrap_or_else(|e| panic!("the programme manager approves 3.00: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Negotiation));
    s.refused(&contract_effective(PA)).unwrap_or_else(|e| {
        panic!(
            "Q-W7-4 (decided 2026-10-28): the port redelivers the EFFECTIVE fact of the \
             contract signed for 4.00, which is not a fact for the current amount of 3.00, \
             yet it is recorded and grants a: {e}"
        )
    });
    assert_eq!(s.state(PA), Some(StateTag::Negotiation));
}
