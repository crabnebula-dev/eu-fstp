//! The shell composes `AcceptGrant` and `ApproveGrant` from the current
//! amount determination it reads off production state (R-NG-03, NOTE 9,
//! Q-W7-7, decided 2026-10-28).
//!
//! `MoneyState::determination` returns the decision id of the current
//! determination. The story starts from genesis by production commands
//! and compares every step with the money reference in both directions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{DecisionId, PlanVersionId, ProposalId};
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    LA, MoneySetup, MoneyStory, PA, PB, accept_decision_n, accept_grant_as, amount_decision,
    approve_decision_n, approve_grant_as, contract_effective_as, contract_of_n, determine,
    milestone_n, money_plan,
};
use fstp_domain_testkit::r#gen::review::{R1, plan_of};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, T0};

/// The current determination of `proposal`, read off production state.
fn production_determination(s: &MoneyStory, proposal: ProposalId) -> Option<DecisionId> {
    s.world.life.rev.sod.state.money().determination(proposal)
}

/// R-NG-03, NOTE 9 (Q-W7-7, decided 2026-10-28): production names the
/// current determination of a proposal, a new one replaces it, and the
/// facts composed from it grant the current amount.
#[test]
fn r_ng_03_production_names_the_current_determination() {
    let mut s = MoneyStory::new(&MoneySetup::sybil([400, 200, 100]), Backend::Production)
        .unwrap_or_else(|e| panic!("three proposals to NEGOTIATION from genesis: {e}"));
    assert_eq!(production_determination(&s, PA), None);
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    assert_eq!(
        production_determination(&s, PA),
        Some(amount_decision(PA, 1))
    );
    assert_eq!(production_determination(&s, PB), None);
    let plan = PlanVersionId::from_raw(4_990u128.saturating_add(PA.raw()));
    let negotiated = money_plan(
        LA,
        PA,
        plan,
        PlanOrigin::Negotiated,
        Some(plan_of(PA)),
        &[(milestone_n(PA, 65), 300, T0)],
    )
    .unwrap_or_else(|e| panic!("{e}"));
    s.run(&negotiated)
        .unwrap_or_else(|e| panic!("R-NG-03: a records a negotiated plan of 3.00: {e}"));
    let again =
        determine(R1, PA, amount_decision(PA, 2), plan, &[100]).unwrap_or_else(|e| panic!("{e}"));
    s.run(&again)
        .unwrap_or_else(|e| panic!("NOTE 9: R1 determines a new amount of 3.00: {e}"));
    let current = production_determination(&s, PA)
        .unwrap_or_else(|| panic!("Q-W7-7: production names the current determination"));
    assert_eq!(current, amount_decision(PA, 2));
    s.run(&accept_grant_as(LA, PA, accept_decision_n(PA, 2), current))
        .unwrap_or_else(|e| panic!("a accepts the current amount: {e}"));
    s.run(&approve_grant_as(
        STAFF_PM,
        PA,
        approve_decision_n(PA, 2),
        current,
    ))
    .unwrap_or_else(|e| panic!("the programme manager approves the current amount: {e}"));
    s.run(&contract_effective_as(PA, contract_of_n(PA, 2)))
        .unwrap_or_else(|e| panic!("the contract of 3.00 grants a: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Granted));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}
