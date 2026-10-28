//! Reproducer for Q-W7-7, answered by Daniel on 2026-10-28 (close-out round 2).
//!
//! `AcceptGrant` and `ApproveGrant` used to carry only their own decision
//! id. One composed against a superseded amount and decided after the new
//! determination counted for the new amount. Daniel's answer: each names
//! the amount determination it accepts, by its decision id, and is refused
//! unless that determination is the current one for the proposal (NOTE 9,
//! R-NG-03).
//!
//! Every story starts from genesis by production commands, with lead a,
//! lead b of the same verified identity, and lead c, under P-04 = [2.00,
//! 4.00] and P-05 = 6.00. Every step is compared with the money reference
//! in both directions. Each `_on_the_reference` twin runs the same story
//! on the references alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{PlanVersionId, ProposalId};
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    LA, MoneySetup, MoneyStory, PA, accept_decision, accept_grant_as, accept_grant_naming,
    amount_decision, approve_decision, approve_grant_as, approve_grant_naming, contract_effective,
    determine, milestone_n, money_plan,
};
use fstp_domain_testkit::r#gen::review::R1;
use fstp_domain_testkit::r#gen::review::plan_of;
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, T0};

fn story(b: Backend) -> MoneyStory {
    MoneyStory::new(&MoneySetup::sybil([400, 200, 100]), b)
        .unwrap_or_else(|e| panic!("three proposals to NEGOTIATION from genesis: {e}"))
}

/// R1 determines a's second amount, 3.00, on a negotiated plan of 3.00
/// with a deduction of 1.00 (R-NG-03, design 2.11).
fn redetermine(s: &mut MoneyStory, proposal: ProposalId) {
    let plan = PlanVersionId::from_raw(4_960u128.saturating_add(proposal.raw()));
    let negotiated = money_plan(
        LA,
        proposal,
        plan,
        PlanOrigin::Negotiated,
        Some(plan_of(proposal)),
        &[(milestone_n(proposal, 62), 300, T0)],
    )
    .unwrap_or_else(|e| panic!("{e}"));
    s.run(&negotiated)
        .unwrap_or_else(|e| panic!("R-NG-03: a records a negotiated plan of 3.00: {e}"));
    let again = determine(R1, proposal, amount_decision(proposal, 2), plan, &[100])
        .unwrap_or_else(|e| panic!("{e}"));
    s.run(&again).unwrap_or_else(|e| {
        panic!("NOTE 9 (decided 2026-10-28): R1 determines a new amount of 3.00: {e}")
    });
}

/// a reserves 4.00 under the first determination. The lead composes an
/// acceptance of it, and the programme manager an approval. R1 then
/// determines 3.00. Both commands arrive after the new determination and
/// name the superseded one, so both are refused. Their decision ids stay
/// unspent. The acceptance and the approval of 3.00 under those ids, and
/// the contract fact, then grant a 3.00.
fn stale_facts(b: Backend) {
    let mut s = story(b);
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    let first = amount_decision(PA, 1);
    let stale_accept = accept_grant_naming(LA, PA, accept_decision(PA), first)
        .unwrap_or_else(|e| panic!("the lead composes an acceptance of 4.00: {e}"));
    let stale_approve = approve_grant_naming(STAFF_PM, PA, approve_decision(PA), first)
        .unwrap_or_else(|e| panic!("the programme manager composes an approval of 4.00: {e}"));
    redetermine(&mut s, PA);
    s.refused(&stale_accept).unwrap_or_else(|e| {
        panic!(
            "Q-W7-7, NOTE 9 (decided 2026-10-28): an acceptance of the superseded 4.00, \
             decided after the new determination, is refused: {e}"
        )
    });
    s.refused(&stale_approve).unwrap_or_else(|e| {
        panic!(
            "Q-W7-7, NOTE 9 (decided 2026-10-28): an approval of the superseded 4.00, decided \
             after the new determination, is refused: {e}"
        )
    });
    assert_eq!(s.state(PA), Some(StateTag::Negotiation));
    let second = amount_decision(PA, 2);
    s.run(&accept_grant_as(LA, PA, accept_decision(PA), second))
        .unwrap_or_else(|e| panic!("a accepts 3.00 under the unspent id: {e}"));
    s.run(&approve_grant_as(
        STAFF_PM,
        PA,
        approve_decision(PA),
        second,
    ))
    .unwrap_or_else(|e| panic!("the programme manager approves 3.00 under the unspent id: {e}"));
    s.run(&contract_effective(PA))
        .unwrap_or_else(|e| panic!("the contract fact grants a: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Granted));
    assert_eq!(
        s.world.money.proposals.get(&PA).and_then(|q| q.granted),
        Some(300),
        "I-13: a is granted the current amount"
    );
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// R-NG-03, NOTE 9 (Q-W7-7, decided 2026-10-28): an acceptance or approval
/// composed against a superseded determination and decided after the new
/// one is refused.
#[test]
fn r_ng_03_acceptance_of_a_superseded_determination_is_refused() {
    stale_facts(Backend::Production);
}

/// R-NG-03, NOTE 9 (Q-W7-7): the same story on the references alone.
#[test]
fn r_ng_03_acceptance_of_a_superseded_determination_is_refused_on_the_reference() {
    stale_facts(Backend::Reference);
}

/// a reserves 4.00 under its only determination. An acceptance and an
/// approval naming a determination never recorded are refused. The ones
/// naming the current determination are accepted.
fn unknown_determination(b: Backend) {
    let mut s = story(b);
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    let never = amount_decision(PA, 7);
    let accept =
        accept_grant_naming(LA, PA, accept_decision(PA), never).unwrap_or_else(|e| panic!("{e}"));
    s.refused(&accept).unwrap_or_else(|e| {
        panic!("Q-W7-7: an acceptance naming a determination never recorded is refused: {e}")
    });
    let approve = approve_grant_naming(STAFF_PM, PA, approve_decision(PA), never)
        .unwrap_or_else(|e| panic!("{e}"));
    s.refused(&approve).unwrap_or_else(|e| {
        panic!("Q-W7-7: an approval naming a determination never recorded is refused: {e}")
    });
    s.grant_facts(PA)
        .unwrap_or_else(|e| panic!("the facts naming the current determination grant a: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Granted));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// R-NG-03, NOTE 9 (Q-W7-7, decided 2026-10-28): an acceptance or approval
/// is refused unless the determination it names is the current one.
#[test]
fn r_ng_03_grant_fact_naming_an_unknown_determination_is_refused() {
    unknown_determination(Backend::Production);
}

/// R-NG-03, NOTE 9 (Q-W7-7): the same story on the references alone.
#[test]
fn r_ng_03_grant_fact_naming_an_unknown_determination_is_refused_on_the_reference() {
    unknown_determination(Backend::Reference);
}

/// R-NG-03 (Q-W7-7, decided 2026-10-28): the grant fact steps of the test
/// kit carry the member `determination` with the id they are given.
#[test]
fn r_ng_03_grant_fact_steps_name_their_determination() {
    let d = amount_decision(PA, 2);
    let a = accept_grant_as(LA, PA, accept_decision(PA), d);
    let p = approve_grant_as(STAFF_PM, PA, approve_decision(PA), d);
    for step in [a, p] {
        assert_eq!(
            fstp_domain_testkit::r#gen::money::named_determination(&step.cmd),
            Some(d),
            "Q-W7-7 (decided 2026-10-28): {:?} names no determination",
            step.cmd
        );
    }
}
