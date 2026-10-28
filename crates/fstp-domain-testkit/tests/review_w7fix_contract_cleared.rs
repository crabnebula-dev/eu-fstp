//! Reproducer for Q-W7-4, answered by Daniel on 2026-10-28 (close-out round 2).
//!
//! A contract fact recorded before a new amount determination used to keep
//! counting, since NOTE 9 names only acceptance and approval. Daniel's
//! answer: a new amount determination also clears any contract fact
//! recorded for the earlier amount, so the contract always matches the
//! current amount. NEGOTIATION to GRANTED then needs the acceptance, the
//! approval and the contract fact all for the current determination.
//!
//! Every story starts from genesis by production commands, with lead a,
//! lead b of the same verified identity, and lead c, under P-04 = [2.00,
//! 4.00] and P-05 = 6.00. Every step is compared with the money reference
//! in both directions. Each `_on_the_reference` twin runs the same story
//! on the references alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{PlanVersionId, ProposalId};
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::record::Record;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    LA, MoneySetup, MoneyStory, PA, accept_decision, accept_decision_n, accept_grant,
    accept_grant_as, amount_decision, approve_decision, approve_grant, approve_grant_as,
    contract_effective, contract_effective_as, contract_of_n, determine, milestone_n, money_plan,
};
use fstp_domain_testkit::r#gen::review::{R1, plan_of};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, T0};

fn story(b: Backend) -> MoneyStory {
    MoneyStory::new(&MoneySetup::sybil([400, 200, 100]), b)
        .unwrap_or_else(|e| panic!("three proposals to NEGOTIATION from genesis: {e}"))
}

/// R1 determines a's second amount, 3.00, on a negotiated plan of 3.00
/// with a deduction of 1.00 (R-NG-03, design 2.11).
fn redetermine(s: &mut MoneyStory, proposal: ProposalId) {
    let plan = PlanVersionId::from_raw(4_970u128.saturating_add(proposal.raw()));
    let negotiated = money_plan(
        LA,
        proposal,
        plan,
        PlanOrigin::Negotiated,
        Some(plan_of(proposal)),
        &[(milestone_n(proposal, 63), 300, T0)],
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

/// The contract of the grant `proposal` in the batch `recs`, if it grants.
fn granted_contract(recs: &[Record], proposal: ProposalId) -> Option<u128> {
    recs.iter().find_map(|r| match r {
        Record::GrantDecided(g) if g.proposal() == proposal => Some(g.contract().raw()),
        _ => None,
    })
}

/// a reserves 4.00. The contract port reports the contract of 4.00
/// EFFECTIVE, and the lead accepts 4.00. R1 then determines 3.00, which
/// clears the acceptance and the contract fact of 4.00. The lead accepts
/// 3.00 and the programme manager approves 3.00. a stays in NEGOTIATION,
/// since no contract fact for 3.00 exists. The contract port then reports
/// the contract of 3.00 EFFECTIVE, which grants a 3.00 on that contract.
fn contract_then_new_amount(b: Backend) {
    let mut s = story(b);
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    s.run(&contract_effective(PA))
        .unwrap_or_else(|e| panic!("the contract of 4.00 is EFFECTIVE: {e}"));
    s.run(&accept_grant(LA, PA))
        .unwrap_or_else(|e| panic!("a accepts 4.00: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Negotiation));
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
    .unwrap_or_else(|e| {
        panic!(
            "Q-W7-4 (decided 2026-10-28): the approval of 3.00 is recorded, and it does not \
             grant a on the contract fact of 4.00: {e}"
        )
    });
    assert_eq!(
        s.state(PA),
        Some(StateTag::Negotiation),
        "Q-W7-4: the new amount cleared the contract fact of 4.00"
    );
    let contract = contract_of_n(PA, 2);
    let recs = s
        .run(&contract_effective_as(PA, contract))
        .unwrap_or_else(|e| panic!("the contract of 3.00 is EFFECTIVE, which grants a: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Granted));
    assert_eq!(
        s.world.money.proposals.get(&PA).and_then(|q| q.granted),
        Some(300)
    );
    if b == Backend::Production {
        assert_eq!(
            granted_contract(&recs, PA),
            Some(contract.raw()),
            "Q-W7-4: the grant names the contract of the current amount: {recs:?}"
        );
    }
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// R-NG-03, NOTE 9 (Q-W7-4, decided 2026-10-28): a new amount clears the
/// contract fact of the earlier amount, so GRANTED needs a contract fact
/// for the current determination.
#[test]
fn r_ng_03_new_amount_clears_the_contract_fact() {
    contract_then_new_amount(Backend::Production);
}

/// R-NG-03, NOTE 9 (Q-W7-4): the same story on the references alone.
#[test]
fn r_ng_03_new_amount_clears_the_contract_fact_on_the_reference() {
    contract_then_new_amount(Backend::Reference);
}

/// a reserves 4.00. The contract of 4.00 is EFFECTIVE and the programme
/// manager approves 4.00. R1 then determines 3.00. The contract port may
/// report a contract EFFECTIVE again, since the fact of 4.00 was cleared.
/// The approval and the acceptance of 3.00 then grant a.
fn contract_reported_again(b: Backend) {
    let mut s = story(b);
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    s.run(&contract_effective(PA))
        .unwrap_or_else(|e| panic!("the contract of 4.00 is EFFECTIVE: {e}"));
    s.run(&approve_grant(STAFF_PM, PA))
        .unwrap_or_else(|e| panic!("the programme manager approves 4.00: {e}"));
    redetermine(&mut s, PA);
    s.run(&contract_effective_as(PA, contract_of_n(PA, 2)))
        .unwrap_or_else(|e| {
            panic!(
                "Q-W7-4 (decided 2026-10-28): the new amount cleared the contract fact, so the \
                 contract of 3.00 is recorded: {e}"
            )
        });
    assert_eq!(s.state(PA), Some(StateTag::Negotiation));
    let second = amount_decision(PA, 2);
    s.run(&approve_grant_as(
        STAFF_PM,
        PA,
        fstp_domain_testkit::r#gen::money::approve_decision_n(PA, 2),
        second,
    ))
    .unwrap_or_else(|e| panic!("the programme manager approves 3.00: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Negotiation));
    s.run(&accept_grant_as(LA, PA, accept_decision(PA), second))
        .unwrap_or_else(|e| panic!("a accepts 3.00, which completes the facts: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Granted));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// R-NG-03, NOTE 9 (Q-W7-4, decided 2026-10-28): after a new amount the
/// contract port reports the contract of that amount, and it counts.
#[test]
fn r_ng_03_contract_fact_is_given_again_after_a_new_amount() {
    contract_reported_again(Backend::Production);
}

/// R-NG-03, NOTE 9 (Q-W7-4): the same story on the references alone.
#[test]
fn r_ng_03_contract_fact_is_given_again_after_a_new_amount_on_the_reference() {
    contract_reported_again(Backend::Reference);
}

/// a reserves 4.00 and the contract of 4.00 is EFFECTIVE. R1 then
/// determines 3.00, which clears that fact. The lead accepts and the
/// programme manager approves 3.00. The port redelivers the EFFECTIVE fact
/// of the contract of 4.00. It is refused, since a signed version is
/// immutable and that contract matches a superseded amount. The contract
/// of 3.00 then grants a 3.00.
fn superseded_contract_redelivered(b: Backend) {
    let mut s = story(b);
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    s.run(&contract_effective(PA))
        .unwrap_or_else(|e| panic!("the contract of 4.00 is EFFECTIVE: {e}"));
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
    s.refused(&contract_effective(PA)).unwrap_or_else(|e| {
        panic!("Q-W7-4 (decided 2026-10-28): the contract of 4.00 is refused for 3.00: {e}")
    });
    assert_eq!(s.state(PA), Some(StateTag::Negotiation));
    let contract = contract_of_n(PA, 2);
    let recs = s
        .run(&contract_effective_as(PA, contract))
        .unwrap_or_else(|e| panic!("the contract of 3.00 is EFFECTIVE, which grants a: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Granted));
    if b == Backend::Production {
        assert_eq!(granted_contract(&recs, PA), Some(contract.raw()));
    }
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// R-NG-03, NOTE 9 (Q-W7-4, decided 2026-10-28): the redelivered fact of
/// a contract a new amount cleared is refused, and the contract of the
/// current amount still grants.
#[test]
fn r_ng_03_contract_of_a_superseded_amount_is_refused_after_a_new_amount() {
    superseded_contract_redelivered(Backend::Production);
}

/// R-NG-03, NOTE 9 (Q-W7-4): the same story on the references alone.
#[test]
fn r_ng_03_contract_of_a_superseded_amount_is_refused_after_a_new_amount_on_the_reference() {
    superseded_contract_redelivered(Backend::Reference);
}

/// a reserves 4.00 and the contract of 4.00 is EFFECTIVE. R1 then
/// determines 3.00, and the contract of 3.00 is EFFECTIVE. The port then
/// redelivers the fact of the contract of 4.00. It is refused, and the
/// contract of 3.00 stays the recorded one, so the acceptance and the
/// approval of 3.00 grant a on it.
fn superseded_contract_after_the_new_one(b: Backend) {
    let mut s = story(b);
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    s.run(&contract_effective(PA))
        .unwrap_or_else(|e| panic!("the contract of 4.00 is EFFECTIVE: {e}"));
    redetermine(&mut s, PA);
    let contract = contract_of_n(PA, 2);
    s.run(&contract_effective_as(PA, contract))
        .unwrap_or_else(|e| panic!("the contract of 3.00 is EFFECTIVE: {e}"));
    s.refused(&contract_effective(PA)).unwrap_or_else(|e| {
        panic!("Q-W7-4 (decided 2026-10-28): the contract of 4.00 is refused for 3.00: {e}")
    });
    let second = amount_decision(PA, 2);
    s.run(&accept_grant_as(LA, PA, accept_decision_n(PA, 2), second))
        .unwrap_or_else(|e| panic!("a accepts 3.00: {e}"));
    let recs = s
        .run(&approve_grant_as(
            STAFF_PM,
            PA,
            approve_decision(PA),
            second,
        ))
        .unwrap_or_else(|e| panic!("the approval of 3.00 grants a: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Granted));
    if b == Backend::Production {
        assert_eq!(granted_contract(&recs, PA), Some(contract.raw()));
    }
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// R-NG-03, NOTE 9 (Q-W7-4, decided 2026-10-28): a cleared contract
/// redelivered after the contract of the current amount is refused.
#[test]
fn r_ng_03_contract_of_a_superseded_amount_is_refused_after_the_new_contract() {
    superseded_contract_after_the_new_one(Backend::Production);
}

/// R-NG-03, NOTE 9 (Q-W7-4): the same story on the references alone.
#[test]
fn r_ng_03_contract_of_a_superseded_amount_is_refused_after_the_new_contract_on_the_reference() {
    superseded_contract_after_the_new_one(Backend::Reference);
}
