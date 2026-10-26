//! I-61, I-58, I-31: an amendment keeps every claimed milestone under its id, at no less than its paid plus pending amount (step W5 integration, fix round 1).
//!
//! `SPEC/02-domain/contracts.md`, payment invariants: I-58 bounds paid plus
//! pending by the milestone amount, I-59 ties every line to a milestone of
//! the effective contract version, and I-61 says an amendment never sets
//! a milestone amount below its paid plus pending amount. So a milestone
//! keeps its identity across contract versions. An amendment plan may
//! name a milestone of the effective contract version under its id. Every
//! new milestone needs a fresh id.
//!
//! `SPEC/02-domain/state-machine.md`, Amendments: an amendment is a new
//! plan version. Only the latest version of a plan chain counts, so a
//! superseded amendment plan is neither proposed nor activated, and one
//! plan backs at most one amendment.
//!
//! The story starts from genesis by production commands. PA is executing
//! on one milestone M0 of 4.00, P-04 = [2.00, 4.00] and P-05 = 10.00.
//! Every step is compared with the money reference in both directions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::amendment::AmendmentRoute;
use fstp_domain::id::{AmendmentId, ContractId, LineId, MilestoneId, PlanVersionId, RequestId};
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::money::{
    FINREL, LA, MoneySetup, MoneyStory, PA, PB, REL, activate_amendment, milestone_n, money_plan,
    propose_amendment, request_payment, route_amendment,
};
use fstp_domain_testkit::r#gen::review::plan_of;
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, Step, T0};

/// The `n`-th amendment plan of PA.
fn amended(n: u128) -> PlanVersionId {
    PlanVersionId::from_raw(4_700u128.saturating_add(n))
}

/// The `n`-th amendment of PA.
fn amendment(n: u128) -> AmendmentId {
    AmendmentId::from_raw(5_700u128.saturating_add(n))
}

/// The contract version that activates amendment `n` of PA.
fn contract(n: u128) -> ContractId {
    ContractId::from_raw(54_700u128.saturating_add(n))
}

/// PA executing on M0 = 4.00, with 4.00 pending on M0 when `claim` is set.
fn executing(b: Backend, claim: i64) -> MoneyStory {
    let mut setup = MoneySetup::sybil([400, 400, 100]);
    setup.drafts.truncate(2);
    setup.p05 = 1_000;
    setup.staff = vec![
        (FINREL, Role::FinanceApprover),
        (REL, Role::PaymentReleaser),
    ];
    let mut s = MoneyStory::new(&setup, b)
        .unwrap_or_else(|e| panic!("PA and PB to NEGOTIATION from genesis: {e}"));
    s.execute(PA)
        .unwrap_or_else(|e| panic!("PA granted 4.00 and executing: {e}"));
    if claim > 0 {
        s.run(&claim_m0(1, claim))
            .unwrap_or_else(|e| panic!("I-58: the lead claims {claim} of M0's 4.00: {e}"));
    }
    s
}

/// The lead's request `n` for `cents` on M0.
fn claim_m0(n: u128, cents: i64) -> Step {
    request_payment(
        LA,
        RequestId::from_raw(34_700u128.saturating_add(n)),
        PA,
        &[(
            LineId::from_raw(134_700u128.saturating_add(n)),
            milestone_n(PA, 0),
            cents,
        )],
    )
    .unwrap_or_else(|e| panic!("{e}"))
}

/// The lead's amendment plan `n` of PA with `milestones`, superseding
/// `supersedes`.
fn plan(n: u128, supersedes: PlanVersionId, milestones: &[(MilestoneId, i64)]) -> Step {
    let ms: Vec<(MilestoneId, i64, fstp_domain::time::Timestamp)> =
        milestones.iter().map(|(m, c)| (*m, *c, T0)).collect();
    money_plan(
        LA,
        PA,
        amended(n),
        PlanOrigin::Amendment,
        Some(supersedes),
        &ms,
    )
    .unwrap_or_else(|e| panic!("{e}"))
}

/// Proposes amendment `n` of PA on plan `p` and routes it through a P-14
/// exemption.
fn propose_exempt(s: &mut MoneyStory, n: u128, p: PlanVersionId) {
    s.run(&propose_amendment(LA, amendment(n), PA, p))
        .unwrap_or_else(|e| panic!("the lead proposes amendment {n}: {e}"));
    s.run(&route_amendment(
        STAFF_PM,
        amendment(n),
        AmendmentRoute::Exempt,
    ))
    .unwrap_or_else(|e| panic!("P-14: the programme manager routes amendment {n}: {e}"));
}

/// I-61, I-58: with 3.00 pending on M0, an amendment that sets M0 to its
/// 3.00 claim and adds M8 = 1.00 activates. M0 is then fully claimed, so a
/// further claim on it is refused.
fn keeping_a_claimed_milestone_activates(b: Backend) {
    let mut s = executing(b, 300);
    let m0 = milestone_n(PA, 0);
    s.run(&plan(
        1,
        plan_of(PA),
        &[(m0, 300), (milestone_n(PA, 8), 100)],
    ))
    .unwrap_or_else(|e| panic!("I-61: the amendment plan keeps M0 under its id: {e}"));
    propose_exempt(&mut s, 1, amended(1));
    s.run(&activate_amendment(amendment(1), contract(1)))
        .unwrap_or_else(|e| {
            panic!("I-61: M0 keeps its 3.00 claim, so the amendment activates: {e}")
        });
    s.refused(&claim_m0(2, 100))
        .unwrap_or_else(|e| panic!("I-58: M0 carries 3.00 pending of 3.00: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// I-61: an amendment that keeps M0 but sets it to 3.00 below its 4.00
/// pending is refused at activation.
fn lowering_a_claimed_milestone_is_refused(b: Backend) {
    let mut s = executing(b, 400);
    let m0 = milestone_n(PA, 0);
    s.run(&plan(
        1,
        plan_of(PA),
        &[(m0, 300), (milestone_n(PA, 8), 100)],
    ))
    .unwrap_or_else(|e| panic!("{e}"));
    propose_exempt(&mut s, 1, amended(1));
    s.refused(&activate_amendment(amendment(1), contract(1)))
        .unwrap_or_else(|e| panic!("I-61: M0 would fall below its 4.00 pending: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// I-61: an amendment may drop or replace a milestone that carries no
/// claim.
fn dropping_an_unclaimed_milestone_activates(b: Backend) {
    let mut s = executing(b, 0);
    s.run(&plan(1, plan_of(PA), &[(milestone_n(PA, 8), 300)]))
        .unwrap_or_else(|e| panic!("{e}"));
    propose_exempt(&mut s, 1, amended(1));
    s.run(&activate_amendment(amendment(1), contract(1)))
        .unwrap_or_else(|e| panic!("I-61: M0 carries no claim, so it may leave: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// I-59, design 2.8: only a milestone of the grant's effective contract
/// version keeps its id. PB's milestone and a milestone of a superseded
/// amendment plan are refused as reused ids.
fn only_contract_milestones_keep_their_id(b: Backend) {
    let mut s = executing(b, 0);
    s.refused(&plan(1, plan_of(PA), &[(milestone_n(PB, 0), 400)]))
        .unwrap_or_else(|e| panic!("I-59: PB's milestone is not PA's to keep: {e}"));
    let m8 = milestone_n(PA, 8);
    s.run(&plan(1, plan_of(PA), &[(m8, 400)]))
        .unwrap_or_else(|e| panic!("{e}"));
    s.refused(&plan(2, amended(1), &[(m8, 400)]))
        .unwrap_or_else(|e| panic!("M8 never reached the contract, so its id is used: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// Only the latest plan version counts: an amendment whose plan a later
/// plan supersedes is not activated, a superseded plan is not proposed,
/// and one plan backs at most one amendment.
fn only_the_live_amendment_plan_counts(b: Backend) {
    let mut s = executing(b, 0);
    let m0 = milestone_n(PA, 0);
    s.run(&plan(1, plan_of(PA), &[(m0, 300)]))
        .unwrap_or_else(|e| panic!("{e}"));
    propose_exempt(&mut s, 1, amended(1));
    s.refused(&propose_amendment(LA, amendment(2), PA, amended(1)))
        .unwrap_or_else(|e| panic!("amendment 1 already names plan 1: {e}"));
    s.run(&plan(2, amended(1), &[(m0, 200)]))
        .unwrap_or_else(|e| panic!("{e}"));
    s.refused(&propose_amendment(LA, amendment(3), PA, amended(1)))
        .unwrap_or_else(|e| panic!("plan 2 supersedes plan 1: {e}"));
    s.refused(&activate_amendment(amendment(1), contract(1)))
        .unwrap_or_else(|e| panic!("plan 2 supersedes amendment 1's plan: {e}"));
    propose_exempt(&mut s, 2, amended(2));
    s.run(&activate_amendment(amendment(2), contract(2)))
        .unwrap_or_else(|e| panic!("the live plan 2 activates: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// I-61, I-58: keeping a claimed milestone at its claim activates.
#[test]
fn i61_i58_amendment_keeping_a_claimed_milestone_activates() {
    keeping_a_claimed_milestone_activates(Backend::Production);
}

/// I-61: an amendment never sets a milestone below its paid plus pending.
#[test]
fn i61_amendment_lowering_a_claimed_milestone_is_refused() {
    lowering_a_claimed_milestone_is_refused(Backend::Production);
}

/// I-61: an unclaimed milestone may leave the contract.
#[test]
fn i61_amendment_dropping_an_unclaimed_milestone_activates() {
    dropping_an_unclaimed_milestone_activates(Backend::Production);
}

/// I-59: only the effective contract version's milestones keep their id.
#[test]
fn i59_amendment_plan_keeps_only_contract_milestone_ids() {
    only_contract_milestones_keep_their_id(Backend::Production);
}

/// I-13, Amendments: only the live amendment plan is proposed or activated.
#[test]
fn i13_amendment_only_the_live_plan_counts() {
    only_the_live_amendment_plan_counts(Backend::Production);
}

/// I-61, I-58, I-59: the amendment milestone stories pass on the
/// references alone.
#[test]
fn i61_amendment_milestone_stories_pass_on_the_reference() {
    keeping_a_claimed_milestone_activates(Backend::Reference);
    lowering_a_claimed_milestone_is_refused(Backend::Reference);
    dropping_an_unclaimed_milestone_activates(Backend::Reference);
    only_contract_milestones_keep_their_id(Backend::Reference);
    only_the_live_amendment_plan_counts(Backend::Reference);
}
