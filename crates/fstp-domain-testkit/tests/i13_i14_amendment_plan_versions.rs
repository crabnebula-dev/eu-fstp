//! I-13, I-14, Q18: an amendment is a new plan version on a GRANTED or IN_EXECUTION grant, and the proposal state never changes (design 2.8 and 2.11).
//!
//! `SPEC/02-domain/state-machine.md`, Amendments: an amendment is a new
//! plan version and a new contract version on a GRANTED or IN_EXECUTION
//! proposal. It runs as a separate workflow, and the proposal state does
//! not change. `SPEC/02-domain/contracts.md`, Rules: an amended total counts
//! against P-05. Design 2.11: activation needs the I-13 range on the
//! amended total and the cap on the identity's counted sum with it (I-14).
//!
//! Who records what: the applicant lead records the amendment plan with
//! `RecordPlanVersion` of origin "amendment", superseding the live plan.
//! The lead proposes the amendment, the programme manager routes it under
//! P-14, and the contract port activates it. Here every amendment is routed
//! through a P-14 exemption. The IRC route has its own test
//! (`r_ir_04_amendment_irc_route`).
//!
//! The story starts from genesis by production commands. Leads a and b
//! share one verified identity, P-04 = [2.00, 4.00] and P-05 = 6.00. Every
//! step is compared with the money reference in both directions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::amendment::AmendmentRoute;
use fstp_domain::id::{AccountId, AmendmentId, ContractId, PlanVersionId, ProposalId};
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    LA, LB, LC, MoneySetup, MoneyStory, PA, PB, PC, activate_amendment, milestone_n, money_plan,
    propose_amendment, route_amendment, start_execution, terminate,
};
use fstp_domain_testkit::r#gen::review::{R1, plan_of};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, Step, T0};

/// The `n`-th amendment plan of `proposal`.
fn amended(proposal: ProposalId, n: u128) -> PlanVersionId {
    PlanVersionId::from_raw(
        4_500u128
            .saturating_add(proposal.raw().saturating_mul(10))
            .saturating_add(n),
    )
}

/// The `n`-th amendment of `proposal`.
fn amendment(proposal: ProposalId, n: u128) -> AmendmentId {
    AmendmentId::from_raw(
        600u128
            .saturating_add(proposal.raw().saturating_mul(10))
            .saturating_add(n),
    )
}

/// The contract version that activates amendment `n` of `proposal`.
fn contract(proposal: ProposalId, n: u128) -> ContractId {
    ContractId::from_raw(
        54_100u128
            .saturating_add(proposal.raw().saturating_mul(10))
            .saturating_add(n),
    )
}

/// The amendment plan `n` of `proposal` by `actor`, with one milestone of
/// `cents`, superseding `supersedes`.
fn amendment_plan(
    actor: AccountId,
    proposal: ProposalId,
    n: u128,
    supersedes: Option<PlanVersionId>,
    cents: i64,
) -> Step {
    money_plan(
        actor,
        proposal,
        amended(proposal, n),
        PlanOrigin::Amendment,
        supersedes,
        &[(milestone_n(proposal, 10u128.saturating_add(n)), cents, T0)],
    )
    .unwrap_or_else(|e| panic!("{e}"))
}

/// Records amendment plan `n` of `proposal` by its lead, proposes it and
/// routes it through a P-14 exemption. Returns whether the contract port's
/// activation was accepted.
fn amend(
    s: &mut MoneyStory,
    lead: AccountId,
    proposal: ProposalId,
    n: u128,
    supersedes: PlanVersionId,
    cents: i64,
) -> bool {
    let before = s.state(proposal);
    s.run(&amendment_plan(lead, proposal, n, Some(supersedes), cents))
        .unwrap_or_else(|e| panic!("Q18: the lead records an amendment plan: {e}"));
    assert_eq!(
        s.state(proposal),
        before,
        "Q18: an amendment plan leaves the proposal state unchanged"
    );
    s.run(&propose_amendment(
        lead,
        amendment(proposal, n),
        proposal,
        amended(proposal, n),
    ))
    .unwrap_or_else(|e| panic!("{e}"));
    s.run(&route_amendment(
        STAFF_PM,
        amendment(proposal, n),
        AmendmentRoute::Exempt,
    ))
    .unwrap_or_else(|e| panic!("{e}"));
    let activated = s
        .attempt(&activate_amendment(
            amendment(proposal, n),
            contract(proposal, n),
        ))
        .unwrap_or_else(|e| panic!("{e}"))
        .is_some();
    assert_eq!(
        s.state(proposal),
        before,
        "Q18: an amendment never changes the proposal state"
    );
    activated
}

fn base(b: Backend) -> MoneyStory {
    let mut s = MoneyStory::new(&MoneySetup::sybil([300, 300, 200]), b)
        .unwrap_or_else(|e| panic!("three proposals to NEGOTIATION from genesis: {e}"));
    s.grant(PA)
        .unwrap_or_else(|e| panic!("a granted 3.00: {e}"));
    s.grant(PB)
        .unwrap_or_else(|e| panic!("b granted 3.00: {e}"));
    s
}

/// On GRANTED and then on IN_EXECUTION, each amendment is a new plan
/// version that supersedes the live plan. The amended total counts against
/// P-05 under the lead's verified identity, and the cap refuses an amended
/// total that the identity's other grants leave no room for.
fn amended_totals_count_against_p05(b: Backend) {
    let mut s = base(b);
    assert_eq!(s.state(PA), Some(StateTag::Granted));
    assert!(
        !amend(&mut s, LA, PA, 1, plan_of(PA), 400),
        "I-14: b's 3.00 plus a's amended 4.00 exceeds P-05 6.00"
    );
    assert_eq!(
        s.world.money.counted(PA),
        300,
        "I-14: the refused amendment never counts"
    );
    assert!(
        amend(&mut s, LA, PA, 2, amended(PA, 1), 200),
        "I-14: b's 3.00 plus a's amended 2.00 lies within P-05"
    );
    assert_eq!(
        s.world.money.counted(PA),
        200,
        "contracts.md: the amended total counts"
    );
    s.run(&start_execution(PA))
        .unwrap_or_else(|e| panic!("NOTE 11: execution starts on the amended plan: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::InExecution));
    assert!(
        amend(&mut s, LA, PA, 3, amended(PA, 2), 300),
        "I-14: b's 3.00 plus a's amended 3.00 makes exactly P-05"
    );
    assert_eq!(s.world.money.counted(PA), 300);
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// I-13: the amended total lies within P-04 inclusive, so 5.00 and 1.00
/// are refused at activation and the P-04 maximum 4.00 is accepted once
/// the cap leaves room for it.
fn amended_totals_lie_within_p04(b: Backend) {
    let mut s = base(b);
    s.run(&terminate(STAFF_PM, PB))
        .unwrap_or_else(|e| panic!("b terminated from GRANTED: {e}"));
    assert!(
        !amend(&mut s, LA, PA, 1, plan_of(PA), 500),
        "I-13: 5.00 lies above the P-04 maximum 4.00"
    );
    assert!(
        !amend(&mut s, LA, PA, 2, amended(PA, 1), 100),
        "I-13: 1.00 lies below the P-04 minimum 2.00"
    );
    assert!(
        amend(&mut s, LA, PA, 3, amended(PA, 2), 400),
        "I-13: the P-04 maximum 4.00 is accepted"
    );
    assert_eq!(s.world.money.counted(PA), 400);
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// An amendment plan is the lead's, on a GRANTED or IN_EXECUTION grant,
/// superseding the live plan. It is refused in NEGOTIATION, on a
/// terminated grant, by a reviewer or the programme manager, and without
/// the chain.
fn amendment_plans_need_an_amendable_grant(b: Backend) {
    let mut s = base(b);
    assert_eq!(s.state(PC), Some(StateTag::Negotiation));
    s.refused(&amendment_plan(LC, PC, 1, Some(plan_of(PC)), 200))
        .unwrap_or_else(|e| panic!("Amendments: NEGOTIATION is not amendable: {e}"));
    for outsider in [R1, STAFF_PM, LB] {
        s.refused(&amendment_plan(outsider, PA, 1, Some(plan_of(PA)), 200))
            .unwrap_or_else(|e| panic!("{outsider:?} does not record PA's plan content: {e}"));
    }
    s.refused(&amendment_plan(LA, PA, 1, None, 200))
        .unwrap_or_else(|e| panic!("a new plan supersedes the live plan: {e}"));
    s.run(&terminate(STAFF_PM, PB))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PB), Some(StateTag::Terminated));
    s.refused(&amendment_plan(LB, PB, 1, Some(plan_of(PB)), 200))
        .unwrap_or_else(|e| panic!("Amendments: a terminated grant is not amendable: {e}"));
    s.run(&amendment_plan(LA, PA, 1, Some(plan_of(PA)), 200))
        .unwrap_or_else(|e| panic!("Q18: the lead's amendment plan on GRANTED: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Granted));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// I-14, contracts.md Rules: amended totals count against P-05, and the
/// cap refuses an amended total above the identity's headroom. The
/// proposal state never changes (Q18).
#[test]
fn i14_q18_amended_totals_count_against_p05() {
    amended_totals_count_against_p05(Backend::Production);
}

/// I-13: the amended total lies within P-04 inclusive.
#[test]
fn i13_q18_amended_totals_lie_within_p04() {
    amended_totals_lie_within_p04(Backend::Production);
}

/// Q18, design 2.8: an amendment plan is the lead's new plan version on a
/// GRANTED or IN_EXECUTION grant.
#[test]
fn i13_q18_amendment_plans_need_an_amendable_grant() {
    amendment_plans_need_an_amendable_grant(Backend::Production);
}

/// I-13, I-14, Q18: the amendment stories pass on the references alone.
#[test]
fn i13_i14_amendment_plan_stories_pass_on_the_reference() {
    amended_totals_count_against_p05(Backend::Reference);
    amended_totals_lie_within_p04(Backend::Reference);
    amendment_plans_need_an_amendable_grant(Backend::Reference);
}
