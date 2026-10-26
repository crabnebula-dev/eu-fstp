//! R-NG-03, I-13, I-14: a negotiated plan carries the recorded deductions, and its total is the granted amount (design 2.8 and 2.11).
//!
//! `SPEC/02-domain/contracts.md`, Amount and recipient cap: the granted
//! amount equals the effective plan total minus recorded deductions, each
//! with a reason, within P-04 inclusive. Design 2.11: the agreed plan total
//! equals the granted amount. A deduction therefore needs a new plan
//! version of origin "negotiated", recorded in NEGOTIATION.
//!
//! Who records what (R-NG-03, `ACTOR_RULES`): the applicant lead proposes
//! the plan content with `RecordPlanVersion`, and an assigned reviewer sets
//! the amount with `DetermineAmount`, naming the negotiated plan as agreed.
//! The negotiated plan supersedes the live plan of the chain. The effective
//! score keeps naming the plan it carried forward (I-09), so the plan total
//! that the deductions reduce stays the effective plan total.
//!
//! The stories start from genesis by production commands, with proposals
//! in NEGOTIATION under P-04 = [2.00, 4.00] and P-05 = 6.00. Leads a and b
//! share one verified identity. Every step is compared with the money
//! reference in both directions. The `_on_the_reference` twin runs the same
//! stories on the references alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::PlanVersionId;
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::record::Record;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    LA, LB, MoneySetup, MoneyStory, PA, PB, PC, accept_grant, amount_decision, approve_grant,
    contract_effective, determine, milestone_n, money_plan, start_execution,
};
use fstp_domain_testkit::r#gen::review::{COORDINATOR, R1, R2, plan_of};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, T0};

/// The negotiated plan of `proposal` with number `n`.
fn negotiated(proposal: fstp_domain::id::ProposalId, n: u128) -> PlanVersionId {
    PlanVersionId::from_raw(
        4_100u128
            .saturating_add(proposal.raw().saturating_mul(10))
            .saturating_add(n),
    )
}

fn story_of(cents: [i64; 3], b: Backend) -> MoneyStory {
    MoneyStory::new(&MoneySetup::sybil(cents), b)
        .unwrap_or_else(|e| panic!("three proposals to NEGOTIATION from genesis: {e}"))
}

/// The lead's negotiated plan `n` of `proposal` with one milestone of
/// `cents`, superseding `supersedes`.
fn negotiated_plan(
    lead: fstp_domain::id::AccountId,
    proposal: fstp_domain::id::ProposalId,
    n: u128,
    supersedes: Option<PlanVersionId>,
    cents: i64,
) -> fstp_domain_testkit::r#gen::roster::Step {
    money_plan(
        lead,
        proposal,
        negotiated(proposal, n),
        PlanOrigin::Negotiated,
        supersedes,
        &[(milestone_n(proposal, 4u128.saturating_add(n)), cents, T0)],
    )
    .unwrap_or_else(|e| panic!("{e}"))
}

/// PA's plan of 5.00 lies above the P-04 maximum 4.00. The lead records a
/// negotiated plan of 4.00, and R1 deducts 1.00 with a reason, naming that
/// plan. The granted amount is 4.00, the agreed plan total, and the
/// contract carries the negotiated plan.
fn a_deduction_with_its_negotiated_plan_is_granted(b: Backend) {
    let mut s = story_of([500, 300, 100], b);
    s.run(&negotiated_plan(LA, PA, 1, Some(plan_of(PA)), 400))
        .unwrap_or_else(|e| panic!("R-NG-03: the lead records a negotiated plan: {e}"));
    assert_eq!(
        s.state(PA),
        Some(StateTag::Negotiation),
        "a negotiated plan leaves the proposal in NEGOTIATION"
    );
    let cut = determine(R1, PA, amount_decision(PA, 1), negotiated(PA, 1), &[100]).unwrap();
    let records = s.run(&cut).unwrap_or_else(|e| {
        panic!("R-NG-03, I-13: 5.00 minus the recorded 1.00 is 4.00, the agreed plan total: {e}")
    });
    let determined = records.iter().any(|r| {
        matches!(r, Record::AmountDetermined { granted, plan_total, agreed, deductions, .. }
            if granted.amount().minor() == 400
                && plan_total.amount().minor() == 500
                && *agreed == negotiated(PA, 1)
                && deductions.len() == 1)
    });
    assert!(
        determined,
        "I-13: the record holds the effective plan total, the deduction, the granted amount and the agreed plan: {records:?}"
    );
    s.run(&accept_grant(LA, PA))
        .unwrap_or_else(|e| panic!("{e}"));
    s.run(&approve_grant(STAFF_PM, PA))
        .unwrap_or_else(|e| panic!("{e}"));
    s.run(&contract_effective(PA))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PA), Some(StateTag::Granted));
    let q = s.world.money.proposals.get(&PA).unwrap();
    assert_eq!(q.granted, Some(400), "I-13: PA is granted 4.00");
    assert_eq!(
        q.effective_plan,
        Some(negotiated(PA, 1)),
        "design 2.11: the contract carries the agreed negotiated plan"
    );
    assert_eq!(s.world.money.counted(PA), 400, "I-14: 4.00 counts");
    s.run(&start_execution(PA))
        .unwrap_or_else(|e| panic!("NOTE 11: execution starts on the negotiated plan: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// The agreed plan's total must equal the granted amount. A negotiated
/// plan of 3.00 on PA's 5.00 is refused with no deduction (5.00) and with
/// one of 1.00 (4.00). Two deductions of 1.00 each make 3.00, which is
/// accepted. The effective plan with a deduction is still refused.
fn the_agreed_total_must_equal_the_granted_amount(b: Backend) {
    let mut s = story_of([500, 300, 100], b);
    s.run(&negotiated_plan(LA, PA, 1, Some(plan_of(PA)), 300))
        .unwrap_or_else(|e| panic!("{e}"));
    for (d, why) in [
        (vec![], "5.00 is not the agreed total 3.00"),
        (vec![100], "4.00 is not the agreed total 3.00"),
    ] {
        let st = determine(R1, PA, amount_decision(PA, 1), negotiated(PA, 1), &d).unwrap();
        s.refused(&st)
            .unwrap_or_else(|e| panic!("I-13, design 2.11: {why}: {e}"));
    }
    let whole = determine(R1, PA, amount_decision(PA, 1), plan_of(PA), &[200]).unwrap();
    s.refused(&whole).unwrap_or_else(|e| {
        panic!("I-13, design 2.11: the effective plan still totals 5.00, not 3.00: {e}")
    });
    let two = determine(
        R1,
        PA,
        amount_decision(PA, 1),
        negotiated(PA, 1),
        &[100, 100],
    )
    .unwrap();
    s.run(&two).unwrap_or_else(|e| {
        panic!("I-13: two recorded deductions of 1.00 make the agreed total 3.00: {e}")
    });
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// The lead records the negotiated plan, in NEGOTIATION only, superseding
/// the live plan. Reviewers, the coordinator and the programme manager do
/// not record plan content. A plan that supersedes nothing breaks the
/// chain. After GRANTED a negotiated plan is refused.
fn the_lead_records_the_negotiated_plan(b: Backend) {
    let mut s = story_of([400, 300, 200], b);
    for outsider in [R1, R2, COORDINATOR, STAFF_PM, LB] {
        s.refused(&negotiated_plan(outsider, PA, 1, Some(plan_of(PA)), 300))
            .unwrap_or_else(|e| {
                panic!("R-NG-03: {outsider:?} does not propose PA's plan content: {e}")
            });
    }
    s.refused(&negotiated_plan(LA, PA, 1, None, 300))
        .unwrap_or_else(|e| panic!("a new plan supersedes the live plan: {e}"));
    s.run(&negotiated_plan(LA, PA, 1, Some(plan_of(PA)), 300))
        .unwrap_or_else(|e| panic!("{e}"));
    s.refused(&negotiated_plan(LA, PA, 2, Some(plan_of(PA)), 200))
        .unwrap_or_else(|e| panic!("the superseded plan is no longer the live plan: {e}"));
    s.run(&negotiated_plan(LA, PA, 2, Some(negotiated(PA, 1)), 200))
        .unwrap_or_else(|e| panic!("a second negotiated plan supersedes the first: {e}"));
    s.grant(PC).unwrap_or_else(|e| panic!("{e}"));
    s.refused(&negotiated_plan(
        fstp_domain_testkit::r#gen::money::LC,
        PC,
        1,
        Some(plan_of(PC)),
        200,
    ))
    .unwrap_or_else(|e| panic!("a negotiated plan needs NEGOTIATION: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// I-14 with a deduction: a holds 4.00 reserved, so b's plan total 3.00
/// breaks the identity's cap of 6.00. A negotiated plan of 2.00 with a
/// recorded deduction of 1.00 makes exactly 6.00.
fn a_deduction_brings_the_sybil_within_the_cap(b: Backend) {
    let mut s = story_of([400, 300, 100], b);
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    let three = determine(R1, PB, amount_decision(PB, 1), plan_of(PB), &[]).unwrap();
    s.refused(&three)
        .unwrap_or_else(|e| panic!("I-14: 4.00 reserved plus 3.00 exceeds 6.00: {e}"));
    s.run(&negotiated_plan(LB, PB, 1, Some(plan_of(PB)), 200))
        .unwrap_or_else(|e| panic!("{e}"));
    let two = determine(R1, PB, amount_decision(PB, 1), negotiated(PB, 1), &[100]).unwrap();
    s.run(&two).unwrap_or_else(|e| {
        panic!("I-14, R-NG-03: 3.00 minus 1.00 is 2.00, which makes exactly P-05: {e}")
    });
    assert_eq!(s.world.money.counted(PB), 200, "I-14: b's 2.00 counts");
    s.grant_facts(PB).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PB), Some(StateTag::Granted));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// R-NG-03, I-13, design 2.11: a recorded deduction with the negotiated
/// plan that carries it is granted, and the contract carries that plan.
#[test]
fn r_ng_03_i13_deduction_with_its_negotiated_plan_is_granted() {
    a_deduction_with_its_negotiated_plan_is_granted(Backend::Production);
}

/// R-NG-03, I-13, design 2.11: an agreed plan whose total differs from the
/// granted amount is refused.
#[test]
fn r_ng_03_i13_agreed_plan_total_must_equal_the_granted_amount() {
    the_agreed_total_must_equal_the_granted_amount(Backend::Production);
}

/// R-NG-03: the applicant lead records the negotiated plan, in NEGOTIATION,
/// superseding the live plan.
#[test]
fn r_ng_03_negotiated_plan_is_recorded_by_the_lead_in_negotiation() {
    the_lead_records_the_negotiated_plan(Backend::Production);
}

/// R-NG-03, I-14: a deduction with its negotiated plan brings a Sybil's
/// amount within the cap of its verified identity.
#[test]
fn r_ng_03_i14_deduction_brings_the_sybil_within_the_cap() {
    a_deduction_brings_the_sybil_within_the_cap(Backend::Production);
}

/// R-NG-03, I-13, I-14: the stories pass on the references alone.
#[test]
fn r_ng_03_i13_negotiated_plan_stories_pass_on_the_reference() {
    a_deduction_with_its_negotiated_plan_is_granted(Backend::Reference);
    the_agreed_total_must_equal_the_granted_amount(Backend::Reference);
    the_lead_records_the_negotiated_plan(Backend::Reference);
    a_deduction_brings_the_sybil_within_the_cap(Backend::Reference);
}
