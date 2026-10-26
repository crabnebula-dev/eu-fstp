//! Review reproducers for step W5 integration: spec fidelity of negotiated
//! plans and amendment plans.
//!
//! Each test fails against the current production code and passes once
//! the defect it names is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::amendment::AmendmentRoute;
use fstp_domain::command::Actor;
use fstp_domain::id::{AmendmentId, ContractId, LineId, PlanVersionId, RequestId};
use fstp_domain::proposal::PlanOrigin;
use fstp_domain_testkit::r#gen::money::{
    FINREL, LA, MoneySetup, MoneyStory, PA, REL, activate_amendment, decline_negotiation,
    milestone_n, money_plan, propose_amendment, request_payment, route_amendment,
};
use fstp_domain_testkit::r#gen::review::plan_of;
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, Step, T0};

/// Runs `step` and reports whether production accepted it. A divergence
/// where production refuses and the reference accepts counts as a refusal,
/// so the test stays independent of how the reference is later fixed.
fn production_accepts(s: &mut MoneyStory, step: &Step) -> bool {
    match s.attempt(step) {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) if e.contains("over-denial") => false,
        Err(e) => panic!("harness: {e}"),
    }
}

/// NOTE 9, R-NG-03, I-13: `DeclineNegotiation` for "no grant amount can
/// keep I-13" must look at the negotiated plans the lead recorded, as the
/// `grant::reachable_amounts` doc and the reference both say.
///
/// PA's plan of 5.00 lies above the P-04 maximum 4.00. The lead records a
/// negotiated plan of 4.00, so a determination with a deduction of 1.00
/// reaches 4.00 and the proposal can be granted
/// (`r_ng_03_i13_deduction_with_its_negotiated_plan_is_granted`). The
/// programme manager's decline must then be refused. Production still
/// reads only the effective plan total, finds 5.00 outside P-04 and
/// records DECLINED with `NoAmountWithinRange`.
#[test]
fn review_w5integ_decline_ignores_negotiated_plan_amounts() {
    let mut s = MoneyStory::new(&MoneySetup::sybil([500, 300, 100]), Backend::Production)
        .unwrap_or_else(|e| panic!("three proposals to NEGOTIATION from genesis: {e}"));
    let negotiated = PlanVersionId::from_raw(4_211);
    s.run(
        &money_plan(
            LA,
            PA,
            negotiated,
            PlanOrigin::Negotiated,
            Some(plan_of(PA)),
            &[(milestone_n(PA, 5), 400, T0)],
        )
        .unwrap(),
    )
    .unwrap_or_else(|e| panic!("R-NG-03: the lead records a negotiated plan of 4.00: {e}"));
    s.refused(&decline_negotiation(Actor::Account(STAFF_PM), PA))
        .unwrap_or_else(|e| {
            panic!(
                "NOTE 9: the negotiated plan of 4.00 keeps I-13, so no failure holds and the decline is refused: {e}"
            )
        });
}

/// I-61, I-31, I-58: an amendment plan must not let the grantee claim a
/// milestone twice.
///
/// Plan intake refuses every milestone id already used, so an amendment
/// plan can never keep a milestone of the contract version. PA is
/// executing on one milestone M0 of 4.00, and the lead has 4.00 pending on
/// M0. The amendment plan replaces M0 with a fresh milestone M7 of 4.00.
/// Activation checks only that the grant's total claims stay within the
/// amended total, so it passes. M0 then leaves the effective contract
/// version with 4.00 still claimed, which sets its amount below its paid
/// plus pending amount (I-61). M7 carries no claim, so the lead can claim
/// another 4.00 on it, and 8.00 is claimed under a 4.00 contract (I-31).
///
/// Either the activation or the second request must be refused.
#[test]
fn review_w5integ_amendment_lets_a_milestone_be_claimed_twice() {
    let mut setup = MoneySetup::sybil([400, 400, 100]);
    setup.drafts.truncate(1);
    setup.p05 = 1_000;
    setup.staff = vec![
        (FINREL, fstp_domain::roles::Role::FinanceApprover),
        (REL, fstp_domain::roles::Role::PaymentReleaser),
    ];
    let mut s = MoneyStory::new(&setup, Backend::Production)
        .unwrap_or_else(|e| panic!("PA to NEGOTIATION from genesis: {e}"));
    s.execute(PA)
        .unwrap_or_else(|e| panic!("PA granted 4.00 and executing: {e}"));
    let m0 = milestone_n(PA, 0);
    s.run(
        &request_payment(
            LA,
            RequestId::from_raw(34_211),
            PA,
            &[(LineId::from_raw(134_211), m0, 400)],
        )
        .unwrap(),
    )
    .unwrap_or_else(|e| panic!("the lead claims all 4.00 of M0: {e}"));
    let amended = PlanVersionId::from_raw(4_212);
    let m7 = milestone_n(PA, 7);
    s.run(
        &money_plan(
            LA,
            PA,
            amended,
            PlanOrigin::Amendment,
            Some(plan_of(PA)),
            &[(m7, 400, T0)],
        )
        .unwrap(),
    )
    .unwrap_or_else(|e| panic!("Q18: the lead records an amendment plan: {e}"));
    let amendment = AmendmentId::from_raw(5_211);
    s.run(&propose_amendment(LA, amendment, PA, amended))
        .unwrap_or_else(|e| panic!("{e}"));
    s.run(&route_amendment(
        STAFF_PM,
        amendment,
        AmendmentRoute::Exempt,
    ))
    .unwrap_or_else(|e| panic!("{e}"));
    let activated = production_accepts(
        &mut s,
        &activate_amendment(amendment, ContractId::from_raw(54_211)),
    );
    if !activated {
        return;
    }
    let second = production_accepts(
        &mut s,
        &request_payment(
            LA,
            RequestId::from_raw(34_212),
            PA,
            &[(LineId::from_raw(134_212), m7, 400)],
        )
        .unwrap(),
    );
    assert!(
        !second,
        "I-61, I-31: the amendment dropped M0 with 4.00 claimed, and M7 takes another 4.00, so 8.00 is claimed under a 4.00 contract"
    );
}
