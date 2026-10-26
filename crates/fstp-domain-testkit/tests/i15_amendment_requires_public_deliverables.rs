//! I-15, R-NG-05: an amendment needs this grant's accepted deliverables public under P-26 (design 6.2, Q8, Q18).
//!
//! Lead a is granted 4.00 from genesis by production commands and starts
//! execution. The property draws the state of a's own deliverables from
//! the five of the test plan, as `i15_repeat_grant_requires_public_deliverables`
//! does. The lead records an amendment plan of 3.00 and proposes it, the
//! programme manager decides that a P-14 exemption applies, and the
//! contract port activates it. An IRC route needs the IRC review of the
//! amendment, which lanes L-REV and L-LIFE record, so it is not drawn. Activation succeeds exactly in the states
//! the reference rule clears. The proposal state never changes (Q18), and
//! the amended total then counts against P-05.
//!
//! Lane L-LIFE refuses plans of origin "amendment" as not implemented
//! (`crates/fstp-domain/src/proposal/intake.rs`), which lies outside lane
//! L-MONEY's files. This test stays red until that refusal is lifted.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::amendment::AmendmentRoute;
use fstp_domain::id::{AmendmentId, ContractId, PlanVersionId};
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    FINREL, LA, MoneySetup, MoneyStory, PA, REL, activate_amendment, milestone_n, money_plan,
    propose_amendment, route_amendment,
};
use fstp_domain_testkit::r#gen::review::plan_of;
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, T0};
use fstp_domain_testkit::vault::PriorDeliverables;
use fstp_prop::{Config, Gen, check_with, run};

const AMENDED: PlanVersionId = PlanVersionId::from_raw(4_011);
const AMENDMENT: AmendmentId = AmendmentId::from_raw(51);

fn base(b: Backend) -> Result<MoneyStory, String> {
    let mut setup = MoneySetup::sybil([400, 400, 100]);
    setup.drafts.truncate(1);
    setup.p05 = 1_000;
    setup.staff = vec![
        (FINREL, fstp_domain::roles::Role::FinanceApprover),
        (REL, fstp_domain::roles::Role::PaymentReleaser),
    ];
    let mut s = MoneyStory::new(&setup, b)?;
    s.execute(PA)?;
    Ok(s)
}

fn record_state(s: &mut MoneyStory, state: PriorDeliverables) -> Result<(), String> {
    use fstp_domain::id::{DeliverableId, LineId, RequestId};
    use fstp_domain_testkit::r#gen::money::{accept_line, record_deliverable, request_payment};
    use fstp_domain_testkit::r#gen::review::R1;
    let r = RequestId::from_raw(34_011);
    let line = LineId::from_raw(134_011);
    let m = milestone_n(PA, 0);
    let d = DeliverableId::from_raw(44_011);
    if state == PriorDeliverables::None {
        return Ok(());
    }
    s.run(&request_payment(LA, r, PA, &[(line, m, 200)])?)?;
    match state {
        PriorDeliverables::None => {}
        PriorDeliverables::PublicUnderP26 => {
            s.run(&accept_line(R1, r, line, 200, false)?)?;
            s.run(&record_deliverable(PA, d, m, "Apache-2.0", true))?;
        }
        PriorDeliverables::PublicUnderOtherLicence => {
            s.run(&accept_line(R1, r, line, 200, false)?)?;
            s.run(&record_deliverable(PA, d, m, "BSD-3-Clause", true))?;
        }
        PriorDeliverables::NotAccepted => {
            s.run(&record_deliverable(PA, d, m, "MIT", false))?;
        }
        PriorDeliverables::SnapshotMissing => {
            s.run(&accept_line(R1, r, line, 200, false)?)?;
        }
    }
    Ok(())
}

fn clears(state: PriorDeliverables) -> bool {
    matches!(
        state,
        PriorDeliverables::None
            | PriorDeliverables::PublicUnderP26
            | PriorDeliverables::NotAccepted
    )
}

fn case(start: &MoneyStory, g: &mut Gen) -> Result<(), String> {
    let mut s = start.clone();
    let state = *g.pick(&PriorDeliverables::ALL);
    let route = AmendmentRoute::Exempt;
    g.note("own deliverables", &state);
    g.note("route", &route);
    record_state(&mut s, state)?;
    s.run(&money_plan(
        LA,
        PA,
        AMENDED,
        PlanOrigin::Amendment,
        Some(plan_of(PA)),
        &[(milestone_n(PA, 7), 300, T0)],
    )?)?;
    s.run(&propose_amendment(LA, AMENDMENT, PA, AMENDED))?;
    s.run(&route_amendment(STAFF_PM, AMENDMENT, route))?;
    let activated = s
        .attempt(&activate_amendment(AMENDMENT, ContractId::from_raw(54_011)))?
        .is_some();
    if activated != clears(state) {
        return Err(format!(
            "I-15: with own deliverables {state:?} the amendment activated: {activated}, the reference rule says {}",
            clears(state)
        ));
    }
    if s.state(PA) != Some(StateTag::InExecution) {
        return Err(format!(
            "Q18: an amendment leaves the proposal state unchanged, PA is in {:?}",
            s.state(PA)
        ));
    }
    if activated && s.world.money.counted(PA) != 300 {
        return Err(format!(
            "I-14: the amended total counts, PA counts {}",
            s.world.money.counted(PA)
        ));
    }
    s.invariants()
}

/// I-15, R-NG-05: an amendment activates exactly when this grant's
/// accepted deliverables are public under its call's P-26.
#[test]
fn i15_amendment_requires_public_deliverables() {
    let start = base(Backend::Production).unwrap_or_else(|e| panic!("base from genesis: {e}"));
    check_with(
        "i15_amendment_requires_public_deliverables",
        Config::default().with_cases(40),
        |g| case(&start, g),
    );
}

/// I-15: the amendment property passes on the references alone.
#[test]
fn i15_amendment_property_passes_on_the_reference() {
    let start = base(Backend::Reference).unwrap_or_else(|e| panic!("base from genesis: {e}"));
    let outcome = run(
        "i15_amendment_property_passes_on_the_reference",
        Config::default().with_cases(40),
        |g| case(&start, g),
    );
    if let Some(f) = outcome.failure() {
        panic!("the reference-backed property failed: {}", f.message);
    }
}
