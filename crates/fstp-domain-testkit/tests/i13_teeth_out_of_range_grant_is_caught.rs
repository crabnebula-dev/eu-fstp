//! I-13 teeth on M-MONEY (design 6.1 "Teeth" and 6.2).
//!
//! The fault folds the records a broken engine would emit through the
//! public structural `apply`: a determination of 5.00 for lead b, whose
//! plan totals 3.00, and the grant of that amount, above the P-04 maximum
//! of 4.00. `always("I-13")` must report it. The `_on_the_reference` twin
//! injects the same fault into the reference-only model and must pass now.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::PA;
use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_domain_testkit::mc::money_model::{
    M_MONEY_STATES, McState, MoneyMc, fault_out_of_range, i13, m_money, state_of,
};
use fstp_mc::{Property, check};

fn caught(backend: Backend) {
    let model =
        MoneyMc::new(m_money(), backend).unwrap_or_else(|e| panic!("M-MONEY from genesis: {e}"));
    let mutant = Injecting::new(&model, fault_out_of_range);
    let properties = vec![
        Property::<Injecting<'_, MoneyMc, _>>::always_with("I-13", i13),
        Property::<Injecting<'_, MoneyMc, _>>::reachable(
            "I-13 witness: a granted",
            |s: &McState| state_of(s, PA) == Some(StateTag::Granted),
        ),
    ];
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(M_MONEY_STATES.saturating_mul(4)).with_stop_when_decided(true),
    );
    if let Err(e) = expect_violation(&outcome, "I-13") {
        panic!("{e}");
    }
}

/// I-13: a grant outside P-04 that does not equal the plan total minus deductions is caught.
#[test]
fn i13_teeth_out_of_range_grant_is_caught() {
    caught(Backend::Production);
}

/// I-13: the same fault is caught on the references alone.
#[test]
fn i13_teeth_out_of_range_grant_is_caught_on_the_reference() {
    caught(Backend::Reference);
}
