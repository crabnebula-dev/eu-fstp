//! I-14 teeth on M-MONEY (design 6.1 "Teeth" and 6.2).
//!
//! The fault folds the records a broken engine would emit through the
//! public structural `apply`: once lead a holds 4.00, a grant of 3.00 to
//! lead b, who shares a's verified identity, so the identity holds 7.00
//! under P-05 = 6.00. `always("I-14")` must report it. The
//! `_on_the_reference` twin injects the same fault into the reference-only
//! model and must pass now.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::PA;
use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_domain_testkit::mc::money_model::{
    M_MONEY_STATES, McState, MoneyMc, fault_above_cap, i14, m_money, state_of,
};
use fstp_mc::{Property, check};

fn caught(backend: Backend) {
    let model =
        MoneyMc::new(m_money(), backend).unwrap_or_else(|e| panic!("M-MONEY from genesis: {e}"));
    let mutant = Injecting::new(&model, fault_above_cap);
    let properties = vec![
        Property::<Injecting<'_, MoneyMc, _>>::always_with("I-14", i14),
        Property::<Injecting<'_, MoneyMc, _>>::reachable(
            "I-14 witness: a granted",
            |s: &McState| state_of(s, PA) == Some(StateTag::Granted),
        ),
    ];
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(M_MONEY_STATES.saturating_mul(4)).with_stop_when_decided(true),
    );
    if let Err(e) = expect_violation(&outcome, "I-14") {
        panic!("{e}");
    }
}

/// I-14: a Sybil grant that takes the identity above P-05 is caught.
#[test]
fn i14_teeth_grant_above_cap_is_caught() {
    caught(Backend::Production);
}

/// I-14: the same fault is caught on the references alone.
#[test]
fn i14_teeth_grant_above_cap_is_caught_on_the_reference() {
    caught(Backend::Reference);
}
