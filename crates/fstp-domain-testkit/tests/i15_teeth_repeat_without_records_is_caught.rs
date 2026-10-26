//! I-15 teeth on the repeat model (design 6.1 "Teeth" and 6.2).
//!
//! The fault folds the records a broken engine would emit through the
//! public structural `apply`: a grant to lead b while lead a, of the same
//! verified identity, holds an accepted line without a public deliverable,
//! or a deliverable outside P-26. `always("I-15")` must report it. The
//! `_on_the_reference` twin injects the same fault into the reference-only
//! model and must pass now.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::PB;
use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_domain_testkit::mc::money_model::{
    M_MONEY_REPEAT_STATES, McState, MoneyMc, fault_repeat_without_records, i15, repeat, state_of,
};
use fstp_mc::{Property, check};

fn caught(backend: Backend) {
    let model = MoneyMc::new(repeat(), backend)
        .unwrap_or_else(|e| panic!("repeat model from genesis: {e}"));
    let mutant = Injecting::new(&model, fault_repeat_without_records);
    let properties = vec![
        Property::<Injecting<'_, MoneyMc, _>>::always_with("I-15", i15),
        Property::<Injecting<'_, MoneyMc, _>>::reachable(
            "I-15 witness: b granted",
            |s: &McState| state_of(s, PB) == Some(StateTag::Granted),
        ),
    ];
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(M_MONEY_REPEAT_STATES.saturating_mul(4)).with_stop_when_decided(true),
    );
    if let Err(e) = expect_violation(&outcome, "I-15") {
        panic!("{e}");
    }
}

/// I-15: a repeat grant with an incomplete public deliverable record is caught.
#[test]
fn i15_teeth_repeat_without_records_is_caught() {
    caught(Backend::Production);
}

/// I-15: the same fault is caught on the references alone.
#[test]
fn i15_teeth_repeat_without_records_is_caught_on_the_reference() {
    caught(Backend::Reference);
}
