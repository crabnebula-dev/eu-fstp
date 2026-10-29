//! I-14 teeth on the reservation part of M-RACE (design 6.1 "Teeth" and 6.2).
//!
//! The fault folds the records a broken engine would emit through the
//! public structural `apply`: once lead a holds a grant of 4.00, a grant
//! of 4.00 to lead b, who shares a's identity. Both negotiations then pass
//! the cap. The race property `always("I-14 race: never both granted")`
//! of M-RACE must report it, so it cannot pass vacuously. The
//! `_on_the_reference` twin injects the same fault into the reference-only
//! model.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_domain_testkit::mc::money_model::{
    M_RACE_RESERVATION_REFERENCE_STATES, MoneyMc, fault_race_second_grant, race,
    race_never_both_granted,
};
use fstp_mc::{Property, check};

/// The name of `race_never_both_granted` in the M-RACE properties.
const RACE: &str = "I-14 race: never both granted";

fn caught(backend: Backend) {
    let model =
        MoneyMc::new(race(), backend).unwrap_or_else(|e| panic!("M-RACE from genesis: {e}"));
    let mutant = Injecting::new(&model, fault_race_second_grant);
    // The race property as M-RACE runs it.
    let properties = vec![Property::<Injecting<'_, MoneyMc, _>>::always_with(
        RACE,
        race_never_both_granted,
    )];
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(M_RACE_RESERVATION_REFERENCE_STATES.saturating_mul(4))
            .with_stop_when_decided(true),
    );
    if let Err(e) = expect_violation(&outcome, RACE) {
        panic!("{e}");
    }
}

/// I-14: a second grant to the same identity in the reservation race is caught.
#[test]
fn i14_teeth_reservation_race_is_caught() {
    caught(Backend::Production);
}

/// I-14: the same fault is caught on the references alone.
#[test]
fn i14_teeth_reservation_race_is_caught_on_the_reference() {
    caught(Backend::Reference);
}
