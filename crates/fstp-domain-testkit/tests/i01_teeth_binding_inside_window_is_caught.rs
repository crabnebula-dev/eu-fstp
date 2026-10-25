//! I-01 teeth on M-SOD (design 6.1 "Teeth" and 6.2).
//!
//! The fault is a Receiving binding inside a cooling-off window: a broken
//! engine records a draft of c in a published call whose sequence number
//! is at most the bar of c's ended programme manager binding. The adapter
//! folds it through the public structural `apply`, and the `I-01`
//! property must report it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_domain_testkit::mc::sod_model::{
    M_SOD_I01_P12_1_STATES, SodModel, fault_receiving_inside_window, i01_config, i01_properties,
};
use fstp_mc::check;

fn caught(backend: Backend) {
    let model = SodModel::new(i01_config(1), backend)
        .unwrap_or_else(|e| panic!("M-SOD start from genesis: {e}"));
    let mutant = Injecting::new(&model, fault_receiving_inside_window);
    let properties = i01_properties::<Injecting<'_, SodModel, _>>();
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(M_SOD_I01_P12_1_STATES.saturating_mul(2)),
    );
    if let Err(e) = expect_violation(&outcome, "I-01") {
        panic!("{e}");
    }
}

/// I-01: a Receiving binding inside the window of an ended Drafting binding is caught.
#[test]
fn i01_teeth_binding_inside_window_is_caught() {
    caught(Backend::Production);
}

/// I-01: the same fault is caught on the reference alone, so the property has teeth.
#[test]
fn i01_teeth_binding_inside_window_is_caught_on_the_reference() {
    caught(Backend::Reference);
}
