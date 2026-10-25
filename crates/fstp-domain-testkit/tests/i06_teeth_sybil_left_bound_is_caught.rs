//! I-06 teeth on M-SOD with identities (design 6.1 "Teeth" and 6.2).
//!
//! The fault: the vault verifies b while a holds a committee binding and b
//! an Applicant binding, and a broken reaction records the new epoch
//! without voiding b's binding. The `I-06` property must report it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_domain_testkit::mc::sod_model::{
    M_SOD_I06_STATES, SodModel, fault_sybil_left_bound, i06_config, i06_properties,
};
use fstp_mc::check;

fn caught(backend: Backend) {
    let model = SodModel::new(i06_config(), backend)
        .unwrap_or_else(|e| panic!("M-SOD start from genesis: {e}"));
    let mutant = Injecting::new(&model, fault_sybil_left_bound);
    let properties = i06_properties::<Injecting<'_, SodModel, _>>();
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(M_SOD_I06_STATES.saturating_mul(2)),
    );
    if let Err(e) = expect_violation(&outcome, "I-06") {
        panic!("{e}");
    }
}

/// I-06: a Sybil left bound after its verification is caught.
#[test]
fn i06_teeth_sybil_left_bound_is_caught() {
    caught(Backend::Production);
}

/// I-06: the same fault is caught on the reference alone.
#[test]
fn i06_teeth_sybil_left_bound_is_caught_on_the_reference() {
    caught(Backend::Reference);
}
