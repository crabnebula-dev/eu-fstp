//! I-67 teeth on M-ACTIVATE for the override of ADR-022 (Daniel,
//! 2026-11-15; M4 design sections 8.1 and 8.4).
//!
//! The fault is a creator that lets the programme manager M1 override:
//! M1 built the draft but is no tenant admin. Where A2's approval would be
//! accepted, so that I-66 holds, the fault appends M1's override with a
//! reason instead. `always("I-67")` must report it, since the amended
//! invariant admits an override by a tenant admin of the builder set only.
//! The production twin injects through the public fold of the engine.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::{
    ActivateConfig, ActivateModel, Backend, REFERENCE_STATES, TRIPWIRE, activation_witness,
    fault_non_admin_override, i67_always,
};
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_mc::check;

fn caught(backend: Backend, measured: usize) {
    let model = ActivateModel::new(ActivateConfig { sybil: false }, backend)
        .unwrap_or_else(|e| panic!("M-ACTIVATE start from genesis: {e}"));
    let mutant = Injecting::new(&model, fault_non_admin_override);
    let properties = vec![
        i67_always::<Injecting<'_, ActivateModel, _>>(),
        activation_witness::<Injecting<'_, ActivateModel, _>>("I-67 witness: activation"),
    ];
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(measured.saturating_mul(4)).with_stop_when_decided(true),
    );
    if let Err(e) = expect_violation(&outcome, "I-67") {
        panic!("{e}");
    }
}

/// I-67, ADR-022: an override by a builder who is no tenant admin is
/// caught, on production.
#[test]
fn i67_teeth_non_admin_override_is_caught() {
    caught(Backend::Production, TRIPWIRE);
}

/// I-67, ADR-022: the same fault is caught on the reference alone.
#[test]
fn i67_teeth_non_admin_override_is_caught_on_the_reference() {
    caught(Backend::Reference, REFERENCE_STATES);
}
