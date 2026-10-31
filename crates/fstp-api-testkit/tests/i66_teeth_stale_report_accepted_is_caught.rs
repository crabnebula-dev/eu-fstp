//! I-66 teeth on M-ACTIVATE (M4 design sections 8.1 and 8.4).
//!
//! The fault is a creator that approves on the report stored at the
//! request and never recomputes it. Where A2 would be refused for a
//! failure or an unacknowledged warning while a request exists, the fault
//! appends A2's activation at the head. `always("I-66")` must report it.
//! The production twin injects through the public fold of the engine, so
//! it is red until the production adapter can append creator records.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::{
    ActivateConfig, ActivateModel, Backend, REFERENCE_STATES, TRIPWIRE, activation_witness,
    fault_stale_report_accepted, i66_always,
};
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_mc::check;

fn caught(backend: Backend, measured: usize) {
    let model = ActivateModel::new(ActivateConfig { sybil: false }, backend)
        .unwrap_or_else(|e| panic!("M-ACTIVATE start from genesis: {e}"));
    let mutant = Injecting::new(&model, fault_stale_report_accepted);
    let properties = vec![
        i66_always::<Injecting<'_, ActivateModel, _>>(),
        activation_witness::<Injecting<'_, ActivateModel, _>>("I-66 witness: activation"),
    ];
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(measured.saturating_mul(4)).with_stop_when_decided(true),
    );
    if let Err(e) = expect_violation(&outcome, "I-66") {
        panic!("{e}");
    }
}

/// I-66: an approval accepted on a stale report is caught, on production.
#[test]
fn i66_teeth_stale_report_accepted_is_caught() {
    caught(Backend::Production, TRIPWIRE);
}

/// I-66: the same fault is caught on the reference alone.
#[test]
fn i66_teeth_stale_report_accepted_is_caught_on_the_reference() {
    caught(Backend::Reference, REFERENCE_STATES);
}
