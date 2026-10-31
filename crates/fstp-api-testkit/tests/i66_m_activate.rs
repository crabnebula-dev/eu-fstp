//! I-66 on M-ACTIVATE (M4 design sections 8.4 and 8.5).
//!
//! Properties: `always("I-66")`, under which every `ProgrammeActivated`
//! names a revision whose recomputed report is clean, `transition("I-66")`,
//! `replay(ledger) == state` and two-way agreement with the reference.
//! Witnesses: an activation, a refusal for an unacknowledged warning, a
//! refusal after acknowledgement and a refusal after a probe flip at
//! approval.
//!
//! The production run is red until lane W2a lands the creator: the
//! production adapter's first call reaches a W0 stub that refuses. The
//! `_on_the_reference` twin runs the same model on the reference alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::{
    ActivateConfig, ActivateModel, Backend, REFERENCE_STATES, TRIPWIRE, i66_properties,
};
use fstp_domain_testkit::harness::mc::check_exhaustive;

fn run(backend: Backend, measured: usize) {
    let model = ActivateModel::new(ActivateConfig { sybil: false }, backend)
        .unwrap_or_else(|e| panic!("M-ACTIVATE start from genesis: {e}"));
    let properties = i66_properties::<ActivateModel>();
    if let Err(e) = check_exhaustive(&model, &properties, measured) {
        panic!("{e}");
    }
}

/// I-66, R-PG-03: no activation while the recomputed report shows a
/// failure or a warning without a live acknowledgement, on production.
#[test]
fn i66_m_activate() {
    run(Backend::Production, TRIPWIRE);
}

/// I-66: the model passes on the reference alone.
#[test]
fn i66_m_activate_on_the_reference() {
    run(Backend::Reference, REFERENCE_STATES);
}
