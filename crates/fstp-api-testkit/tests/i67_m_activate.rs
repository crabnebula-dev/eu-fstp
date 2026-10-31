//! I-67 on M-ACTIVATE (M4 design sections 8.4 and 8.5).
//!
//! Properties: `always("I-67")` and `transition("I-67")`, under which
//! every approver is a tenant admin outside the builder set recomputed
//! from raw records and shares no verified identity with a builder (Q1 A,
//! Q2 B), with `replay(ledger) == state` and two-way agreement. Witnesses
//! without the Sybil pair: activation by a non-builder admin, refusal of
//! an admin who acknowledged a warning, refusal of an admin who granted a
//! draft binding. With the Sybil pair, A2 is M1's person (T-SOD-SYBIL):
//! no activation happens, and A2's refusal is a witness.
//!
//! The production runs are red until lane W2a lands the creator. The
//! `_on_the_reference` twins run the reference alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::{
    ActivateConfig, ActivateModel, Backend, REFERENCE_STATES, REFERENCE_SYBIL_STATES, TRIPWIRE,
    i67_properties, i67_sybil_properties,
};
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_mc::Property;

fn run<'a>(
    sybil: bool,
    backend: Backend,
    measured: usize,
    properties: Vec<Property<'a, ActivateModel>>,
) {
    let model = ActivateModel::new(ActivateConfig { sybil }, backend)
        .unwrap_or_else(|e| panic!("M-ACTIVATE start from genesis: {e}"));
    if let Err(e) = check_exhaustive(&model, &properties, measured) {
        panic!("{e}");
    }
}

fn plain<'a>() -> Vec<Property<'a, ActivateModel>> {
    i67_properties::<ActivateModel>()
}

fn sybil<'a>() -> Vec<Property<'a, ActivateModel>> {
    i67_sybil_properties::<ActivateModel>()
}

/// I-67, R-PG-03: the approver is a second person who did not build the
/// programme, on production.
#[test]
fn i67_m_activate() {
    run(false, Backend::Production, TRIPWIRE, plain());
}

/// I-67: the model passes on the reference alone.
#[test]
fn i67_m_activate_on_the_reference() {
    run(false, Backend::Reference, REFERENCE_STATES, plain());
}

/// I-67, T-SOD-SYBIL: a second account of a builder's person never
/// approves, on production.
#[test]
fn i67_m_activate_with_a_sybil_pair() {
    run(true, Backend::Production, TRIPWIRE, sybil());
}

/// I-67, T-SOD-SYBIL: the Sybil model passes on the reference alone.
#[test]
fn i67_m_activate_with_a_sybil_pair_on_the_reference() {
    run(true, Backend::Reference, REFERENCE_SYBIL_STATES, sybil());
}
