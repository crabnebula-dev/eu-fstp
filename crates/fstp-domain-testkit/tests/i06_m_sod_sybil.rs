//! I-06 on M-SOD with identities (design 6.2 and 6.3).
//!
//! Accounts a and b share an identity, and c has another. a may be a
//! committee member or a programme manager; b, unverified at the start, may
//! be a committee member or draft, and the vault may verify it; c may draft.
//! Properties: `always("two-way")`, `always("I-06")`, `transition("SoD-09")`,
//! `always("I-01")`, and witnesses that the Sybil is voided at verification
//! and that a distinct identity applies while a Judging binding is held.
//! The GRANTED half of the second witness needs the lifecycle (W4).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::sod_model::{M_SOD_I06_STATES, SodModel, i06_config, i06_properties};

fn run(backend: Backend) {
    let model = SodModel::new(i06_config(), backend)
        .unwrap_or_else(|e| panic!("M-SOD start from genesis: {e}"));
    let properties = i06_properties::<SodModel>();
    if let Err(e) = check_exhaustive(&model, &properties, M_SOD_I06_STATES) {
        panic!("{e}");
    }
}

/// I-06, SoD-09, T-SOD-SYBIL: a Sybil discovered at verification loses its
/// Receiving binding in the same step, and no grant goes to an unverified account.
#[test]
fn i06_m_sod_sybil() {
    run(Backend::Production);
}

/// I-06: the model passes on the reference alone.
#[test]
fn i06_m_sod_sybil_reference() {
    run(Backend::Reference);
}
