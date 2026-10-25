//! I-04 on M-EXCL (design 6.2 and 6.3).
//!
//! Two accounts and three classes: x is revealed in K1 on verification, or
//! put in K3 by a new affiliation; y is in K2, which the one P-13 edit adds.
//! Properties: `always("two-way")`, `always("I-04")`, `transition("SoD-06")`,
//! and witnesses: blocked at binding, revealed at verification and voided
//! in the same step, voided at the P-13 edit, voided at a new affiliation,
//! and a team member or guardian voided.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::excl_model::{ExclModel, M_EXCL_STATES, excl_properties};

fn run(backend: Backend) {
    let model =
        ExclModel::new(backend).unwrap_or_else(|e| panic!("M-EXCL start from genesis: {e}"));
    let properties = excl_properties::<ExclModel>();
    if let Err(e) = check_exhaustive(&model, &properties, M_EXCL_STATES) {
        panic!("{e}");
    }
}

/// I-04, SoD-06: excluded accounts are refused at binding, and an exclusion
/// learnt later voids their Receiving bindings in the same step.
#[test]
fn i04_m_excl() {
    run(Backend::Production);
}

/// I-04: M-EXCL passes on the reference alone.
#[test]
fn i04_m_excl_reference() {
    run(Backend::Reference);
}
