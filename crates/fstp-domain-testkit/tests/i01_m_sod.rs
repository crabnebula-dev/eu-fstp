//! I-01 on M-SOD at P-12 = 0, 1 and 2, and across two programmes (design 6.2 and 6.3).
//!
//! The start state comes from genesis through production commands. The
//! subject c may be a programme manager, a committee member or an IRC
//! member and may draft, with at most two bindings, while staff publish up
//! to three calls. Properties: `always("two-way")`, `always("I-01")`,
//! `transition("SoD-01")`, `transition("SoD-05")`, and witnesses that a
//! former programme manager holds Applicant in the first call after the bar
//! (the P-12 calls after the end are barred), holds a Judging role after
//! the bar, and that a call was published while a binding was held.
//!
//! Each production run is exhaustive under a tripwire at twice the count
//! measured on the reference backend. The `_reference` twins run the same
//! model on the reference alone, which must pass every property.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::sod_model::{
    M_SOD_I01_P12_0_STATES, M_SOD_I01_P12_1_STATES, M_SOD_I01_P12_2_STATES,
    M_SOD_TWO_PROGRAMMES_STATES, SodConfig, SodModel, i01_config, i01_properties,
    two_programmes_config, two_programmes_properties,
};

fn run_i01(config: SodConfig, backend: Backend, measured: usize) {
    let model =
        SodModel::new(config, backend).unwrap_or_else(|e| panic!("M-SOD start from genesis: {e}"));
    let properties = i01_properties::<SodModel>();
    if let Err(e) = check_exhaustive(&model, &properties, measured) {
        panic!("{e}");
    }
}

/// I-01, SoD-01, SoD-05 at P-12 = 0: only the calls published up to the
/// end are barred, so the first call after the end is open.
#[test]
fn i01_m_sod_p12_0() {
    run_i01(i01_config(0), Backend::Production, M_SOD_I01_P12_0_STATES);
}

/// I-01, SoD-01, SoD-05 at P-12 = 1: the first call after the end is
/// barred and the next is open.
#[test]
fn i01_m_sod_p12_1() {
    run_i01(i01_config(1), Backend::Production, M_SOD_I01_P12_1_STATES);
}

/// I-01, SoD-01, SoD-05 at P-12 = 2: the first two calls after the end are
/// barred and the third is open.
#[test]
fn i01_m_sod_p12_2() {
    run_i01(i01_config(2), Backend::Production, M_SOD_I01_P12_2_STATES);
}

/// I-01, R-PC-01: one account in two programmes. A binding in one
/// programme never counts in the other, and roles never bind across them.
#[test]
fn i01_m_sod_two_programmes() {
    let model = SodModel::new(two_programmes_config(), Backend::Production)
        .unwrap_or_else(|e| panic!("M-SOD start from genesis: {e}"));
    let properties = two_programmes_properties::<SodModel>();
    if let Err(e) = check_exhaustive(&model, &properties, M_SOD_TWO_PROGRAMMES_STATES) {
        panic!("{e}");
    }
}

/// I-01: M-SOD at P-12 = 0 passes on the reference alone.
#[test]
fn i01_m_sod_p12_0_reference() {
    run_i01(i01_config(0), Backend::Reference, M_SOD_I01_P12_0_STATES);
}

/// I-01: M-SOD at P-12 = 1 passes on the reference alone.
#[test]
fn i01_m_sod_p12_1_reference() {
    run_i01(i01_config(1), Backend::Reference, M_SOD_I01_P12_1_STATES);
}

/// I-01: M-SOD at P-12 = 2 passes on the reference alone.
#[test]
fn i01_m_sod_p12_2_reference() {
    run_i01(i01_config(2), Backend::Reference, M_SOD_I01_P12_2_STATES);
}

/// I-01: the two-programme instance passes on the reference alone.
#[test]
fn i01_m_sod_two_programmes_reference() {
    let model = SodModel::new(two_programmes_config(), Backend::Reference)
        .unwrap_or_else(|e| panic!("M-SOD start from genesis: {e}"));
    let properties = two_programmes_properties::<SodModel>();
    if let Err(e) = check_exhaustive(&model, &properties, M_SOD_TWO_PROGRAMMES_STATES) {
        panic!("{e}");
    }
}
