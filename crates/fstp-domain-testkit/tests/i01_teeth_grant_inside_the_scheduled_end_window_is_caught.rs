//! I-01 teeth for scheduled ends on M-SOD (design 6.1 "Teeth"; Cooling-off
//! NOTE, decided 2026-10-25).
//!
//! The fault is a grant recorded between a scheduled instant and its
//! System end. The adapter folds it through the public structural `apply`,
//! and `transition("Cooling-off window")` must report it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_domain_testkit::mc::sod_model::{
    M_SOD_SCHEDULED_STATES, SodModel, fault_grant_inside_the_window, scheduled_config,
    scheduled_properties,
};
use fstp_mc::check;

fn caught(backend: Backend) {
    let model = SodModel::new(scheduled_config(), backend)
        .unwrap_or_else(|e| panic!("M-SOD start from genesis: {e}"));
    let mutant = Injecting::new(&model, fault_grant_inside_the_window);
    let properties = scheduled_properties::<Injecting<'_, SodModel, _>>();
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(M_SOD_SCHEDULED_STATES.saturating_mul(2)),
    );
    if let Err(e) = expect_violation(&outcome, "Cooling-off window") {
        panic!("{e}");
    }
}

/// I-01 (Cooling-off NOTE): a grant recorded between a scheduled instant
/// and its System end is caught.
#[test]
fn i01_teeth_grant_inside_the_scheduled_end_window_is_caught() {
    caught(Backend::Production);
}

/// I-01 (Cooling-off NOTE): the same fault is caught on the reference alone.
#[test]
fn i01_teeth_grant_inside_the_scheduled_end_window_is_caught_on_the_reference() {
    caught(Backend::Reference);
}
