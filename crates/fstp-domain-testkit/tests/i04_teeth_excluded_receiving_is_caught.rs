//! I-04 teeth on M-EXCL (design 6.1 "Teeth" and 6.2).
//!
//! The fault: a broken engine adds y to x's proposal as a team member while
//! y is in an excluded class of the call. The `I-04` property must report it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_domain_testkit::mc::excl_model::{
    ExclModel, M_EXCL_STATES, excl_properties, fault_excluded_member,
};
use fstp_mc::check;

fn caught(backend: Backend) {
    let model =
        ExclModel::new(backend).unwrap_or_else(|e| panic!("M-EXCL start from genesis: {e}"));
    let mutant = Injecting::new(&model, fault_excluded_member);
    let properties = excl_properties::<Injecting<'_, ExclModel, _>>();
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(M_EXCL_STATES.saturating_mul(2)),
    );
    if let Err(e) = expect_violation(&outcome, "I-04") {
        panic!("{e}");
    }
}

/// I-04: an excluded account holding a Receiving binding is caught.
#[test]
fn i04_teeth_excluded_receiving_is_caught() {
    caught(Backend::Production);
}

/// I-04: the same fault is caught on the reference alone.
#[test]
fn i04_teeth_excluded_receiving_is_caught_on_the_reference() {
    caught(Backend::Reference);
}
