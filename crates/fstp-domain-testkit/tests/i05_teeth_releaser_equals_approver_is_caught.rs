//! I-05 teeth on M-PAY (design 6.1 "Teeth" and 6.2).
//!
//! The fault folds the record a broken engine would emit through the
//! public structural `apply`: a release of the approved request by its
//! finance approver. `always("I-05")` must report it. The
//! `_on_the_reference` twin injects the same fault into the reference-only
//! model and must pass now.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_domain_testkit::mc::pay_model::{
    M_PAY_STATES, PayMc, PayState, fault_releaser_is_approver, i05,
};
use fstp_domain_testkit::reference::payment::RequestState;
use fstp_mc::{Property, check};

fn caught(backend: Backend) {
    let model = PayMc::new(backend).unwrap_or_else(|e| panic!("M-PAY from genesis: {e}"));
    let mutant = Injecting::new(&model, fault_releaser_is_approver);
    let properties = vec![
        Property::<Injecting<'_, PayMc, _>>::always_with("I-05", i05),
        Property::<Injecting<'_, PayMc, _>>::reachable("I-05 witness: paid", |s: &PayState| {
            s.request() == Some(RequestState::Paid)
        }),
    ];
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(M_PAY_STATES.saturating_mul(4)).with_stop_when_decided(true),
    );
    if let Err(e) = expect_violation(&outcome, "I-05") {
        panic!("{e}");
    }
}

/// I-05, SoD-04: a release by the finance approver of the same payment is caught.
#[test]
fn i05_teeth_releaser_equals_approver_is_caught() {
    caught(Backend::Production);
}

/// I-05: the same fault is caught on the references alone.
#[test]
fn i05_teeth_releaser_equals_approver_is_caught_on_the_reference() {
    caught(Backend::Reference);
}
