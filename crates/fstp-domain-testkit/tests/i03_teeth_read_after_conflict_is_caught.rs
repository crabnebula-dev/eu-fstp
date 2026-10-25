//! I-03 teeth on M-CONFLICT (design 6.1 "Teeth" and 6.2).
//!
//! The fault is a content read recorded for an account that has a
//! declared or detected conflict on the proposal, folded through the
//! public structural `apply`. The `I-03` property must report it. The run
//! checks `always("I-03")` and one witness, and stops once both are
//! decided, because the mutant's state space has no fixed size.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_domain_testkit::mc::conflict_model::{
    ConflictModel, M_CONFLICT_TRUTHFUL_STATES, always_i03, fault_read_after_conflict,
    read_after_clearance, truthful_config,
};
use fstp_mc::{Property, check};

fn caught(backend: Backend) {
    let model = ConflictModel::new(truthful_config(), backend)
        .unwrap_or_else(|e| panic!("M-CONFLICT start from genesis: {e}"));
    let mutant = Injecting::new(&model, fault_read_after_conflict);
    let properties = vec![
        always_i03::<Injecting<'_, ConflictModel, _>>(),
        Property::<Injecting<'_, ConflictModel, _>>::reachable(
            "I-03 witness: content read after a no-conflict declaration",
            read_after_clearance,
        ),
    ];
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(M_CONFLICT_TRUTHFUL_STATES.saturating_mul(4)).with_stop_when_decided(true),
    );
    if let Err(e) = expect_violation(&outcome, "I-03") {
        panic!("{e}");
    }
}

/// I-03: a read after a conflict fact is caught.
#[test]
fn i03_teeth_read_after_conflict_is_caught() {
    caught(Backend::Production);
}

/// I-03: the same fault is caught on the references alone.
#[test]
fn i03_teeth_read_after_conflict_is_caught_on_the_reference() {
    caught(Backend::Reference);
}
