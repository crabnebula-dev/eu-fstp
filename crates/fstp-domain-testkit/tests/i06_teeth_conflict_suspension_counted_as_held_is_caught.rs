//! I-06 teeth for the conflict-of-interest suspension on M-SOD (design 6.1 "Teeth" and 6.2).
//!
//! Two faults, each of which the `I-06` property must report:
//!
//! - The vault merges c into the identity of a and b while one holds a
//!   Drafting binding and the other a Judging one. A broken reaction
//!   suspends the Judging binding under a rule other than I-06. That is
//!   not the conflict-of-interest marker, so the binding still counts as
//!   held, and I-06 stays broken.
//! - A broken engine reinstates a Judging binding under a
//!   conflict-of-interest suspension while the identity clash lasts.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_domain_testkit::mc::sod_model::{
    M_SOD_I06_STATES, SodMcState, SodModel, fault_conflict_suspension_counted_as_held,
    fault_conflict_suspension_reinstated, i06_config, i06_properties,
};
use fstp_mc::check;

fn caught(backend: Backend, fault: fn(&SodMcState) -> Option<SodMcState>) {
    let model = SodModel::new(i06_config(), backend)
        .unwrap_or_else(|e| panic!("M-SOD start from genesis: {e}"));
    let mutant = Injecting::new(&model, fault);
    let properties = i06_properties::<Injecting<'_, SodModel, _>>();
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(M_SOD_I06_STATES.saturating_mul(2)),
    );
    if let Err(e) = expect_violation(&outcome, "I-06") {
        panic!("{e}");
    }
}

/// I-06: a suspension that still counts as held after a merge is caught.
#[test]
fn i06_teeth_conflict_suspension_counted_as_held_is_caught() {
    caught(
        Backend::Production,
        fault_conflict_suspension_counted_as_held,
    );
}

/// I-06: the same fault is caught on the reference alone.
#[test]
fn i06_teeth_conflict_suspension_counted_as_held_is_caught_on_the_reference() {
    caught(
        Backend::Reference,
        fault_conflict_suspension_counted_as_held,
    );
}

/// I-06: a reinstatement while the identity clash lasts is caught.
#[test]
fn i06_teeth_conflict_suspension_reinstated_during_the_clash_is_caught() {
    caught(Backend::Production, fault_conflict_suspension_reinstated);
}

/// I-06: the same fault is caught on the reference alone.
#[test]
fn i06_teeth_conflict_suspension_reinstated_during_the_clash_is_caught_on_the_reference() {
    caught(Backend::Reference, fault_conflict_suspension_reinstated);
}
