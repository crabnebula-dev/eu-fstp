//! I-65 teeth (M4 design sections 8.1 and 8.4).
//!
//! The fault is an alternative bridge that applies a proposal directly:
//! it saves the proposed value with import provenance and no resolution.
//!
//! - On M-IMPORT, the fault applies the first unresolved proposal whose
//!   value decodes. `always("I-65")` must report it.
//! - On the twin machine, twin B's adapter applies every decodable
//!   proposal right after it is recorded. The run must fail with a
//!   counterexample named by I-65.
//!
//! The production twins inject through the public fold of the engine or
//! through an alternative production adapter, never a production hook.
//! So they are red until the production adapter can append creator
//! records.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::import_model::{
    Backend, Fault, ImportModel, REFERENCE_STATES, TRIPWIRE, TwinMachine, activation_witness,
    fault_auto_applied_proposal, i65_always,
};
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_prop_failure, expect_violation};
use fstp_mc::check;
use fstp_prop::{Config, run_machine};

fn caught_on_the_model(backend: Backend, measured: usize) {
    let model =
        ImportModel::new(backend).unwrap_or_else(|e| panic!("M-IMPORT start from genesis: {e}"));
    let mutant = Injecting::new(&model, fault_auto_applied_proposal);
    let properties = vec![
        i65_always::<Injecting<'_, ImportModel, _>>(),
        activation_witness::<Injecting<'_, ImportModel, _>>("I-65 witness: activation"),
    ];
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(measured.saturating_mul(4)).with_stop_when_decided(true),
    );
    if let Err(e) = expect_violation(&outcome, "I-65") {
        panic!("{e}");
    }
}

fn caught_on_the_twins(backend: Backend, name: &str) {
    let machine = TwinMachine {
        backend,
        fault: Some(Fault::AutoApply),
    };
    let outcome = run_machine(name, Config::default(), &machine);
    if let Err(e) = expect_prop_failure(&outcome, "I-65") {
        panic!("{e}");
    }
}

/// I-65: an auto-applied proposal is caught on M-IMPORT, on production.
#[test]
fn i65_teeth_auto_applied_proposal_is_caught() {
    caught_on_the_model(Backend::Production, TRIPWIRE);
}

/// I-65: the same fault is caught on M-IMPORT on the reference alone.
#[test]
fn i65_teeth_auto_applied_proposal_is_caught_on_the_reference() {
    caught_on_the_model(Backend::Reference, REFERENCE_STATES);
}

/// I-65: an auto-applying adapter is caught by the twin machine, on
/// production.
#[test]
fn i65_teeth_auto_applied_proposal_is_caught_by_the_twins() {
    caught_on_the_twins(
        Backend::Production,
        "i65_teeth_auto_applied_proposal_is_caught_by_the_twins",
    );
}

/// I-65: the same fault is caught by the twin machine on the reference
/// alone.
#[test]
fn i65_teeth_auto_applied_proposal_is_caught_by_the_twins_on_the_reference() {
    caught_on_the_twins(
        Backend::Reference,
        "i65_teeth_auto_applied_proposal_is_caught_by_the_twins_on_the_reference",
    );
}
