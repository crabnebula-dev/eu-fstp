//! I-01 with SoD-01 and SoD-05, machine over random role and draft sequences (design 6.2).
//!
//! Commands: `GrantRole` of every role, `EndRole`, `PublishCall`,
//! `EditPolicy` of P-12, `CreateDraft`, `AddTeamMember`, `AddGuardian` and
//! vault changes. Every command is compared with the independent reference
//! (`reference::sod`) in both directions, and every accepted one must hold
//! the binding, end and bar the reference expects. After every step the
//! ledger extends the previous one and replays to the state (I-23), and the
//! reference view of the ledger satisfies I-01, I-02, I-04 and I-06.
//!
//! Edge bias: P-12 edits draw 0, 1 and 2. Time moves by zero or one
//! microsecond per step, so an end and a publication can share an instant.
//! Calls are published while bindings are held.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::{Backend, SodFocus, SodMachine};
use fstp_prop::{Config, check_machine_with, run_machine};

/// I-01, SoD-01, SoD-05: production accepts exactly the role and draft
/// commands the reference accepts, with the reference's bars, and no
/// account ever holds two of Drafting, Judging and Receiving.
#[test]
fn i01_sod01_sod05_bindings_match_reference() {
    let machine = SodMachine::new(SodFocus::I01);
    check_machine_with(
        "i01_sod01_sod05_bindings_match_reference",
        Config::default().with_cases(SodFocus::I01.cases),
        &machine,
    );
}

/// I-01: the same machine with the reference as its own engine passes.
/// So the generators, expectations and invariants agree with the
/// reference's verdicts, and a failure of the production run is a
/// production defect, not a test defect.
#[test]
fn i01_sod01_sod05_machine_agrees_with_its_reference() {
    let machine = SodMachine::with_backend(SodFocus::I01, Backend::Reference);
    let outcome = run_machine(
        "i01_sod01_sod05_machine_agrees_with_its_reference",
        Config::default().with_cases(SodFocus::I01.cases),
        &machine,
    );
    if let Some(f) = outcome.failure() {
        panic!("the reference-backed machine failed: {}", f.message);
    }
}
