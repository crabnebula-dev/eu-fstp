//! I-04 with SoD-06, machine over Receiving bindings and vault changes (design 6.2).
//!
//! Commands: drafts, team members and guardians, verifications that reveal
//! pending exclusions, new affiliations reported by the vault, and P-13
//! edits that add classes. The excluded applicant comes from the W2 vault
//! fixture `excluded_applicant`. Invariant: no account the vault knows to
//! be in an excluded class of the call's effective P-13 holds a Receiving
//! binding that is not voided (Q5, P-13 NOTE 7). Every vault change and
//! P-13 edit must void exactly the bindings the reference expects, in the
//! same batch. Entry into NEGOTIATION needs the lifecycle and joins in W4.
//!
//! Proposed test-plan row for Daniel (design 6.2, accepted under Q12):
//! "Random Receiving bindings, affiliation changes, verifications and P-13
//! edits never leave an active Receiving binding for an account the vault
//! knows to be excluded."

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::{Backend, SodFocus, SodMachine};
use fstp_prop::{Config, check_machine_with, run_machine};

/// I-04, SoD-06: no excluded account holds a Receiving role in the programme.
#[test]
fn i04_sod06_excluded_account_holds_no_receiving_role() {
    let machine = SodMachine::new(SodFocus::I04);
    check_machine_with(
        "i04_sod06_excluded_account_holds_no_receiving_role",
        Config::default().with_cases(SodFocus::I04.cases),
        &machine,
    );
}

/// I-04: the same machine with the reference as its own engine passes.
#[test]
fn i04_sod06_machine_agrees_with_its_reference() {
    let machine = SodMachine::with_backend(SodFocus::I04, Backend::Reference);
    let outcome = run_machine(
        "i04_sod06_machine_agrees_with_its_reference",
        Config::default().with_cases(SodFocus::I04.cases),
        &machine,
    );
    if let Some(f) = outcome.failure() {
        panic!("the reference-backed machine failed: {}", f.message);
    }
}
