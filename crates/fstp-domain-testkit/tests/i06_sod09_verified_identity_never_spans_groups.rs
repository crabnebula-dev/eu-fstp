//! I-06 with SoD-09, machine over Sybil grants, drafts and verifications (design 6.2).
//!
//! The Sybil pair comes from the W2 vault fixture `sybil_pair`. A third,
//! unverified account shares its identity, and the vault verifies it as an
//! environment event, processed in the same step. Invariant over the
//! ground truth: for each verified identity, the bindings of its verified
//! accounts that are not voided, with their bars, satisfy the I-01 rule.
//! Every grant needs a true `IsVerified` (SoD-09), and every verification
//! must void exactly the Receiving bindings the reference expects.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::{Backend, SodFocus, SodMachine};
use fstp_prop::{Config, check_machine_with, run_machine};

/// I-06, SoD-09, TH-03: no two accounts of one verified identity hold
/// bindings that together break I-01.
#[test]
fn i06_sod09_verified_identity_never_spans_groups() {
    let machine = SodMachine::new(SodFocus::I06);
    check_machine_with(
        "i06_sod09_verified_identity_never_spans_groups",
        Config::default().with_cases(SodFocus::I06.cases),
        &machine,
    );
}

/// I-06: the same machine with the reference as its own engine passes.
#[test]
fn i06_sod09_machine_agrees_with_its_reference() {
    let machine = SodMachine::with_backend(SodFocus::I06, Backend::Reference);
    let outcome = run_machine(
        "i06_sod09_machine_agrees_with_its_reference",
        Config::default().with_cases(SodFocus::I06.cases),
        &machine,
    );
    if let Some(f) = outcome.failure() {
        panic!("the reference-backed machine failed: {}", f.message);
    }
}
