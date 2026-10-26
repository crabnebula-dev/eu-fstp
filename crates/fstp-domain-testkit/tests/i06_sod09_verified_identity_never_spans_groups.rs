//! I-06 with SoD-09, machine over Sybil grants, drafts, verifications and identity merges (design 6.2).
//!
//! The Sybil pair comes from the W2 vault fixture `sybil_pair`. A third,
//! unverified account shares its identity, and the vault verifies it as an
//! environment event, processed in the same step. The vault also merges a
//! subject into another subject's identity, mostly a Drafting holder with
//! a Judging holder, and reinstatements of suspended bindings are drawn.
//! Invariant over the ground truth: for each verified identity, the
//! bindings of its verified accounts that count, with their bars, satisfy
//! the I-01 rule. Voided bindings and conflict-of-interest suspensions do
//! not count (Identity discovery, decided 2026-10-25). Every grant needs a
//! true `IsVerified` (SoD-09). Every vault change must void exactly the
//! Receiving bindings, and suspend exactly the Judging bindings, that the
//! reference expects.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::{Backend, SodFocus, SodMachine};
use fstp_prop::{Config, check_machine_with, run_machine};

/// I-06, SoD-09, TH-03: no two accounts of one verified identity hold
/// bindings that together break I-01, identity merges of Drafting and
/// Judging holders included.
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
