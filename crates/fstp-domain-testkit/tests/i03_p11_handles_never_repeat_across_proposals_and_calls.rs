//! R-AN-01 and P-11 handles, machine over assignment runs across proposals and calls (design 2.7 and 6.2).
//!
//! `SPEC/02-domain/roles-and-sod.md` (Anonymous reviewer handles): with
//! P-11 anonymous each reviewer gets a separate handle per proposal, and
//! handles are never reused across proposals or calls. The machine
//! assigns over four proposals in two calls and draws an issued handle
//! again in a third of its assignments. Every `Assign` is compared with
//! the reference in both directions, and the invariant checks that no
//! handle value appears on two assignments in the cell. The I-03 checks
//! of the review machine run too, since anonymous reviewers still declare.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::review::{RevFocus, ReviewMachine};
use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_prop::{Config, check_machine_with, run_machine};

/// R-AN-01, I-03: no handle value is issued on two assignments across
/// proposals and calls.
#[test]
fn i03_p11_handles_never_repeat_across_proposals_and_calls() {
    let machine = ReviewMachine::new(RevFocus::R_AN_01);
    check_machine_with(
        "i03_p11_handles_never_repeat_across_proposals_and_calls",
        Config::default().with_cases(RevFocus::R_AN_01.cases),
        &machine,
    );
}

/// R-AN-01: the same machine with the references as its own engine passes.
#[test]
fn i03_p11_handles_machine_agrees_with_its_reference() {
    let machine = ReviewMachine::with_backend(RevFocus::R_AN_01, Backend::Reference);
    let outcome = run_machine(
        "i03_p11_handles_machine_agrees_with_its_reference",
        Config::default().with_cases(RevFocus::R_AN_01.cases),
        &machine,
    );
    if let Some(f) = outcome.failure() {
        panic!("the reference-backed machine failed: {}", f.message);
    }
}
