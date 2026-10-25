//! I-03 with R-CF-02, machine over assignments, declarations, reads and vault relations (design 6.2).
//!
//! Commands: `Assign`, `DeclareConflict` on assignments and at proposal
//! level, `ReadContent` by the coordinator, reviewers, the IRC member and
//! the applicant team, `Unassign` and `Withdraw`. Environment: relations
//! and mentoring between Judging and applicant identities, added and
//! removed mid-run, each processed in the same step. Every command is
//! compared with the reference in both directions, and every vault
//! reaction must record the detections and releases the reference
//! expects. Invariant: no read or act record for an account and a
//! proposal follows the first conflict fact for them. No read happens
//! while the vault finds a conflict. Every read by a reviewer or the
//! coordinator follows their no-conflict declaration. Acts of later lanes
//! join this machine with those lanes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::review::{RevFocus, ReviewMachine};
use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_prop::{Config, check_machine_with, run_machine};

/// I-03, R-CF-02: a conflicted person never reads or acts on the proposal.
#[test]
fn i03_rcf02_conflicted_person_cannot_read_or_act() {
    let machine = ReviewMachine::new(RevFocus::I03);
    check_machine_with(
        "i03_rcf02_conflicted_person_cannot_read_or_act",
        Config::default().with_cases(RevFocus::I03.cases),
        &machine,
    );
}

/// I-03: the same machine with the references as its own engine passes.
#[test]
fn i03_rcf02_machine_agrees_with_its_reference() {
    let machine = ReviewMachine::with_backend(RevFocus::I03, Backend::Reference);
    let outcome = run_machine(
        "i03_rcf02_machine_agrees_with_its_reference",
        Config::default().with_cases(RevFocus::I03.cases),
        &machine,
    );
    if let Some(f) = outcome.failure() {
        panic!("the reference-backed machine failed: {}", f.message);
    }
}
