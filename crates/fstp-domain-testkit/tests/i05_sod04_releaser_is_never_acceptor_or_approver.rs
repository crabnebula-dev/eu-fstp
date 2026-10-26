//! I-05 with SoD-04 and SoD-12, machine over random payment chains (design 2.12 and 6.2).
//!
//! The start state comes from genesis by production commands: lead c
//! granted 4.00 over two milestones and in execution. R1, R2 and R3 are
//! assigned reviewers. R1 is also a payment releaser, R2 also a finance
//! approver, FINREL both, and REL a payment releaser only. The vault
//! records R3 as the mentor of lead c. Commands: requests of one or two
//! lines, line decisions in full or lower with a reason, requested
//! changes, approvals, releases, confirmations, withdrawals and closures
//! by the programme manager, by random accounts. Every command is
//! compared with the payment reference in both directions. After every
//! step no release was made by a line acceptor or the approver of its
//! request (I-05, SoD-04), and no mentor accepted a line (SoD-12).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::mc::pay_model::PayMachine;
use fstp_prop::{Config, check_machine_with, run_machine};

/// I-05, SoD-04, SoD-12, R-EX-04: the releaser is never an acceptor or the approver.
#[test]
fn i05_sod04_releaser_is_never_acceptor_or_approver() {
    let machine = PayMachine::new(Backend::Production);
    check_machine_with(
        "i05_sod04_releaser_is_never_acceptor_or_approver",
        Config::default().with_cases(64),
        &machine,
    );
}

/// I-05: the same machine with the reference as its own engine passes.
#[test]
fn i05_sod04_machine_agrees_with_its_reference() {
    let machine = PayMachine::new(Backend::Reference);
    let outcome = run_machine(
        "i05_sod04_machine_agrees_with_its_reference",
        Config::default().with_cases(64),
        &machine,
    );
    if let Some(f) = outcome.failure() {
        panic!("the reference-backed machine failed: {}", f.message);
    }
}
