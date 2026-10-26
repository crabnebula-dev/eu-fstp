//! I-13 and I-14, machine over random grant sequences (design 6.2).
//!
//! The start state comes from genesis by production commands: four
//! proposals in NEGOTIATION under P-04 = [2.00, 4.00] and P-05 = 6.00,
//! with plans of 5.00, 3.00, 1.00 and 4.00. Leads a, b and the fourth lead
//! share one verified identity, and lead c has another. Commands:
//! amount determinations by assigned and unassigned accounts with
//! deductions, the three grant facts, NEGOTIATION to DECLINED, withdrawal,
//! P-05 edits, execution start and termination. Every command of this lane
//! is compared with the money reference in both directions, and every
//! accepted one must hold the records the reference expects. After every
//! step I-13, I-14, I-15 and I-64 hold on the reference view, with the cap
//! counted per verified identity in plain integer arithmetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::money::{MoneyFocus, MoneyMachine};
use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_prop::{Config, check_machine_with, run_machine};

/// I-13, I-14, R-NG-03: production accepts exactly the grant commands the
/// reference accepts, and no grant or reservation leaves P-04 or the cap.
#[test]
fn i13_i14_grant_sequences_respect_range_and_cap() {
    let machine = MoneyMachine::new(MoneyFocus::GRANTS, Backend::Production);
    check_machine_with(
        "i13_i14_grant_sequences_respect_range_and_cap",
        Config::default().with_cases(64),
        &machine,
    );
}

/// I-13, I-14: the same machine with the reference as its own engine passes.
#[test]
fn i13_i14_grant_machine_agrees_with_its_reference() {
    let machine = MoneyMachine::new(MoneyFocus::GRANTS, Backend::Reference);
    let outcome = run_machine(
        "i13_i14_grant_machine_agrees_with_its_reference",
        Config::default().with_cases(64),
        &machine,
    );
    if let Some(f) = outcome.failure() {
        panic!("the reference-backed machine failed: {}", f.message);
    }
}
