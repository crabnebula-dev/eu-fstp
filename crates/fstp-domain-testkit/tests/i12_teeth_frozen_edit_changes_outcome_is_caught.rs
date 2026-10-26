//! I-12 teeth for the twin machine (design 6.1 "Teeth" and 6.2 row I-12).
//!
//! A broken engine that computed a stage 1 close from the programme head
//! instead of the call's frozen snapshot would break I-12 by
//! construction point 3 (design 2.4). The faulty machine makes twin B do
//! exactly that. At each stage 1 close after a P-02 edit, it builds the
//! `Stage1Closed` record and the exit transition from the head P-02,
//! and folds them through the public structural `fstp_engine::apply`.
//! No production hook exists. The twin comparison must report the fault
//! under I-12 with a counterexample that fails again on replay.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::twin::TwinMachine;
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_prop::{Config, run_machine};

/// Commands per machine case, as in the twin machine.
const COMMANDS: usize = 120;

/// Cases of the faulty machine. A case catches the fault once twin B
/// edits P-02 before a stage 1 close.
const CASES: u32 = 128;

/// I-12: a stage 1 close of twin B built from the head instead of the
/// snapshot is caught by the twin comparison.
#[test]
fn i12_teeth_frozen_edit_changes_outcome_is_caught() {
    let outcome = run_machine(
        "i12_teeth_frozen_edit_changes_outcome_is_caught",
        Config::default().with_cases(CASES),
        &TwinMachine::head_reading(COMMANDS),
    );
    if let Err(e) = expect_prop_failure(&outcome, "I-12") {
        panic!("{e}");
    }
    let message = outcome
        .failure()
        .map(|f| f.message.clone())
        .unwrap_or_default();
    assert!(
        message.contains("CloseStage1") && message.contains("Stage1Closed"),
        "the counterexample must be the head-read stage 1 close, not another I-12 failure:\n{message}"
    );
}
