//! I-23 teeth: a changed past entry is caught (design 6.1 "Teeth" and 6.2).
//!
//! - On M-LEDGER, a fault action runs an honest action, so the ledger
//!   grows and still replays to the state. Its read then shows the latest
//!   earlier score entry under other command bytes, as a store that
//!   rewrote a past entry during an append would. Only the prefix checks
//!   of `transition("I-23")` can report it.
//! - On the ledger machine, every read of the ledger shows entry 1 under
//!   other command bytes, while the ledger kept for the next step stays
//!   the store's own. Only the prefix checks of the invariant can report it.
//! - Over-denial: an M-LEDGER that drops every correction can no longer
//!   reach the witness of a score correction.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{
    Dropping, Injecting, expect_prop_failure, expect_unreachable, expect_violation,
};
use fstp_domain_testkit::mc::ledger_model::{
    LedgerAction, LedgerMachine, LedgerModel, M_LEDGER_STATES, change_past_score,
    m_ledger_properties,
};
use fstp_mc::check;
use fstp_prop::{Config, run_machine};

/// I-23: a past score entry changed during an honest append is caught by
/// the prefix checks of `transition("I-23")` on M-LEDGER.
#[test]
fn i23_teeth_changed_past_entry_is_caught() {
    let model = LedgerModel::new().unwrap_or_else(|e| panic!("{e}"));
    let mutant = Injecting::new(&model, change_past_score);
    let properties = m_ledger_properties::<Injecting<'_, LedgerModel, _>>();
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(M_LEDGER_STATES.saturating_mul(4)),
    );
    if let Err(e) = expect_violation(&outcome, "I-23") {
        panic!("{e}");
    }
}

/// I-23: on the ledger machine over the full engine, a read of the ledger
/// whose first entry changed is caught by the prefix checks of the I-23 invariant.
#[test]
fn i23_teeth_machine_changed_past_entry_is_caught() {
    let machine = LedgerMachine::tampering(16);
    let outcome = run_machine(
        "i23_teeth_machine_changed_past_entry_is_caught",
        Config::default().with_cases(16),
        &machine,
    );
    if let Err(e) = expect_prop_failure(&outcome, "I-23") {
        panic!("{e}");
    }
}

/// I-23: an engine that refuses every correction loses the witness of a
/// score correction, so the witness guards against over-denial.
#[test]
fn i23_teeth_dropped_corrections_hide_the_correction_witness() {
    let model = LedgerModel::new().unwrap_or_else(|e| panic!("{e}"));
    let mutant = Dropping::new(&model, |a: &LedgerAction| {
        matches!(a, LedgerAction::Correct(_))
    });
    let properties = m_ledger_properties::<Dropping<'_, LedgerModel, _>>();
    let outcome = check(&mutant, &properties, &tripwire(M_LEDGER_STATES));
    if let Err(e) = expect_unreachable(&outcome, "I-23 witness: a score correction") {
        panic!("{e}");
    }
}
