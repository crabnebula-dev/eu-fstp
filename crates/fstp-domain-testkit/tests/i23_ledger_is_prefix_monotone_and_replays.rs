//! I-23 over the full engine: the machine of design 6.2 and its non-vacuity witness.
//!
//! The machine drives the reference driver over a `MemStore` from genesis.
//! Its commands come from every lane that exists. They are policy edits,
//! calls, role grants, ends and reinstatements, drafts and submissions,
//! assignments, unassignments, declarations and reads. The lifecycle runs
//! with score corrections, withdrawal, expiry, re-entry and declines. One
//! stage 2 path records a revision that supersedes the submitted plan,
//! with stage 2 scores, a correction and a ranking. Past NEGOTIATION, PR1
//! runs the amount, the grant facts, the start of execution, one payment
//! and the termination. Vault changes release, void and suspend.
//!
//! After every command:
//! - an accepted command appended one batch under its own command id and
//!   instant, and a refused one appended nothing;
//! - for `CorrectScore`, `EditPolicy`, `EndRole` and `ReinstateBinding`,
//!   the engine accepts exactly when the ghost reference accepts;
//! - the old ledger is a prefix of the new one, field by field and by the
//!   canonical bytes that `fstp_ledger::verify_append_only` compares;
//! - replay of the ledger equals the state, also for a driver opened over
//!   a copy of the store, and the stored bytes decode to the same entries;
//! - every correction targets an existing record of the same kind.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::mc::ledger_model::{LedgerMachine, correction_kinds, witness_run};
use fstp_prop::{Config, check_machine_with};

/// Commands per machine case.
const COMMANDS: usize = 120;

/// Cases of the machine.
const CASES: u32 = 128;

/// I-23: over random command sequences of every lane, the ledger only
/// grows, it replays to the state after every execute, and every
/// correction targets an existing record of the same kind.
#[test]
fn i23_ledger_is_prefix_monotone_and_replays() {
    check_machine_with(
        "i23_ledger_is_prefix_monotone_and_replays",
        Config::default().with_cases(CASES),
        &LedgerMachine::new(COMMANDS),
    );
}

/// I-23: the scripted run that the machine draws from reaches NEGOTIATION
/// and records every correction kind through the engine: a score
/// correction, a stage 2 score correction, a superseding plan, a second
/// policy version, a binding end, a suspension and its reinstatement, a
/// binding void and a release. No command emits a
/// score void in M2, so the corrections property covers voids by injection. Every
/// I-23 check holds after each of its steps. So the machine cannot pass
/// by refusing everything.
#[test]
fn i23_ledger_witness_records_every_correction_kind() {
    let run = witness_run().unwrap_or_else(|e| panic!("{e}"));
    let missing: Vec<&str> = correction_kinds(&run.ledger)
        .into_iter()
        .filter(|(_, held)| !held)
        .map(|(name, _)| name)
        .collect();
    assert!(
        missing.is_empty(),
        "the witness ledger holds no {missing:?}"
    );
}
