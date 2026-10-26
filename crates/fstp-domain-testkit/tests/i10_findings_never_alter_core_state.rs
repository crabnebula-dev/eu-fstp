//! I-10, twin machine (design 6.2, test plan row I-10).
//!
//! Both twins start from genesis at M-LIFE-S1's setup with P-28 on: PR1
//! admitted to STAGE1 with three reviewers assigned and declared, or PR1
//! in STAGE2 after every reviewer scored and the close. Random lifecycle
//! commands run on both twins: scores, corrections, closes by every
//! actor, stage 2 questions, answers and rankings, expiry, publication of
//! call 2, re-entry, withdrawal, content reads, clock moves and vault
//! conflicts. Twin B also receives finding commands through the engine's
//! finding decider: `Record` findings of every kind, severity, criterion
//! and confidence, with generated strings and injection phrases, `Mark`
//! by reviewers, the lead and the System, and `Regenerate` with random
//! models. Twin A never sees a finding.
//!
//! Assertions after every step: each core command gives identical records
//! or identical refusals, a finding command emits only finding records,
//! the core projections are identical, and the core ledgers are identical
//! once finding records are removed.

#![allow(clippy::panic)]

use fstp_domain_testkit::mc::findings_model::{TwinMachine, TwinStart};
use fstp_prop::{Config, check_machine_with};

fn machine(from: TwinStart) -> TwinMachine {
    match TwinMachine::new(from, false) {
        Ok(m) => m,
        Err(e) => panic!("twin start from genesis: {e}"),
    }
}

/// I-10, TH-01: fuzzed findings, including adversarial content, never alter
/// the core state, from STAGE1 on.
#[test]
fn i10_findings_never_alter_core_state() {
    check_machine_with(
        "i10_findings_never_alter_core_state",
        Config::default(),
        &machine(TwinStart::Stage1),
    );
}

/// I-10, TH-01: the same twins from STAGE2 on, through questions,
/// rankings, expiry and re-entry.
#[test]
fn i10_findings_never_alter_core_state_from_stage2() {
    check_machine_with(
        "i10_findings_never_alter_core_state_from_stage2",
        Config::default(),
        &machine(TwinStart::Stage2),
    );
}
