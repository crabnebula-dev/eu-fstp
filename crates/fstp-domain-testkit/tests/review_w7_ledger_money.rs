//! Review reproducer for the M2 final review (W7): I-23 over money commands.
//!
//! Design 6.1 asks every machine's invariant to check that the ledger
//! only grows and replays to the state. The money machines decide on the
//! domain state alone, so the I-23 machine over the full engine must run
//! the money commands itself. The test fails while the scripted path of
//! the ledger machine stops at NEGOTIATION.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::record::Record as CoreRecord;
use fstp_domain_testkit::r#gen::review::PR1;
use fstp_domain_testkit::mc::ledger_model::{
    LedgerCmd, LedgerGhost, LedgerMachine, LedgerSut, act_step, script,
};
use fstp_engine::Record;
use fstp_prop::StateMachine;

/// One machine step through the machine's own run, postcondition, state
/// update and invariant. Returns whether the command was accepted.
fn step(m: &LedgerMachine, ghost: &mut LedgerGhost, sut: &mut LedgerSut, cmd: &LedgerCmd) -> bool {
    let out = m.run(sut, cmd);
    m.postcondition(ghost, cmd, &out)
        .unwrap_or_else(|e| panic!("postcondition: {e}"));
    let accepted = out.applied.as_ref().is_ok_and(|a| a.accepted);
    m.next_state(ghost, cmd);
    m.invariant(ghost, sut)
        .unwrap_or_else(|e| panic!("I-23 after {}: {e}", out.context));
    accepted
}

/// I-23, design 6.1: the scripted path of PR1 in the ledger machine runs
/// the amount determination, the grant facts, the start of execution, an
/// amendment, a payment and the termination through the full engine. The
/// ledger only grows and replays to the state after each of them, and
/// every step of the script is accepted.
#[test]
fn review_w7_ledger_machine_runs_the_money_commands() {
    let m = LedgerMachine::new(0);
    let mut ghost = m.init_model();
    let mut sut = m.init_sut();
    assert!(step(
        &m,
        &mut ghost,
        &mut sut,
        &LedgerCmd::Setup { revise: false }
    ));
    for act in script(PR1, false) {
        let now = ghost
            .now
            .unwrap_or_else(|| panic!("no instant after the setup"));
        let s = act_step(&ghost, PR1, act).unwrap_or_else(|e| panic!("{act:?}: {e}"));
        let cmd = LedgerCmd::Core {
            now,
            step: Box::new(s),
            scripted: Some(PR1),
        };
        assert!(
            step(&m, &mut ghost, &mut sut, &cmd),
            "the scripted {act:?} is accepted: {:?}",
            sut.run.as_ref().map(|r| r.ledger.last())
        );
    }
    let ledger = sut
        .run
        .as_ref()
        .map(|r| r.ledger.clone())
        .unwrap_or_default();
    let has = |f: &dyn Fn(&CoreRecord) -> bool| {
        ledger
            .iter()
            .any(|e| matches!(&e.record, Record::Core(r) if f(r)))
    };
    for (name, held) in [
        (
            "AmountDetermined",
            has(&|r| matches!(r, CoreRecord::AmountDetermined { .. })),
        ),
        (
            "GrantDecided",
            has(&|r| matches!(r, CoreRecord::GrantDecided(_))),
        ),
        (
            "AmendmentActivated",
            has(&|r| matches!(r, CoreRecord::AmendmentActivated { .. })),
        ),
        (
            "PaymentConfirmed",
            has(&|r| matches!(r, CoreRecord::PaymentConfirmed { .. })),
        ),
        (
            "TerminationRecorded",
            has(&|r| matches!(r, CoreRecord::TerminationRecorded { .. })),
        ),
    ] {
        assert!(held, "I-23: the machine's ledger holds no {name}");
    }
}
