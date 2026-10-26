//! I-23, NOTE 3: the structural fold refuses a score correction or void once its stage sealed, and replays every ledger the engine writes (design 5.1, Q2).
//!
//! `SPEC/02-domain/state-machine.md` NOTE 3: scores seal when the proposal
//! leaves the stage, and only a recorded complaint remedy reopens them.
//! Design 5.1, "Fold checks": the fold refuses a correction to a sealed
//! stage with `FoldError::SealedStage`. M2 records no complaint remedy, so
//! a sealed stage never reopens here.
//!
//! The base is the witness ledger, built from genesis through the full
//! engine over a `MemStore` (`mc::ledger_model::witness_run`). PR1 left
//! STAGE1 and STAGE2 and sits in NEGOTIATION, with current stage 1 and
//! stage 2 scores of R1. PR2 is still in STAGE1 with a current stage 1
//! score of R1. Each case folds one record through the public structural
//! `fstp_engine::apply`, so a replay never takes a correction or a void
//! that `decide` could not have written. The fold still takes a first
//! score on a sealed stage. `decide` never writes one, and whether the fold
//! should refuse it is open for Daniel. The controls keep the open stage
//! foldable and the engine's own ledger replayable.
//!
//! NOTE 8: a second ledger defers PR1 from STAGE2 in call 1 and re-enters
//! it into STAGE2 in call 2. Its stage 2 keys from call 1 sealed at the
//! deferral. PR1 is in STAGE2 again, so only the recorded seal refuses a
//! correction or a void of them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, DeclarationSubject};
use fstp_domain::engine::FoldError;
use fstp_domain::record::{Record, ScoreRecorded, ScoreVoided};
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::{ScoreKey, ScoreVector, VoidCause};
use fstp_domain::time::{MICROS_PER_DAY, Timestamp};
use fstp_domain_testkit::r#gen::policy::text;
use fstp_domain_testkit::r#gen::review::{COORDINATOR, L1, PR1, PR2, R1, R2, declare, plan_of};
use fstp_domain_testkit::r#gen::roster::{Step, call, publish};
use fstp_domain_testkit::harness::teeth::inject_envelope;
use fstp_domain_testkit::mc::ledger_model::{
    CorrectionView, LedgerRun, first_revision, genesis_steps, ledger_judges, ledger_setup,
    ledger_truth, stage1_key, stage2_key, witness_run,
};
use fstp_domain_testkit::mc::life_model::{
    T_EVAL, admit, assign_declared, close, expire, knock_out, reenter, revision_of, score,
    submit_revision,
};
use fstp_engine::{Record as EngineRecord, replay};
use fstp_ledger::Seq;

fn base() -> (LedgerRun, CorrectionView) {
    let run = witness_run().unwrap_or_else(|e| panic!("{e}"));
    let view = CorrectionView::of(&run.ledger).unwrap_or_else(|e| panic!("{e}"));
    (run, view)
}

/// The correction of `key` that names the entry of its current value.
fn correction(view: &CorrectionView, key: ScoreKey) -> Record {
    let current = view
        .live
        .get(&key)
        .copied()
        .unwrap_or_else(|| panic!("{key:?} has a current value in the witness ledger"));
    Record::ScoreRecorded(ScoreRecorded {
        key,
        values: ScoreVector(vec![0, 0]),
        supersedes: Some(Seq::from_raw(current)),
        reason: Some(text(94_000)),
    })
}

fn void(key: ScoreKey) -> Record {
    Record::ScoreVoided(ScoreVoided {
        key,
        cause: VoidCause::Conflict,
    })
}

/// Folds `record` after the head of the witness ledger. A refused fold
/// must leave the state unchanged.
fn fold(run: &LedgerRun, view: &CorrectionView, record: Record) -> Result<(), FoldError> {
    let mut state = run.scenario.state().clone();
    let before = state.clone();
    let seq = Seq::from_raw(view.head.saturating_add(1));
    let at = state.now_floor();
    let out = inject_envelope(&mut state, seq, at, &EngineRecord::Core(record));
    if out.is_err() {
        assert_eq!(state, before, "a refused fold changed the state");
    }
    out
}

/// I-23, NOTE 3: a stage 1 score correction after PR1 left STAGE1 is
/// refused as a correction to a sealed stage.
#[test]
fn i23_note3_stage1_correction_after_sealing_is_refused() {
    let (run, view) = base();
    let record = correction(&view, stage1_key(R1, PR1));
    assert_eq!(
        fold(&run, &view, record),
        Err(FoldError::SealedStage),
        "NOTE 3: PR1's stage 1 scores sealed when it left STAGE1"
    );
}

/// I-23, NOTE 3: a stage 1 score void after PR1 left STAGE1 is refused as
/// a change to a sealed stage.
#[test]
fn i23_note3_stage1_void_after_sealing_is_refused() {
    let (run, view) = base();
    assert_eq!(
        fold(&run, &view, void(stage1_key(R1, PR1))),
        Err(FoldError::SealedStage),
        "NOTE 3: a void would change a sealed stage 1 result"
    );
}

/// I-23, NOTE 3: a stage 2 score correction after PR1 left STAGE2 is refused.
#[test]
fn i23_note3_stage2_correction_after_sealing_is_refused() {
    let (run, view) = base();
    let record = correction(&view, stage2_key(R1, PR1));
    assert_eq!(
        fold(&run, &view, record),
        Err(FoldError::SealedStage),
        "NOTE 3: PR1's stage 2 scores sealed when it left STAGE2"
    );
}

/// I-23, NOTE 3: a stage 2 score void after PR1 left STAGE2 is refused.
#[test]
fn i23_note3_stage2_void_after_sealing_is_refused() {
    let (run, view) = base();
    assert_eq!(
        fold(&run, &view, void(stage2_key(R1, PR1))),
        Err(FoldError::SealedStage),
        "NOTE 3: a void would change a sealed stage 2 result"
    );
}

/// I-23, NOTE 3: while PR2 is in STAGE1, a correction naming the current
/// entry and a void of a current value both still fold.
#[test]
fn i23_note3_open_stage_corrections_and_voids_still_fold() {
    let (run, view) = base();
    let key = stage1_key(R1, PR2);
    assert_eq!(
        fold(&run, &view, correction(&view, key)),
        Ok(()),
        "I-23: PR2 is in STAGE1, so a correction of its current stage 1 score folds"
    );
    assert_eq!(
        fold(&run, &view, void(key)),
        Ok(()),
        "I-23: PR2 is in STAGE1, so a void of its current stage 1 score folds"
    );
}

/// I-23: the engine's own witness ledger replays to the engine's state
/// once the sealed-stage rule is in the fold. It holds stage 1 and stage 2
/// scores and corrections recorded before each stage sealed.
#[test]
fn i23_note3_engine_ledger_replays_with_sealed_stages() {
    let (run, _) = base();
    let replayed = replay(&run.ledger)
        .unwrap_or_else(|e| panic!("I-23: the fold refused a ledger the engine wrote: {e:?}"));
    assert_eq!(
        &replayed,
        run.scenario.state(),
        "I-23: the replay of the engine's ledger differs from its state"
    );
}

// ---------------------------------------------------------------------------
// NOTE 8: the stage 2 keys of the first call stay sealed after re-entry
// ---------------------------------------------------------------------------

/// The stage 2 window of PR1 ends P-07 = 28 days after its close at
/// `T_EVAL`, which opened the round.
fn window_end() -> Timestamp {
    Timestamp::from_micros(
        T_EVAL
            .micros()
            .saturating_add(28_i64.saturating_mul(MICROS_PER_DAY)),
    )
}

/// The ledger of PR1 by L1 run from genesis through the full engine. PR1
/// reaches STAGE2 in call 1. L1 submits a first revision without a
/// question, and R1 alone scores it, below P-03 = 2. The window closes
/// with no rank, so `ExpireStage2` defers it (NOTE 8).
/// Call 2 is published and `ReEnter` takes PR1 back to STAGE2 in call 2.
/// The stage 2 keys of call 1 held current values when PR1 left STAGE2.
fn reentered() -> (LedgerRun, CorrectionView) {
    let setup = ledger_setup(ledger_judges(), &[(L1, PR1)], 1);
    let mut run = LedgerRun::new(
        ledger_truth(&setup),
        &genesis_steps(&setup).unwrap_or_else(|e| panic!("{e}")),
    )
    .unwrap_or_else(|e| panic!("genesis: {e}"));
    let mut steps: Vec<Step> = Vec::new();
    for r in [R1, R2] {
        steps.extend(assign_declared(r, PR1, call(1), AssignmentKind::Reviewer));
    }
    steps.push(declare(
        COORDINATOR,
        DeclarationSubject::Proposal(PR1),
        false,
        false,
    ));
    steps.push(knock_out(PR1, true));
    steps.push(admit(PR1));
    steps.push(score(R1, stage1_key(R1, PR1), &[2, 1]));
    steps.push(score(R2, stage1_key(R2, PR1), &[2, 2]));
    steps.push(close(Actor::Account(COORDINATOR), PR1));
    steps.push(first_revision(PR1, plan_of(PR1)).unwrap_or_else(|e| panic!("{e}")));
    steps.push(submit_revision(L1, PR1, revision_of(PR1, 1)));
    steps.push(score(R1, stage2_key(R1, PR1), &[1, 1]));
    for s in &steps {
        run.checked(T_EVAL, s)
            .unwrap_or_else(|e| panic!("PR1 to STAGE2 with stage 2 scores: {e}"));
    }
    let end = window_end();
    for s in [expire(PR1), publish(call(2)), reenter(PR1, call(2))] {
        run.checked(end, &s)
            .unwrap_or_else(|e| panic!("NOTE 8: deferral and re-entry: {e}"));
    }
    let view = CorrectionView::of(&run.ledger).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        view.states.get(&PR1),
        Some(&StateTag::Stage2),
        "NOTE 8: PR1 re-entered STAGE2 in call 2"
    );
    assert!(
        view.live.contains_key(&stage2_key(R1, PR1)),
        "the stage 2 score of R1 from call 1 is still a current value"
    );
    (run, view)
}

/// I-23, NOTE 3, NOTE 8: after DEFERRED re-enters STAGE2, a correction of
/// a stage 2 score from the first call is refused as a sealed stage. PR1 is
/// in STAGE2 again, so only the recorded seal can refuse it.
#[test]
fn i23_note8_stage2_correction_after_reentry_is_refused() {
    let (run, view) = reentered();
    let record = correction(&view, stage2_key(R1, PR1));
    assert_eq!(
        fold(&run, &view, record),
        Err(FoldError::SealedStage),
        "NOTE 3: the stage 2 scores of call 1 sealed at the deferral and stay sealed after re-entry"
    );
}

/// I-23, NOTE 3, NOTE 8: after DEFERRED re-enters STAGE2, a void of a
/// stage 2 score from the first call is refused as a sealed stage.
#[test]
fn i23_note8_stage2_void_after_reentry_is_refused() {
    let (run, view) = reentered();
    assert_eq!(
        fold(&run, &view, void(stage2_key(R1, PR1))),
        Err(FoldError::SealedStage),
        "NOTE 3: a void would change a stage 2 result sealed before the re-entry"
    );
}

/// I-23, NOTE 8: the engine's own ledger through the deferral and the
/// re-entry replays to the engine's state with the seal in the fold.
#[test]
fn i23_note8_engine_ledger_replays_after_reentry() {
    let (run, _) = reentered();
    let replayed = replay(&run.ledger)
        .unwrap_or_else(|e| panic!("I-23: the fold refused a ledger the engine wrote: {e:?}"));
    assert_eq!(
        &replayed,
        run.scenario.state(),
        "I-23: the replay of the engine's ledger differs from its state"
    );
}
