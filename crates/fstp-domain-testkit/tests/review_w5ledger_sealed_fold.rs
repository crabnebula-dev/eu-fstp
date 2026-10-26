//! Review of W5 lane L-LEDGER: the structural fold and sealed stages.
//!
//! Design 5.1, "Fold checks": the fold refuses a correction whose target
//! is missing or of another kind, and it refuses a correction to a sealed
//! stage (Q2). `SPEC/02-domain/state-machine.md` NOTE 3: scores seal when
//! the proposal leaves the stage, and only a recorded complaint remedy
//! reopens them. `FoldError::SealedStage` exists for this, but no fold
//! returns it.
//!
//! Reproducer: the witness ledger takes PR1 through stage 1 to
//! NEGOTIATION. A stage 1 correction of R1's score on PR1, naming the
//! entry of its current value, is then folded through the public
//! structural `apply`. The fold accepts it, so a replay takes a ledger
//! that `decide` could never have written.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::record::{Record, ScoreRecorded};
use fstp_domain::scoring::ScoreVector;
use fstp_domain_testkit::r#gen::policy::text;
use fstp_domain_testkit::r#gen::review::{PR1, R1};
use fstp_domain_testkit::harness::teeth::inject_envelope;
use fstp_domain_testkit::mc::ledger_model::{CorrectionView, stage1_key, witness_run};
use fstp_engine::Record as EngineRecord;
use fstp_ledger::Seq;

/// Design 5.1 and NOTE 3: the structural fold refuses a stage 1 score
/// correction once the proposal has left STAGE1.
#[test]
fn review_w5ledger_fold_refuses_a_correction_to_a_sealed_stage() {
    let run = witness_run().unwrap_or_else(|e| panic!("{e}"));
    let view = CorrectionView::of(&run.ledger).unwrap_or_else(|e| panic!("{e}"));
    let key = stage1_key(R1, PR1);
    let current = view
        .live
        .get(&key)
        .copied()
        .expect("R1 has a current stage 1 score on PR1");
    let record = EngineRecord::Core(Record::ScoreRecorded(ScoreRecorded {
        key,
        values: ScoreVector(vec![0, 0]),
        supersedes: Some(Seq::from_raw(current)),
        reason: Some(text(93_000)),
    }));
    let mut state = run.scenario.state().clone();
    let seq = Seq::from_raw(view.head.saturating_add(1));
    let at = state.now_floor();
    let folded = inject_envelope(&mut state, seq, at, &record);
    assert!(
        folded.is_err(),
        "the fold accepted a correction of a stage 1 score after PR1 left STAGE1; \
         design 5.1 expects FoldError::SealedStage"
    );
}
