//! Review of W5 lane L-LEDGER: the strength of the I-23 checks.
//!
//! Each test fails against the lane as written and passes once the gap
//! it names is closed.
//!
//! - The corrections reference accepts a correction to a sealed stage,
//!   which design 5.1 and NOTE 3 forbid.
//! - The teeth fault of M-LEDGER is caught by the "ledger must grow" and
//!   replay checks, so it never shows that the prefix check bites.
//! - The ledger machine never takes a proposal through a stage 2
//!   revision, so no stage 2 score, stage 2 correction or superseding plan
//!   is ever recorded over the full engine.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core::cell::RefCell;

use fstp_domain::record::{Record, ScoreRecorded};
use fstp_domain::scoring::{ScoreVector, Stage};
use fstp_domain_testkit::r#gen::policy::text;
use fstp_domain_testkit::r#gen::review::{PR1, R1};
use fstp_domain_testkit::harness::prop::replay_matches;
use fstp_domain_testkit::mc::ledger_model::{
    CorrectionView, LedgerAction, LedgerCmd, LedgerGhost, LedgerMachine, LedgerModel, LedgerOutput,
    LedgerSut, change_past_score, make_entry, stage1_key, witness_run,
};
use fstp_engine::Record as EngineRecord;
use fstp_ledger::Seq;
use fstp_mc::Model;
use fstp_prop::{Config, Gen, StateMachine, run_machine};

/// I-23, design 5.1 and NOTE 3: the independent corrections reference
/// refuses a stage 1 score correction once the proposal left STAGE1.
#[test]
fn review_w5ledger_reference_refuses_a_correction_to_a_sealed_stage() {
    let run = witness_run().unwrap_or_else(|e| panic!("{e}"));
    let view = CorrectionView::of(&run.ledger).unwrap_or_else(|e| panic!("{e}"));
    let key = stage1_key(R1, PR1);
    let current = view.live.get(&key).copied().expect("R1 scored PR1");
    let record = EngineRecord::Core(Record::ScoreRecorded(ScoreRecorded {
        key,
        values: ScoreVector(vec![0, 0]),
        supersedes: Some(Seq::from_raw(current)),
        reason: Some(text(94_000)),
    }));
    let seq = Seq::from_raw(view.head.saturating_add(1));
    let entry = make_entry(seq, run.scenario.state().now_floor(), [0xee; 16], record)
        .unwrap_or_else(|e| panic!("{e}"));
    let mut extended = run.ledger.clone();
    extended.push(entry);
    assert!(
        CorrectionView::of(&extended).is_err(),
        "I-23: the corrections reference accepted a stage 1 correction after PR1 \
         reached NEGOTIATION; design 5.1 refuses a correction to a sealed stage"
    );
}

/// I-23 teeth (design 6.1): the changed past entry must leave only the
/// prefix check to catch it. The faulted state's ledger must still grow
/// and still replay to the state, as a store that rewrote a past entry
/// during an honest append would leave it.
#[test]
fn review_w5ledger_teeth_fault_is_left_to_the_prefix_check() {
    let model = LedgerModel::new().unwrap_or_else(|e| panic!("{e}"));
    let start = model.init().into_iter().next().expect("one start state");
    let scored = model
        .step(&start, &LedgerAction::Score(R1))
        .expect("R1 scores from the start");
    let faulted = change_past_score(&scored).expect("the fault applies after a score");
    let grew = faulted.run.ledger.len() > scored.run.ledger.len();
    let replays = replay_matches(&faulted.run.ledger, faulted.run.scenario.state()).is_ok();
    assert!(
        grew && replays,
        "I-23 teeth: the fault is caught by the growth check (grew = {grew}) or the \
         replay check (replays = {replays}), so removing the prefix check from \
         transition(\"I-23\") would leave i23_teeth_changed_past_entry_is_caught green"
    );
}

/// The ledger machine with a record of whether stage 2 corrections and
/// superseding plans were appended.
struct Watching {
    inner: LedgerMachine,
    stage2_correction: RefCell<bool>,
    superseding_plan: RefCell<bool>,
}

impl StateMachine for Watching {
    type Model = LedgerGhost;
    type Sut = LedgerSut;
    type Command = LedgerCmd;
    type Output = LedgerOutput;

    fn init_model(&self) -> LedgerGhost {
        self.inner.init_model()
    }

    fn init_sut(&self) -> LedgerSut {
        self.inner.init_sut()
    }

    fn command(&self, g: &mut Gen, model: &LedgerGhost) -> LedgerCmd {
        self.inner.command(g, model)
    }

    fn precondition(&self, model: &LedgerGhost, cmd: &LedgerCmd) -> bool {
        self.inner.precondition(model, cmd)
    }

    fn run(&self, sut: &mut LedgerSut, cmd: &LedgerCmd) -> LedgerOutput {
        let out = self.inner.run(sut, cmd);
        if let Ok(applied) = &out.applied {
            for r in &applied.appended {
                match r {
                    Record::ScoreRecorded(s)
                        if s.key.stage == Stage::Two && s.supersedes.is_some() =>
                    {
                        self.stage2_correction.replace(true);
                    }
                    Record::PlanVersionRecorded(p) if p.supersedes.is_some() => {
                        self.superseding_plan.replace(true);
                    }
                    _ => {}
                }
            }
        }
        out
    }

    fn postcondition(
        &self,
        model: &LedgerGhost,
        cmd: &LedgerCmd,
        out: &LedgerOutput,
    ) -> Result<(), String> {
        self.inner.postcondition(model, cmd, out)
    }

    fn next_state(&self, model: &mut LedgerGhost, cmd: &LedgerCmd) {
        self.inner.next_state(model, cmd);
    }

    fn invariant(&self, model: &LedgerGhost, sut: &LedgerSut) -> Result<(), String> {
        self.inner.invariant(model, sut)
    }

    fn max_commands(&self) -> usize {
        self.inner.max_commands()
    }
}

/// I-23 (design 6.2): the machine over the full engine records a stage 2
/// score correction and a superseding plan, so those corrections are
/// checked against the prefix, replay and target rules too.
#[test]
fn review_w5ledger_machine_records_stage2_corrections() {
    let machine = Watching {
        inner: LedgerMachine::new(120),
        stage2_correction: RefCell::new(false),
        superseding_plan: RefCell::new(false),
    };
    let outcome = run_machine(
        "i23_ledger_is_prefix_monotone_and_replays",
        Config::default().with_cases(128),
        &machine,
    );
    assert!(outcome.is_passed(), "the machine itself failed");
    let s2 = *machine.stage2_correction.borrow();
    let plan = *machine.superseding_plan.borrow();
    assert!(
        s2 && plan,
        "I-23: over 128 machine cases, stage 2 score correction recorded = {s2}, \
         superseding plan recorded = {plan}"
    );
}
