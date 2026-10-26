//! I-34 and I-35 teeth on the assignment machine (design 6.1 "Teeth", SPEC/09-milestones.md NOTE 1).
//!
//! The machine of `i34_i35_assignment_respects_orgs_and_proximity` runs
//! over production. The fault is an engine that skips one guard: when
//! production refuses an `Assign` under I-34 (or I-35), the broken engine
//! emits the `Assigned` record that an accepting engine would write.
//!
//! The wrapper also hides the reference verdict of the faulted step. The
//! two-way comparison then cannot mask the fault, and only the record
//! check of the target invariant can catch it. Each teeth test asserts
//! that the run fails with a counterexample that names its invariant and
//! that fails again on replay.
//!
//! Scope: the forged record reaches the step output only. Neither the
//! system ledger nor the model folds it. `ReviewMachine` checks I-34 and
//! I-35 per step, on the records each step appends, and has no state-level
//! check of either. So these teeth prove that the per-step record check
//! catches a forged assignment. They do not prove that a forged assignment
//! held in the ledger is caught on replay or by a later step (audit doc,
//! Q-W6-4).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command};
use fstp_domain::record::{Assigned, Record};
use fstp_domain::refusal::RuleRef;
use fstp_domain_testkit::r#gen::review::{
    RevCmd, RevFocus, RevModel, RevOutput, RevSut, ReviewMachine,
};
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_domain_testkit::reference::sod::Verdict;
use fstp_engine::ExecError;
use fstp_ledger::Seq;
use fstp_prop::{Config, Gen, StateMachine, run_machine};

/// The review machine with one guard skipped: an `Assign` that production
/// refuses under `skipped` is recorded as if it were accepted.
struct SkippedGuard {
    inner: ReviewMachine,
    skipped: RuleRef,
    /// Whether the guard is skipped at all. The control run sets it false.
    faulty: bool,
}

impl SkippedGuard {
    /// The `Assigned` record the broken engine writes for `cmd`, when
    /// production refused it under the skipped guard.
    fn fault(&self, cmd: &RevCmd, out: &RevOutput) -> Option<Record> {
        if !self.faulty {
            return None;
        }
        let RevCmd::Core { step, .. } = cmd else {
            return None;
        };
        let Command::Assign {
            assignment,
            proposal,
            reviewer,
            kind,
            handle,
        } = &step.cmd
        else {
            return None;
        };
        let (assignment, proposal, reviewer, kind, handle) =
            (*assignment, *proposal, *reviewer, *kind, *handle);
        let refused = match &out.result {
            Err(ExecError::Refused(r)) => r.rule == self.skipped,
            _ => false,
        };
        // The I-34 record check covers reviewer assignments only.
        let in_scope = self.skipped != RuleRef::I34 || kind == AssignmentKind::Reviewer;
        let Actor::Account(by) = step.actor else {
            return None;
        };
        let call = out.rev.proposals.get(&proposal)?.current_call;
        (refused && in_scope).then_some(Record::Assigned(Assigned {
            assignment,
            proposal,
            call,
            reviewer,
            kind,
            handle,
            by,
            epoch: out.rev.epoch,
        }))
    }
}

impl StateMachine for SkippedGuard {
    type Model = RevModel;
    type Sut = RevSut;
    type Command = RevCmd;
    type Output = RevOutput;

    fn init_model(&self) -> RevModel {
        self.inner.init_model()
    }

    fn init_sut(&self) -> RevSut {
        self.inner.init_sut()
    }

    fn command(&self, g: &mut Gen, model: &RevModel) -> RevCmd {
        self.inner.command(g, model)
    }

    fn precondition(&self, model: &RevModel, cmd: &RevCmd) -> bool {
        self.inner.precondition(model, cmd)
    }

    fn run(&self, sut: &mut RevSut, cmd: &RevCmd) -> RevOutput {
        let mut out = self.inner.run(sut, cmd);
        if let Some(record) = self.fault(cmd, &out) {
            out.context = format!("{} (guard {:?} skipped)", out.context, self.skipped);
            out.verdict = Verdict::Unjudged;
            out.result = Ok(Seq::from_raw(u64::MAX));
            out.appended = vec![record];
        }
        out
    }

    fn postcondition(&self, model: &RevModel, cmd: &RevCmd, out: &RevOutput) -> Result<(), String> {
        self.inner.postcondition(model, cmd, out)
    }

    fn next_state(&self, model: &mut RevModel, cmd: &RevCmd) {
        self.inner.next_state(model, cmd);
    }

    fn invariant(&self, model: &RevModel, sut: &RevSut) -> Result<(), String> {
        self.inner.invariant(model, sut)
    }

    fn max_commands(&self) -> usize {
        self.inner.max_commands()
    }
}

fn outcome(name: &str, skipped: RuleRef, faulty: bool) -> fstp_prop::Outcome {
    let machine = SkippedGuard {
        inner: ReviewMachine::new(RevFocus::I34_I35),
        skipped,
        faulty,
    };
    run_machine(
        name,
        Config::default().with_cases(RevFocus::I34_I35.cases),
        &machine,
    )
}

fn caught(name: &str, skipped: RuleRef, id: &str) {
    if let Err(e) = expect_prop_failure(&outcome(name, skipped, true), id) {
        panic!("{e}");
    }
}

/// I-34, I-35: the wrapper without the fault passes, so each teeth failure
/// below comes from the skipped guard and not from the wrapper.
#[test]
fn i34_i35_teeth_wrapper_without_the_fault_passes() {
    let o = outcome(
        "i34_i35_teeth_wrapper_without_the_fault_passes",
        RuleRef::I34,
        false,
    );
    if let Some(f) = o.failure() {
        panic!("the unfaulted wrapper failed: {}", f.message);
    }
}

/// I-34, SoD-10: a reviewer assignment that adds no new organisation while
/// the proposal spans fewer than P-39 is caught by the I-34 record check.
#[test]
fn i34_teeth_same_organisation_below_p39_is_caught() {
    caught(
        "i34_teeth_same_organisation_below_p39_is_caught",
        RuleRef::I34,
        "I-34",
    );
}

/// I-35, SoD-11: an assignment of a reviewer whose organisation lists an
/// affiliation that the proposal's team declares is caught by the I-35
/// record check.
#[test]
fn i35_teeth_reviewer_on_the_proximity_list_is_caught() {
    caught(
        "i35_teeth_reviewer_on_the_proximity_list_is_caught",
        RuleRef::I35,
        "I-35",
    );
}
