//! Stateful testing: random command sequences checked against a model.
//!
//! A [`StateMachine`] describes a model, a system under test and the commands
//! that drive both. Each case generates a sequence of commands from the model,
//! runs each command on the system under test, and checks the postcondition
//! and the invariant after every step. A failing sequence shrinks through the
//! same choice-sequence mechanism as every other generator, so the report shows
//! a minimal command sequence.

use core::fmt::Debug;
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::exec::Silence;
use crate::generator::{Gen, Many};
use crate::runner::{Config, DEFAULT_MAX_CHOICES, Outcome, fail_check, run_at};

/// Default maximum number of commands per case.
pub const DEFAULT_MAX_COMMANDS: usize = 32;

/// A model-based description of a stateful system.
///
/// Each step generates a command from the current model and skips it when the
/// precondition is false. Otherwise it runs the command on the system under
/// test and checks the postcondition against the model state before the
/// command. Then it advances the model and checks the invariant.
pub trait StateMachine {
    /// The reference model.
    type Model;
    /// The system under test.
    type Sut;
    /// A command applied to both the model and the system under test.
    type Command: Debug;
    /// What the system under test returns for a command.
    type Output: Debug;

    /// Creates the initial model.
    fn init_model(&self) -> Self::Model;

    /// Creates a fresh system under test. Called once per case.
    fn init_sut(&self) -> Self::Sut;

    /// Generates the next command from the current model.
    fn command(&self, g: &mut Gen, model: &Self::Model) -> Self::Command;

    /// Returns whether `cmd` may run in `model`. Commands that fail it are skipped.
    ///
    /// Shrinking can delete earlier commands, so a later command can become
    /// invalid. The precondition keeps such commands out of the run.
    fn precondition(&self, _model: &Self::Model, _cmd: &Self::Command) -> bool {
        true
    }

    /// Runs `cmd` on the system under test.
    fn run(&self, sut: &mut Self::Sut, cmd: &Self::Command) -> Self::Output;

    /// Advances the model by `cmd`.
    fn next_state(&self, model: &mut Self::Model, cmd: &Self::Command);

    /// Checks the output of `cmd` against the model state before the command.
    fn postcondition(
        &self,
        _model: &Self::Model,
        _cmd: &Self::Command,
        _output: &Self::Output,
    ) -> Result<(), String> {
        Ok(())
    }

    /// Checks that the model and the system under test agree after a step.
    fn invariant(&self, _model: &Self::Model, _sut: &Self::Sut) -> Result<(), String> {
        Ok(())
    }

    /// Maximum number of commands per case.
    fn max_commands(&self) -> usize {
        DEFAULT_MAX_COMMANDS
    }
}

/// The property that drives one case of a state machine.
fn machine_property<M: StateMachine>(machine: &M, g: &mut Gen) -> Result<(), String> {
    let mut model = machine.init_model();
    let mut sut = machine.init_sut();
    machine
        .invariant(&model, &sut)
        .map_err(|e| format!("invariant failed before the first command: {e}"))?;
    let mut many = Many::new(0, machine.max_commands());
    let mut step: usize = 0;
    loop {
        let start = g.position();
        if !many.more(g) {
            break;
        }
        let cmd = machine.command(g, &model);
        g.end_span(start);
        if !machine.precondition(&model, &cmd) {
            continue;
        }
        step = step.saturating_add(1);
        g.note_with(|| format!("step {step}: {cmd:?}"));
        let output = machine.run(&mut sut, &cmd);
        if let Err(e) = machine.postcondition(&model, &cmd, &output) {
            return Err(format!(
                "postcondition failed at step {step}: {e}\n  command: {cmd:?}\n  output: {output:?}"
            ));
        }
        machine.next_state(&mut model, &cmd);
        if let Err(e) = machine.invariant(&model, &sut) {
            return Err(format!("invariant failed after step {step} ({cmd:?}): {e}"));
        }
    }
    Ok(())
}

/// Checks a state machine with [`Config::from_env`] and panics with a report on failure.
///
/// The report lists the minimal command sequence as `step N: command` notes.
///
/// # Panics
///
/// Panics with the failure report when a sequence fails, and when an
/// `FSTP_PROP_*` variable is malformed.
#[track_caller]
pub fn check_machine<M: StateMachine>(name: &str, machine: &M) {
    check_machine_with(name, Config::default(), machine);
}

/// Checks a state machine with `cfg` plus environment overrides, like
/// [`crate::check_with`], and panics with a report on failure.
///
/// # Panics
///
/// Panics with the failure report when a sequence fails, and when an
/// `FSTP_PROP_*` variable is malformed.
#[track_caller]
pub fn check_machine_with<M: StateMachine>(name: &str, cfg: Config, machine: &M) {
    let cfg = cfg.with_env();
    if let Outcome::Failed(f) = run_at(
        name,
        &cfg,
        &|g: &mut Gen| machine_property(machine, g),
        std::panic::Location::caller(),
    ) {
        fail_check(f);
    }
}

/// Runs a state machine with exactly `cfg` and returns the outcome. Never panics.
#[track_caller]
pub fn run_machine<M: StateMachine>(name: &str, cfg: Config, machine: &M) -> Outcome {
    run_at(
        name,
        &cfg,
        &|g: &mut Gen| machine_property(machine, g),
        std::panic::Location::caller(),
    )
}

/// Returns the commands that a run of `choices` executes, for example the
/// minimal sequence of a [`crate::Failure`].
///
/// It replays the choices through the model only: generation, preconditions
/// and model transitions. The system under test is never created. When the
/// replay panics, it returns the commands collected up to that point.
pub fn commands_for<M: StateMachine>(machine: &M, choices: &[u64]) -> Vec<M::Command> {
    let _quiet = Silence::begin();
    let mut out = Vec::new();
    let mut g = Gen::replay(choices.to_vec(), DEFAULT_MAX_CHOICES.max(choices.len()));
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let mut model = machine.init_model();
        let mut many = Many::new(0, machine.max_commands());
        while many.more(&mut g) {
            let cmd = machine.command(&mut g, &model);
            if !machine.precondition(&model, &cmd) {
                continue;
            }
            machine.next_state(&mut model, &cmd);
            out.push(cmd);
        }
    }));
    out
}
