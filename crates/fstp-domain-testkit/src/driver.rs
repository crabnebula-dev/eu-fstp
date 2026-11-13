//! The driver abstraction of the M2 machines (M3 design section 14.6,
//! lane m3/m2-over-http).
//!
//! The SoD machine of [`crate::r#gen::roster`] drives a
//! [`crate::r#gen::roster::Driver`]: the production engine over a
//! `MemStore` and the synthetic vault, or the reference alone. A third
//! driver runs the same commands through a running cell: its HTTP API,
//! its PostgreSQL store and its real vault (`fstp-celltest`). [`M2Driver`]
//! is what the three share, so a harness can send one command to two
//! drivers and compare them step by step.
//!
//! Each method takes what the machine hands its driver: a setup from
//! genesis, one core step at an instant, one vault change with its
//! reaction, or the System commands due at an instant. The driver answers
//! with the head after the step or the refusal, and gives the M2 core
//! records of its ledger in order.

use fstp_domain::record::Record;
use fstp_domain::refusal::Refusal;
use fstp_domain::time::Timestamp;
use fstp_engine::ExecError;
use fstp_ledger::Seq;

use crate::r#gen::policy::core_records;
use crate::r#gen::roster::{Backend, Driver, SodWorld, Step, VaultOp};
use crate::scenario::Scenario;
use crate::vault::GroundTruth;

/// A driver of the M2 machines.
pub trait M2Driver {
    /// The vault facts the driver holds, as the machine sees them.
    fn truth(&self) -> &GroundTruth;

    /// Starts from genesis over `truth` and runs the setup `steps` at
    /// `at`, each of which must be accepted. Returns the head after the
    /// last step, or the first refusal.
    ///
    /// # Errors
    ///
    /// The refusal of the first setup step that did not run.
    fn start(
        &mut self,
        truth: &GroundTruth,
        steps: &[Step],
        at: Timestamp,
    ) -> Result<Seq, ExecError>;

    /// Runs `step` at `now`.
    ///
    /// # Errors
    ///
    /// The driver's refusal of the step.
    fn execute(&mut self, step: &Step, now: Timestamp) -> Result<Seq, ExecError>;

    /// Changes the vault with `op` at `now` and processes the change.
    ///
    /// # Errors
    ///
    /// A refused reaction, or a change that left the epoch where the
    /// state already was.
    fn change_vault(&mut self, op: VaultOp, now: Timestamp) -> Result<Seq, ExecError>;

    /// Runs every System command that `fstp_domain::due` lists at `now`.
    ///
    /// # Errors
    ///
    /// The refusal of a due command.
    fn run_due(&mut self, now: Timestamp) -> Result<Seq, ExecError>;

    /// The M2 core records of the driver's ledger, in order.
    fn core_records(&self) -> Vec<Record>;
}

impl M2Driver for Driver {
    fn truth(&self) -> &GroundTruth {
        Driver::truth(self)
    }

    fn start(
        &mut self,
        truth: &GroundTruth,
        steps: &[Step],
        at: Timestamp,
    ) -> Result<Seq, ExecError> {
        *self = match self {
            Driver::Engine(_) => match Scenario::new(truth.clone()) {
                Ok(s) => Driver::Engine(Box::new(s)),
                Err(_) => return Err(ExecError::Refused(Refusal::not_implemented())),
            },
            Driver::Reference(..) => Driver::Reference(
                Box::new(SodWorld::new(Backend::Reference, truth.clone())),
                Vec::new(),
            ),
        };
        let mut last = Ok(Seq::ZERO);
        for step in steps {
            last = Driver::execute(self, step, at);
            if last.is_err() {
                break;
            }
        }
        last
    }

    fn execute(&mut self, step: &Step, now: Timestamp) -> Result<Seq, ExecError> {
        Driver::execute(self, step, now)
    }

    fn change_vault(&mut self, op: VaultOp, now: Timestamp) -> Result<Seq, ExecError> {
        Driver::change_vault(self, op, now)
    }

    fn run_due(&mut self, now: Timestamp) -> Result<Seq, ExecError> {
        Driver::run_due(self, now)
    }

    fn core_records(&self) -> Vec<Record> {
        match self {
            Driver::Engine(s) => core_records(&s.entries().unwrap_or_default()),
            Driver::Reference(_, records) => records.clone(),
        }
    }
}
