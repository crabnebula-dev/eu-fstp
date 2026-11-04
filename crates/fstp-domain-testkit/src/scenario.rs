//! Scenario builder that reaches start states from genesis through production commands (design section 6.1).
//!
//! A [`Scenario`] runs production commands through the reference driver
//! from an empty ledger, over a synthetic vault. No model starts from a
//! hand-built state. The scenario also collects the instants of the reduced
//! clock as the test marks them.
//!
//! Self-tests that need domain behaviour are deferred to the lanes that
//! make them possible:
//! - a scenario from genesis reaches a published call (L-POL);
//! - a vault change and its `VaultChanged` run in one scenario step (L-SOD);
//! - a scenario from genesis reaches STAGE2 and NEGOTIATION (L-LIFE);
//! - every state a scenario reaches equals the replay of its ledger, over
//!   accepted commands (L-POL first).

use fstp_domain::command::{Actor, Ctx, Via};
use fstp_domain::id::CommandId;
use fstp_domain::time::Timestamp;
use fstp_engine::{Command, Engine, EngineState, ExecError, OpenError, Record};
use fstp_ledger::{Entry, MemStore, RecordStore, Seq, StoreError};

use crate::clock::ReducedClock;
use crate::vault::{GroundTruth, SyntheticVault};

/// A ledger built from genesis by production commands over a synthetic vault.
///
/// A scenario is a value: it derives `Clone`, `PartialEq`, `Eq` and `Hash`,
/// so an fstp-mc model state can hold one and step it. Ghost state that the
/// domain does not store lives beside it in the model state, updated by the
/// model on each accepted command (design section 6.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Scenario {
    engine: Engine<MemStore<Record>, SyntheticVault>,
    clock: ReducedClock,
    /// The number of command ids drawn by [`Scenario::ctx`].
    drawn: u64,
}

impl Scenario {
    /// An empty ledger over a vault holding `truth`.
    pub fn new(truth: GroundTruth) -> Result<Scenario, OpenError> {
        Ok(Scenario {
            engine: Engine::open(MemStore::new(), SyntheticVault::new(truth))?,
            clock: ReducedClock::default(),
            drawn: 0,
        })
    }

    /// Runs `cmd` through the reference driver. A refused step records
    /// nothing and is reported to the test.
    pub fn execute(&mut self, cmd: Command, ctx: Ctx) -> Result<Seq, ExecError> {
        self.engine.execute(cmd, ctx)
    }

    /// Runs the core command `cmd` of a setup or a model step. A
    /// `CreateProgramme` and an `ActivateProgramme` append the entries of
    /// the creator path that `crate::activation::run_core` composes, since
    /// only the creator's approval activates a programme (D2e). Every
    /// other command runs through [`Scenario::execute`].
    pub fn run_core(
        &mut self,
        cmd: &fstp_domain::command::Command,
        ctx: Ctx,
    ) -> Result<Seq, ExecError> {
        crate::activation::run_core(&mut self.engine, cmd, ctx)
    }

    /// Changes the vault facts with `change`, then processes the change in
    /// the same step (design section 6.1). Returns the new head, or `None`
    /// when the change left the epoch where the state already is. On a
    /// refusal the facts stay changed and the ledger records nothing.
    pub fn change_vault(
        &mut self,
        change: impl FnOnce(&mut GroundTruth),
        ctx: Ctx,
    ) -> Result<Option<Seq>, ExecError> {
        change(self.engine.oracle_mut().truth_mut());
        self.engine.sync_vault(ctx)
    }

    /// A context for one command at `now` by `actor` through the web, with a
    /// command id drawn fresh for this scenario.
    pub fn ctx(&mut self, now: Timestamp, actor: Actor) -> Ctx {
        self.drawn = self.drawn.saturating_add(1);
        let mut id = [0u8; 16];
        let (head, tail) = id.split_at_mut(8);
        head.copy_from_slice(b"scenario");
        tail.copy_from_slice(&self.drawn.to_be_bytes());
        Ctx {
            now,
            actor,
            command: CommandId::from_bytes(id),
            via: Via::Web,
            tenant_admin: false,
            second_tenant_admin: None,
            binds_tenant_admin: false,
        }
    }

    /// The state reached so far.
    pub fn state(&self) -> &EngineState {
        self.engine.state()
    }

    /// The vault facts.
    pub fn truth(&self) -> &GroundTruth {
        self.engine.oracle().truth()
    }

    /// The driver, for a test that needs its store or head.
    pub fn engine(&self) -> &Engine<MemStore<Record>, SyntheticVault> {
        &self.engine
    }

    /// Every ledger entry, in order.
    pub fn entries(&self) -> Result<Vec<Entry<Record>>, StoreError> {
        let mut out = Vec::new();
        self.engine.store().read(Seq::ZERO, usize::MAX, &mut out)?;
        Ok(out)
    }

    /// Marks `instant` as a scenario instant of the reduced clock: an
    /// opening, a deadline, a window end or a next-call opening.
    pub fn mark(&mut self, instant: Timestamp) {
        self.clock.insert(instant);
    }

    /// The reduced clock over the marked instants.
    pub fn clock(&self) -> &ReducedClock {
        &self.clock
    }

    /// How many command ids [`Scenario::ctx`] has drawn. The next id is
    /// drawn from this count plus one.
    pub fn drawn(&self) -> u64 {
        self.drawn
    }

    /// The scenario's parts, for a model that starts from its state: the
    /// driver and the reduced clock.
    pub fn into_parts(self) -> (Engine<MemStore<Record>, SyntheticVault>, ReducedClock) {
        (self.engine, self.clock)
    }
}
