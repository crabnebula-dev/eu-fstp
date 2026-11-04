//! The engine port over the M2 engine (design section 6.1).
//!
//! `execute` runs the production driver `fstp_engine::Engine` over an
//! in-memory ledger and the synthetic vault, so the domain re-runs every
//! guard, the I-85 and P-77 refusals through `Via::Mcp` included. It
//! records each call with its `ExecMeta`.
//!
//! The driver decides with `fstp_engine::CreatorDecider` over the cell's
//! [`CellEnvironment`] (`shell.rs`), so creator commands get the shell
//! facts a cell supplies: probes, SoD previews, the vault's Q35 answers,
//! the attested tenant admin set, the ports, the theme and the synthetic
//! legal-wording profile (design 3.2 `CreatorInputs`). The API core reads
//! the same facts through `AsyncEngine::creator_inputs`. Once an upload is
//! registered, the port runs the cell's proposer and records its
//! proposals as the system ([`ImportShell`]), as the shell does in design
//! 3.3 step 2.
//!
//! The fake holds the pending-action status change of requirement 1 of
//! section 6.1: an execution that names a pending action already confirmed
//! is refused and appends nothing, as the `WHERE status = 'open'` update
//! of `api.pending_actions` aborts its transaction.
//!
//! `dry_run` runs the same driver on a copy, which appends nothing to the
//! real ledger, and records every vault answer the copy obtained. A dry
//! run never runs the proposer, and it peeks at the probes without
//! running them (`CellEnvironment::set_dry`).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use fstp_api_core::port::{AsyncEngine, ExecError, ExecMeta, PendingId, PortError};
use fstp_domain::command::Ctx;
use fstp_domain::oracle::{Answer, Query};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_engine::{Command, CreatorDecider, CreatorEnvironment, Engine, EngineState, Record};
use fstp_ledger::{MemStore, Seq};

use super::fixture::World;
use super::shell::{CellEnvironment, ImportShell};
use super::{CellOracle, lock};

/// The production driver over the fake ledger and vault, with the cell's
/// creator environment.
pub type FakeLedger = Engine<MemStore<Record>, CellOracle, CreatorDecider<CellEnvironment>>;

/// One `execute` call and its result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Execution {
    /// The command.
    pub cmd: Command,
    /// Its context.
    pub ctx: Ctx,
    /// Its metadata.
    pub meta: ExecMeta,
    /// The result.
    pub result: Result<Seq, ExecError>,
    /// The vault answers the execution obtained.
    pub asks: Vec<(Query, Answer)>,
}

/// One `dry_run` call and its result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DryRun {
    /// The command.
    pub cmd: Command,
    /// Its context.
    pub ctx: Ctx,
    /// Every vault answer the dry run obtained, in order.
    pub asks: Vec<(Query, Answer)>,
    /// The result.
    pub result: Result<(), Refusal>,
}

#[derive(Debug)]
struct Inner {
    engine: FakeLedger,
    executions: Vec<Execution>,
    dry_runs: Vec<DryRun>,
    confirmed: BTreeSet<PendingId>,
    /// The proposer run of the cell, if it has stores to run over.
    imports: Option<ImportShell>,
}

/// The fake engine port. Cloning shares the ledger and the log.
#[derive(Clone, Debug)]
pub struct FakeEngine {
    inner: Arc<Mutex<Inner>>,
}

/// The refusal a dry run reports for a driver error that is not a domain
/// refusal, such as a store failure. It fails closed.
const fn driver_refusal() -> Refusal {
    Refusal::new(RuleRef::OracleDown, RefusalReason::OracleUnavailable)
}

/// The port error of a driver error that is not a domain refusal.
fn port_error(e: &fstp_engine::ExecError) -> ExecError {
    match e {
        fstp_engine::ExecError::Refused(r) => ExecError::Refused(*r),
        fstp_engine::ExecError::Duplicate { .. } | fstp_engine::ExecError::ReservedCommandId => {
            ExecError::Port(PortError::Refused)
        }
        _ => ExecError::Port(PortError::Unavailable),
    }
}

impl FakeEngine {
    /// The engine over a copy of `world`'s ledger, asking `oracle`, with
    /// a detached creator environment over the world's admin set: no
    /// prober, no recorder of vault answers and no proposer
    /// (`CellEnvironment::detached`).
    pub fn open(world: &World, oracle: CellOracle) -> Result<FakeEngine, fstp_engine::OpenError> {
        let env = CellEnvironment::detached(oracle.with_fresh_log(), world.admins.clone());
        FakeEngine::open_with(world, oracle, env, None)
    }

    /// The engine over a copy of `world`'s ledger, asking `oracle`, with
    /// the creator environment `env` and the proposer run `imports`.
    pub fn open_with(
        world: &World,
        oracle: CellOracle,
        env: CellEnvironment,
        imports: Option<ImportShell>,
    ) -> Result<FakeEngine, fstp_engine::OpenError> {
        let engine = Engine::open_with(world.store.clone(), oracle, CreatorDecider(env))?;
        Ok(FakeEngine {
            inner: Arc::new(Mutex::new(Inner {
                engine,
                executions: Vec::new(),
                dry_runs: Vec::new(),
                confirmed: BTreeSet::new(),
                imports,
            })),
        })
    }

    /// The shell facts of `cmd` by `ctx`, as the creator environment
    /// answers them for a decision.
    pub fn creator_inputs_now(
        &self,
        state: &EngineState,
        cmd: &fstp_creator::CreatorCommand,
        ctx: &Ctx,
    ) -> fstp_creator::CreatorInputs {
        lock(&self.inner)
            .engine
            .decider()
            .0
            .creator_inputs(state, cmd, ctx)
    }

    /// Every `execute` call, in order.
    pub fn executions(&self) -> Vec<Execution> {
        lock(&self.inner).executions.clone()
    }

    /// Every `execute` call that appended, in order.
    pub fn appended(&self) -> Vec<Execution> {
        lock(&self.inner)
            .executions
            .iter()
            .filter(|e| e.result.is_ok())
            .cloned()
            .collect()
    }

    /// Every `dry_run` call, in order.
    pub fn dry_runs(&self) -> Vec<DryRun> {
        lock(&self.inner).dry_runs.clone()
    }

    /// The ledger head.
    pub fn head(&self) -> Seq {
        lock(&self.inner).engine.head()
    }

    /// A copy of the engine state.
    pub fn state(&self) -> EngineState {
        lock(&self.inner).engine.state().clone()
    }

    /// The pending actions whose confirmation appended.
    pub fn confirmed(&self) -> BTreeSet<PendingId> {
        lock(&self.inner).confirmed.clone()
    }

    /// Runs `cmd` with `ctx` straight on the driver, outside the port and
    /// unrecorded: a change of the world around the cell under test, such
    /// as a tenant admin ending a binding.
    pub fn environment(&self, cmd: Command, ctx: Ctx) -> Result<Seq, fstp_engine::ExecError> {
        lock(&self.inner).engine.execute(cmd, ctx)
    }

    /// Runs the core setup command `cmd` with `ctx` straight on the driver,
    /// outside the port and unrecorded, as [`FakeEngine::environment`]
    /// does. A `CreateProgramme` and an `ActivateProgramme` append the
    /// entries of the creator path that
    /// `fstp_domain_testkit::activation::run_core` composes, since only the
    /// creator's approval activates a programme (D2e).
    pub fn setup_step(
        &self,
        cmd: &fstp_domain::Command,
        ctx: Ctx,
    ) -> Result<Seq, fstp_engine::ExecError> {
        fstp_domain_testkit::activation::run_core(&mut lock(&self.inner).engine, cmd, ctx)
    }

    /// Appends `records` as one entry at `at` straight to the ledger, past
    /// every guard, and folds it: a forged change of the world around the
    /// cell under test, such as an entry a parallel lane's command would
    /// append. The fold still refuses an entry it cannot fold (I-23).
    pub fn append_forged(
        &self,
        at: fstp_domain::time::Timestamp,
        command: [u8; 16],
        records: Vec<Record>,
    ) -> Result<Seq, String> {
        use fstp_ledger::RecordStore;
        let mut inner = lock(&self.inner);
        let (mut store, oracle, decider) = inner.engine.clone().into_parts();
        let head = store.head();
        let seq = store
            .append(head, at.micros(), command, records)
            .map_err(|e| format!("append: {e:?}"))?;
        inner.engine =
            Engine::open_with(store, oracle, decider).map_err(|e| format!("fold: {e:?}"))?;
        Ok(seq)
    }

    fn execute_now(&self, cmd: Command, ctx: Ctx, meta: ExecMeta) -> Result<Seq, ExecError> {
        let mut inner = lock(&self.inner);
        let already = meta.pending.is_some_and(|p| inner.confirmed.contains(&p));
        let (result, asks) = if already {
            (Err(ExecError::Port(PortError::Refused)), Vec::new())
        } else {
            let oracle = inner.engine.oracle().with_fresh_log();
            let saved = std::mem::replace(inner.engine.oracle_mut(), oracle);
            let result = inner
                .engine
                .execute(cmd.clone(), ctx)
                .map_err(|e| port_error(&e));
            let asks = inner.engine.oracle().asks();
            *inner.engine.oracle_mut() = saved;
            (result, asks)
        };
        if let (Ok(_), Some(p)) = (&result, meta.pending) {
            inner.confirmed.insert(p);
        }
        if let (Ok(_), Command::Import(fstp_import::ImportCommand::RegisterDocument(doc))) =
            (&result, &cmd)
        {
            // Design 3.3 step 2: the shell runs the proposer and records
            // its proposals as the system. A batch the engine refuses
            // leaves the document with no proposals, and the import
            // screen shows the manual form.
            let batch = inner
                .imports
                .as_ref()
                .and_then(|shell| shell.proposals(doc, &ctx));
            if let Some((record, system)) = batch {
                let _ = inner.engine.execute(Command::Import(record), system);
            }
        }
        inner.executions.push(Execution {
            cmd,
            ctx,
            meta,
            result: result.clone(),
            asks,
        });
        result
    }

    fn dry_run_now(&self, cmd: &Command, ctx: Ctx) -> Result<(), Refusal> {
        self.dry_run_with_answers(cmd, ctx).0
    }

    /// Runs a dry run and returns its result with every vault answer it
    /// obtained, in order, refused or not (`overview.md` NOTE 5). The
    /// engine port's dry run with answers, once `port.rs` declares it,
    /// is this.
    pub fn dry_run_with_answers(
        &self,
        cmd: &Command,
        ctx: Ctx,
    ) -> (Result<(), Refusal>, Vec<Answer>) {
        let mut inner = lock(&self.inner);
        let mut copy = inner.engine.clone();
        let oracle = copy.oracle().with_fresh_log();
        *copy.oracle_mut() = oracle;
        // The copy shares the prober. As a dry run it peeks at the probes
        // and never runs them, so only the execution runs them.
        copy.decider_mut().0.set_dry(true);
        let result = match copy.execute(cmd.clone(), ctx) {
            Ok(_) => Ok(()),
            Err(fstp_engine::ExecError::Refused(r)) => Err(r),
            Err(_) => Err(driver_refusal()),
        };
        let asks = copy.oracle().asks();
        let answers = asks.iter().map(|(_, a)| a.clone()).collect();
        inner.dry_runs.push(DryRun {
            cmd: cmd.clone(),
            ctx,
            asks,
            result,
        });
        (result, answers)
    }
}

impl AsyncEngine for FakeEngine {
    async fn execute(&self, cmd: Command, ctx: Ctx, meta: ExecMeta) -> Result<Seq, ExecError> {
        self.execute_now(cmd, ctx, meta)
    }

    async fn dry_run(&self, cmd: &Command, ctx: Ctx) -> Result<(), Refusal> {
        self.dry_run_now(cmd, ctx)
    }

    async fn dry_run_answers(&self, cmd: &Command, ctx: Ctx) -> (Result<(), Refusal>, Vec<Answer>) {
        self.dry_run_with_answers(cmd, ctx)
    }

    fn snapshot(&self) -> Arc<EngineState> {
        Arc::new(self.state())
    }

    fn creator_inputs(
        &self,
        state: &EngineState,
        cmd: &fstp_creator::CreatorCommand,
        ctx: &Ctx,
    ) -> fstp_creator::CreatorInputs {
        self.creator_inputs_now(state, cmd, ctx)
    }
}
