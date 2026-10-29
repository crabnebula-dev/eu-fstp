//! The engine port over the M2 engine (design section 6.1).
//!
//! `execute` runs the production driver `fstp_engine::Engine` over an
//! in-memory ledger and the synthetic vault, so the domain re-runs every
//! guard, the I-85 and P-77 refusals through `Via::Mcp` included. It
//! records each call with its `ExecMeta`.
//!
//! The fake holds the pending-action status change of requirement 1 of
//! section 6.1: an execution that names a pending action already confirmed
//! is refused and appends nothing, as the `WHERE status = 'open'` update
//! of `api.pending_actions` aborts its transaction.
//!
//! `dry_run` runs the same driver on a copy, which appends nothing to the
//! real ledger, and records every vault answer the copy obtained.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use fstp_api_core::port::{AsyncEngine, ExecError, ExecMeta, PendingId, PortError};
use fstp_domain::command::Ctx;
use fstp_domain::oracle::{Answer, Query};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_engine::{Command, Engine, EngineState, Record};
use fstp_ledger::{MemStore, Seq};

use super::fixture::World;
use super::{CellOracle, lock};

/// The production driver over the fake ledger and vault.
pub type FakeLedger = Engine<MemStore<Record>, CellOracle>;

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
    /// The engine over a copy of `world`'s ledger, asking `oracle`.
    pub fn open(world: &World, oracle: CellOracle) -> Result<FakeEngine, fstp_engine::OpenError> {
        let engine = Engine::open(world.store.clone(), oracle)?;
        Ok(FakeEngine {
            inner: Arc::new(Mutex::new(Inner {
                engine,
                executions: Vec::new(),
                dry_runs: Vec::new(),
                confirmed: BTreeSet::new(),
            })),
        })
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

    fn snapshot(&self) -> Arc<EngineState> {
        Arc::new(self.state())
    }
}
