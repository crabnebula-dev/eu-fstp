//! The M2 generator equivalence through `fstp_cell::engine::CellEngine`
//! over the in-memory store (M3 design sections 5.2 and 14.6, I-23).
//!
//! Moved from `fstp-cell/tests/engine_mem.rs`: the admission of M2 steps
//! and the ground-truth vault live in `fstp_celltest::mc::driver_model`,
//! which `fstp-cell` tests cannot depend on.
//!
//! The paths of `driver_model::paths` run through `CellEngine` over a
//! `MemStore` and through the M2 reference engine
//! (`fstp_domain_testkit::scenario::Scenario`). A route writes some
//! entries outside the engine: the step-up grant of a high-risk step and
//! the creator path's composed entry of a setup `CreateProgramme` or
//! `ActivateProgramme` (strict D2e). The harness stops the engine,
//! appends them to the store and starts the engine again, which replays
//! the store (design section 5.5).
//!
//! Daniel's decision of 2026-11-15 ("Compare after set-up"): each side's
//! set-up is checked on its own, the cell's tenant admin bootstrap and the
//! reference's vault change. The scenario after it is compared step by
//! step on the M2 core records, with ledger positions relative to each
//! side's head at the scenario start.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use fstp_cell::engine::{CellEngine, EngineError, Unanchored, VaultClient};
use fstp_cell_core::driver::{ExecError, VaultFault};
use fstp_cell_core::gate::Admitted;
use fstp_cell_core::tenant::TenantCommand;
use fstp_cell_core::{CellCommand, CellRecord, CellRefusal, CellState};
use fstp_celltest::mc::driver_model::{self as d, AdmitError, paths};
use fstp_domain::command::{Actor, Ctx, Via};
use fstp_domain::id::{CommandId, VaultEpoch};
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::refusal::Refusal;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::activation::{activation_records, open_records, relative_positions};
use fstp_domain_testkit::r#gen::review::run_records;
use fstp_domain_testkit::r#gen::roster::{ADMIN, Step, T0};
use fstp_domain_testkit::scenario::Scenario;
use fstp_domain_testkit::vault::{GroundTruth, SyntheticVault};
use fstp_ledger::{Entry, MemStore, RecordStore, Seq};
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{JoinHandle, Shutdown};

/// The cell id of the in-memory store.
const CELL: [u8; 16] = [0xCE; 16];

/// The ground-truth vault of the M2 generators, as the engine reaches it.
#[derive(Clone)]
struct TruthVault(GroundTruth);

impl VaultClient for TruthVault {
    fn epoch(&self) -> impl Future<Output = Result<VaultEpoch, VaultFault>> + Send {
        std::future::ready(Ok(self.0.epoch()))
    }

    fn ask(
        &self,
        queries: &[Query],
        _reaction_for: Option<VaultEpoch>,
        _at: Timestamp,
    ) -> impl Future<Output = Result<Answers, VaultFault>> + Send {
        let mut out = Answers::new();
        let mut ok = true;
        for q in queries {
            match self.0.try_answer(q) {
                Some(a) => out.insert(q.clone(), a),
                None => ok = false,
            }
        }
        std::future::ready(if ok {
            Ok(out)
        } else {
            Err(VaultFault::Unavailable)
        })
    }

    fn ack(
        &self,
        _epoch: VaultEpoch,
        _seq: Seq,
        _link: [u8; 32],
    ) -> impl Future<Output = Result<(), VaultFault>> + Send {
        std::future::ready(Ok(()))
    }
}

/// A running `CellEngine` over a `MemStore`, which the harness stops to
/// append route entries.
struct Cell {
    rt: TokioRuntime,
    vault: TruthVault,
    shutdown: Shutdown,
    /// The store's commit clock: the instant of the step being run, so a
    /// step-up stays fresh at commit as at admission (I-78).
    clock: Arc<AtomicI64>,
    running: Option<(CellEngine, JoinHandle<Unanchored<MemStore<CellRecord>>>)>,
}

impl Cell {
    /// Starts the engine over `store`, which it replays.
    fn start(rt: TokioRuntime, vault: TruthVault, store: MemStore<CellRecord>) -> Cell {
        let mut c = Cell {
            rt,
            vault,
            shutdown: Shutdown::new(),
            clock: Arc::new(AtomicI64::new(T0.micros())),
            running: None,
        };
        c.restart(store);
        c
    }

    fn restart(&mut self, store: MemStore<CellRecord>) {
        let rt = self.rt.clone();
        let vault = self.vault.clone();
        let shutdown = self.shutdown.clone();
        let tick = Arc::clone(&self.clock);
        let commit: fstp_cell::engine::CommitClock = Arc::new(move || tick.load(Ordering::SeqCst));
        let running = self.rt.block_on(async move {
            let store = Unanchored::open(store, CELL)
                .await
                .expect("store open")
                .with_commit_clock(commit);
            CellEngine::start(&rt, store, vault, &shutdown, 4)
                .await
                .unwrap_or_else(|_| panic!("the engine did not start"))
        });
        self.running = Some(running);
    }

    /// Stops the engine and gives its store back.
    fn stop(&mut self) -> MemStore<CellRecord> {
        let (engine, task) = self.running.take().expect("running");
        drop(engine);
        self.rt
            .block_on(task)
            .unwrap_or_else(|_| panic!("the engine task failed"))
            .into_inner()
    }

    fn state(&self) -> std::sync::Arc<CellState> {
        self.running.as_ref().expect("running").0.state()
    }

    /// Appends `batches` (command id, instant, records) outside the
    /// engine, then starts it again.
    fn append(&mut self, batches: Vec<([u8; 16], Timestamp, Vec<CellRecord>)>) {
        let mut store = self.stop();
        for (command, at, batch) in batches {
            let head = store.head();
            store
                .append(head, at.micros(), command, batch)
                .unwrap_or_else(|e| panic!("route append: {e:?}"));
        }
        self.restart(store);
    }

    fn execute(&self, admitted: Admitted) -> Result<(), ExecError> {
        self.clock.store(admitted.at().micros(), Ordering::SeqCst);
        let (engine, _) = self.running.as_ref().expect("running");
        match self.rt.block_on(engine.execute(admitted)) {
            Ok(_) => Ok(()),
            Err(EngineError::Exec(e)) => Err(e),
            Err(e) => panic!("the engine failed: {e:?}"),
        }
    }

    /// The whole store, read through a stop and a restart.
    fn entries(&mut self) -> Vec<Entry<CellRecord>> {
        let store = self.stop();
        let mut out = Vec::new();
        store
            .read(Seq::ZERO, usize::MAX, &mut out)
            .unwrap_or_else(|e| panic!("read: {e:?}"));
        self.restart(store);
        out
    }
}

/// Admits `step` as its actor on the cell's state ([`admit_as`]).
fn admit(cell: &mut Cell, step: &Step, at: Timestamp, id: [u8; 16]) -> Result<Admitted, String> {
    let Actor::Account(actor) = step.actor else {
        return Err(format!("{:?} is a system step", step.cmd.kind()));
    };
    let cmd = CellCommand::Engine(fstp_engine::Command::Core(step.cmd.clone()));
    admit_as(cell, cmd, actor, at, id)
}

/// Admits `cmd` by `actor` on the cell's state, appending the step-up
/// grant first when the gate needs one, as `driver_model::Shell` does.
/// The `Err` is a gate refusal.
fn admit_as(
    cell: &mut Cell,
    cmd: CellCommand,
    actor: fstp_domain::id::AccountId,
    at: Timestamp,
    id: [u8; 16],
) -> Result<Admitted, String> {
    let state = cell.state();
    // The gate folds a step-up grant into a copy of the ledger, so the
    // engine stops while the command is admitted.
    let mut store = cell.stop();
    let admitted = match d::admit(
        d::GateState::with_ledger(&state, &store),
        cmd,
        actor,
        at,
        id,
    ) {
        Ok(a) => a,
        Err(AdmitError::Denied(deny)) => {
            cell.restart(store);
            return Err(format!("denied: {deny:?}"));
        }
        Err(e @ AdmitError::NotImplemented(_)) => panic!("{e}"),
    };
    if let Some(u) = admitted.stepup()
        && state.auth().stepup_grant(u.id).is_none()
    {
        let session = d::session_of(actor, u.asserted_at);
        let grant = d::stepup_grant(&state, actor, &session, u.action_digest, u.asserted_at, id)
            .unwrap_or_else(|e| panic!("{e}"))
            .expect("the step-up route refuses the grant the gate admitted");
        for e in grant.entries() {
            let head = store.head();
            store
                .append(head, e.at.micros(), e.command, e.batch)
                .unwrap_or_else(|e| panic!("grant append: {e:?}"));
        }
    }
    cell.restart(store);
    Ok(admitted)
}

/// The composed entry of a setup `CreateProgramme` or `ActivateProgramme`
/// on the cell's state, as `driver_model::Shell::execute_composed` builds
/// it. The inner `Err` is the domain refusal.
fn composed(
    cell: &mut Cell,
    truth: &GroundTruth,
    step: &Step,
    at: Timestamp,
    id: [u8; 16],
) -> Result<(), Refusal> {
    let Actor::Account(actor) = step.actor else {
        panic!("a composed step names no account");
    };
    let state = cell.state();
    let engine_cmd = fstp_engine::Command::Core(step.cmd.clone());
    let a = fstp_cell_core::attest_at(&state, actor, &engine_cmd, id, at);
    let ctx = Ctx {
        now: at,
        actor: step.actor,
        command: CommandId::from_bytes(id),
        via: Via::Web,
        tenant_admin: a.tenant_admin || step.flags.tenant_admin,
        second_tenant_admin: None,
        binds_tenant_admin: a.binds_tenant_admin,
    };
    let oracle = SyntheticVault::new(truth.clone());
    let records = match &step.cmd {
        fstp_domain::Command::CreateProgramme { policy } => {
            open_records(state.engine(), &oracle, policy, &ctx)
        }
        cmd => activation_records(state.engine(), &oracle, cmd, &ctx),
    };
    let records = match records {
        Ok(r) => r,
        Err(fstp_engine::ExecError::Refused(r)) => return Err(r),
        Err(e) => panic!("composed step: {e:?}"),
    };
    cell.append(vec![(
        id,
        at,
        records.into_iter().map(CellRecord::Engine).collect(),
    )]);
    Ok(())
}

/// The M2 core records of `entries`, `GuidePublished` left out (an M4
/// record of the generators' synthetic Guide, I-52).
fn core_records(entries: &[Entry<CellRecord>]) -> Vec<fstp_domain::Record> {
    entries
        .iter()
        .filter_map(|e| match &e.record {
            CellRecord::Engine(fstp_engine::Record::Core(
                fstp_domain::Record::GuidePublished { .. },
            )) => None,
            CellRecord::Engine(fstp_engine::Record::Core(c)) => Some(c.clone()),
            _ => None,
        })
        .collect()
}

/// What the cell did with one step.
#[derive(Debug)]
enum Got {
    /// It appended the step's entry.
    Appended,
    /// The domain refused it.
    Refused(Refusal),
    /// The gate refused it, for the reason given.
    Denied(#[allow(dead_code)] String),
}

fn is_composed(cmd: &fstp_domain::Command) -> bool {
    matches!(
        cmd,
        fstp_domain::Command::CreateProgramme { .. }
            | fstp_domain::Command::ActivateProgramme { .. }
    )
}

/// Design sections 5.2 and 14.6, I-23: the M2 generators through
/// `CellEngine` over the in-memory store give the same M2 records, step
/// for step, as through the M2 reference engine (module documentation).
#[test]
fn seam_cell_engine_matches_reference_engine_over_mem_store() {
    for target in paths::STATES {
        let path = paths::to(target).unwrap();
        let truth = paths::truth(true);
        let rt = TokioRuntime::new_multi_thread(2).expect("runtime");
        let mut cell = Cell::start(rt, TruthVault(truth.clone()), MemStore::new());
        // The cell's set-up: ADMIN made tenant admin from the tenant fold.
        let boot = CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: ADMIN });
        let a = admit_as(&mut cell, boot, ADMIN, T0, [0xB0; 16])
            .unwrap_or_else(|e| panic!("bootstrap: {e}"));
        cell.execute(a).expect("the tenant admin bootstrap");
        // The reference's set-up: the vault change the bootstrap processed.
        let mut engine = Scenario::new(truth.clone()).unwrap();
        let ctx = engine.ctx(T0, Actor::Account(ADMIN));
        engine
            .change_vault(|_| {}, ctx)
            .expect("reference vault change");
        let engine_start = engine.engine().head();
        let cell_start = cell.entries().last().map_or(Seq::ZERO, |e| e.seq);
        let mut compared = 0usize;
        for (i, p) in path.iter().enumerate() {
            let context = format!("{target:?} step {i} {:?}", p.step.cmd.kind());
            let want = run_records(&mut engine, &p.step, p.at).unwrap();
            let before = cell.entries().len();
            let id = [u8::try_from(i % 170).unwrap(); 16];
            let got = if is_composed(&p.step.cmd) {
                match composed(&mut cell, &truth, &p.step, p.at, id) {
                    Ok(()) => Got::Appended,
                    Err(r) => Got::Refused(r),
                }
            } else {
                match admit(&mut cell, &p.step, p.at, id) {
                    Ok(a) => match cell.execute(a) {
                        Ok(()) => Got::Appended,
                        Err(ExecError::Refused(CellRefusal::Domain(r))) => Got::Refused(r),
                        Err(e) => panic!("{context}: CellEngine failed with {e:?}"),
                    },
                    Err(deny) => Got::Denied(deny),
                }
            };
            match (want, got) {
                (Ok(records), Got::Appended) => {
                    let entries = cell.entries();
                    let got =
                        relative_positions(&core_records(&entries[before..]), cell_start).unwrap();
                    let want = relative_positions(&records, engine_start).unwrap();
                    assert_eq!(got, want, "{context}");
                    compared += 1;
                }
                (Err(w), Got::Refused(r)) => assert_eq!(r, w, "{context}"),
                // The gate refused a step the reference refuses too.
                (Err(_), Got::Denied(_)) => {}
                (w, c) => panic!("{context}: the reference gave {w:?}, CellEngine gave {c:?}"),
            }
        }
        assert!(
            compared + 2 >= path.len(),
            "{target:?}: only {compared} of {} steps appended",
            path.len()
        );
        drop(cell.stop());
    }
}
