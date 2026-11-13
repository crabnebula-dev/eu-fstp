//! The erasure runner of a cell: one erasure batch from root epoch `e` to
//! `e + 1`, in the order of M3 design section 3.5 (I-81, R-KY-02,
//! ADR-007, and ADR-004 "Reconciliation" as Daniel answered it on
//! 2026-10-29).
//!
//! Lane W3a (agent two, test author) wrote these tests before the runner.
//! Each test runs `fstp_cell::tasks` erasure runner through the seam
//! [`run_erasure`]. The seam refuses with `NotImplemented` until the
//! runner exists, so each test is red for that reason only. The
//! production agent replaces the seam body and leaves the assertions
//! alone.
//!
//! The steps of one batch (design section 3.5):
//!
//! 1. Record the requests and an intent row. The keys cannot be opened
//!    from here on.
//! 2. Rotate each affected group to a new generation, resealing every
//!    surviving sibling.
//! 3. Create `R(e+1)` in custody, wrap a fresh `S(e+1)` under it, and
//!    reseal every live group secret under `S(e+1)`.
//! 4. Commit the new rows in one transaction.
//! 5. Take a keystore snapshot and verify it from a scratch restore.
//! 6. Destroy `R(e)` in custody and keep the receipt.
//! 7. Append `KeyEpochDestroyed` and the `TextErased` records in one
//!    batch.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod stepup_common;

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use fstp_auth::{Method, SessionView};
use fstp_cell::engine::{CellEngine, Unanchored, VaultClient, read_after};
use fstp_cell::tasks::SystemClock;
use fstp_cell::tasks::erasure::{self, ErasureEvent, ErasureRunner, OpenRefusal};
use fstp_cell_core::driver::VaultFault;
use fstp_cell_core::gate::{self, Action, HighRiskAction, LoginPolicy, StepUpView};
use fstp_cell_core::tenant::TenantCommand;
use fstp_cell_core::text::{TextCommand, TextRecord};
use fstp_cell_core::{CellCommand, CellRecord, KeyRecord, action_digest};
use fstp_crypto::aead;
use fstp_custody::{
    Aad, BackendId, Custody as CustodyBackend, CustodyError, CustodyHandle, DestroyReceipt,
    EcdsaSignature, Refusal, RootLabel, RootRef, SealKey, SignKeyRef, UsageCursor, UsagePage,
    WrappedSealKey,
};
use fstp_domain::id::{AccountId, VaultEpoch};
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::time::Timestamp;
use fstp_ledger::{MemStore, Seq};
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{Runtime as _, Shutdown};

/// An operation of the runner, in the order it completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    /// Step 1: the erasure requests and the intent row were committed.
    RequestRecorded,
    /// Step 2: the affected groups were rotated to a new generation.
    GroupsRotated,
    /// Step 3: `R(epoch)` was created in custody.
    RootCreated { epoch: u64 },
    /// Step 3: `S(epoch)` was wrapped under `R(epoch)`.
    SealKeyWrapped { epoch: u64 },
    /// Step 3: every live group secret was resealed under `S(epoch)`.
    GroupsResealed { epoch: u64 },
    /// Step 4: the new rows of `epoch` were committed.
    Committed { epoch: u64 },
    /// Step 5: a keystore snapshot under `R(epoch)` was taken.
    SnapshotTaken { epoch: u64 },
    /// Step 5: the snapshot opened a sample of live keys from a scratch
    /// restore.
    SnapshotVerified { epoch: u64 },
    /// Step 6: `R(epoch)` was destroyed in custody and its receipt kept.
    RootDestroyed { epoch: u64 },
    /// Step 7: the completion batch was committed.
    CompletionRecorded { epoch: u64 },
}

/// How custody behaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Custody {
    /// Every operation succeeds.
    Healthy,
    /// The runner process crashes right after it completes operation
    /// number `k` of the healthy run, counted from 0. It then restarts
    /// and resumes from the stored phase.
    CrashAfter(usize),
    /// Operation number `k` of the healthy run fails once, with a custody,
    /// store or snapshot error. The runner retries.
    FailAt(usize),
}

/// What a run did.
#[derive(Debug)]
struct ErasureRun {
    /// The epoch the batch started from: `e`.
    from: u64,
    /// Every operation, across restarts, in order of completion.
    ops: Vec<Op>,
    /// Every ledger record the run appended, in order.
    ledger: Vec<CellRecord>,
    /// For each open of an erased text tried after `RequestRecorded` and
    /// before `CompletionRecorded`, whether it returned the text.
    opened_after_request: Vec<bool>,
    /// The texts the runner reported erased.
    erased: Vec<[u8; 16]>,
    /// The number of custody calls that changed custody state: creates
    /// and destroys.
    custody_changes: usize,
    /// The number of custody calls served: creates, wraps, unwraps and
    /// destroys.
    custody_calls: usize,
}

/// The cell of these tests.
const CELL: [u8; 16] = [0xE5; 16];
/// The tenant admin who requests the erasures.
const ADMIN: AccountId = AccountId::from_raw(1);
/// The two text groups.
const G1: [u8; 16] = [0x61; 16];
const G2: [u8; 16] = [0x62; 16];

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A custody call, for the failure script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Create,
    Wrap,
    Unwrap,
    Destroy,
}

/// An in-memory custody backend that counts state changes and served
/// calls, and fails the next call of one kind once.
#[derive(Default)]
struct SimCustody {
    roots: Mutex<BTreeMap<Vec<u8>, [u8; 32]>>,
    next: Mutex<u64>,
    changes: Mutex<usize>,
    calls: Mutex<usize>,
    fail: Mutex<Option<Call>>,
}

#[derive(Clone, Default)]
struct Custodian(Arc<SimCustody>);

impl Custodian {
    fn fails(&self, call: Call) -> bool {
        let mut f = lock(&self.0.fail);
        if *f == Some(call) {
            *f = None;
            true
        } else {
            false
        }
    }

    fn root(&self, root: &RootRef) -> Result<aead::Key, CustodyError> {
        let rk = *lock(&self.0.roots)
            .get(&root.handle.0)
            .ok_or(CustodyError::Refused(Refusal::UnknownRoot))?;
        aead::Key::from_bytes(&rk).map_err(CustodyError::Crypto)
    }
}

const DOWN: CustodyError = CustodyError::Transport("scripted custody failure");

impl CustodyBackend for Custodian {
    fn create_root(
        &self,
        label: RootLabel,
    ) -> impl Future<Output = Result<RootRef, CustodyError>> + Send {
        let r = (|| {
            if self.fails(Call::Create) {
                return Err(DOWN);
            }
            let mut key = [0u8; 32];
            fstp_crypto::random_bytes(&mut key).map_err(CustodyError::Crypto)?;
            let handle = {
                let mut n = lock(&self.0.next);
                *n += 1;
                n.to_be_bytes().to_vec()
            };
            lock(&self.0.roots).insert(handle.clone(), key);
            *lock(&self.0.changes) += 1;
            *lock(&self.0.calls) += 1;
            Ok(RootRef {
                backend: BackendId::Simulator,
                cell: label.cell,
                chain: label.chain,
                epoch: label.epoch,
                handle: CustodyHandle(handle),
            })
        })();
        std::future::ready(r)
    }

    fn wrap(
        &self,
        root: &RootRef,
        key: &SealKey,
        aad: &Aad,
    ) -> impl Future<Output = Result<WrappedSealKey, CustodyError>> + Send {
        let r = (|| {
            if self.fails(Call::Wrap) {
                return Err(DOWN);
            }
            let k = self.root(root)?;
            let s = aead::seal(&k, &aad.0, key.expose()).map_err(CustodyError::Crypto)?;
            let mut out = s.nonce.to_vec();
            out.extend_from_slice(&s.body);
            *lock(&self.0.calls) += 1;
            Ok(WrappedSealKey(out))
        })();
        std::future::ready(r)
    }

    fn unwrap(
        &self,
        root: &RootRef,
        w: &WrappedSealKey,
        aad: &Aad,
    ) -> impl Future<Output = Result<SealKey, CustodyError>> + Send {
        let r = (|| {
            if self.fails(Call::Unwrap) {
                return Err(DOWN);
            }
            let k = self.root(root)?;
            let (nonce, body) = w.0.split_at(aead::NONCE_LEN);
            let nonce: [u8; aead::NONCE_LEN] = nonce.try_into().unwrap();
            let pt = aead::open(&k, &nonce, &aad.0, body)
                .map_err(|_| CustodyError::Refused(Refusal::UnwrapFailed))?;
            *lock(&self.0.calls) += 1;
            Ok(SealKey::from_bytes(pt.as_slice().try_into().unwrap()))
        })();
        std::future::ready(r)
    }

    fn destroy(
        &self,
        root: &RootRef,
    ) -> impl Future<Output = Result<DestroyReceipt, CustodyError>> + Send {
        let r = (|| {
            if self.fails(Call::Destroy) {
                return Err(DOWN);
            }
            if lock(&self.0.roots).remove(&root.handle.0).is_none() {
                return Err(CustodyError::Refused(Refusal::UnknownRoot));
            }
            *lock(&self.0.changes) += 1;
            *lock(&self.0.calls) += 1;
            Ok(DestroyReceipt(root.handle.0.clone()))
        })();
        std::future::ready(r)
    }

    fn sign(
        &self,
        _key: &SignKeyRef,
        _digest: &[u8; 32],
    ) -> impl Future<Output = Result<EcdsaSignature, CustodyError>> + Send {
        std::future::ready(Err(CustodyError::Refused(Refusal::NoSignKey)))
    }

    fn usage_since(
        &self,
        _root: &RootRef,
        _cursor: UsageCursor,
    ) -> impl Future<Output = Result<UsagePage, CustodyError>> + Send {
        std::future::ready(Ok(UsagePage::default()))
    }
}

/// A vault at the genesis epoch: these commands ask no query.
struct GenesisVault;

impl VaultClient for GenesisVault {
    fn epoch(&self) -> impl Future<Output = Result<VaultEpoch, VaultFault>> + Send {
        std::future::ready(Ok(VaultEpoch::GENESIS))
    }

    fn ask(
        &self,
        _queries: &[Query],
        _reaction_for: Option<VaultEpoch>,
        _at: Timestamp,
    ) -> impl Future<Output = Result<Answers, VaultFault>> + Send {
        std::future::ready(Err(VaultFault::Unavailable))
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

/// The tenant admin's session.
const SESSION: [u8; 16] = [0x5E; 16];
/// The command id byte of the first tenant admin grant.
const GRANT_ADMIN: u8 = 0xA0;

/// An empty store that holds the step-up for the first tenant admin
/// grant, as the ledger granted it (`stepup_common`), and that step-up's
/// id.
fn store_with_admin_stepup() -> Result<(MemStore<CellRecord>, [u8; 16]), &'static str> {
    let mut mem = MemStore::new();
    let stepup = stepup_common::grant_stepup(
        &mut mem,
        SESSION,
        ADMIN,
        &CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: ADMIN }),
        [GRANT_ADMIN; 16],
        fstp_cell::tasks::system_now(),
    )
    .map_err(|_| "the step-up was not granted")?;
    Ok((mem, stepup))
}

/// Runs `cmd` as the tenant admin, through the gate, with the fresh
/// strong step-up `stepup` that the ledger granted, when it is high
/// risk.
async fn as_admin(
    engine: &CellEngine,
    cmd: CellCommand,
    id: u8,
    stepup: Option<[u8; 16]>,
) -> Result<(), &'static str> {
    let now = Timestamp::from_micros(fstp_cell::tasks::system_now());
    let session = SessionView {
        id: SESSION,
        account: ADMIN,
        method: Method::Passkey,
        started: now,
        last_used: now,
    };
    let command_id = [id; 16];
    let action = Action::Command(cmd.clone());
    let high = HighRiskAction::of(&action).map_err(|_| "no risk class")?;
    let stepup = high.zip(stepup).map(|(_, stepup)| StepUpView {
        id: stepup,
        session: session.id,
        action_digest: action_digest(&cmd, command_id),
        asserted_at: now,
        strong: true,
        consumed: false,
    });
    let policy = LoginPolicy {
        stepup_freshness_us: 5 * 60 * 1_000_000,
    };
    let admitted = gate::admit_command(
        &engine.state(),
        &session,
        action,
        command_id,
        stepup.as_ref(),
        now,
        &policy,
    )
    .map_err(|_| "the gate refused the tenant admin")?;
    engine
        .execute(admitted)
        .await
        .map(|_| ())
        .map_err(|_| "the tenant admin command failed")
}

fn op_of(e: ErasureEvent) -> Op {
    match e {
        ErasureEvent::RequestRecorded => Op::RequestRecorded,
        ErasureEvent::GroupsRotated => Op::GroupsRotated,
        ErasureEvent::RootCreated { epoch } => Op::RootCreated { epoch },
        ErasureEvent::SealKeyWrapped { epoch } => Op::SealKeyWrapped { epoch },
        ErasureEvent::GroupsResealed { epoch } => Op::GroupsResealed { epoch },
        ErasureEvent::Committed { epoch } => Op::Committed { epoch },
        ErasureEvent::SnapshotTaken { epoch } => Op::SnapshotTaken { epoch },
        ErasureEvent::SnapshotVerified { epoch } => Op::SnapshotVerified { epoch },
        ErasureEvent::RootDestroyed { epoch } => Op::RootDestroyed { epoch },
        ErasureEvent::CompletionRecorded { epoch } => Op::CompletionRecorded { epoch },
    }
}

/// The custody call that operation `k` of a healthy batch makes, if any.
/// Steps 1, 2, 3 (reseal), 4 and 5 (snapshot) call no custody operation,
/// so a failure there cannot be scripted and the batch runs healthy.
fn call_at(k: usize) -> Option<Call> {
    match k {
        2 => Some(Call::Create),
        3 => Some(Call::Wrap),
        7 => Some(Call::Unwrap),
        8 => Some(Call::Destroy),
        _ => None,
    }
}

/// Seam: starts a cell over in-memory parts with two texts in one group
/// and a third text in another group, all live under root epoch `e`.
/// Requests the erasure of `texts` of the first group, tries to open each
/// erased text after the request, then runs the erasure runner under
/// `custody` until the batch completes. A request in `late` arrives once
/// the runner has completed `late.0` operations and names the text
/// `late.1`.
fn run_erasure(
    texts: &[[u8; 16]],
    custody: Custody,
    late: Option<(usize, [u8; 16])>,
) -> Result<ErasureRun, &'static str> {
    let rt = TokioRuntime::new_multi_thread(2).map_err(|_| "no runtime")?;
    let rt2 = rt.clone();
    let texts = texts.to_vec();
    rt.block_on(async move {
        let (mem, stepup) = store_with_admin_stepup()?;
        let store = Unanchored::open(mem, CELL)
            .await
            .map_err(|_| "the store did not open")?;
        let shutdown = Shutdown::new();
        let (engine, task) = CellEngine::start(&rt2, store, GenesisVault, &shutdown, 8)
            .await
            .map_err(|_| "the engine did not start")?;
        as_admin(
            &engine,
            CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: ADMIN }),
            GRANT_ADMIN,
            Some(stepup),
        )
        .await?;
        for (n, t) in [T1, T2, T3].into_iter().enumerate() {
            let id = 0xA1 + u8::try_from(n).unwrap();
            as_admin(
                &engine,
                CellCommand::Text(TextCommand::PutText { id: t }),
                id,
                None,
            )
            .await?;
        }
        let sim = Custodian::default();
        let mut runner = ErasureRunner::genesis(sim.clone(), engine.clone(), CELL)
            .await
            .map_err(|_| "the key chain did not start")?;
        runner.add_group(G1).map_err(|_| "no group 1")?;
        runner.add_group(G2).map_err(|_| "no group 2")?;
        runner
            .put_text(G1, T1, b"synthetic text one")
            .map_err(|_| "no T1")?;
        runner
            .put_text(G1, T2, b"synthetic text two")
            .map_err(|_| "no T2")?;
        runner
            .put_text(G2, T3, b"synthetic text three")
            .map_err(|_| "no T3")?;
        let from = runner.keystore().epoch();
        let before = engine.state().head();
        let changes_before = *lock(&sim.0.changes);
        let calls_before = *lock(&sim.0.calls);
        as_admin(
            &engine,
            CellCommand::Text(TextCommand::EraseTexts {
                ids: texts.clone(),
                cause: 2,
            }),
            0xB0,
            None,
        )
        .await?;
        let opened_after_request: Vec<bool> = texts
            .iter()
            .map(|t| runner.open_text(&engine.state(), *t).is_ok())
            .collect();
        if let Custody::FailAt(k) = custody {
            *lock(&sim.0.fail) = call_at(k);
        }
        let mut ops: Vec<Op> = Vec::new();
        let mut erased: Vec<[u8; 16]> = Vec::new();
        let mut late = late;
        let mut crashed = false;
        let mut failures = 0usize;
        loop {
            if let Some((at, t)) = late
                && ops.len() >= at
            {
                late = None;
                as_admin(
                    &engine,
                    CellCommand::Text(TextCommand::EraseTexts {
                        ids: vec![t],
                        cause: 2,
                    }),
                    0xB1,
                    None,
                )
                .await?;
            }
            match runner.step().await {
                Ok(Some(e)) => ops.push(op_of(e)),
                Ok(None) => break,
                Err(_) => {
                    failures += 1;
                    if failures > 16 {
                        return Err("the runner did not recover from a failure");
                    }
                    continue;
                }
            }
            if let Custody::CrashAfter(k) = custody
                && !crashed
                && ops.len() == k + 1
            {
                // The process crashes: only the durable keystore and the
                // ledger survive. The runner resumes from them.
                crashed = true;
                erased.extend_from_slice(runner.erased());
                let store = runner.keystore().clone();
                drop(runner);
                runner = ErasureRunner::resume(sim.clone(), engine.clone(), store)
                    .await
                    .map_err(|_| "the runner did not resume")?;
            }
        }
        erased.extend_from_slice(runner.erased());
        let custody_changes = *lock(&sim.0.changes) - changes_before;
        let custody_calls = *lock(&sim.0.calls) - calls_before;
        drop(runner);
        drop(engine);
        let store = task.await.map_err(|_| "the engine task failed")?;
        let ledger = read_after(&store, before)
            .await
            .map_err(|_| "the ledger read failed")?
            .into_iter()
            .map(|e| e.record)
            .collect();
        Ok(ErasureRun {
            from,
            ops,
            ledger,
            opened_after_request,
            erased,
            custody_changes,
            custody_calls,
        })
    })
}

/// The first two texts, in the first group.
const T1: [u8; 16] = [0x71; 16];
const T2: [u8; 16] = [0x72; 16];
/// The third text, in the second group.
const T3: [u8; 16] = [0x73; 16];

fn run(texts: &[[u8; 16]], custody: Custody) -> ErasureRun {
    run_erasure(texts, custody, None).unwrap_or_else(|e| panic!("{e}"))
}

/// The operations of one healthy batch from epoch `e`, in design order.
fn design_order(e: u64) -> Vec<Op> {
    let next = e + 1;
    vec![
        Op::RequestRecorded,
        Op::GroupsRotated,
        Op::RootCreated { epoch: next },
        Op::SealKeyWrapped { epoch: next },
        Op::GroupsResealed { epoch: next },
        Op::Committed { epoch: next },
        Op::SnapshotTaken { epoch: next },
        Op::SnapshotVerified { epoch: next },
        Op::RootDestroyed { epoch: e },
        Op::CompletionRecorded { epoch: e },
    ]
}

/// `ops` with repeats removed, keeping the first of each. A resumed run
/// may redo an idempotent step. It may never reorder steps.
fn first_of_each(ops: &[Op]) -> Vec<Op> {
    let mut out: Vec<Op> = Vec::new();
    for op in ops {
        if !out.contains(op) {
            out.push(*op);
        }
    }
    out
}

fn count(ops: &[Op], op: Op) -> usize {
    ops.iter().filter(|o| **o == op).count()
}

/// I-81, design section 3.5: a healthy batch runs the seven steps in
/// design order, each once.
#[test]
fn i81_cell_erasure_runner_runs_the_design_steps_in_order() {
    let r = run(&[T1], Custody::Healthy);
    assert_eq!(r.ops, design_order(r.from), "{r:?}");
}

/// I-81, design section 3.5: an erasure is complete only at step 7. The
/// completion batch holds `EpochDestroyed` for `e` and `TextsErased` for
/// the requested texts. It is appended after the destroy receipt, and
/// after the request record.
#[test]
fn i81_cell_erasure_completion_is_recorded_only_after_the_destroy_receipt() {
    let r = run(&[T1, T2], Custody::Healthy);
    let destroyed = r
        .ops
        .iter()
        .position(|o| *o == Op::RootDestroyed { epoch: r.from });
    let completed = r
        .ops
        .iter()
        .position(|o| *o == Op::CompletionRecorded { epoch: r.from });
    let requested = r.ledger.iter().position(|x| {
        matches!(x, CellRecord::Text(TextRecord::ErasureRequested { ids, .. }) if ids == &vec![T1, T2])
    });
    let epoch_record = r.ledger.iter().position(|x| {
        matches!(x, CellRecord::Key(KeyRecord::EpochDestroyed { epoch, .. }) if *epoch == r.from)
    });
    let erased_record = r.ledger.iter().position(
        |x| matches!(x, CellRecord::Text(TextRecord::TextsErased { ids }) if ids == &vec![T1, T2]),
    );
    let ok = matches!((destroyed, completed), (Some(d), Some(c)) if d < c)
        && matches!(
            (requested, epoch_record, erased_record),
            (Some(q), Some(k), Some(t)) if q < k && q < t
        );
    assert!(ok, "{r:?}");
}

/// I-81, design section 3.4: a text under destruction cannot be opened
/// from the moment its request is recorded.
#[test]
fn i81_cell_text_cannot_be_opened_once_its_erasure_is_requested() {
    let r = run(&[T1, T2], Custody::Healthy);
    assert!(
        !r.opened_after_request.is_empty() && r.opened_after_request.iter().all(|o| !o),
        "{r:?}"
    );
}

/// I-81, design section 3.5: a crash after any operation loses nothing.
/// The runner resumes from the stored phase, keeps the design order, and
/// destroys the old root exactly once, after the snapshot is verified.
#[test]
fn i81_cell_erasure_runner_resumes_after_a_crash_at_every_step() {
    let steps = design_order(0).len();
    let mut bad = Vec::new();
    for k in 0..steps {
        let r = run(&[T1], Custody::CrashAfter(k));
        let ok = first_of_each(&r.ops) == design_order(r.from)
            && count(&r.ops, Op::RootDestroyed { epoch: r.from }) == 1
            && r.erased == vec![T1];
        if !ok {
            bad.push((k, r));
        }
    }
    assert!(bad.is_empty(), "crash points that broke the batch: {bad:?}");
}

/// I-81, design section 3.5 (M-SHRED fault "custody failure after any
/// operation"): a custody failure at any step delays the batch and never
/// reorders it. The old root is destroyed once, and only after the new
/// rows commit and the snapshot verifies.
#[test]
fn i81_cell_erasure_runner_survives_a_custody_failure_at_every_step() {
    let steps = design_order(0).len();
    let mut bad = Vec::new();
    for k in 0..steps {
        let r = run(&[T1], Custody::FailAt(k));
        let ok = first_of_each(&r.ops) == design_order(r.from)
            && count(&r.ops, Op::RootDestroyed { epoch: r.from }) == 1
            && r.erased == vec![T1];
        if !ok {
            bad.push((k, r));
        }
    }
    assert!(
        bad.is_empty(),
        "failure points that broke the batch: {bad:?}"
    );
}

/// I-81, design section 3.5: a request that arrives while a batch runs
/// joins the next batch, which follows at once. Two root epochs are
/// destroyed, in order, and each text is erased in its own batch.
#[test]
fn i81_cell_erasure_request_during_a_batch_joins_the_next_batch() {
    let r = run_erasure(&[T1], Custody::Healthy, Some((3, T3))).unwrap_or_else(|e| panic!("{e}"));
    let destroyed: Vec<u64> = r
        .ops
        .iter()
        .filter_map(|o| match o {
            Op::RootDestroyed { epoch } => Some(*epoch),
            _ => None,
        })
        .collect();
    let batches: Vec<Vec<[u8; 16]>> = r
        .ledger
        .iter()
        .filter_map(|x| match x {
            CellRecord::Text(TextRecord::TextsErased { ids }) => Some(ids.clone()),
            _ => None,
        })
        .collect();
    assert!(
        destroyed == vec![r.from, r.from + 1] && batches == vec![vec![T1], vec![T3]],
        "{r:?}"
    );
}

/// I-24, ADR-004 "Reconciliation" (Daniel, 2026-10-29): every custody
/// call has its `RecordKeyOp` ledger record, so key records reconcile with
/// custody operations. Daniel decided on 2026-11-13 that ADR-004 wins
/// (m3-exit-audit section 7, item 3, Q-KEYOP): the expected count is
/// one record per custody call (create, wrap, unwrap, destroy), not one
/// per state change.
#[test]
fn i24_cell_erasure_runner_records_a_key_op_for_each_custody_change() {
    let r = run(&[T1], Custody::Healthy);
    let key_ops = r
        .ledger
        .iter()
        .filter(|x| matches!(x, CellRecord::Key(KeyRecord::KeyOpRecorded { .. })))
        .count();
    assert!(
        r.custody_changes >= 2 && key_ops == r.custody_calls,
        "{r:?}"
    );
}

/// The resume predicate itself: it keeps the first of each operation, so
/// a redone step passes and a reordered one fails.
#[test]
fn i81_resume_predicate_refuses_a_reordered_batch() {
    let mut redone = design_order(4);
    redone.insert(3, Op::RootCreated { epoch: 5 });
    let mut reordered = design_order(4);
    reordered.swap(5, 8);
    let ok =
        first_of_each(&redone) == design_order(4) && first_of_each(&reordered) != design_order(4);
    assert!(ok, "the resume predicate is wrong");
}

/// What the erasure task of a started cell did with one requested text.
#[derive(Debug)]
struct TaskRun {
    /// Whether the text opened through the handle before its request.
    opened_before: bool,
    /// The texts the task reported erased, without any caller driving it.
    erased: Vec<[u8; 16]>,
    /// How the text opened through the handle after the batch.
    after: Result<(), OpenRefusal>,
    /// Whether the task left the drain once shutdown was triggered.
    drained: bool,
}

/// Seam: runs the erasure task of design section 3.5 as a started cell
/// runs it (`fstp_cell::engine::startup::start`), with no caller that
/// drives the runner. Stores `T1` through the handle, records its erasure
/// request, and waits up to ten seconds for the task to report it erased.
fn run_erasure_task() -> Result<TaskRun, &'static str> {
    let rt = TokioRuntime::new_multi_thread(2).map_err(|_| "no runtime")?;
    let rt2 = rt.clone();
    rt.block_on(async move {
        let (mem, stepup) = store_with_admin_stepup()?;
        let store = Unanchored::open(mem, CELL)
            .await
            .map_err(|_| "the store did not open")?;
        let shutdown = Shutdown::new();
        let (engine, task) = CellEngine::start(&rt2, store, GenesisVault, &shutdown, 8)
            .await
            .map_err(|_| "the engine did not start")?;
        as_admin(
            &engine,
            CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: ADMIN }),
            GRANT_ADMIN,
            Some(stepup),
        )
        .await?;
        as_admin(
            &engine,
            CellCommand::Text(TextCommand::PutText { id: T1 }),
            0xA1,
            None,
        )
        .await?;
        let runner = ErasureRunner::genesis(Custodian::default(), engine.clone(), CELL)
            .await
            .map_err(|_| "the key chain did not start")?;
        let (handle, run) = erasure::task(runner, SystemClock::new(rt2.clone()), shutdown.signal());
        drop(rt2.spawn(run));
        handle.add_group(G1).await.map_err(|_| "no group 1")?;
        handle
            .put_text(G1, T1, b"synthetic text one".to_vec())
            .await
            .map_err(|_| "no T1")?;
        let opened_before = handle
            .open_text(T1)
            .await
            .is_ok_and(|t| t.as_slice() == b"synthetic text one");
        as_admin(
            &engine,
            CellCommand::Text(TextCommand::EraseTexts {
                ids: vec![T1],
                cause: 2,
            }),
            0xB0,
            None,
        )
        .await?;
        for _ in 0..500 {
            if !handle.erased().is_empty() {
                break;
            }
            rt2.sleep(Duration::from_millis(20)).await;
        }
        let erased = handle.erased();
        let after = handle.open_text(T1).await.map(|_| ());
        shutdown.trigger();
        drop(engine);
        let drained = fstp_rt::timeout(&rt2, Duration::from_secs(10), shutdown.drained())
            .await
            .is_ok();
        let _ = task.await;
        Ok(TaskRun {
            opened_before,
            erased,
            after,
            drained,
        })
    })
}

/// I-81, design section 3.5 ("erasure completes in seconds, and no batch
/// waits for a timer"): the erasure task of a started cell runs a batch
/// to its end as soon as the request is in the ledger, with no caller
/// driving the runner. The text then resolves to its erasure-log entry,
/// and the task joins the drain (ADR-002).
#[test]
fn i81_cell_erasure_task_completes_a_requested_batch_on_its_own() {
    let r = run_erasure_task().unwrap_or_else(|e| panic!("{e}"));
    let ok =
        r.opened_before && r.erased == vec![T1] && r.after == Err(OpenRefusal::Erased) && r.drained;
    assert!(ok, "{r:?}");
}

/// The context of the notice companion signature
/// (`fstp_contract::notice_companion::NOTICE_COMPANION_CONTEXT`, M9 D6).
const COMPANION_CONTEXT: &[u8] = b"fstp-notice-companion-v1";

/// What the signing key test saw.
struct SignerRun {
    first: Vec<u8>,
    again: Vec<u8>,
    after_batch: Vec<u8>,
    rotated: Vec<u8>,
    after_restart: Vec<u8>,
    history: Vec<(u32, Vec<u8>)>,
    anchor_refused: bool,
    from: u64,
    to: u64,
    signature_verifies: bool,
    due_now: bool,
    due_in_a_year: bool,
}

/// Seam: a cell with one text, the notice companion key created through
/// the keystore, an erasure batch that crashes before its commit and
/// resumes, then a rotation and a restart.
fn run_signer() -> Result<SignerRun, &'static str> {
    use fstp_cell::tasks::erasure::SIGNER_LIFETIME_US;
    use fstp_keys::Purpose;
    let rt = TokioRuntime::new_multi_thread(2).map_err(|_| "no runtime")?;
    let rt2 = rt.clone();
    rt.block_on(async move {
        let (mem, stepup) = store_with_admin_stepup()?;
        let store = Unanchored::open(mem, CELL)
            .await
            .map_err(|_| "the store did not open")?;
        let shutdown = Shutdown::new();
        let (engine, _task) = CellEngine::start(&rt2, store, GenesisVault, &shutdown, 8)
            .await
            .map_err(|_| "the engine did not start")?;
        as_admin(
            &engine,
            CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: ADMIN }),
            GRANT_ADMIN,
            Some(stepup),
        )
        .await?;
        as_admin(
            &engine,
            CellCommand::Text(TextCommand::PutText { id: T1 }),
            0xA1,
            None,
        )
        .await?;
        let sim = Custodian::default();
        let mut runner = ErasureRunner::genesis(sim.clone(), engine.clone(), CELL)
            .await
            .map_err(|_| "the key chain did not start")?;
        runner.add_group(G1).map_err(|_| "no group 1")?;
        runner
            .put_text(G1, T1, b"synthetic text one")
            .map_err(|_| "no T1")?;
        let first = runner
            .ensure_signer(Purpose::NoticeCompanion)
            .map_err(|_| "no notice companion key")?;
        let again = runner
            .ensure_signer(Purpose::NoticeCompanion)
            .map_err(|_| "no notice companion key")?;
        let anchor_refused = runner.ensure_signer(Purpose::Anchor).is_err();
        let key = runner
            .signer(Purpose::NoticeCompanion)
            .map_err(|_| "no signer")?;
        let sig = key
            .sign_with_context(b"synthetic notice digest", COMPANION_CONTEXT)
            .map_err(|_| "no signature")?;
        let signature_verifies = fstp_crypto::composite::verify_with_context(
            &first,
            b"synthetic notice digest",
            COMPANION_CONTEXT,
            &sig.to_bytes(),
        )
        .is_ok();
        let from = runner.keystore().epoch();
        as_admin(
            &engine,
            CellCommand::Text(TextCommand::EraseTexts {
                ids: vec![T1],
                cause: 2,
            }),
            0xB0,
            None,
        )
        .await?;
        let mut steps = 0usize;
        let mut crashed = false;
        while runner.step().await.map_err(|_| "a step failed")?.is_some() {
            steps += 1;
            if !crashed && steps == 5 {
                // The process crashes after the reseal, before the commit.
                crashed = true;
                let store = runner.keystore().clone();
                drop(runner);
                runner = ErasureRunner::resume(sim.clone(), engine.clone(), store)
                    .await
                    .map_err(|_| "the runner did not resume")?;
            }
        }
        let to = runner.keystore().epoch();
        // A restart from the durable keystore under the new epoch only.
        let store = runner.keystore().clone();
        drop(runner);
        let mut runner = ErasureRunner::resume(sim.clone(), engine.clone(), store)
            .await
            .map_err(|_| "the runner did not resume after the batch")?;
        let after_batch = runner
            .signer(Purpose::NoticeCompanion)
            .map_err(|_| "the key did not survive the batch")?
            .public_key()
            .to_bytes()
            .to_vec();
        let rotated = runner
            .rotate_signer(Purpose::NoticeCompanion)
            .map_err(|_| "no rotation")?;
        let store = runner.keystore().clone();
        drop(runner);
        let runner = ErasureRunner::resume(sim.clone(), engine.clone(), store)
            .await
            .map_err(|_| "the runner did not resume after the rotation")?;
        let after_restart = runner
            .signer(Purpose::NoticeCompanion)
            .map_err(|_| "the rotated key did not reopen")?
            .public_key()
            .to_bytes()
            .to_vec();
        let ks = runner.keystore();
        let now = fstp_cell::tasks::system_now();
        Ok(SignerRun {
            first,
            again,
            after_batch,
            rotated,
            after_restart,
            history: ks.signer_public_keys(Purpose::NoticeCompanion),
            anchor_refused,
            from,
            to,
            signature_verifies,
            due_now: ks.signer_due(Purpose::NoticeCompanion, now),
            due_in_a_year: ks.signer_due(Purpose::NoticeCompanion, now + SIGNER_LIFETIME_US),
        })
    })
}

/// R-CR-04, ADR-004, M9 decision CD4: the keystore creates the notice
/// companion key once, under the chain's seal key that custody wraps.
/// The key signs under the companion context, survives an erasure batch
/// with a crash before its commit (resealed under the new epoch, while
/// the old root is destroyed), and rotates to a new generation whose
/// predecessor's public key stays listed. No other purpose is held.
#[test]
fn r_cr_04_keystore_holds_and_rotates_the_notice_companion_key() {
    let r = run_signer().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.first, r.again, "one key per purpose");
    assert!(r.anchor_refused, "the Anchor key is not the keystore's");
    assert!(r.signature_verifies, "the key signs a companion signature");
    assert_eq!(r.to, r.from + 1, "the batch moved the epoch");
    assert_eq!(r.after_batch, r.first, "the key survives the batch");
    assert_ne!(r.rotated, r.first, "a rotation makes a new key");
    assert_eq!(r.after_restart, r.rotated, "the new generation reopens");
    assert_eq!(
        r.history,
        vec![(1, r.first.clone()), (2, r.rotated.clone())]
    );
    assert!(
        !r.due_now && r.due_in_a_year,
        "yearly rotation is due after one year"
    );
}
