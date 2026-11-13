//! The async engine of a cell (design sections 5.2, 5.4 and 5.5, ADR-007,
//! I-23, NOTE 2 to NOTE 5).
//!
//! One engine task per cell owns `CellState` and runs one
//! [`DriverCore`] at a time (single writer). Handlers send [`Admitted`]
//! commands over a bounded channel through [`CellEngine::execute`], the
//! only way a command reaches `DriverCore` (design section 5.4).
//!
//! The task is the shell of the sans-IO driver. It answers each
//! [`Need`] with one call: a store read or append ([`CellStore`]), or a
//! vault call ([`VaultClient`]). The store is any
//! [`fstp_ledger::AsyncRecordStore`] of `CellRecord` that also reports the
//! chain link and witness receipt of each committed append. The anchoring
//! in-memory store of [`crate::witness`] runs the append protocol of
//! design section 5.3 in memory, for tests and the demo path.
//! [`pg::PgCellStore`] runs it over `fstp_pgstore::PgRecordStore`, the
//! store of a serving cell. [`Unanchored`] wraps a plain store, such as
//! `fstp_ledger::MemStore`, for tests and models: it records no receipts.
//!
//! # Start and restart
//!
//! [`CellEngine::start`] replays the whole store into `CellState` before
//! the engine takes a command (design section 5.5). A crash retry under a
//! committed command id is then reported as a duplicate of the stored
//! entry, and a new command commits after the replayed head (ADR-007).
//!
//! # Bounded calls
//!
//! Every vault call is bounded by [`VAULT_TIMEOUT`] and every store call
//! by [`STORE_TIMEOUT`], on the cell's runtime timer. A vault call that
//! does not answer in time fails as [`VaultFault::Unavailable`], so the
//! command fails closed (NOTE 2). A store call that does not answer in
//! time fails as [`StoreError::Unavailable`]. The store call carries the
//! witness round trips of the append, so a hung witness fails the same
//! way. A store is cancel safe: an append dropped at its timeout is
//! resolved before the next one, as a crash is (design section 7.2). So
//! one hung call never blocks the single writer for later commands.
//!
//! # Step-up at commit
//!
//! A store checks [`SideEffects::stepup_fresh_until`] against its own
//! commit instant, read from its [`CommitClock`] (design section 8.4,
//! ADR-008, I-78). A stale or replayed step-up refuses the append with
//! [`CellAppendError`]. The engine reports it as the refusal of
//! [`stepup_refusal`], which names I-78, never as an outage. Nothing is
//! committed.
//!
//! # Shutdown
//!
//! The task holds a participant signal of the cell's
//! [`fstp_rt::Shutdown`]. Once shutdown is triggered, it finishes the
//! command in flight, refuses every queued and later command with
//! [`EngineError::ShuttingDown`], and drops its signal (ADR-002). The
//! bounds above keep the command in flight from outliving the drain by
//! more than one call.

pub mod chan;
pub mod pg;
pub mod serve;
pub mod startup;

use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use fstp_cell_core::driver::{
    Done, DriverCore, Event, ExecError, Link, Need, ReceiptRef, SideEffects, Step, VaultFault,
};
use fstp_cell_core::gate::Admitted;
use fstp_cell_core::{CellRecord, CellRefusal, CellState, FoldError};
use fstp_domain::id::VaultEpoch;
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::time::Timestamp;
use fstp_ledger::{AppendError, AsyncRecordStore, Entry, Seq, StoreError};
use fstp_rt::future::{Either, race};
use fstp_rt::{JoinHandle, Runtime, Shutdown, ShutdownSignal};

use chan::{Receiver, ReplyTx, Sender};

/// How many entries one store read asks for.
pub const READ_PAGE: usize = 4096;

/// The default bound of the engine's command channel.
pub const DEFAULT_QUEUE: usize = 64;

/// The bound of one vault call. Interim reading of lane W3a: the design
/// fixes no vault timeout, and this one matches the 10-second call
/// timeout of design section 10.2.
pub const VAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// The bound of one store call, witness round trips included. Interim
/// reading of lane W3a, as [`VAULT_TIMEOUT`].
pub const STORE_TIMEOUT: Duration = Duration::from_secs(10);

/// The clock a store reads its commit instant from, in UTC microseconds.
/// Production uses [`system_commit_clock`]. Tests pass a scripted one.
pub type CommitClock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// The system clock as a [`CommitClock`].
pub fn system_commit_clock() -> CommitClock {
    Arc::new(crate::tasks::system_now)
}

/// Why a store refused an append of a cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellAppendError {
    /// The ledger refused the append, or the store failed.
    Ledger(AppendError),
    /// The batch's step-up was no longer fresh at the store's commit
    /// instant: `stepup_fresh_until` lies before it (design section 8.4,
    /// ADR-008, I-78). Nothing was committed.
    StepUpStale,
    /// The batch's step-up was consumed by an earlier commit (design
    /// section 5.3). Nothing was committed.
    StepUpReplayed,
}

impl From<AppendError> for CellAppendError {
    fn from(e: AppendError) -> CellAppendError {
        CellAppendError::Ledger(e)
    }
}

impl CellAppendError {
    /// The error as the plain ledger contract carries it. A step-up
    /// refusal has no ledger form, so it reads as a store failure there.
    /// The ledger path carries no side effects, so it never meets one.
    pub fn into_ledger(self) -> AppendError {
        match self {
            CellAppendError::Ledger(e) => e,
            CellAppendError::StepUpStale | CellAppendError::StepUpReplayed => {
                AppendError::Store(StoreError::Unavailable)
            }
        }
    }
}

/// Whether a batch whose step-up is valid up to `fresh_until` may commit
/// at `now` (design section 8.4: `now - asserted_at <= P-71`).
pub fn stepup_fresh_at(fresh_until: Option<i64>, now: i64) -> bool {
    fresh_until.is_none_or(|until| now <= until)
}

/// The cell's vault, as the engine reaches it (design sections 5.2 and
/// 6.2). Every fault fails the command closed (NOTE 2).
pub trait VaultClient: Send + Sync + 'static {
    /// The vault's current epoch.
    fn epoch(&self) -> impl Future<Output = Result<VaultEpoch, VaultFault>> + Send;

    /// Answers to `queries` at `at`. `reaction_for` names the epoch of a
    /// reaction, whose questions see the provisional fact (NOTE 4). Each
    /// answer carries the keyed digest of its query (NOTE 5).
    fn ask(
        &self,
        queries: &[Query],
        reaction_for: Option<VaultEpoch>,
        at: Timestamp,
    ) -> impl Future<Output = Result<Answers, VaultFault>> + Send;

    /// Acknowledges the committed reaction to `epoch`, at ledger sequence
    /// `seq` with chain link `link` (NOTE 4). Acknowledgements are
    /// idempotent.
    fn ack(
        &self,
        epoch: VaultEpoch,
        seq: Seq,
        link: Link,
    ) -> impl Future<Output = Result<(), VaultFault>> + Send;
}

/// One append the driver asks for (design section 5.3).
#[derive(Clone, Debug)]
pub struct AppendRequest {
    /// The expected head.
    pub expected: Seq,
    /// UTC microseconds.
    pub at: i64,
    /// The command id.
    pub command: [u8; 16],
    /// The records.
    pub batch: Vec<CellRecord>,
    /// The insert-only side effects.
    pub side: SideEffects,
}

/// What a committed append left in the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Committed {
    /// The ledger head after the append.
    pub head: Seq,
    /// The chain link of the last entry of the batch.
    pub link: Link,
    /// The witness receipt of the append, when the store anchors.
    pub receipt: Option<ReceiptRef>,
}

/// The chain link and witness receipt of one stored entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredCommit {
    /// The chain link of the entry.
    pub link: Link,
    /// The witness receipt that covers it, when the store anchors.
    pub receipt: Option<ReceiptRef>,
}

/// A record store of a cell: the ledger contract of
/// [`AsyncRecordStore`], plus the append with its side effects and the
/// chain link and receipt of what it committed (design sections 5.3 and
/// 7.2).
pub trait CellStore: AsyncRecordStore<CellRecord> + Send + Sync + 'static {
    /// Appends `req` atomically, with the refusal order of
    /// [`AsyncRecordStore::append`], and reports the chain link and the
    /// receipt of the append. It refuses a batch whose step-up is stale
    /// at its commit instant or already consumed ([`CellAppendError`]).
    ///
    /// The engine drops the call at [`STORE_TIMEOUT`]. A store resolves
    /// such a dropped append before its next one, as after a crash.
    fn append_cell(
        &mut self,
        req: AppendRequest,
    ) -> impl Future<Output = Result<Committed, CellAppendError>> + Send;

    /// The chain link and receipt of the entry at `seq`, or `None` past
    /// the head.
    fn stored_commit(
        &self,
        seq: Seq,
    ) -> impl Future<Output = Result<Option<StoredCommit>, StoreError>> + Send;

    /// The cell whose ledger this is. The engine keys its reaction
    /// command ids by it (I-20, Daniel's decision of 2026-11-13).
    fn cell(&self) -> [u8; 16];
}

/// Reads every entry of `store` after `after`, in pages.
///
/// # Errors
///
/// The store's error.
pub async fn read_after<S: AsyncRecordStore<CellRecord> + Sync>(
    store: &S,
    after: Seq,
) -> Result<Vec<Entry<CellRecord>>, StoreError> {
    let mut out: Vec<Entry<CellRecord>> = Vec::new();
    let mut from = after.raw().checked_add(1).ok_or(StoreError::Full)?;
    loop {
        let before = out.len();
        store.read(Seq::from_raw(from), READ_PAGE, &mut out).await?;
        let got = out.len().saturating_sub(before);
        if got < READ_PAGE {
            return Ok(out);
        }
        let n = u64::try_from(got).map_err(|_| StoreError::Full)?;
        from = from.checked_add(n).ok_or(StoreError::Full)?;
    }
}

/// A plain store wrapped as a [`CellStore`] that anchors nothing. It
/// computes chain links with `fstp_audit::chain::ChainWriter` over the
/// canonical text of each entry, so a vault acknowledgement names a real
/// link. It records no witness receipt. It checks step-up freshness
/// against its commit clock, as every store does. Single use of a
/// step-up holds by structure: the batch carries `StepUpConsumed`, and
/// the driver's fold refuses a second one.
///
/// It is for tests and models over `fstp_ledger::MemStore`. A cell that
/// serves requests runs an anchoring store (I-24): the start-up paths
/// [`startup::start`] and [`startup::start_pg`] are typed over
/// [`startup::StartStore`], which only the anchoring stores implement.
pub struct Unanchored<S> {
    inner: S,
    cell: fstp_audit::CellId,
    writer: fstp_audit::ChainWriter,
    links: Vec<Link>,
    commands: std::collections::BTreeSet<[u8; 16]>,
    clock: CommitClock,
}

impl<S: AsyncRecordStore<CellRecord> + Send + Sync + 'static> Unanchored<S> {
    /// Opens `inner` for `cell` and computes the link of every stored
    /// entry.
    ///
    /// # Errors
    ///
    /// The store's read error, or [`StoreError::Unavailable`] when an
    /// entry has no chain row.
    pub async fn open(inner: S, cell: [u8; 16]) -> Result<Unanchored<S>, StoreError> {
        let cell = fstp_audit::CellId(cell);
        let mut s = Unanchored {
            inner,
            cell,
            writer: fstp_audit::ChainWriter::genesis(cell, fstp_audit::ChainId::App),
            links: Vec::new(),
            commands: std::collections::BTreeSet::new(),
            clock: system_commit_clock(),
        };
        let entries = read_after(&s.inner, Seq::ZERO).await?;
        s.extend(&entries)?;
        Ok(s)
    }

    /// The store with `clock` as its commit clock.
    #[must_use]
    pub fn with_commit_clock(mut self, clock: CommitClock) -> Unanchored<S> {
        self.clock = clock;
        self
    }

    /// The wrapped store.
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// The wrapped store, by reference.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    fn extend(&mut self, entries: &[Entry<CellRecord>]) -> Result<(), StoreError> {
        for e in entries {
            let stored = fstp_audit::StoredEntry {
                seq: e.seq.raw(),
                at: e.at,
                command: e.command,
                schema: e.schema,
                key_ix: 0,
                body: fstp_ledger::Canonical::canonical(&e.record),
            };
            let row = self
                .writer
                .append(
                    self.cell,
                    fstp_audit::ChainId::App,
                    e.at,
                    fstp_audit::RowKind::Ledger { seq: e.seq.raw() },
                    Some(&stored),
                )
                .map_err(|_| StoreError::Unavailable)?;
            self.links.push(row.link.0);
            self.commands.insert(e.command);
        }
        Ok(())
    }
}

impl<S: AsyncRecordStore<CellRecord> + Send + Sync + 'static> AsyncRecordStore<CellRecord>
    for Unanchored<S>
{
    fn head(&self) -> impl Future<Output = Result<Seq, StoreError>> + Send {
        self.inner.head()
    }

    async fn append(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<CellRecord>,
    ) -> Result<Seq, AppendError> {
        let req = AppendRequest {
            expected,
            at,
            command,
            batch,
            side: SideEffects::default(),
        };
        self.append_cell(req)
            .await
            .map(|c| c.head)
            .map_err(CellAppendError::into_ledger)
    }

    fn read(
        &self,
        from: Seq,
        limit: usize,
        out: &mut Vec<Entry<CellRecord>>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.inner.read(from, limit, out)
    }
}

impl<S: AsyncRecordStore<CellRecord> + Send + Sync + 'static> CellStore for Unanchored<S> {
    fn cell(&self) -> [u8; 16] {
        self.cell.0
    }

    async fn append_cell(&mut self, req: AppendRequest) -> Result<Committed, CellAppendError> {
        // The command check and the head check come first (ADR-007), so a
        // retry of a committed command is still a duplicate. The step-up
        // check runs only for an append that would commit.
        if !self.commands.contains(&req.command)
            && self.inner.head().await.map_err(AppendError::Store)? == req.expected
            && !stepup_fresh_at(req.side.stepup_fresh_until, (self.clock)())
        {
            return Err(CellAppendError::StepUpStale);
        }
        let head = self
            .inner
            .append(req.expected, req.at, req.command, req.batch)
            .await?;
        let written = read_after(&self.inner, req.expected)
            .await
            .map_err(AppendError::Store)?;
        self.extend(&written).map_err(AppendError::Store)?;
        let link = self
            .links
            .last()
            .copied()
            .ok_or(AppendError::Store(StoreError::Unavailable))?;
        Ok(Committed {
            head,
            link,
            receipt: None,
        })
    }

    fn stored_commit(
        &self,
        seq: Seq,
    ) -> impl Future<Output = Result<Option<StoredCommit>, StoreError>> + Send {
        let link = usize::try_from(seq.raw())
            .ok()
            .and_then(|i| i.checked_sub(1))
            .and_then(|i| self.links.get(i).copied());
        std::future::ready(Ok(link.map(|link| StoredCommit {
            link,
            receipt: None,
        })))
    }
}

/// Why the engine did not run a command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineError {
    /// The driver finished the command with an error. A commit the store
    /// refused under the step-up rule is `ExecError::Refused` naming
    /// I-78 ([`stepup_refusal`]).
    Exec(ExecError),
    /// The cell is shutting down. The command was not run and appended
    /// nothing (ADR-002).
    ShuttingDown,
    /// The engine task has stopped.
    Stopped,
}

/// Why the engine did not start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartError {
    /// The store could not be read.
    Store(StoreError),
    /// The stored ledger does not fold (I-23).
    Fold(FoldError),
}

struct Job {
    admitted: Admitted,
    reply: ReplyTx<Result<Done, EngineError>>,
}

/// A handle on the engine task of one cell. Cloning it gives another
/// handle on the same task.
#[derive(Clone)]
pub struct CellEngine {
    tx: Sender<Job>,
    snapshot: Arc<Mutex<Arc<CellState>>>,
    shutdown: Shutdown,
    clock: CommitClock,
}

impl std::fmt::Debug for CellEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CellEngine")
            .field("shutting_down", &self.shutdown.is_triggered())
            .finish_non_exhaustive()
    }
}

fn lock_snapshot(m: &Mutex<Arc<CellState>>) -> MutexGuard<'_, Arc<CellState>> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl CellEngine {
    /// The same engine handle on the cell clock `clock`. The cell's own
    /// tasks read their instants from [`CellEngine::now`], so a test world
    /// that moves its clock moves theirs. Handles cloned from it share it.
    #[must_use]
    pub fn with_clock(mut self, clock: CommitClock) -> CellEngine {
        self.clock = clock;
        self
    }

    /// The current instant of the cell clock, in UTC microseconds. The
    /// system clock unless [`CellEngine::with_clock`] set another.
    pub fn now(&self) -> i64 {
        (self.clock)()
    }

    /// Replays `store` into `CellState` and spawns the engine task on
    /// `rt` (design section 5.5). The task joins `shutdown` as a
    /// participant. The join handle gives the store back once the task
    /// ends: when every handle is dropped, or after shutdown.
    ///
    /// # Errors
    ///
    /// [`StartError`] when the store cannot be read or does not fold.
    pub async fn start<R: Runtime, S: CellStore, V: VaultClient>(
        rt: &R,
        store: S,
        vault: V,
        shutdown: &Shutdown,
        queue: usize,
    ) -> Result<(CellEngine, JoinHandle<S>), StartError> {
        let entries = read_after(&store, Seq::ZERO)
            .await
            .map_err(StartError::Store)?;
        let state = fstp_cell_core::replay(&entries).map_err(StartError::Fold)?;
        Ok(CellEngine::spawn(rt, store, vault, state, shutdown, queue))
    }

    /// Spawns the engine task over a state already replayed from `store`.
    fn spawn<R: Runtime, S: CellStore, V: VaultClient>(
        rt: &R,
        store: S,
        vault: V,
        state: CellState,
        shutdown: &Shutdown,
        queue: usize,
    ) -> (CellEngine, JoinHandle<S>) {
        let (tx, rx) = chan::channel(queue);
        let snapshot = Arc::new(Mutex::new(Arc::new(state.clone())));
        let signal = shutdown.signal();
        let task = EngineTask {
            store,
            vault,
            rt: rt.clone(),
            state,
            snapshot: Arc::clone(&snapshot),
        };
        let handle = rt.spawn(task.run(rx, signal));
        (
            CellEngine {
                tx,
                snapshot,
                shutdown: shutdown.clone(),
                clock: system_commit_clock(),
            },
            handle,
        )
    }

    /// Runs one admitted command and gives its result (design section
    /// 5.4: the only way a command reaches `DriverCore`).
    ///
    /// # Errors
    ///
    /// [`EngineError::Exec`] for the driver's refusal,
    /// [`EngineError::CommitDenied`] for a commit the store refused under
    /// the step-up rule, [`EngineError::ShuttingDown`] once shutdown is
    /// triggered, and
    /// [`EngineError::Stopped`] when the task has ended.
    pub async fn execute(&self, admitted: Admitted) -> Result<Done, EngineError> {
        if self.shutdown.is_triggered() {
            return Err(EngineError::ShuttingDown);
        }
        let (reply, rx) = chan::reply();
        if self.tx.send(Job { admitted, reply }).await.is_err() {
            return Err(if self.shutdown.is_triggered() {
                EngineError::ShuttingDown
            } else {
                EngineError::Stopped
            });
        }
        rx.recv().await.unwrap_or(Err(EngineError::Stopped))
    }

    /// The state after the last committed command. Reads use it and never
    /// wait for the writer (risk R8: reads are served while writes are
    /// refused).
    pub fn state(&self) -> Arc<CellState> {
        Arc::clone(&lock_snapshot(&self.snapshot))
    }

    /// Whether the cell's shutdown was triggered.
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.is_triggered()
    }
}

struct EngineTask<S, V, R> {
    store: S,
    vault: V,
    rt: R,
    state: CellState,
    snapshot: Arc<Mutex<Arc<CellState>>>,
}

impl<S: CellStore, V: VaultClient, R: Runtime> EngineTask<S, V, R> {
    async fn run(mut self, mut rx: Receiver<Job>, signal: ShutdownSignal) -> S {
        loop {
            let next = race(rx.recv(), signal.notified()).await;
            let job = match next {
                Either::Left(Some(job)) => job,
                Either::Left(None) | Either::Right(()) => break,
            };
            if signal.is_triggered() {
                job.reply.send(Err(EngineError::ShuttingDown));
                break;
            }
            let result = self.execute(job.admitted).await;
            *lock_snapshot(&self.snapshot) = Arc::new(self.state.clone());
            job.reply.send(result);
        }
        rx.close();
        for job in rx.drain() {
            job.reply.send(Err(EngineError::ShuttingDown));
        }
        drop(signal);
        self.store
    }

    /// Drives one `DriverCore` to its end.
    async fn execute(&mut self, admitted: Admitted) -> Result<Done, EngineError> {
        let at = admitted.at();
        let mut driver = DriverCore::start(admitted).in_cell(self.store.cell());
        let mut event: Option<Event> = None;
        let mut receipt: Option<ReceiptRef> = None;
        loop {
            match driver.step(&mut self.state, event.take()) {
                Step::Done(Ok(mut done)) => {
                    done.receipt = match done.duplicate {
                        None => receipt,
                        Some(seq) => self
                            .stored_commit(seq)
                            .await
                            .map_err(exec_store)?
                            .and_then(|c| c.receipt),
                    };
                    return Ok(done);
                }
                Step::Done(Err(e)) => return Err(EngineError::Exec(e)),
                Step::Need(need) => {
                    event = Some(self.answer(need, at, &mut receipt).await?);
                }
            }
        }
    }

    /// A store read, bounded by [`STORE_TIMEOUT`].
    async fn read_after(&self, after: Seq) -> Result<Vec<Entry<CellRecord>>, StoreError> {
        fstp_rt::timeout(&self.rt, STORE_TIMEOUT, read_after(&self.store, after))
            .await
            .unwrap_or(Err(StoreError::Unavailable))
    }

    /// The stored commit of `seq`, bounded by [`STORE_TIMEOUT`].
    async fn stored_commit(&self, seq: Seq) -> Result<Option<StoredCommit>, StoreError> {
        fstp_rt::timeout(&self.rt, STORE_TIMEOUT, self.store.stored_commit(seq))
            .await
            .unwrap_or(Err(StoreError::Unavailable))
    }

    /// One append, bounded by [`STORE_TIMEOUT`]. A dropped append is
    /// resolved by the store before its next one (design section 7.2).
    async fn append(&mut self, req: AppendRequest) -> Result<Committed, CellAppendError> {
        let rt = self.rt.clone();
        fstp_rt::timeout(&rt, STORE_TIMEOUT, self.store.append_cell(req))
            .await
            .unwrap_or(Err(CellAppendError::Ledger(AppendError::Store(
                StoreError::Unavailable,
            ))))
    }

    /// A vault call, bounded by [`VAULT_TIMEOUT`]. A call that does not
    /// answer in time fails closed (NOTE 2).
    async fn bound_vault<T>(
        &self,
        call: impl Future<Output = Result<T, VaultFault>>,
    ) -> Result<T, VaultFault> {
        fstp_rt::timeout(&self.rt, VAULT_TIMEOUT, call)
            .await
            .unwrap_or(Err(VaultFault::Unavailable))
    }

    async fn answer(
        &mut self,
        need: Need,
        at: Timestamp,
        receipt: &mut Option<ReceiptRef>,
    ) -> Result<Event, EngineError> {
        Ok(match need {
            Need::ReadFrom(after) => Event::Read(self.read_after(after).await.map_err(exec_store)?),
            Need::Epoch => Event::Epoch(self.bound_vault(self.vault.epoch()).await),
            Need::Ask {
                queries,
                reaction_for,
            } => Event::Answers(
                self.bound_vault(self.vault.ask(&queries, reaction_for, at))
                    .await,
            ),
            Need::Append {
                expected,
                at,
                command,
                batch,
                side,
            } => {
                let req = AppendRequest {
                    expected,
                    at,
                    command,
                    batch,
                    side,
                };
                match self.append(req).await {
                    Ok(c) => {
                        *receipt = c.receipt;
                        Event::Appended(Ok((c.head, c.link)))
                    }
                    Err(CellAppendError::Ledger(e)) => Event::Appended(Err(e)),
                    // The store refused the commit under the step-up rule,
                    // so the command ends here with the typed denial and
                    // appends nothing (design section 8.4, I-78).
                    Err(CellAppendError::StepUpStale | CellAppendError::StepUpReplayed) => {
                        return Err(EngineError::Exec(stepup_refusal()));
                    }
                }
            }
            Need::Ack { epoch, seq, link } => {
                // A re-acknowledgement names link zero: the stored link of
                // the named sequence is filled in here (driver readings).
                let link = if link == [0; 32] {
                    match self.stored_commit(seq).await.map_err(exec_store)? {
                        Some(c) => c.link,
                        None => return Err(EngineError::Exec(ExecError::Protocol)),
                    }
                } else {
                    link
                };
                Event::Acked(self.bound_vault(self.vault.ack(epoch, seq, link)).await)
            }
        })
    }
}

/// The refusal of a commit whose step-up was stale at the commit instant
/// or already consumed: I-78, as the decider refuses a step-up
/// (`fstp_cell_core::decide`). It is a refusal, never a store outage.
pub fn stepup_refusal() -> ExecError {
    ExecError::Refused(CellRefusal::Domain(Refusal::new(
        RuleRef::I78,
        RefusalReason::GuardFailed,
    )))
}

fn exec_store(e: StoreError) -> EngineError {
    EngineError::Exec(ExecError::Store(e))
}
