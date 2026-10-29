//! The anchoring store: the append protocol of design section 5.3 over a
//! [`Database`], with the `fstp_audit` anchorer core (I-24, ADR-010).
//!
//! One append is one transaction:
//!
//! 1. the lock, then the command check before the head check (ADR-007);
//! 2. each entry sealed under the ledger key with a fresh nonce;
//! 3. one chain row per entry, linked by `fstp_audit::ChainWriter` over
//!    the stored bytes;
//! 4. the insert-only side effects, where a replayed step-up aborts;
//! 5. the prepare of the prospective head to the witness, with its
//!    composite anchor, and its receipt, taken through
//!    `Anchorer::signed_receipt` with the pinned witness keys of
//!    [`StoreKeys::witness`] (ADR-010 "Keys", I-90);
//! 6. the anchor row with the receipt, then COMMIT.
//!
//! The step-up's freshness is checked against the store's commit clock
//! at step 4 and again just before COMMIT, after the receipt (design
//! section 8.4, ADR-008, I-78). A batch that waited past P-71 in the
//! queue or for the witness is refused with
//! [`CellAppendError::StepUpStale`], and its prepare is aborted.
//!
//! The append is cancel safe. The engine drops an append at its timeout,
//! and the next append first ends the dropped one as a failure before
//! COMMIT, or as an unknown COMMIT outcome, then resolves it as below.
//!
//! The chain holds ledger rows and, later, event rows (design section
//! 7.1), so a chain row number `n` is not a ledger sequence. The store
//! keeps the row of each ledger sequence and resolves links and receipts
//! through it.
//!
//! COMMIT is sent only with the receipt for the head's own `(n, link)`.
//! A known failure after the prepare sends `Abort { n, link }` before the
//! same row is prepared again. An unknown outcome is resolved from the
//! chain before the next append, or at the next start: a present row is
//! extended, and a missing one raises `PossibleDeletion`, then sends
//! `InDoubtAbsent { n, link }` (design section 7.2).
//!
//! [`MemDatabase`] keeps the tables in memory. It is the store of tests
//! and of the demo path. A serving cell runs
//! [`crate::engine::pg::PgCellStore`] over `fstp_pgstore::PgRecordStore`
//! instead. The sealed rows and the chain are real. The
//! plaintext entries are kept beside them in a `fstp_ledger::MemStore`,
//! so reads need no decryption, which a database store does instead.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use fstp_audit::anchor::{AnchorRow, Receipt, sign_anchor};
use fstp_audit::anchorer::{
    Anchorer, CommitOutcome, Next, PhaseName, PrepareWitness, Step, WitnessFault,
};
use fstp_audit::witness::Prepare;
use fstp_audit::{
    CellId, ChainId, ChainWriter, CompositeSigningKey, Link, RowKind, StoredEntry, StoredRow,
};
use fstp_cell_core::CellRecord;
use fstp_cell_core::driver::ReceiptRef;
use fstp_crypto::composite::CompositePublicKey;
use fstp_keys::envelope::{self, DataKey, SealContext};
use fstp_keys::{Chain, GroupId, ObjectId, Purpose};
use fstp_ledger::{
    AppendError, AsyncRecordStore, Canonical, Entry, MemStore, RecordStore, SCHEMA_V1, Seq,
    StoreError,
};

use crate::engine::{
    AppendRequest, CellAppendError, CellStore, CommitClock, Committed, StoredCommit,
    stepup_fresh_at, system_commit_clock,
};

/// The group id of the ledger key in the App chain (ADR-004 part 2: the
/// `Ledger` group never takes part in an erasure).
pub const LEDGER_GROUP: [u8; 16] = *b"fstp-ledger-grp1";

/// The committed tables of one cell database.
#[derive(Debug, Default)]
pub struct Tables {
    ledger: MemStore<CellRecord>,
    commands: BTreeMap<[u8; 16], Seq>,
    stored: Vec<StoredEntry>,
    rows: Vec<StoredRow>,
    /// The chain row number of each ledger sequence.
    ledger_rows: BTreeMap<u64, u64>,
    anchors: Vec<AnchorRow>,
    stepups: BTreeSet<[u8; 16]>,
    sessions_ended: BTreeSet<[u8; 16]>,
    possible_deletions: BTreeSet<(u64, Link)>,
}

impl Tables {
    /// The plaintext ledger.
    pub fn ledger(&self) -> &MemStore<CellRecord> {
        &self.ledger
    }

    /// The stored ledger rows, sealed.
    pub fn stored(&self) -> &[StoredEntry] {
        &self.stored
    }

    /// The chain rows with their links.
    pub fn rows(&self) -> &[StoredRow] {
        &self.rows
    }

    /// The `audit.anchor` rows.
    pub fn anchors(&self) -> &[AnchorRow] {
        &self.anchors
    }

    /// The raised `PossibleDeletion` alerts, by `(n, link)`.
    pub fn possible_deletions(&self) -> &BTreeSet<(u64, Link)> {
        &self.possible_deletions
    }

    /// The chain head, or `None` at genesis.
    pub fn chain_head(&self) -> Option<(u64, Link)> {
        self.rows.last().map(|r| (r.row.n, r.link))
    }

    /// The link of chain row `n`.
    fn link_at(&self, n: u64) -> Option<Link> {
        let i = usize::try_from(n.checked_sub(1)?).ok()?;
        self.rows.get(i).map(|r| r.link)
    }

    /// The chain row number of ledger sequence `seq`.
    pub fn row_of(&self, seq: Seq) -> Option<u64> {
        self.ledger_rows.get(&seq.raw()).copied()
    }

    /// The link and the covering receipt of ledger sequence `seq`: the
    /// first anchor whose head is at or after its row.
    fn commit_of(&self, seq: Seq) -> Option<StoredCommit> {
        let n = self.row_of(seq)?;
        let link = self.link_at(n)?;
        let receipt = self
            .anchors
            .iter()
            .find(|a| a.receipt.fields.n >= n)
            .map(|a| ReceiptRef {
                witness_seq: a.receipt.fields.witness_seq,
            });
        Some(StoredCommit {
            link: link.0,
            receipt,
        })
    }

    /// Applies a transaction. The caller checked its head.
    fn apply(&mut self, tx: Transaction) -> Result<(), StoreError> {
        let first = Seq::from_raw(tx.expected.raw().checked_add(1).ok_or(StoreError::Full)?);
        RecordStore::append(&mut self.ledger, tx.expected, tx.at, tx.command, tx.batch)
            .map_err(|_| StoreError::Unavailable)?;
        self.commands.insert(tx.command, first);
        self.stored.extend(tx.stored);
        for r in &tx.rows {
            if let RowKind::Ledger { seq } = r.row.kind {
                self.ledger_rows.insert(seq, r.row.n);
            }
        }
        self.rows.extend(tx.rows);
        self.anchors.push(tx.anchor);
        if let Some(s) = tx.stepup {
            self.stepups.insert(s);
        }
        self.sessions_ended.extend(tx.sessions_ended);
        Ok(())
    }
}

/// The rows of one append transaction.
#[derive(Debug)]
pub struct Transaction {
    expected: Seq,
    at: i64,
    command: [u8; 16],
    batch: Vec<CellRecord>,
    stored: Vec<StoredEntry>,
    rows: Vec<StoredRow>,
    anchor: AnchorRow,
    stepup: Option<[u8; 16]>,
    sessions_ended: Vec<[u8; 16]>,
}

impl Transaction {
    /// The prospective chain head.
    pub fn head(&self) -> Option<(u64, Link)> {
        self.rows.last().map(|r| (r.row.n, r.link))
    }
}

/// The outcome of COMMIT, as the cell sees it.
pub type CommitResult = CommitOutcome;

/// A cell database, as the anchoring store reaches it.
pub trait Database: Send + Sync + 'static {
    /// The committed tables.
    fn tables(&self) -> &Tables;

    /// Commits `tx` atomically. [`CommitOutcome::Unknown`] means the
    /// connection was lost while COMMIT was in flight.
    fn commit(&mut self, tx: Transaction) -> impl Future<Output = CommitOutcome> + Send;

    /// Raises `PossibleDeletion` for `head` to tenant admins and the
    /// auditor view, durably and keyed by `(n, link)`.
    fn raise_possible_deletion(
        &mut self,
        head: (u64, Link),
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Reads the chain rows, the stored ledger rows and the anchor rows
    /// back, as an auditor or the start-up verification sees them
    /// (design section 7.2 "Start-up").
    fn read_chain(&self) -> ChainRead;
}

/// The chain as read back from a database.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainRead {
    /// The chain rows with their links.
    pub rows: Vec<StoredRow>,
    /// The stored ledger rows, sealed.
    pub stored: Vec<StoredEntry>,
    /// The `audit.anchor` rows.
    pub anchors: Vec<AnchorRow>,
}

/// The in-memory database.
#[derive(Debug, Default)]
pub struct MemDatabase {
    tables: Tables,
}

impl MemDatabase {
    /// An empty database.
    pub fn new() -> MemDatabase {
        MemDatabase::default()
    }

    /// Commits `tx` at once. A database wrapper uses it to model a commit
    /// whose answer is lost.
    pub fn apply(&mut self, tx: Transaction) -> CommitOutcome {
        match self.tables.apply(tx) {
            Ok(()) => CommitOutcome::Committed,
            Err(_) => CommitOutcome::Failed,
        }
    }
}

impl Database for MemDatabase {
    fn tables(&self) -> &Tables {
        &self.tables
    }

    fn commit(&mut self, tx: Transaction) -> impl Future<Output = CommitOutcome> + Send {
        std::future::ready(self.apply(tx))
    }

    fn raise_possible_deletion(
        &mut self,
        head: (u64, Link),
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.tables.possible_deletions.insert(head);
        std::future::ready(Ok(()))
    }

    fn read_chain(&self) -> ChainRead {
        ChainRead {
            rows: self.tables.rows.clone(),
            stored: self.tables.stored.clone(),
            anchors: self.tables.anchors.clone(),
        }
    }
}

/// The keys an anchoring store writes and checks with.
pub struct StoreKeys {
    /// The App chain's composite `Anchor` key (design section 3.9).
    pub anchor: CompositeSigningKey,
    /// The current ledger data key.
    pub ledger: DataKey,
    /// The pinned witness receipt keys, each an encoded composite public
    /// key (ADR-010 "Keys", I-90). A receipt is accepted only when one of
    /// them verifies its signature. [`AnchoredStore::new`] refuses an
    /// empty set and any key that does not decode.
    pub witness: Vec<Vec<u8>>,
}

/// Why [`AnchoredStore::new`] refused its keys (ADR-010 "Keys", I-90).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeysRefused {
    /// No witness receipt key is pinned. Such a store would accept no
    /// receipt, yet still send each prepare to the witness.
    NoWitnessPin,
    /// A pinned witness key is not an encoded composite public key.
    WitnessPin,
}

impl std::fmt::Debug for StoreKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoreKeys(..)")
    }
}

/// The anchoring store of one cell.
pub struct AnchoredStore<D, W> {
    db: D,
    witness: W,
    anchorer: Anchorer,
    cell: CellId,
    keys: StoreKeys,
    /// Whether the start-up check of the witness's open prepare is done.
    started: bool,
    /// The clock of the commit instant.
    clock: CommitClock,
}

impl<D, W> std::fmt::Debug for AnchoredStore<D, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnchoredStore")
            .field("cell", &self.cell)
            .field("anchorer", &self.anchorer.phase().name())
            .finish_non_exhaustive()
    }
}

fn ok<T, E>(r: Result<T, E>) -> Result<T, AppendError> {
    r.map_err(|_| AppendError::Store(StoreError::Unavailable))
}

fn unavailable<T, E: From<AppendError>>() -> Result<T, E> {
    Err(E::from(AppendError::Store(StoreError::Unavailable)))
}

/// How the start-up resolution of an open prepare ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolved {
    /// No prepare was open.
    Nothing,
    /// The open prepare's row exists: it committed.
    Committed,
    /// The row was missing: `PossibleDeletion` was raised and
    /// `InDoubtAbsent` recorded.
    AbsentRecorded,
}

/// What the start-up resolution can still ask the witness.
pub trait OpenPrepare {
    /// The outstanding prepare at the witness.
    fn open_prepare(
        &self,
    ) -> impl Future<Output = Result<Option<(u64, Link)>, WitnessFault>> + Send;
}

impl<L: super::WitnessLink> OpenPrepare for super::WitnessClient<L> {
    fn open_prepare(
        &self,
    ) -> impl Future<Output = Result<Option<(u64, Link)>, WitnessFault>> + Send {
        self.outstanding()
    }
}

impl<D: Database, W: PrepareWitness + OpenPrepare + Send + Sync + 'static> AnchoredStore<D, W> {
    /// A store over `db` for `cell`. It resolves no prepare yet: call
    /// [`AnchoredStore::start`] before the first append, or the first
    /// append does it.
    ///
    /// # Errors
    ///
    /// A [`KeysRefused`] for an empty witness pin set, or a pinned key
    /// that is not an encoded composite public key (ADR-010 "Keys", I-90).
    /// `fstp_pgstore::PgRecordStore::new` refuses an empty pin set too, so
    /// no store of the cell starts with a pin set that accepts no receipt.
    pub fn new(
        db: D,
        witness: W,
        cell: [u8; 16],
        keys: StoreKeys,
    ) -> Result<AnchoredStore<D, W>, KeysRefused> {
        if keys.witness.is_empty() {
            return Err(KeysRefused::NoWitnessPin);
        }
        if !keys
            .witness
            .iter()
            .all(|k| CompositePublicKey::from_bytes(k).is_ok())
        {
            return Err(KeysRefused::WitnessPin);
        }
        Ok(AnchoredStore {
            db,
            witness,
            anchorer: Anchorer::new(),
            cell: CellId(cell),
            keys,
            started: false,
            clock: system_commit_clock(),
        })
    }

    /// The store with `clock` as its commit clock. Production keeps the
    /// system clock of [`AnchoredStore::new`].
    #[must_use]
    pub fn with_commit_clock(mut self, clock: CommitClock) -> AnchoredStore<D, W> {
        self.clock = clock;
        self
    }

    /// The database.
    pub fn db(&self) -> &D {
        &self.db
    }

    /// The witness client.
    pub fn witness(&self) -> &W {
        &self.witness
    }

    /// The pinned witness receipt keys ([`StoreKeys::witness`]). The
    /// start-up verification checks the stored receipts under the same
    /// set, so one pin set serves both checks.
    pub fn witness_keys(&self) -> &[Vec<u8>] {
        &self.keys.witness
    }

    /// The database and the witness client, for a restart.
    pub fn into_parts(self) -> (D, W, StoreKeys) {
        (self.db, self.witness, self.keys)
    }

    /// ADR-010 "Start-up": learns the open prepare from the witness and
    /// resolves it from the chain before the cell serves.
    ///
    /// # Errors
    ///
    /// [`StoreError::Unavailable`] when the witness cannot be reached or
    /// the resolution cannot finish. Writes stay refused until it does.
    pub async fn start(&mut self) -> Result<Resolved, StoreError> {
        if self.started {
            return Ok(Resolved::Nothing);
        }
        let open = self
            .witness
            .open_prepare()
            .await
            .map_err(|_| StoreError::Unavailable)?;
        self.anchorer = Anchorer::restart(open);
        let mut resolved = Resolved::Nothing;
        if open.is_some() {
            let head = open.ok_or(StoreError::Unavailable)?;
            let link = self.db.tables().link_at(head.0);
            resolved = if link == Some(head.1) {
                Resolved::Committed
            } else {
                Resolved::AbsentRecorded
            };
        }
        self.resolve().await.map_err(|_| StoreError::Unavailable)?;
        self.started = true;
        Ok(resolved)
    }

    /// Runs the follow-ups the anchorer owes: an abort, a chain read, an
    /// alert or an in-doubt record.
    async fn resolve(&mut self) -> Result<(), AppendError> {
        loop {
            match self.anchorer.next() {
                Next::Nothing => return Ok(()),
                Next::SendAbort { head } => match self.witness.abort(head).await {
                    Ok(()) => ok(self.anchorer.abort_recorded())?,
                    Err(WitnessFault::UnknownPrepare) => {
                        ok(self.anchorer.abort_unknown_at_witness())?;
                    }
                    Err(_) => return unavailable(),
                },
                Next::ReadChain { head } => {
                    let link = self.db.tables().link_at(head.0);
                    ok(self.anchorer.chain_read(link.as_ref()).map(|_| ()))?;
                }
                Next::RaisePossibleDeletion { head } => {
                    self.db
                        .raise_possible_deletion(head)
                        .await
                        .map_err(AppendError::Store)?;
                    ok(self.anchorer.possible_deletion_raised())?;
                }
                Next::SendInDoubtAbsent { head } => {
                    match self.witness.in_doubt_absent(head).await {
                        Ok(()) => ok(self.anchorer.in_doubt_recorded())?,
                        Err(WitnessFault::UnknownPrepare) => {
                            ok(self.anchorer.in_doubt_unknown_at_witness())?;
                        }
                        Err(_) => return unavailable(),
                    }
                }
                Next::Run(_)
                | Next::SendPrepare
                | Next::AwaitReceipt
                | Next::InsertAnchor
                | Next::SendCommit
                | Next::AwaitOutcome => return unavailable(),
            }
        }
    }

    /// Ends an append that was dropped before it finished, as a crash
    /// would end it. Before COMMIT it failed, so a prepare is aborted.
    /// With COMMIT sent its outcome is unknown, so the chain is read.
    fn recover_cancelled(&mut self) -> Result<(), AppendError> {
        match self.anchorer.phase().name() {
            PhaseName::Open
            | PhaseName::Prepared
            | PhaseName::Receipted
            | PhaseName::AnchorInserted => ok(self.anchorer.failed().map(|_| ())),
            PhaseName::CommitSent => ok(self.anchorer.outcome(CommitOutcome::Unknown).map(|_| ())),
            PhaseName::Idle
            | PhaseName::MustAbort
            | PhaseName::InDoubt
            | PhaseName::MustRaise
            | PhaseName::MustRecordInDoubt => Ok(()),
        }
    }

    /// Ends an append whose prepare the witness may hold, then sends the
    /// abort it owes before the same row is prepared again.
    async fn abort_prepared(&mut self) {
        let _ = self.anchorer.failed();
        let _ = self.resolve().await;
    }

    fn step(&mut self, s: Step) -> Result<(), AppendError> {
        let r = self.anchorer.step_done(s);
        ok(r)
    }

    /// Ends an open transaction that failed before its prepare.
    fn fail_open<T>(&mut self, e: impl Into<CellAppendError>) -> Result<T, CellAppendError> {
        let _ = self.anchorer.failed();
        Err(e.into())
    }

    fn seal(
        &self,
        seq: Seq,
        at: i64,
        command: [u8; 16],
        record: &CellRecord,
    ) -> Result<Vec<u8>, AppendError> {
        let mut object = [0u8; 16];
        for (d, s) in object.iter_mut().zip(seq.raw().to_be_bytes().iter()) {
            *d = *s;
        }
        let ctx = SealContext {
            cell: fstp_keys::CellId(self.cell.0),
            chain: Chain::App,
            purpose: Purpose::Ledger,
            group: GroupId(LEDGER_GROUP),
            generation: 1,
            object: ObjectId(object),
        };
        let mut text = Vec::new();
        text.extend_from_slice(&at.to_be_bytes());
        text.extend_from_slice(&command);
        text.extend_from_slice(&record.canonical());
        let blob = envelope::seal_blob(&self.keys.ledger, &ctx, &text)
            .map_err(|_| AppendError::Store(StoreError::Unavailable))?;
        envelope::encode_sealed_blob(&blob).map_err(|_| AppendError::Store(StoreError::Unavailable))
    }

    async fn append_anchored(&mut self, req: AppendRequest) -> Result<Committed, CellAppendError> {
        if !self.started {
            self.start().await.map_err(AppendError::Store)?;
        }
        self.recover_cancelled()?;
        self.resolve().await?;
        let r = self.anchorer.begin(true);
        ok(r)?;
        self.step(Step::Lock)?;
        // The command check comes before the head check (ADR-007).
        let tables = self.db.tables();
        if let Some(at) = tables.commands.get(&req.command).copied() {
            return self.fail_open(AppendError::DuplicateCommand { at });
        }
        self.step(Step::CommandCheck)?;
        let head = RecordStore::head(self.db.tables().ledger());
        if head != req.expected {
            return self.fail_open(AppendError::StaleHead { head });
        }
        self.step(Step::HeadCheck)?;
        if req.batch.is_empty() {
            return self.fail_open(AppendError::Store(StoreError::EmptyBatch));
        }
        let mut stored = Vec::with_capacity(req.batch.len());
        let mut seq = head;
        for record in &req.batch {
            seq = Seq::from_raw(
                seq.raw()
                    .checked_add(1)
                    .ok_or(AppendError::Store(StoreError::Full))?,
            );
            let body = match self.seal(seq, req.at, req.command, record) {
                Ok(b) => b,
                Err(e) => return self.fail_open(e),
            };
            stored.push(StoredEntry {
                seq: seq.raw(),
                at: req.at,
                command: req.command,
                schema: SCHEMA_V1,
                key_ix: 0,
                body,
            });
        }
        self.step(Step::SealLedger)?;
        let prev = self
            .db
            .tables()
            .chain_head()
            .unwrap_or((0, fstp_audit::chain::genesis(self.cell, ChainId::App)));
        let mut writer = ChainWriter::resume(prev.0, prev.1);
        let mut rows = Vec::with_capacity(stored.len());
        for e in &stored {
            match writer.append(
                self.cell,
                ChainId::App,
                req.at,
                RowKind::Ledger { seq: e.seq },
                Some(e),
            ) {
                Ok(r) => rows.push(r),
                Err(_) => return self.fail_open(AppendError::Store(StoreError::Full)),
            }
        }
        self.step(Step::InsertChain)?;
        if let Some(s) = req.side.stepup_consumed
            && self.db.tables().stepups.contains(&s)
        {
            // A replayed step-up violates the primary key (design 5.3).
            return self.fail_open(CellAppendError::StepUpReplayed);
        }
        if !stepup_fresh_at(req.side.stepup_fresh_until, (self.clock)()) {
            // Stale before the prepare: nothing reached the witness.
            return self.fail_open(CellAppendError::StepUpStale);
        }
        self.step(Step::SideEffects)?;
        let new_head = writer.head();
        let anchor = match sign_anchor(
            &self.keys.anchor,
            self.cell,
            ChainId::App,
            new_head.0,
            &new_head.1,
            req.at,
        ) {
            Ok(a) => a,
            Err(_) => return self.fail_open(AppendError::Store(StoreError::Unavailable)),
        };
        let prepare = Prepare {
            prev,
            stored_hashes: rows.iter().map(|r| r.row.stored_hash).collect(),
            anchor: anchor.clone(),
        };
        let r = self.anchorer.prepared(new_head);
        ok(r)?;
        let receipt: Receipt = match self.witness.prepare(&prepare).await {
            Ok(rc) => rc,
            Err(WitnessFault::Refused) => {
                let r = self.anchorer.prepare_refused();
                ok(r)?;
                return unavailable();
            }
            Err(_) => {
                self.abort_prepared().await;
                return unavailable();
            }
        };
        // ADR-010 "Keys", I-24, I-90: the receipt must name this cell and
        // chain, verify under a pinned witness key, and be for the
        // prepared head's own `(n, link)`. COMMIT is never sent on any
        // other receipt, and the prepare it answered is aborted.
        if self
            .anchorer
            .signed_receipt(self.cell, ChainId::App, &receipt, &self.keys.witness)
            .is_err()
        {
            self.abort_prepared().await;
            return unavailable();
        }
        let r = self.anchorer.anchor_inserted();
        ok(r)?;
        // Design section 8.4, ADR-008: freshness again at commit. The
        // witness round trip may have taken the batch past P-71, so the
        // clock is read after the receipt, just before COMMIT.
        if !stepup_fresh_at(req.side.stepup_fresh_until, (self.clock)()) {
            self.abort_prepared().await;
            return Err(CellAppendError::StepUpStale);
        }
        let tx = Transaction {
            expected: req.expected,
            at: req.at,
            command: req.command,
            batch: req.batch,
            stored,
            rows,
            anchor: AnchorRow {
                anchor,
                receipt: receipt.clone(),
            },
            stepup: req.side.stepup_consumed,
            sessions_ended: req.side.sessions_ended,
        };
        let r = self.anchorer.commit_sent();
        ok(r)?;
        let outcome = self.db.commit(tx).await;
        let r = self.anchorer.outcome(outcome);
        ok(r)?;
        match outcome {
            CommitOutcome::Committed => Ok(Committed {
                // The ledger head: the last sequence of the batch, which
                // is not the chain row number once event rows exist.
                head: seq,
                link: new_head.1.0,
                receipt: Some(ReceiptRef {
                    witness_seq: receipt.fields.witness_seq,
                }),
            }),
            CommitOutcome::Failed => {
                let _ = self.resolve().await;
                unavailable()
            }
            CommitOutcome::Unknown => unavailable(),
        }
    }
}

impl<D: Database, W: PrepareWitness + OpenPrepare + Send + Sync + 'static>
    AsyncRecordStore<CellRecord> for AnchoredStore<D, W>
{
    fn head(&self) -> impl Future<Output = Result<Seq, StoreError>> + Send {
        std::future::ready(Ok(RecordStore::head(self.db.tables().ledger())))
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
            side: fstp_cell_core::driver::SideEffects::default(),
        };
        self.append_anchored(req)
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
        std::future::ready(RecordStore::read(
            self.db.tables().ledger(),
            from,
            limit,
            out,
        ))
    }
}

impl<D: Database, W: PrepareWitness + OpenPrepare + Send + Sync + 'static> CellStore
    for AnchoredStore<D, W>
{
    async fn append_cell(&mut self, req: AppendRequest) -> Result<Committed, CellAppendError> {
        self.append_anchored(req).await
    }

    fn stored_commit(
        &self,
        seq: Seq,
    ) -> impl Future<Output = Result<Option<StoredCommit>, StoreError>> + Send {
        std::future::ready(Ok(self.db.tables().commit_of(seq)))
    }
}
