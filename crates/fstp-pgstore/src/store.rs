//! `PgRecordStore`: the append protocol of design section 5.3 over the
//! writer role, with the prepare, receipt and commit tail of section 7.2
//! (ADR-007, ADR-010, I-23, I-24, I-77, I-78).
//!
//! One append is one transaction as `c_<cell>_writer`:
//!
//! 1. `pg_advisory_xact_lock(1)`: one writer per cell database.
//! 2. A command id already in `ledger.command` is `DuplicateCommand`,
//!    whatever head the caller expects.
//! 3. A head other than `expected` is `StaleHead`. Then the time bound,
//!    an empty batch and a full ledger, in the order of
//!    `fstp_ledger::RecordStore::append`, then the side-effect limits.
//! 4. Each record's canonical text is sealed under the ledger key with a
//!    random nonce and the ADR-007 AAD, and inserted row by row. Before
//!    the first seal of a generation, a generation that already names a
//!    stored row is refused (ADR-004).
//! 5. One `audit.chain` row per entry. `fstp_audit::ChainWriter`
//!    computes each link from the stored row bytes, and the insert
//!    trigger recomputes it.
//! 6. Side effects as inserts only: step-up consumptions, session ends
//!    and sealed outbox rows. A replayed step-up, a second end of a
//!    session or a second outbox row with one id or idem violates a
//!    unique key, and the whole append aborts.
//! 7. The prospective head is signed and prepared at the witness. Its
//!    receipt must be for this cell, chain and head, and signed by a
//!    pinned witness key. It goes into `audit.anchor` in the same
//!    transaction.
//! 8. COMMIT. A known failure sends `Abort { n, link }`. An unknown
//!    outcome is resolved before the next append, under the rule of
//!    `fstp_audit::anchorer::Next::ReadChain`.
//!
//! `fstp_audit::anchorer::Anchorer` holds the order of these steps. The
//! store reports each outcome to it and never sends COMMIT without the
//! receipt for its own head (I-24).
//!
//! Each later step of the anchorer core (an abort, a chain read, an
//! alert, an in-doubt record) runs in a new transaction that first takes
//! `pg_advisory_xact_lock(1)`, and holds it while it reaches the witness
//! or writes. A reader view under the read rule of
//! `fstp_audit::verify::ChainView` therefore never sees the witness log
//! change between its reads.
//!
//! A refused append writes no row and sends nothing to the witness. Every
//! step before COMMIT can abort; an aborted attempt leaves sealed rows in
//! the WAL only, which is safe because no nonce is ever reused.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use fstp_audit::anchor::{Anchor, AnchorRow, Receipt, decode_receipt, encode_receipt};
use fstp_audit::anchorer::{
    Anchorer, CommitOutcome, Next, Phase, PrepareWitness, Resolution, Step, WitnessFault,
};
use fstp_audit::witness::{MAX_PREPARE_ROWS, Prepare};
use fstp_audit::{
    AuditError, CellId, ChainId, ChainRow, ChainWriter, CompositeSigningKey, Link, RowKind,
    StoredRow,
};
use fstp_json::{Object, Value};
use fstp_keys::{DekId, ObjectId};
use fstp_ledger::{
    AppendError, AsyncRecordStore, Canonical, Entry, MAX_AT, SCHEMA_V1, Seq, StoreError,
};
use fstp_pgwire::{Client, ErrorKind, Transaction, Uuid};
use fstp_rt::Runtime;

use crate::error::{AppendFault, DbFault, DecodeError, StoreFault};
use crate::outbox::{
    MAX_OUTBOX_BODY, MAX_OUTBOX_ROWS, OutboxKeys, OutboxRow, caller_kind, open_outbox_body,
    seal_outbox_body,
};
use crate::pool::{Pool, Role};
use crate::seal::{LedgerKeys, ledger_aad, open_stored_entry};
use crate::stored::{MAX_SEALED_LEN, MIN_SEALED_LEN, StoredEntry, decode_stored_entry};

/// Decodes a record from its canonical text at a schema version. The
/// composer passes it in, so the store never names the record type
/// (design section 5.3).
pub type Decode<T> = fn(canonical: &[u8], schema: u16) -> Result<T, DecodeError>;

/// The store's clock: UTC microseconds, or `None` when it cannot tell.
/// It stamps anchors and checks step-up freshness at commit. A cell
/// passes its own clock, so a test world can run a cell on a test clock.
pub type Clock = Arc<dyn Fn() -> Option<i64> + Send + Sync>;

/// The system clock in UTC microseconds.
pub fn system_clock() -> Option<i64> {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(d.as_micros()).ok()
}

/// The `auth_log.session_end.cause` of a session ended by a
/// `SessionEnded` ledger record. Idle and absolute expiry write no row.
///
/// Reading, interim, pending Daniel: design section 4.2 names no cause
/// codes, and `SessionEnded` carries no cause. So every row the store
/// writes has this one cause, "ended by a record".
pub const SESSION_END_BY_RECORD: i16 = 1;

/// The `ops.outbox.kind` of a `PossibleDeletion` alert (design section
/// 7.2 "In doubt"). Its body is `be64(n) || link`, sealed under its own
/// outbox data key, and its idem is [`possible_deletion_idem`], so one
/// `(n, link)` raises one alert however often it is raised.
///
/// Reading, interim, pending Daniel: the alert is an outbox row for the
/// tenant admins. The auditor view reads the same `(n, link)` from the
/// witness log, as `fstp_audit::Verified::possible_deletions`.
pub const OUTBOX_POSSIBLE_DELETION: i16 = 1;

/// The most sessions one append may end.
const MAX_SESSIONS_ENDED: usize = 65_536;

/// The rows one read query asks for. A page whose rows exceed the
/// client's result limit is asked for again in halves, down to one row.
const READ_PAGE: usize = 1000;

const LOCK_SQL: &str = "SELECT pg_catalog.pg_advisory_xact_lock(1::pg_catalog.int8)";
const COMMAND_SQL: &str = "SELECT first_seq FROM ledger.command WHERE command = $1";
const HEAD_SQL: &str = "SELECT coalesce(max(seq), 0)::pg_catalog.int8 FROM ledger.entry";
const KEY_IX_USED_SQL: &str = "SELECT EXISTS (SELECT 1 FROM ledger.entry WHERE key_ix = $1)";
const INSERT_COMMAND_SQL: &str =
    "INSERT INTO ledger.command (command, first_seq, last_seq, at) VALUES ($1, $2, $3, $4)";
const INSERT_ENTRY_SQL: &str = "INSERT INTO ledger.entry (seq, at, command, schema, key_ix, body) \
     VALUES ($1, $2, $3, $4, $5, $6)";
const CHAIN_HEAD_SQL: &str = "SELECT n, link FROM audit.chain ORDER BY n DESC LIMIT 1";
const INSERT_CHAIN_SQL: &str = "INSERT INTO audit.chain \
     (n, at, kind, ledger_seq, stored_hash, body, link) VALUES ($1, $2, 1, $3, $4, NULL, $5)";
const INSERT_STEPUP_SQL: &str =
    "INSERT INTO auth_log.stepup_consumed (challenge_id, ledger_seq) VALUES ($1, $2)";
const INSERT_SESSION_END_SQL: &str =
    "INSERT INTO auth_log.session_end (session_id, at, cause, ledger_seq) VALUES ($1, $2, $3, $4)";
const INSERT_OUTBOX_SQL: &str = "INSERT INTO ops.outbox (id, kind, idem, dek, body, created_at) \
     VALUES ($1, $2, $3, $4, $5, $6)";
const INSERT_ANCHOR_SQL: &str = "INSERT INTO audit.anchor \
     (n, link, at, signature, witness_seq, receipt) VALUES ($1, $2, $3, $4, $5, $6)";
const LINK_AT_SQL: &str = "SELECT link FROM audit.chain WHERE n = $1";
const ROW_OF_SEQ_SQL: &str = "SELECT n, link FROM audit.chain WHERE ledger_seq = $1";
const COVERING_ANCHOR_SQL: &str =
    "SELECT witness_seq FROM audit.anchor WHERE n >= $1 ORDER BY n LIMIT 1";
const CHAIN_ROWS_SQL: &str = "SELECT n, at, kind, ledger_seq, stored_hash, body, link \
     FROM audit.chain WHERE n >= $1 ORDER BY n LIMIT $2";
const ANCHOR_ROWS_SQL: &str = "SELECT n, link, at, signature, receipt \
     FROM audit.anchor WHERE n >= $1 ORDER BY n LIMIT $2";
const ALERT_EXISTS_SQL: &str = "SELECT EXISTS (SELECT 1 FROM ops.outbox WHERE idem = $1)";
const INSERT_ALERT_SQL: &str = "INSERT INTO ops.outbox (id, kind, idem, dek, body, created_at) \
     VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (idem) DO NOTHING";
const ALERTS_SQL: &str = "SELECT id, idem, dek, body FROM ops.outbox WHERE kind = $1";
/// Each row in the layout of [`decode_stored_entry`].
const READ_SQL: &str = "SELECT '\\x01'::pg_catalog.bytea || pg_catalog.int8send(seq) \
     || pg_catalog.int8send(at) || command || pg_catalog.int2send(schema) \
     || pg_catalog.int4send(key_ix) || pg_catalog.int4send(pg_catalog.octet_length(body)) || body \
     FROM ledger.entry WHERE seq >= $1 ORDER BY seq LIMIT $2";

/// Signs the anchor of a prospective head (design section 7.2, R-CR-03).
pub trait AnchorSigner: Send + Sync {
    /// The anchor of `cell`'s `chain` at head `(n, link)`, stamped `at`.
    ///
    /// # Errors
    ///
    /// The signer's refusal.
    fn sign_anchor(
        &self,
        cell: CellId,
        chain: ChainId,
        n: u64,
        link: &Link,
        at: i64,
    ) -> Result<Anchor, AuditError>;
}

/// The production signer: the chain's composite `Anchor` key, through
/// `fstp_audit::anchor::sign_anchor`. That call refuses until lane W2g
/// lands composite signing, and the store then refuses every append at
/// the prepare step.
impl AnchorSigner for CompositeSigningKey {
    fn sign_anchor(
        &self,
        cell: CellId,
        chain: ChainId,
        n: u64,
        link: &Link,
        at: i64,
    ) -> Result<Anchor, AuditError> {
        fstp_audit::anchor::sign_anchor(self, cell, chain, n, link, at)
    }
}

/// A consumed step-up challenge: one `auth_log.stepup_consumed` row.
///
/// One id keys a step-up end to end: the challenge id of `POST
/// /auth/stepup`. The route issues `GrantStepUp` under it as its command
/// id, `fstp_cell_core::stepup_id` makes it the step-up id of
/// `StepUpGranted`, and the consuming batch's `StepUpConsumed { id }`
/// names it. So this row's `challenge_id` is the id of that
/// `StepUpConsumed` record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StepUpUse {
    /// The challenge id, which is the step-up id.
    pub challenge: [u8; 16],
    /// The index in the batch of the record that consumes it, so the row
    /// names that record's entry (`fstp-cell-core` appends
    /// `StepUpConsumed` last).
    pub record: usize,
}

/// An ended session: one `auth_log.session_end` row, with cause
/// [`SESSION_END_BY_RECORD`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionEnd {
    /// The session id.
    pub session: [u8; 16],
    /// The index in the batch of the `SessionEnded` record that ends it,
    /// so the row names that record's entry.
    pub record: usize,
}

/// The insert-only side effects of one append (design section 5.3 step
/// 6, ADR-007 "Insert-only side effects").
///
/// `fstp_cell_core::driver::SideEffects` (lane W2c) carries the step-up
/// and the sessions without record indices, and no outbox rows yet. The
/// composer (lane W3a) finds each record in the batch it appends.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SideEffects {
    /// A consumed step-up challenge.
    pub stepup_consumed: Option<StepUpUse>,
    /// The last UTC microsecond at which the batch may commit under its
    /// step-up. Checked before the prepare and again just before COMMIT.
    pub stepup_fresh_until: Option<i64>,
    /// Ended sessions.
    pub sessions_ended: Vec<SessionEnd>,
    /// Messages to enqueue: one sealed `ops.outbox` row each, under its
    /// own data key (design gap G12).
    pub outbox: Vec<OutboxRow>,
}

/// What a committed append left (design sections 5.3 and 7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Committed {
    /// The ledger head after the append: the sequence of its last entry.
    pub head: Seq,
    /// The chain row number of that entry. A chain row number is not a
    /// ledger sequence once event rows exist (design section 7.1).
    pub n: u64,
    /// The chain link of that entry, which the witness receipted.
    pub link: Link,
    /// The witness sequence of the receipt the append committed on.
    pub witness_seq: u64,
}

/// The chain link of one stored ledger entry, and the witness receipt
/// that covers it: the first anchor at or after its chain row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredCommit {
    /// The chain row number of the entry.
    pub n: u64,
    /// The chain link of the entry.
    pub link: Link,
    /// The witness sequence of the covering receipt. Every committed
    /// append holds its receipt, so it is `None` only for rows the store
    /// did not write (I-24).
    pub witness_seq: Option<u64>,
}

/// The App chain as read back for `fstp_audit::verify` (design section
/// 7.2 "Start-up"): every chain row, every stored ledger row and every
/// anchor with its receipt, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainRows {
    /// The chain rows with their links, by row number.
    pub rows: Vec<StoredRow>,
    /// The stored ledger rows, sealed, by sequence.
    pub stored: Vec<fstp_audit::StoredEntry>,
    /// The `audit.anchor` rows, by row number.
    pub anchors: Vec<AnchorRow>,
}

/// The idem digest of the `PossibleDeletion` alert for `(n, link)`:
/// `SHA-256("fstp-possible-deletion-v1" || cell || be64(n) || link)`.
pub fn possible_deletion_idem(cell: &[u8; 16], n: u64, link: &Link) -> [u8; 32] {
    let mut h = fstp_crypto::Sha256::new();
    h.update(b"fstp-possible-deletion-v1");
    h.update(cell);
    h.update(&n.to_be_bytes());
    h.update(&link.0);
    h.finish()
}

/// Whether a composite public key is pinnable: it has the composite key
/// length.
fn pinnable(key: &[u8]) -> bool {
    key.len() == fstp_audit::PUBLIC_KEY_LEN
}

/// Whether one of the pinned witness keys signed the receipt `rc`. Both
/// halves of the composite signature must verify (I-90).
///
/// The check is `fstp_audit::anchor::receipt_signature_verifies`, under
/// the receipt context ADR-010 records.
fn receipt_signed(rc: &Receipt, witness_keys: &[Vec<u8>]) -> bool {
    fstp_audit::anchor::receipt_signature_verifies(rc, witness_keys)
}

/// The record store of one cell over its writer role (design section
/// 5.3).
pub struct PgRecordStore<R: Runtime, T, W> {
    pool: Pool<R>,
    cell: [u8; 16],
    keys: Arc<LedgerKeys>,
    signer: Arc<dyn AnchorSigner>,
    witness: W,
    witness_keys: Vec<Vec<u8>>,
    outbox_keys: Arc<dyn OutboxKeys>,
    decode: Decode<T>,
    schema: u16,
    clock: Clock,
    anchorer: Anchorer,
}

/// What steps 1 to 6 of an append left for the prepare.
struct Staged {
    prev: (u64, Link),
    head: (u64, Link),
    stored_hashes: Vec<[u8; 32]>,
    new_head: Seq,
}

/// A withdrawal of a prepared head at the witness.
#[derive(Clone, Copy)]
enum Withdraw {
    Abort,
    InDoubtAbsent,
}

fn i64_of(n: u64) -> Result<i64, StoreFault> {
    i64::try_from(n).map_err(|_| StoreFault::Refused("a number beyond the database range"))
}

fn u64_of(n: i64) -> Result<u64, StoreFault> {
    u64::try_from(n).map_err(|_| StoreFault::Corrupt("a negative stored number"))
}

fn link_of(bytes: &[u8]) -> Result<Link, StoreFault> {
    <[u8; 32]>::try_from(bytes)
        .map(Link)
        .map_err(|_| StoreFault::Corrupt("a link that is not 32 bytes"))
}

fn uuid_bytes(u: &Uuid) -> [u8; 16] {
    *u.as_bytes()
}

/// The `int4` of a key generation index, bit for bit.
fn key_ix_column(key_ix: u32) -> i32 {
    i32::from_be_bytes(key_ix.to_be_bytes())
}

/// A database error of a side-effect insert: a unique violation is a
/// replay of that row, `replayed` (I-77, I-78). Each insert names its own
/// table's replay, so a refusal names the row that conflicted.
fn side_fault(e: fstp_pgwire::Error, replayed: AppendFault) -> AppendFault {
    let f = DbFault::from(e);
    if f.is_unique_violation() {
        replayed
    } else {
        AppendFault::Fault(StoreFault::Database(f))
    }
}

/// A database error of an outbox insert: a unique violation is a second
/// row with one id or idem (TH-21).
fn outbox_fault(e: fstp_pgwire::Error) -> AppendFault {
    let f = DbFault::from(e);
    if f.is_unique_violation() {
        AppendFault::OutboxDuplicate
    } else {
        AppendFault::Fault(StoreFault::Database(f))
    }
}

fn db(e: fstp_pgwire::Error) -> AppendFault {
    AppendFault::Fault(StoreFault::from(e))
}

fn out_of_order<E>(_: E) -> StoreFault {
    StoreFault::OutOfOrder
}

/// The entry with these parts, built through the `fstp-ledger` decoder,
/// so its envelope rules hold for every entry the store returns.
fn entry_of<T>(
    seq: u64,
    at: i64,
    command: &[u8; 16],
    schema: u16,
    record: T,
) -> Result<Entry<T>, StoreFault> {
    let mut command_hex = String::with_capacity(32);
    for b in command {
        command_hex.push_str(&format!("{b:02x}"));
    }
    let mut o = Object::with_capacity(5);
    o.insert("seq", Value::String(seq.to_string()));
    o.insert("at", Value::from(at));
    o.insert("command", Value::String(command_hex));
    o.insert("schema", Value::from(schema));
    o.insert("record", Value::Null);
    let envelope = <Entry<Value> as fstp_json::FromJson>::from_json(&Value::Object(o))
        .map_err(|_| StoreFault::Corrupt("an entry envelope outside the ledger rules"))?;
    Ok(envelope.map_record(|_| record))
}

/// Runs `sql` page by page inside `tx` and hands each row to `each`.
/// `sql` takes a start key `$1` and a row limit `$2`, and orders by that
/// key. `each` returns the row's key, so the next page starts after it. A
/// page whose rows pass the client's result limit is read again in
/// halves, down to one row, as [`PgRecordStore::read_entries`] does.
async fn read_pages<R: Runtime>(
    tx: &mut Transaction<'_, R>,
    sql: &'static str,
    mut each: impl FnMut(&fstp_pgwire::Row) -> Result<u64, StoreFault>,
) -> Result<(), StoreFault> {
    let mut from: u64 = 1;
    let mut page = READ_PAGE;
    loop {
        let start = i64_of(from)?;
        let lim = i64::try_from(page).unwrap_or(i64::MAX);
        let rows = match tx.query(sql, &[&start, &lim]).await {
            Ok(rows) => rows,
            Err(e) if e.kind() == ErrorKind::ResultTooLarge && page > 1 => {
                page = page.div_ceil(2).max(1);
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let mut last = None;
        for row in &rows {
            last = Some(each(row)?);
        }
        let Some(last) = last.filter(|_| rows.len() >= page) else {
            return Ok(());
        };
        from = last
            .checked_add(1)
            .ok_or(StoreFault::Corrupt("a row key past u64::MAX"))?;
    }
}

/// The side-effect limits, checked before any row is written.
fn check_side(side: &SideEffects, batch_len: usize) -> Result<(), StoreFault> {
    if side.sessions_ended.len() > MAX_SESSIONS_ENDED {
        return Err(StoreFault::Refused(
            "more ended sessions than one append holds",
        ));
    }
    if side.outbox.len() > MAX_OUTBOX_ROWS {
        return Err(StoreFault::Refused(
            "more outbox rows than one append holds",
        ));
    }
    let in_batch = |record: usize| record < batch_len;
    if side.stepup_consumed.is_some_and(|s| !in_batch(s.record))
        || side.sessions_ended.iter().any(|s| !in_batch(s.record))
    {
        return Err(StoreFault::Refused(
            "a side-effect row names no record of its batch",
        ));
    }
    for row in &side.outbox {
        if caller_kind(row.kind).is_none() {
            return Err(StoreFault::Refused("an outbox kind outside 2..=32767"));
        }
        if row.body.len() > MAX_OUTBOX_BODY {
            return Err(StoreFault::Refused("an outbox body over its limit"));
        }
    }
    Ok(())
}

impl<R: Runtime, T, W: PrepareWitness> PgRecordStore<R, T, W> {
    /// The store of the cell of `pool`, which must serve the writer role.
    /// It seals ledger bodies under `keys`, signs anchors with `signer`,
    /// prepares at `witness`, accepts receipts signed by one of the
    /// pinned `witness_keys` (ADR-010 "Keys"), seals outbox rows under
    /// data keys from `outbox_keys`, and decodes records with `decode`.
    /// It writes schema version [`SCHEMA_V1`] and reads the system clock.
    ///
    /// The store starts with no prepare in flight. After a restart, the
    /// composer learns the witness's open prepare and calls
    /// [`PgRecordStore::resolve_in_doubt`] before it serves requests
    /// (ADR-010 "Start-up").
    ///
    /// # Errors
    ///
    /// [`StoreFault::WrongRole`] for a pool of another role, and
    /// [`StoreFault::Refused`] for an empty pin set or a pinned key that is
    /// not a composite public key.
    pub fn new(
        pool: Pool<R>,
        keys: Arc<LedgerKeys>,
        signer: Arc<dyn AnchorSigner>,
        witness: W,
        witness_keys: Vec<Vec<u8>>,
        outbox_keys: Arc<dyn OutboxKeys>,
        decode: Decode<T>,
    ) -> Result<Self, StoreFault> {
        if pool.role() != Role::Writer {
            return Err(StoreFault::WrongRole);
        }
        if witness_keys.is_empty() || !witness_keys.iter().all(|k| pinnable(k)) {
            return Err(StoreFault::Refused(
                "the pinned witness keys are empty or not composite keys",
            ));
        }
        Ok(PgRecordStore {
            cell: pool.cell(),
            pool,
            keys,
            signer,
            witness,
            witness_keys,
            outbox_keys,
            decode,
            schema: SCHEMA_V1,
            clock: Arc::new(system_clock),
            anchorer: Anchorer::new(),
        })
    }

    /// The same store writing schema version `schema` from now on.
    ///
    /// # Errors
    ///
    /// [`StoreFault::Refused`] for 0 or a version above `i16::MAX`, which
    /// the `smallint` column cannot hold.
    pub fn with_schema(mut self, schema: u16) -> Result<Self, StoreFault> {
        if schema == 0 || i16::try_from(schema).is_err() {
            return Err(StoreFault::Refused("a schema version outside 1..=32767"));
        }
        self.schema = schema;
        Ok(self)
    }

    /// The same store with another clock.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Replaces the ledger keys, for example after the current generation
    /// reached [`crate::LEDGER_KEY_SEALS`].
    pub fn set_keys(&mut self, keys: Arc<LedgerKeys>) {
        self.keys = keys;
    }

    /// Replaces the pinned witness keys, for example after the witness
    /// announced a new key signed by the old one (ADR-010 "Keys").
    ///
    /// # Errors
    ///
    /// [`StoreFault::Refused`] as for [`PgRecordStore::new`]. The pins stay
    /// as they were.
    pub fn set_witness_keys(&mut self, witness_keys: Vec<Vec<u8>>) -> Result<(), StoreFault> {
        if witness_keys.is_empty() || !witness_keys.iter().all(|k| pinnable(k)) {
            return Err(StoreFault::Refused(
                "the pinned witness keys are empty or not composite keys",
            ));
        }
        self.witness_keys = witness_keys;
        Ok(())
    }

    /// The cell.
    pub fn cell(&self) -> [u8; 16] {
        self.cell
    }

    /// The witness client.
    pub fn witness(&self) -> &W {
        &self.witness
    }

    /// The pinned witness receipt keys (ADR-010 "Keys"). The start-up
    /// verification checks the stored receipts under the same set.
    pub fn witness_keys(&self) -> &[Vec<u8>] {
        &self.witness_keys
    }

    /// Where the anchorer core stands.
    pub fn phase(&self) -> &Phase {
        self.anchorer.phase()
    }

    fn audit_cell(&self) -> CellId {
        CellId(self.cell)
    }

    /// The head of the ledger.
    ///
    /// # Errors
    ///
    /// A pool, database or stored-row fault.
    pub async fn ledger_head(&self) -> Result<Seq, StoreFault> {
        let mut client = self.pool.get().await?;
        let row = client.query_one(HEAD_SQL, &[]).await?;
        let head: i64 = row.get(0)?;
        client.release();
        Ok(Seq::from_raw(u64_of(head)?))
    }

    /// Reads at most `limit` entries from `from`, opened and decoded, and
    /// pushes them onto `out` only if every one of them reads. A gap in
    /// the stored sequence, a body that does not open under its AAD, or a
    /// record the decoder refuses fails the whole read.
    ///
    /// It reads in pages of at most 1 000 rows. A page whose rows pass the
    /// client's result limit is read again in halves, so a large `limit`
    /// reads like a small one.
    ///
    /// # Errors
    ///
    /// A pool, database, open or decode fault, or [`StoreFault::Corrupt`].
    pub async fn read_entries(
        &self,
        from: Seq,
        limit: usize,
        out: &mut Vec<Entry<T>>,
    ) -> Result<(), StoreFault> {
        let Ok(start) = i64::try_from(from.raw().max(1)) else {
            return Ok(());
        };
        if limit == 0 {
            return Ok(());
        }
        let mut client = self.pool.get().await?;
        let mut read = Vec::new();
        let mut want = u64_of(start)?;
        let mut left = limit;
        let mut page = READ_PAGE;
        while left > 0 {
            let ask = left.min(page);
            let next = i64_of(want)?;
            let lim = i64::try_from(ask).unwrap_or(i64::MAX);
            let rows = match client.query(READ_SQL, &[&next, &lim]).await {
                Ok(rows) => rows,
                Err(e) if e.kind() == ErrorKind::ResultTooLarge && page > 1 => {
                    page = page.div_ceil(2).max(1);
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let got = rows.len();
            for row in rows {
                let bytes: Vec<u8> = row.get(0)?;
                let e = decode_stored_entry(&bytes)?;
                if e.seq != want {
                    return Err(StoreFault::Corrupt("a gap in the stored ledger"));
                }
                want = want
                    .checked_add(1)
                    .ok_or(StoreFault::Corrupt("a sequence past u64::MAX"))?;
                let plain = open_stored_entry(&self.keys, &self.cell, &e)?;
                let record = (self.decode)(&plain, e.schema)?;
                read.push(entry_of(e.seq, e.at, &e.command, e.schema, record)?);
            }
            if got < ask {
                break;
            }
            left = left.saturating_sub(got);
        }
        client.release();
        out.extend(read);
        Ok(())
    }

    /// The chain row and link of ledger entry `seq` and the witness
    /// receipt that covers it: the first anchor at or after that row.
    /// `None` for a sequence the store holds no entry of.
    ///
    /// # Errors
    ///
    /// A pool, database or stored-row fault.
    pub async fn stored_commit(&self, seq: Seq) -> Result<Option<StoredCommit>, StoreFault> {
        let Ok(seq) = i64::try_from(seq.raw()) else {
            return Ok(None);
        };
        let mut client = self.pool.get().await?;
        let Some(row) = client.query_opt(ROW_OF_SEQ_SQL, &[&seq]).await? else {
            client.release();
            return Ok(None);
        };
        let n: i64 = row.get(0)?;
        let link: Vec<u8> = row.get(1)?;
        let witness_seq = match client.query_opt(COVERING_ANCHOR_SQL, &[&n]).await? {
            Some(r) => {
                let w: i64 = r.get(0)?;
                Some(u64_of(w)?)
            }
            None => None,
        };
        client.release();
        Ok(Some(StoredCommit {
            n: u64_of(n)?,
            link: link_of(&link)?,
            witness_seq,
        }))
    }

    /// The App chain as `fstp_audit::verify` reads it: every chain row,
    /// every stored ledger row and every anchor with its receipt (design
    /// section 7.2 "Start-up").
    ///
    /// The three reads run in one transaction under
    /// `pg_advisory_xact_lock(1)`, so no append commits between them and
    /// the view is one state of the chain (`fstp_audit::verify::ChainView`
    /// read rule). Each reads in pages, as [`PgRecordStore::read_entries`]
    /// does.
    ///
    /// # Errors
    ///
    /// A pool, database or stored-row fault, or [`StoreFault::Corrupt`] for
    /// a row outside the table rules, such as a chain row whose kind and
    /// columns disagree or a receipt that does not decode.
    pub async fn read_chain_rows(&self) -> Result<ChainRows, StoreFault> {
        let mut client = self.pool.get().await?;
        let mut tx = client.transaction().await?;
        tx.execute(LOCK_SQL, &[]).await?;
        let mut out = ChainRows::default();
        read_pages(&mut tx, CHAIN_ROWS_SQL, |row| {
            let n: i64 = row.get(0)?;
            let at: i64 = row.get(1)?;
            let kind: i16 = row.get(2)?;
            let ledger_seq: Option<i64> = row.get(3)?;
            let stored_hash: Vec<u8> = row.get(4)?;
            let body: Option<Vec<u8>> = row.get(5)?;
            let link: Vec<u8> = row.get(6)?;
            let kind = match (kind, ledger_seq, body) {
                (1, Some(seq), None) => RowKind::Ledger { seq: u64_of(seq)? },
                (2, None, Some(body)) => RowKind::Event { body },
                _ => {
                    return Err(StoreFault::Corrupt(
                        "a chain row whose kind and columns differ",
                    ));
                }
            };
            let stored_hash = <[u8; 32]>::try_from(stored_hash.as_slice())
                .map_err(|_| StoreFault::Corrupt("a stored hash that is not 32 bytes"))?;
            out.rows.push(StoredRow {
                row: ChainRow {
                    n: u64_of(n)?,
                    at,
                    kind,
                    stored_hash,
                },
                link: link_of(&link)?,
            });
            u64_of(n)
        })
        .await?;
        read_pages(&mut tx, READ_SQL, |row| {
            let bytes: Vec<u8> = row.get(0)?;
            let e = decode_stored_entry(&bytes)?;
            let seq = e.seq;
            out.stored.push(e.to_audit());
            Ok(seq)
        })
        .await?;
        let cell = self.audit_cell();
        read_pages(&mut tx, ANCHOR_ROWS_SQL, |row| {
            let n: i64 = row.get(0)?;
            let link: Vec<u8> = row.get(1)?;
            let at: i64 = row.get(2)?;
            let signature: Vec<u8> = row.get(3)?;
            let receipt: Vec<u8> = row.get(4)?;
            let receipt = decode_receipt(&receipt)
                .map_err(|_| StoreFault::Corrupt("a stored receipt that does not decode"))?;
            out.anchors.push(AnchorRow {
                anchor: Anchor {
                    cell,
                    chain: ChainId::App,
                    n: u64_of(n)?,
                    link: link_of(&link)?,
                    at,
                    signature,
                },
                receipt,
            });
            u64_of(n)
        })
        .await?;
        tx.commit().await?;
        client.release();
        Ok(out)
    }

    /// Drives every unfinished step of an earlier append to its end: an
    /// abort the witness has not recorded, or an in-doubt prepare with
    /// its read, alert and in-doubt record. It gives the resolution when
    /// it resolved an in-doubt prepare.
    ///
    /// Each step that reads the chain, reaches the witness or writes an
    /// alert runs in a new transaction under `pg_advisory_xact_lock(1)`
    /// (`fstp_audit::verify::ChainView`, W2e obligation).
    ///
    /// # Errors
    ///
    /// The witness or database fault that stopped it. The unfinished step
    /// stays, and the next call resumes it.
    pub async fn settle(&mut self) -> Result<Option<Resolution>, StoreFault> {
        let mut resolution = None;
        loop {
            match self.anchorer.next() {
                Next::Nothing => return Ok(resolution),
                // A dropped append future left the core mid-way. Before the
                // prepare nothing reached the witness; after it the prepare
                // is withdrawn; after COMMIT was sent the outcome is unknown.
                Next::Run(_)
                | Next::SendPrepare
                | Next::AwaitReceipt
                | Next::InsertAnchor
                | Next::SendCommit => {
                    self.anchorer.failed().map_err(out_of_order)?;
                }
                Next::AwaitOutcome => {
                    self.anchorer
                        .outcome(CommitOutcome::Unknown)
                        .map_err(out_of_order)?;
                }
                Next::SendAbort { head } => {
                    match self.withdraw_locked(head, Withdraw::Abort).await? {
                        Ok(()) => self.anchorer.abort_recorded().map_err(out_of_order)?,
                        Err(WitnessFault::UnknownPrepare) => self
                            .anchorer
                            .abort_unknown_at_witness()
                            .map_err(out_of_order)?,
                        Err(f) => return Err(StoreFault::Witness(f)),
                    }
                }
                Next::ReadChain { head } => {
                    resolution = Some(self.read_chain(head).await?);
                }
                Next::RaisePossibleDeletion { head } => {
                    resolution = Some(Resolution::AbsentRaisePossibleDeletion);
                    let mut client = self.pool.get().await?;
                    let mut tx = client.transaction().await?;
                    tx.execute(LOCK_SQL, &[]).await?;
                    self.insert_alert(&mut tx, head).await?;
                    tx.commit().await?;
                    client.release();
                    self.anchorer
                        .possible_deletion_raised()
                        .map_err(out_of_order)?;
                }
                Next::SendInDoubtAbsent { head } => {
                    resolution = Some(Resolution::AbsentRaisePossibleDeletion);
                    match self.withdraw_locked(head, Withdraw::InDoubtAbsent).await? {
                        Ok(()) => self.anchorer.in_doubt_recorded().map_err(out_of_order)?,
                        Err(WitnessFault::UnknownPrepare) => self
                            .anchorer
                            .in_doubt_unknown_at_witness()
                            .map_err(out_of_order)?,
                        Err(f) => return Err(StoreFault::Witness(f)),
                    }
                }
            }
        }
    }

    /// Sends the withdrawal of `head` to the witness while this session
    /// holds `pg_advisory_xact_lock(1)`, and gives the witness's answer.
    /// The transaction writes nothing. It only orders the message after
    /// every open append and reader view, and before the next one.
    ///
    /// # Errors
    ///
    /// A pool or database fault before the message was sent. The step
    /// then stays due.
    async fn withdraw_locked(
        &self,
        head: (u64, Link),
        what: Withdraw,
    ) -> Result<Result<(), WitnessFault>, StoreFault> {
        let mut client = self.pool.get().await?;
        let mut tx = client.transaction().await?;
        tx.execute(LOCK_SQL, &[]).await?;
        let answer = match what {
            Withdraw::Abort => self.witness.abort(head).await,
            Withdraw::InDoubtAbsent => self.witness.in_doubt_absent(head).await,
        };
        // The witness answered, so its answer stands. A failed COMMIT of a
        // transaction that wrote nothing only ends the session, which
        // releases the lock too.
        if tx.commit().await.is_ok() {
            client.release();
        }
        Ok(answer)
    }

    /// Resolves the in-doubt prepare `head`, as the witness reports it at
    /// start-up or as an unknown COMMIT left it (ADR-010 "In doubt").
    ///
    /// It reads row `n` in a new transaction after it takes
    /// `pg_advisory_xact_lock(1)`, so an append whose COMMIT is still in
    /// flight is seen. A row with the prepared link was committed. A
    /// missing row, or one with another link, raises `PossibleDeletion`
    /// durably, keyed by `(n, link)`, and only then sends
    /// `InDoubtAbsent { n, link }`, under the lock again.
    ///
    /// # Errors
    ///
    /// [`StoreFault::OtherHeadPending`] while another prepared head waits,
    /// and the faults of [`PgRecordStore::settle`].
    pub async fn resolve_in_doubt(&mut self, head: (u64, Link)) -> Result<Resolution, StoreFault> {
        match self.anchorer.phase() {
            Phase::Idle => self.anchorer = Anchorer::in_doubt(head),
            Phase::InDoubt { head: h }
            | Phase::MustRaise { head: h }
            | Phase::MustRecordInDoubt { head: h }
                if *h == head => {}
            _ => return Err(StoreFault::OtherHeadPending),
        }
        self.settle().await?.ok_or(StoreFault::OutOfOrder)
    }

    /// Raises `PossibleDeletion` for each of `heads`, as the start-up does
    /// for every `InDoubtAbsent` record the witness holds (design section
    /// 7.2 "In doubt"). Each insert runs under `pg_advisory_xact_lock(1)`
    /// and is keyed by `(n, link)`, so a head raised before changes
    /// nothing and draws no new key.
    ///
    /// # Errors
    ///
    /// A pool or database fault, or the key provider's refusal.
    pub async fn raise_possible_deletions(
        &mut self,
        heads: &[(u64, Link)],
    ) -> Result<(), StoreFault> {
        for head in heads {
            let mut client = self.pool.get().await?;
            let mut tx = client.transaction().await?;
            tx.execute(LOCK_SQL, &[]).await?;
            self.insert_alert(&mut tx, *head).await?;
            tx.commit().await?;
            client.release();
        }
        Ok(())
    }

    /// Reads row `n` under the advisory lock and resolves `head`. A
    /// missing row raises its alert in the same transaction.
    async fn read_chain(&mut self, head: (u64, Link)) -> Result<Resolution, StoreFault> {
        let n = i64_of(head.0)?;
        let mut client = self.pool.get().await?;
        let mut tx = client.transaction().await?;
        tx.execute(LOCK_SQL, &[]).await?;
        let link = match tx.query_opt(LINK_AT_SQL, &[&n]).await? {
            Some(row) => {
                let bytes: Vec<u8> = row.get(0)?;
                Some(link_of(&bytes)?)
            }
            None => None,
        };
        let r = self
            .anchorer
            .chain_read(link.as_ref())
            .map_err(out_of_order)?;
        if r == Resolution::AbsentRaisePossibleDeletion {
            self.insert_alert(&mut tx, head).await?;
            tx.commit().await?;
            client.release();
            self.anchorer
                .possible_deletion_raised()
                .map_err(out_of_order)?;
        } else {
            tx.commit().await?;
            client.release();
        }
        Ok(r)
    }

    /// Inserts the `PossibleDeletion` alert of `head`, once per
    /// `(n, link)`, sealed under a fresh data key of its own. The caller
    /// holds the advisory lock, so the existence check and the insert are
    /// one step for every store of the cell. An alert already raised
    /// draws no new key.
    async fn insert_alert(
        &self,
        tx: &mut Transaction<'_, R>,
        head: (u64, Link),
    ) -> Result<(), StoreFault> {
        let idem = possible_deletion_idem(&self.cell, head.0, &head.1);
        let exists: bool = tx
            .query_one(ALERT_EXISTS_SQL, &[&idem.as_slice()])
            .await?
            .get(0)?;
        if exists {
            return Ok(());
        }
        let id: [u8; 16] = fstp_crypto::random_array().map_err(|_| StoreFault::SealRefused)?;
        let mut plain = Vec::with_capacity(40);
        plain.extend_from_slice(&head.0.to_be_bytes());
        plain.extend_from_slice(&head.1.0);
        let key = self.outbox_keys.create(ObjectId(id)).await?;
        let body = seal_outbox_body(
            &self.cell,
            &key,
            &id,
            OUTBOX_POSSIBLE_DELETION.unsigned_abs(),
            &idem,
            &plain,
        )?;
        let created_at = (self.clock)().unwrap_or(0);
        tx.execute(
            INSERT_ALERT_SQL,
            &[
                &Uuid::from_bytes(id),
                &OUTBOX_POSSIBLE_DELETION,
                &idem.as_slice(),
                &Uuid::from_bytes(key.dek.0),
                &body,
                &created_at,
            ],
        )
        .await?;
        Ok(())
    }

    /// Every durable `PossibleDeletion` alert, as `(n, link)`, in that
    /// order.
    ///
    /// # Errors
    ///
    /// A pool or database fault, the key provider's refusal, or an alert
    /// whose key is refused, that does not open, or whose idem is not the
    /// one of its `(n, link)`.
    pub async fn possible_deletions(&self) -> Result<Vec<(u64, Link)>, StoreFault> {
        let mut client = self.pool.get().await?;
        let rows = client
            .query(ALERTS_SQL, &[&OUTBOX_POSSIBLE_DELETION])
            .await?;
        client.release();
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let id: Uuid = row.get(0)?;
            let idem: Vec<u8> = row.get(1)?;
            let dek: Uuid = row.get(2)?;
            let body: Vec<u8> = row.get(3)?;
            let id = uuid_bytes(&id);
            let key = self
                .outbox_keys
                .open(DekId(uuid_bytes(&dek)), ObjectId(id))
                .await?
                .ok_or(StoreFault::OpenFailed)?;
            if key.dek.0 != uuid_bytes(&dek) {
                return Err(StoreFault::OpenFailed);
            }
            let plain = open_outbox_body(
                &self.cell,
                &key,
                &id,
                OUTBOX_POSSIBLE_DELETION.unsigned_abs(),
                &idem,
                &body,
            )?;
            let (n, link) = plain
                .split_first_chunk::<8>()
                .ok_or(StoreFault::Corrupt("an alert body of the wrong length"))?;
            let n = u64::from_be_bytes(*n);
            let link = link_of(link)?;
            if possible_deletion_idem(&self.cell, n, &link).as_slice() != idem.as_slice() {
                return Err(StoreFault::Corrupt("an alert whose idem is another head's"));
            }
            out.push((n, link));
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Whether the batch may commit under its step-up now.
    fn fresh(&self, side: &SideEffects) -> bool {
        match (side.stepup_consumed, side.stepup_fresh_until) {
            (None, None) => true,
            (_, Some(until)) => (self.clock)().is_some_and(|now| now <= until),
            (Some(_), None) => false,
        }
    }

    /// Appends `batch` with its side effects (design section 5.3).
    ///
    /// # Errors
    ///
    /// The contract refusals as [`AppendFault::Refused`], in the order of
    /// `fstp_ledger::RecordStore::append`, then [`AppendFault::StepUpStale`],
    /// [`AppendFault::StepUpReplayed`], [`AppendFault::SessionEndReplayed`],
    /// [`AppendFault::OutboxDuplicate`], an unresolved earlier prepare, a
    /// witness, signing, receipt or database fault, or an unknown commit
    /// outcome. Only [`AppendFault::Unknown`] may have committed.
    pub async fn append_with(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<T>,
        side: &SideEffects,
    ) -> Result<Seq, AppendFault>
    where
        T: Canonical,
    {
        self.append_committed(expected, at, command, batch, side)
            .await
            .map(|c| c.head)
    }

    /// [`PgRecordStore::append_with`], reporting what the commit left: the
    /// new ledger head, the chain row and link of its last entry, and the
    /// witness sequence of the receipt it committed on (design sections
    /// 5.3 and 7.2). A vault acknowledgement names that link (NOTE 4), and
    /// the engine reports the receipt with the commit.
    ///
    /// # Errors
    ///
    /// As [`PgRecordStore::append_with`].
    pub async fn append_committed(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<T>,
        side: &SideEffects,
    ) -> Result<Committed, AppendFault>
    where
        T: Canonical,
    {
        self.settle().await.map_err(AppendFault::Pending)?;
        self.anchorer
            .begin(true)
            .map_err(|_| AppendFault::Pending(StoreFault::OutOfOrder))?;
        let mut client = match self.pool.get().await {
            Ok(c) => c,
            Err(e) => {
                let _ = self.anchorer.failed();
                return Err(AppendFault::Fault(StoreFault::Pool(e)));
            }
        };
        let result = self
            .run_append(&mut client, expected, at, command, &batch, side)
            .await;
        client.release();
        if matches!(self.anchorer.phase(), Phase::MustAbort { .. }) {
            // Send a due abort now, under the lock. A failure keeps it due,
            // and the next append sends it first. An unknown outcome waits
            // for the next append, whose read then waits for the old
            // backend to end.
            let _ = self.settle().await;
        }
        result
    }

    async fn run_append(
        &mut self,
        client: &mut Client<R>,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: &[T],
        side: &SideEffects,
    ) -> Result<Committed, AppendFault>
    where
        T: Canonical,
    {
        let mut tx = match client.transaction().await {
            Ok(tx) => tx,
            Err(e) => {
                let _ = self.anchorer.failed();
                return Err(db(e));
            }
        };
        let staged = match self
            .stage(&mut tx, expected, at, command, batch, side)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                let _ = tx.rollback().await;
                let _ = self.anchorer.failed();
                return Err(e);
            }
        };
        // Step 7: sign and prepare the prospective head.
        let anchor = match (self.clock)() {
            Some(now) => self.signer.sign_anchor(
                self.audit_cell(),
                ChainId::App,
                staged.head.0,
                &staged.head.1,
                now,
            ),
            None => {
                let _ = tx.rollback().await;
                let _ = self.anchorer.failed();
                return Err(StoreFault::Refused("no clock to stamp the anchor").into());
            }
        };
        let anchor = match anchor {
            Ok(a) => a,
            Err(e) => {
                let _ = tx.rollback().await;
                let _ = self.anchorer.failed();
                return Err(StoreFault::Audit(e).into());
            }
        };
        let prepare = Prepare {
            prev: staged.prev,
            stored_hashes: staged.stored_hashes,
            anchor,
        };
        if self.anchorer.prepared(staged.head).is_err() {
            let _ = tx.rollback().await;
            let _ = self.anchorer.failed();
            return Err(StoreFault::OutOfOrder.into());
        }
        let receipt = match self.witness.prepare(&prepare).await {
            Ok(r) => r,
            Err(WitnessFault::Refused) => {
                let _ = tx.rollback().await;
                let _ = self.anchorer.prepare_refused();
                return Err(StoreFault::Witness(WitnessFault::Refused).into());
            }
            Err(f) => {
                let _ = tx.rollback().await;
                let _ = self.anchorer.failed();
                return Err(StoreFault::Witness(f).into());
            }
        };
        // The receipt must be for this cell, this chain and this head.
        let ours = receipt.cell == self.audit_cell()
            && receipt.chain == ChainId::App
            && self.anchorer.receipt(&receipt.fields).is_ok();
        let receipt_bytes = encode_receipt(&receipt);
        let (Ok(receipt_bytes), true) = (receipt_bytes, ours) else {
            let _ = tx.rollback().await;
            let _ = self.anchorer.failed();
            return Err(StoreFault::Witness(WitnessFault::Refused).into());
        };
        // And it must be signed by a pinned witness key. A receipt that is
        // not is treated as a mismatched one: roll back, then abort.
        if !receipt_signed(&receipt, &self.witness_keys) {
            let _ = tx.rollback().await;
            let _ = self.anchorer.failed();
            return Err(StoreFault::ReceiptUnsigned.into());
        }
        let inserted = async {
            let n = i64_of(staged.head.0)?;
            let witness_seq = i64_of(receipt.fields.witness_seq)?;
            tx.execute(
                INSERT_ANCHOR_SQL,
                &[
                    &n,
                    &staged.head.1.0.as_slice(),
                    &prepare.anchor.at,
                    &prepare.anchor.signature,
                    &witness_seq,
                    &receipt_bytes,
                ],
            )
            .await
            .map_err(StoreFault::from)?;
            Ok::<(), StoreFault>(())
        }
        .await;
        if let Err(e) = inserted {
            let _ = tx.rollback().await;
            let _ = self.anchorer.failed();
            return Err(e.into());
        }
        if self.anchorer.anchor_inserted().is_err() {
            let _ = tx.rollback().await;
            let _ = self.anchorer.failed();
            return Err(StoreFault::OutOfOrder.into());
        }
        // Freshness is checked again at the commit instant (I-78).
        if !self.fresh(side) {
            let _ = tx.rollback().await;
            let _ = self.anchorer.failed();
            return Err(AppendFault::StepUpStale);
        }
        if self.anchorer.commit_sent().is_err() {
            let _ = tx.rollback().await;
            let _ = self.anchorer.failed();
            return Err(StoreFault::OutOfOrder.into());
        }
        // Step 8.
        match tx.commit().await {
            Ok(()) => {
                let _ = self.anchorer.outcome(CommitOutcome::Committed);
                Ok(Committed {
                    head: staged.new_head,
                    n: staged.head.0,
                    link: staged.head.1,
                    witness_seq: receipt.fields.witness_seq,
                })
            }
            Err(e) if matches!(e.kind(), ErrorKind::Db | ErrorKind::RolledBack) => {
                let _ = self.anchorer.outcome(CommitOutcome::Failed);
                Err(db(e))
            }
            Err(_) => {
                let _ = self.anchorer.outcome(CommitOutcome::Unknown);
                Err(AppendFault::Unknown)
            }
        }
    }

    /// Steps 1 to 6 inside the open transaction.
    async fn stage(
        &mut self,
        tx: &mut Transaction<'_, R>,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: &[T],
        side: &SideEffects,
    ) -> Result<Staged, AppendFault>
    where
        T: Canonical,
    {
        let step = |a: &mut Anchorer, s: Step| a.step_done(s).map_err(out_of_order);
        // 1. One writer per cell database.
        tx.execute(LOCK_SQL, &[]).await.map_err(db)?;
        step(&mut self.anchorer, Step::Lock)?;
        // 2. The command id before the head (ADR-007).
        if let Some(row) = tx
            .query_opt(COMMAND_SQL, &[&command.as_slice()])
            .await
            .map_err(db)?
        {
            let first: i64 = row.get(0).map_err(db)?;
            return Err(AppendFault::Refused(AppendError::DuplicateCommand {
                at: Seq::from_raw(u64_of(first)?),
            }));
        }
        step(&mut self.anchorer, Step::CommandCheck)?;
        // 3. The head, then the store errors in the contract's order.
        let row = tx.query_one(HEAD_SQL, &[]).await.map_err(db)?;
        let head: i64 = row.get(0).map_err(db)?;
        let head = Seq::from_raw(u64_of(head)?);
        if head != expected {
            return Err(AppendFault::Refused(AppendError::StaleHead { head }));
        }
        if !(-MAX_AT..=MAX_AT).contains(&at) {
            return Err(AppendFault::Refused(AppendError::Store(
                StoreError::TimeOutOfRange,
            )));
        }
        if batch.is_empty() {
            return Err(AppendFault::Refused(AppendError::Store(
                StoreError::EmptyBatch,
            )));
        }
        let new_head = u64::try_from(batch.len())
            .ok()
            .and_then(|len| head.raw().checked_add(len))
            .filter(|h| i64::try_from(*h).is_ok())
            .ok_or(AppendFault::Refused(AppendError::Store(StoreError::Full)))?;
        if batch.len() > MAX_PREPARE_ROWS {
            return Err(StoreFault::Refused("a batch over the prepare limit").into());
        }
        check_side(side, batch.len())?;
        if !self.fresh(side) {
            return Err(AppendFault::StepUpStale);
        }
        step(&mut self.anchorer, Step::HeadCheck)?;
        // 4. Sealed entries, row by row. A generation this process has not
        // sealed with yet must name no stored row (ADR-004).
        let current = self.keys.current();
        if current.seal_count() == 0 {
            let used: bool = tx
                .query_one(KEY_IX_USED_SQL, &[&key_ix_column(current.key_ix())])
                .await
                .map_err(db)?
                .get(0)
                .map_err(db)?;
            if used {
                return Err(StoreFault::KeyGenerationReused.into());
            }
        }
        let first = head
            .raw()
            .checked_add(1)
            .ok_or(AppendFault::Refused(AppendError::Store(StoreError::Full)))?;
        let schema = i16::try_from(self.schema)
            .map_err(|_| StoreFault::Refused("a schema version beyond smallint"))?;
        tx.execute(
            INSERT_COMMAND_SQL,
            &[
                &command.as_slice(),
                &i64_of(first)?,
                &i64_of(new_head)?,
                &at,
            ],
        )
        .await
        .map_err(db)?;
        let mut entries = Vec::with_capacity(batch.len());
        let mut seq = head.raw();
        for record in batch {
            seq = seq.checked_add(1).ok_or(StoreFault::Corrupt("sequence"))?;
            let plain = record.canonical();
            if plain.len() > MAX_SEALED_LEN.saturating_sub(MIN_SEALED_LEN) {
                return Err(StoreFault::Refused("a record over the body limit").into());
            }
            let aad = ledger_aad(&self.cell, seq, at, &command, self.schema);
            let (key_ix, sealed) = self.keys.seal(&aad, &plain)?;
            tx.execute(
                INSERT_ENTRY_SQL,
                &[
                    &i64_of(seq)?,
                    &at,
                    &command.as_slice(),
                    &schema,
                    &key_ix_column(key_ix),
                    &sealed,
                ],
            )
            .await
            .map_err(db)?;
            entries.push(StoredEntry {
                seq,
                at,
                command,
                schema: self.schema,
                key_ix,
                sealed,
            });
        }
        step(&mut self.anchorer, Step::SealLedger)?;
        // 5. One chain row per entry, after the head read under the lock.
        let prev = match tx.query_opt(CHAIN_HEAD_SQL, &[]).await.map_err(db)? {
            Some(row) => {
                let n: i64 = row.get(0).map_err(db)?;
                let link: Vec<u8> = row.get(1).map_err(db)?;
                (u64_of(n)?, link_of(&link)?)
            }
            None => (
                0,
                fstp_audit::chain::genesis(self.audit_cell(), ChainId::App),
            ),
        };
        let mut writer = ChainWriter::resume(prev.0, prev.1);
        let mut stored_hashes = Vec::with_capacity(entries.len());
        for e in &entries {
            let row = writer
                .append(
                    self.audit_cell(),
                    ChainId::App,
                    e.at,
                    RowKind::Ledger { seq: e.seq },
                    Some(&e.to_audit()),
                )
                .map_err(StoreFault::Audit)?;
            tx.execute(
                INSERT_CHAIN_SQL,
                &[
                    &i64_of(row.row.n)?,
                    &row.row.at,
                    &i64_of(e.seq)?,
                    &row.row.stored_hash.as_slice(),
                    &row.link.0.as_slice(),
                ],
            )
            .await
            .map_err(db)?;
            stored_hashes.push(row.row.stored_hash);
        }
        step(&mut self.anchorer, Step::InsertChain)?;
        // 6. Side effects, inserts only. Each auth_log row names the entry
        // of the record it belongs to.
        let seq_of = |record: usize| -> Result<i64, StoreFault> {
            let offset = u64::try_from(record)
                .map_err(|_| StoreFault::Refused("a record index beyond u64"))?;
            i64_of(
                first
                    .checked_add(offset)
                    .ok_or(StoreFault::Corrupt("sequence"))?,
            )
        };
        if let Some(s) = side.stepup_consumed {
            tx.execute(
                INSERT_STEPUP_SQL,
                &[&Uuid::from_bytes(s.challenge), &seq_of(s.record)?],
            )
            .await
            .map_err(|e| side_fault(e, AppendFault::StepUpReplayed))?;
        }
        for s in &side.sessions_ended {
            tx.execute(
                INSERT_SESSION_END_SQL,
                &[
                    &Uuid::from_bytes(s.session),
                    &at,
                    &SESSION_END_BY_RECORD,
                    &seq_of(s.record)?,
                ],
            )
            .await
            .map_err(|e| side_fault(e, AppendFault::SessionEndReplayed))?;
        }
        for row in &side.outbox {
            self.insert_outbox_row(tx, row, at).await?;
        }
        step(&mut self.anchorer, Step::SideEffects)?;
        Ok(Staged {
            prev,
            head: writer.head(),
            stored_hashes,
            new_head: Seq::from_raw(new_head),
        })
    }

    /// Seals `row` under a fresh data key of its own and inserts it,
    /// stamped with the batch time `at`.
    async fn insert_outbox_row(
        &self,
        tx: &mut Transaction<'_, R>,
        row: &OutboxRow,
        at: i64,
    ) -> Result<(), AppendFault> {
        let kind =
            caller_kind(row.kind).ok_or(StoreFault::Refused("an outbox kind outside 2..=32767"))?;
        let key = self.outbox_keys.create(ObjectId(row.id)).await?;
        let body = seal_outbox_body(&self.cell, &key, &row.id, row.kind, &row.idem, &row.body)?;
        tx.execute(
            INSERT_OUTBOX_SQL,
            &[
                &Uuid::from_bytes(row.id),
                &kind,
                &row.idem.as_slice(),
                &Uuid::from_bytes(key.dek.0),
                &body,
                &at,
            ],
        )
        .await
        .map_err(outbox_fault)?;
        Ok(())
    }
}

impl<R, T, W> AsyncRecordStore<T> for PgRecordStore<R, T, W>
where
    R: Runtime,
    T: Canonical + Send + Sync,
    W: PrepareWitness + Send + Sync,
{
    async fn head(&self) -> Result<Seq, StoreError> {
        self.ledger_head().await.map_err(StoreError::from)
    }

    async fn append(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<T>,
    ) -> Result<Seq, AppendError> {
        self.append_with(expected, at, command, batch, &SideEffects::default())
            .await
            .map_err(AppendError::from)
    }

    async fn read(
        &self,
        from: Seq,
        limit: usize,
        out: &mut Vec<Entry<T>>,
    ) -> Result<(), StoreError> {
        self.read_entries(from, limit, out)
            .await
            .map_err(StoreError::from)
    }
}
