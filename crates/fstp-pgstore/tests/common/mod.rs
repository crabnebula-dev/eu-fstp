//! Shared helpers of the `fstp-pgstore` test binaries (M3 design sections
//! 4, 5.3, 5.5, 5.6, 7.1 and 7.2, ADR-007, ADR-010).
//!
//! - [`CellDb`]: one application database `c_<cell>` on the named server
//!   `app`, with the five login roles of design section 4.1. Its migrator
//!   applies the application migrations, then grants every row of the
//!   reference plan through `fstp_meta.apply_grant`.
//! - [`reference`]: the role plan of design section 4.1, written from the
//!   design text by the W2e test author.
//! - [`REFERENCE_APP`]: a reference schema from design sections 4.1, 4.2
//!   and 7.1. The harness self-tests and the teeth run over it, so the
//!   predicates are proven before the production migrations exist.
//! - [`FakeWitness`]: a witness that receipts prepares with a real
//!   composite signature and records every message in order.
//! - [`Rec`]: the record type of the tests, with its canonical bytes and
//!   its decoder.
//! - [`Store`]: one adapter over `PgRecordStore`, its text store, its
//!   checkpoints and its pool.
//!
//! # Seams
//!
//! The W0 stub of `fstp-pgstore` has no migrations, no pool constructor,
//! no append, no text store and no checkpoints. Every adapter call that
//! needs one returns a [`Gap`] that names it, so each test is red for that
//! reason and never for a compile error. When lane W2e lands the code,
//! only the section "Seams" of this file changes. The tests, the
//! reference and the predicates stay as they are.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "a shared test module: each test binary uses part of it"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::{Future, ready};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fstp_audit::anchor::{Receipt, ReceiptFields, receipt_message};
use fstp_audit::anchorer::{PrepareWitness, Resolution, WitnessFault};
use fstp_audit::chain::{ChainId, ChainRow, Link, RowKind, StoredEntry, StoredRow};
use fstp_audit::witness::{Prepare, RecordKind, witness_genesis, witness_link};
use fstp_audit::{CellId, CompositeSigningKey};
use fstp_ledger::{AppendError, Canonical, Entry, Seq, StoreError};
use fstp_migrate::{Migration, MigrationSet};
use fstp_pgtest::{PgServer, RoleLogin};
use fstp_pgwire::{Client, ClientTls, Config, Password};
use fstp_rt::tokio::TokioRuntime;

// ---------------------------------------------------------------------------
// Gaps.

/// A seam that refuses: the production API it needs does not exist yet.
/// Red for the right reason.
#[derive(Clone, PartialEq, Eq)]
pub struct Gap(pub String);

impl fmt::Debug for Gap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (NotImplemented)", self.0)
    }
}

impl fmt::Display for Gap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (NotImplemented)", self.0)
    }
}

impl From<Gap> for String {
    fn from(g: Gap) -> String {
        g.to_string()
    }
}

/// A refusal of the seam `seam`.
pub fn gap<T>(seam: &str) -> Result<T, Gap> {
    Err(Gap(seam.to_owned()))
}

/// The value of a seam call, or a panic that names the gap. For tests
/// outside a property.
pub fn must<T>(r: Result<T, Gap>) -> T {
    r.unwrap_or_else(|g| panic!("{g}"))
}

// ---------------------------------------------------------------------------
// Seams. Lane W2e replaced each refusal below with a call into production.
//
// The two pieces that stay test-side are named here:
//
// - [`TestSigner`] signs anchors with a real composite key through
//   `fstp_crypto::composite`, as design section 14.4 lets the tests do.
//   The production signer, `fstp_audit::anchor::sign_anchor`, still
//   refuses until lane W2g lands composite signing.
// - [`TestTextKeys`], [`TestOutboxKeys`] and the ledger key registry
//   stand in for lane W2f's keystore. Each open of a store is a process
//   start, so it draws a new ledger key generation and keeps the older
//   ones for reading (ADR-004, ADR-007).

use fstp_audit::anchor::{Anchor, anchor_message};
use fstp_ledger::AsyncRecordStore;
use fstp_pgstore::{
    AnchorSigner, Checkpoints, KeyFuture, LedgerKey, LedgerKeys, OutboxKey, OutboxKeys,
    PgRecordStore, Pool, Role, SessionEnd, SideEffects, StepUpUse, TextKey, TextKeys, TextLookup,
    TextRef, TextStore,
};

/// The seams that were refusals until lane W2e landed. Kept as names for
/// the doc comments of the test files.
pub const MIGRATIONS_SEAM: &str = "closed: fstp_pgstore::MIGRATIONS";
/// Closed: `fstp_migrate::catalogue::APPLY_GRANT_SQL`.
pub const APPLY_GRANT_SEAM: &str = "closed: fstp_migrate::catalogue::APPLY_GRANT_SQL";
/// Closed: `Pool::open`, `PgRecordStore` and `AsyncRecordStore`.
pub const STORE_SEAM: &str = "closed: fstp_pgstore::PgRecordStore";
/// Closed: `PgRecordStore::append_with`.
pub const SIDE_SEAM: &str = "closed: fstp_pgstore::PgRecordStore::append_with";
/// Closed: `PgRecordStore::resolve_in_doubt` and `possible_deletions`.
pub const IN_DOUBT_SEAM: &str = "closed: fstp_pgstore::PgRecordStore::resolve_in_doubt";
/// Closed: `fstp_pgstore::Checkpoints`.
pub const CHECKPOINT_SEAM: &str = "closed: fstp_pgstore::Checkpoints";
/// Closed: `fstp_pgstore::TextStore`.
pub const TEXT_SEAM: &str = "closed: fstp_pgstore::TextStore";
/// Closed: `fstp_pgstore::Pool::open`.
pub const POOL_SEAM: &str = "closed: fstp_pgstore::Pool::open";
/// Closed: `fstp_pgstore::encode_stored_entry`.
pub const STORED_ENTRY_SEAM: &str = "closed: fstp_pgstore::encode_stored_entry";

/// The application migrations, in order (design section 4.6).
pub fn app_migrations() -> Result<&'static [Migration], Gap> {
    Ok(fstp_pgstore::MIGRATIONS)
}

/// `fstp_migrate::catalogue::APPLY_GRANT_SQL` (design section 4.1).
pub fn apply_grant_sql() -> Result<&'static str, Gap> {
    Ok(fstp_migrate::catalogue::APPLY_GRANT_SQL)
}

/// The stored-row encoding whose one spelling `decode_stored_entry`
/// accepts. `None` when the encoder refuses the row.
pub fn encode_stored_entry(e: &fstp_pgstore::StoredEntry) -> Result<Option<Vec<u8>>, Gap> {
    Ok(fstp_pgstore::encode_stored_entry(e).ok())
}

/// The parts of a stored row the decoder tests name: sequence, time,
/// command, schema version and sealed body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowParts {
    /// The ledger sequence.
    pub seq: u64,
    /// UTC microseconds.
    pub at: i64,
    /// The command id.
    pub command: [u8; 16],
    /// The schema version.
    pub schema: u16,
    /// The sealed body.
    pub sealed: Vec<u8>,
}

/// A `fstp_pgstore::StoredEntry` of `p`, with key generation 0. Lane W2e
/// added the `key_ix` field.
pub fn stored_entry(p: &RowParts) -> fstp_pgstore::StoredEntry {
    fstp_pgstore::StoredEntry {
        seq: p.seq,
        at: p.at,
        command: p.command,
        schema: p.schema,
        key_ix: 0,
        sealed: p.sealed.clone(),
    }
}

/// The parts of `e`. Seam, as [`stored_entry`].
pub fn row_parts(e: &fstp_pgstore::StoredEntry) -> RowParts {
    RowParts {
        seq: e.seq,
        at: e.at,
        command: e.command,
        schema: e.schema,
        sealed: e.sealed.clone(),
    }
}

/// Decodes a test record from its canonical bytes at `schema`. This is
/// the `fstp_pgstore::Decode<Rec>` the store gets. It accepts only the
/// one spelling [`Rec::canonical`] writes, at schema 1.
pub fn decode_rec(canonical: &[u8], schema: u16) -> Result<Rec, fstp_pgstore::DecodeError> {
    match Rec::parse(canonical) {
        Some(r) if schema == 1 => Ok(r),
        _ => Err(fstp_pgstore::DecodeError::Record(
            "a test record outside its one spelling",
        )),
    }
}

/// The role of a login `c_<cell>_<suffix>`.
fn role_of(user: &str) -> Role {
    let suffix = user.rsplit('_').next().unwrap_or("");
    *Role::ALL
        .iter()
        .find(|r| r.suffix() == suffix)
        .unwrap_or_else(|| panic!("no role suffix in {user}"))
}

/// The `fstp-pgwire` configuration of `login` against the database of
/// `db`.
fn login_config(login: &RoleLogin, db: &CellDb) -> Config {
    let p = login.conn_params(db.server, &db.dbname);
    let tls = ClientTls::new(p.server_ca_pem, p.client_cert_pem, p.client_key_pem)
        .unwrap_or_else(|e| panic!("{e}"));
    Config::new(
        p.host.clone(),
        p.port,
        p.user.as_str(),
        Password::new(p.password.as_str()).unwrap_or_else(|e| panic!("{e}")),
        p.dbname.clone(),
        tls,
    )
    .unwrap_or_else(|e| panic!("{e}"))
    .connect_timeout(Some(Duration::from_secs(20)))
}

/// Opens a pool for the role of `login` in cell `cell`, against the
/// database of `db`. A pool serves one cell (design section 4.7, I-82).
pub fn open_pool(
    cell: [u8; 16],
    login: &RoleLogin,
    db: &CellDb,
) -> Result<Result<(), String>, Gap> {
    let config = login_config(login, db);
    let role = role_of(config.user());
    Ok(block_on(Pool::open(rt().clone(), cell, role, config, 2))
        .map(|_| ())
        .map_err(|e| e.to_string()))
}

/// A pool of `suffix` for the cell of `db`.
fn pool_of(db: &CellDb, suffix: &str) -> Pool<TokioRuntime> {
    block_on(Pool::open(
        rt().clone(),
        db.cell,
        role_of(&db.role(suffix)),
        db.config(suffix),
        4,
    ))
    .unwrap_or_else(|e| panic!("the {suffix} pool: {e}"))
}

/// Signs anchors with a composite key through `fstp_crypto::composite`
/// (design section 14.4). The witness does not check anchor signatures,
/// so any key serves.
pub struct TestSigner {
    key: fstp_crypto::composite::CompositeSigningKey,
}

impl AnchorSigner for TestSigner {
    fn sign_anchor(
        &self,
        cell: CellId,
        chain: ChainId,
        n: u64,
        link: &Link,
        at: i64,
    ) -> Result<Anchor, fstp_audit::AuditError> {
        let msg = anchor_message(cell, chain, n, link, at);
        let sig = self
            .key
            .sign_with_context(&msg, fstp_audit::anchor::ANCHOR_CONTEXT)
            .map_err(|_| fstp_audit::AuditError::NotImplemented("the test signer"))?;
        Ok(Anchor {
            cell,
            chain,
            n,
            link: *link,
            at,
            signature: sig.to_bytes().to_vec(),
        })
    }
}

/// The ledger key generations each cell drew, by cell: `(key_ix, dek,
/// key bytes)`.
type KeyRegistry = BTreeMap<[u8; 16], Vec<(u32, [u8; 16], [u8; 32])>>;

fn key_registry() -> &'static Mutex<KeyRegistry> {
    static KEYS: OnceLock<Mutex<KeyRegistry>> = OnceLock::new();
    KEYS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Draws a new ledger key generation for `cell`, as a process start does,
/// and returns every generation of the cell with the new one current.
fn ledger_keys(cell: [u8; 16]) -> LedgerKeys {
    let mut reg = key_registry()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let gens = reg.entry(cell).or_default();
    let ix = u32::try_from(gens.len()).unwrap();
    let bytes: [u8; 32] = fstp_crypto::random_array().unwrap();
    gens.push((ix, fresh16(), bytes));
    let key = |(ix, dek, bytes): &(u32, [u8; 16], [u8; 32])| {
        LedgerKey::new(
            *ix,
            fstp_keys::DekId(*dek),
            fstp_crypto::aead::Key::from_bytes(bytes).unwrap(),
        )
    };
    let (current, older) = gens.split_last().unwrap();
    let mut keys = LedgerKeys::new(key(current));
    for g in older {
        keys = keys.with_older(key(g)).unwrap();
    }
    keys
}

/// The text data keys every test drew: dek -> (group, key bytes).
type TextKeyRegistry = BTreeMap<[u8; 16], ([u8; 16], [u8; 32])>;

/// An in-memory stand-in for lane W2f's text keystore. Each text gets
/// its own data key in one group, generation 1.
#[derive(Clone, Copy, Debug)]
pub struct TestTextKeys;

fn text_keys() -> &'static Mutex<TextKeyRegistry> {
    static KEYS: OnceLock<Mutex<TextKeyRegistry>> = OnceLock::new();
    KEYS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

impl TextKeys for TestTextKeys {
    fn create(
        &self,
        text: fstp_keys::ObjectId,
    ) -> impl Future<Output = Result<TextKey, fstp_pgstore::StoreFault>> + Send {
        let _ = text;
        let dek = fresh16();
        let group = fresh16();
        let bytes: [u8; 32] = fstp_crypto::random_array().unwrap();
        text_keys()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(dek, (group, bytes));
        ready(Ok(TextKey {
            dek: fstp_keys::DekId(dek),
            group: fstp_keys::GroupId(group),
            generation: 1,
            key: fstp_keys::envelope::DataKey::from_bytes(&bytes).unwrap(),
        }))
    }

    fn open(
        &self,
        dek: fstp_keys::DekId,
        text: fstp_keys::ObjectId,
    ) -> impl Future<Output = Result<Option<TextKey>, fstp_pgstore::StoreFault>> + Send {
        let _ = text;
        let found = text_keys()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&dek.0)
            .copied();
        ready(Ok(found.map(|(group, bytes)| TextKey {
            dek,
            group: fstp_keys::GroupId(group),
            generation: 1,
            key: fstp_keys::envelope::DataKey::from_bytes(&bytes).unwrap(),
        })))
    }
}

/// Draws no new generation: the current key is the last generation
/// `cell` drew, again, as a process start that reuses a `key_ix` would
/// hold it (ADR-004 forbids it).
pub fn ledger_keys_reusing_last(cell: [u8; 16]) -> LedgerKeys {
    let reg = key_registry()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let gens = reg
        .get(&cell)
        .unwrap_or_else(|| panic!("no generation yet"));
    let (ix, dek, bytes) = *gens.last().unwrap();
    LedgerKeys::new(LedgerKey::new(
        ix,
        fstp_keys::DekId(dek),
        fstp_crypto::aead::Key::from_bytes(&bytes).unwrap(),
    ))
}

/// The data key ids of every ledger key generation `cell` drew.
pub fn ledger_deks(cell: [u8; 16]) -> Vec<[u8; 16]> {
    key_registry()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&cell)
        .map(|g| g.iter().map(|(_, dek, _)| *dek).collect())
        .unwrap_or_default()
}

/// The outbox data keys every test drew: dek -> (row id, key bytes).
type OutboxKeyRegistry = BTreeMap<[u8; 16], ([u8; 16], [u8; 32])>;

fn outbox_keys() -> &'static Mutex<OutboxKeyRegistry> {
    static KEYS: OnceLock<Mutex<OutboxKeyRegistry>> = OnceLock::new();
    KEYS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// An in-memory stand-in for lane W2f's keystore of outbox data keys.
/// Each row gets its own fresh key, and a key opens for its own row
/// only.
#[derive(Clone, Copy, Debug)]
pub struct TestOutboxKeys;

impl OutboxKeys for TestOutboxKeys {
    fn create(&self, row: fstp_keys::ObjectId) -> KeyFuture<'_, OutboxKey> {
        let dek = fresh16();
        let bytes: [u8; 32] = fstp_crypto::random_array().unwrap();
        outbox_keys()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(dek, (row.0, bytes));
        Box::pin(ready(Ok(OutboxKey {
            dek: fstp_keys::DekId(dek),
            key: fstp_crypto::aead::Key::from_bytes(&bytes).unwrap(),
        })))
    }

    fn open(
        &self,
        dek: fstp_keys::DekId,
        row: fstp_keys::ObjectId,
    ) -> KeyFuture<'_, Option<OutboxKey>> {
        let found = outbox_keys()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&dek.0)
            .copied();
        Box::pin(ready(Ok(found.filter(|(id, _)| *id == row.0).map(
            |(_, bytes)| OutboxKey {
                dek,
                key: fstp_crypto::aead::Key::from_bytes(&bytes).unwrap(),
            },
        ))))
    }
}

/// Opens the sealed body of an `ops.outbox` row with the key the test
/// keystore drew for it, under the outbox AAD of the row.
pub fn open_outbox_row(cell: &[u8; 16], row: &OutboxStored) -> Option<Vec<u8>> {
    let (id, bytes) = outbox_keys()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&row.dek)
        .copied()?;
    if id != row.id {
        return None;
    }
    let key = fstp_crypto::aead::Key::from_bytes(&bytes).ok()?;
    let (nonce, body) = row.body.split_first_chunk::<12>()?;
    let aad = fstp_pgstore::outbox_aad(cell, &row.id, row.kind, &row.idem);
    fstp_crypto::aead::open(&key, nonce, &aad, body)
        .ok()
        .map(|p| p.to_vec())
}

/// One stored `ops.outbox` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxStored {
    /// The row id.
    pub id: [u8; 16],
    /// The kind.
    pub kind: u16,
    /// The idempotency key.
    pub idem: Vec<u8>,
    /// The data key id.
    pub dek: [u8; 16],
    /// The sealed body.
    pub body: Vec<u8>,
}

/// The record store of one cell over its writer role, with the witness
/// `witness`: `PgRecordStore<TokioRuntime, Rec, FakeWitness>` opened with
/// [`decode_rec`], plus its text store and checkpoints over the app role.
pub struct Store {
    store: PgRecordStore<TokioRuntime, Rec, FakeWitness>,
    texts: TextStore<TokioRuntime, TestTextKeys>,
    checkpoints: Checkpoints<TokioRuntime>,
    anchor_key: Vec<u8>,
}

impl Store {
    /// Opens the store of `db` with `witness`. A second open of the same
    /// database is a restart of the cell process.
    pub fn open(db: &CellDb, witness: &FakeWitness) -> Result<Store, Gap> {
        Store::open_pinned(db, witness, vec![witness.public_key()])
    }

    /// As [`Store::open`], pinning `witness_keys` in place of the
    /// witness's own key (ADR-010 "Keys").
    pub fn open_pinned(
        db: &CellDb,
        witness: &FakeWitness,
        witness_keys: Vec<Vec<u8>>,
    ) -> Result<Store, Gap> {
        Store::open_with_keys(db, witness, witness_keys, Arc::new(ledger_keys(db.cell)))
    }

    /// As [`Store::open`], with the writer's result limit set to
    /// `max_result_bytes`.
    pub fn open_limited(
        db: &CellDb,
        witness: &FakeWitness,
        max_result_bytes: usize,
    ) -> Result<Store, Gap> {
        let limits = fstp_pgwire::Limits {
            max_result_bytes,
            ..fstp_pgwire::Limits::default()
        };
        let writer = db.config("writer").limits(limits);
        Store::open_full(
            db,
            witness,
            vec![witness.public_key()],
            Arc::new(ledger_keys(db.cell)),
            writer,
        )
    }

    /// As [`Store::open_pinned`], with the ledger keys `keys` in place of
    /// a new generation.
    pub fn open_with_keys(
        db: &CellDb,
        witness: &FakeWitness,
        witness_keys: Vec<Vec<u8>>,
        keys: Arc<LedgerKeys>,
    ) -> Result<Store, Gap> {
        Store::open_full(db, witness, witness_keys, keys, db.config("writer"))
    }

    fn open_full(
        db: &CellDb,
        witness: &FakeWitness,
        witness_keys: Vec<Vec<u8>>,
        keys: Arc<LedgerKeys>,
        writer: Config,
    ) -> Result<Store, Gap> {
        let signer = Arc::new(TestSigner {
            key: fstp_crypto::composite::generate().unwrap(),
        });
        let anchor_key = signer.key.public_key().to_bytes().to_vec();
        let writer = block_on(Pool::open(
            rt().clone(),
            db.cell,
            role_of(&db.role("writer")),
            writer,
            4,
        ))
        .unwrap_or_else(|e| panic!("the writer pool: {e}"));
        let store = PgRecordStore::new(
            writer,
            Arc::clone(&keys),
            signer,
            witness.clone(),
            witness_keys,
            Arc::new(TestOutboxKeys),
            decode_rec,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let app = pool_of(db, "app");
        let texts = TextStore::new(app.clone(), TestTextKeys).unwrap_or_else(|e| panic!("{e}"));
        let checkpoints = Checkpoints::new(app, keys).unwrap_or_else(|e| panic!("{e}"));
        Ok(Store {
            store,
            texts,
            checkpoints,
            anchor_key,
        })
    }

    /// The public key of the store's anchor signer.
    pub fn anchor_key(&self) -> Vec<u8> {
        self.anchor_key.clone()
    }

    /// `AsyncRecordStore::head`.
    pub fn head(&self) -> Result<Result<Seq, StoreError>, Gap> {
        Ok(block_on(AsyncRecordStore::head(&self.store)))
    }

    /// `AsyncRecordStore::append`.
    pub fn append(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<Rec>,
    ) -> Result<Result<Seq, AppendError>, Gap> {
        Ok(block_on(AsyncRecordStore::append(
            &mut self.store,
            expected,
            at,
            command,
            batch,
        )))
    }

    /// The append of design section 5.3 with its side-effect rows.
    pub fn append_with(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<Rec>,
        side: &Side,
    ) -> Result<Result<Seq, AppendError>, Gap> {
        // fstp-cell-core appends StepUpConsumed and the SessionEnded
        // reactions after the command's records, so the rows name the
        // last entry of the batch.
        let last = batch.len().saturating_sub(1);
        let side = SideEffects {
            stepup_consumed: side.stepup_consumed.map(|challenge| StepUpUse {
                challenge,
                record: last,
            }),
            stepup_fresh_until: side.stepup_fresh_until,
            sessions_ended: side
                .sessions_ended
                .iter()
                .map(|session| SessionEnd {
                    session: *session,
                    record: last,
                })
                .collect(),
            outbox: Vec::new(),
        };
        Ok(
            block_on(self.store.append_with(expected, at, command, batch, &side))
                .map_err(AppendError::from),
        )
    }

    /// The append of design section 5.3 with production side effects, and
    /// the store's own fault.
    pub fn append_effects(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<Rec>,
        side: &SideEffects,
    ) -> Result<Seq, fstp_pgstore::AppendFault> {
        block_on(self.store.append_with(expected, at, command, batch, side))
    }

    /// `PgRecordStore::append_committed`: the append of design section
    /// 5.3 with production side effects, and what its commit left.
    pub fn append_committed(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<Rec>,
        side: &SideEffects,
    ) -> Result<fstp_pgstore::Committed, fstp_pgstore::AppendFault> {
        block_on(
            self.store
                .append_committed(expected, at, command, batch, side),
        )
    }

    /// `PgRecordStore::stored_commit`.
    pub fn stored_commit(&self, seq: Seq) -> Option<fstp_pgstore::StoredCommit> {
        block_on(self.store.stored_commit(seq)).unwrap_or_else(|e| panic!("{e}"))
    }

    /// `PgRecordStore::read_chain_rows`.
    pub fn read_chain_rows(&self) -> fstp_pgstore::ChainRows {
        block_on(self.store.read_chain_rows()).unwrap_or_else(|e| panic!("{e}"))
    }

    /// The pinned witness receipt keys of the store.
    pub fn witness_keys(&self) -> Vec<Vec<u8>> {
        self.store.witness_keys().to_vec()
    }

    /// `PgRecordStore::settle`: drives a due abort or in-doubt step.
    pub fn settle(&mut self) -> Result<Option<Resolution>, String> {
        block_on(self.store.settle()).map_err(|e| e.to_string())
    }

    /// Whether the anchorer core holds no unfinished step.
    pub fn idle(&self) -> bool {
        matches!(self.store.phase(), fstp_audit::anchorer::Phase::Idle)
    }

    /// `AsyncRecordStore::read`, decrypted and decoded.
    pub fn read(
        &self,
        from: Seq,
        limit: usize,
    ) -> Result<Result<Vec<Entry<Rec>>, StoreError>, Gap> {
        let mut out = Vec::new();
        Ok(block_on(AsyncRecordStore::read(&self.store, from, limit, &mut out)).map(|()| out))
    }

    /// Resolves the in-doubt prepare `head` as the anchorer core asks:
    /// read row `n` under `pg_advisory_xact_lock(1)`, then raise
    /// `PossibleDeletion` and send `InDoubtAbsent` if the row is missing.
    /// An `Err` names a witness or database failure; the core then stays
    /// in doubt.
    pub fn resolve_in_doubt(
        &mut self,
        head: (u64, Link),
    ) -> Result<Result<Resolution, String>, Gap> {
        Ok(block_on(self.store.resolve_in_doubt(head)).map_err(|e| e.to_string()))
    }

    /// Every durable `PossibleDeletion` alert, as `(n, link)`.
    pub fn possible_deletions(&self) -> Result<Vec<(u64, Link)>, Gap> {
        Ok(block_on(self.store.possible_deletions()).unwrap_or_else(|e| panic!("{e}")))
    }

    /// Writes a sealed checkpoint of `state` at ledger sequence `seq`.
    pub fn put_checkpoint(&mut self, seq: Seq, state: &[u8]) -> Result<Result<(), String>, Gap> {
        Ok(block_on(self.checkpoints.put(seq, state)).map_err(|e| e.to_string()))
    }

    /// The checkpoint with the highest sequence, opened.
    pub fn latest_checkpoint(&self) -> Result<Result<Option<Checkpoint>, String>, Gap> {
        Ok(block_on(self.checkpoints.latest())
            .map(|c| c.map(|c| (c.seq, c.state)))
            .map_err(|e| e.to_string()))
    }

    /// `TextStore::put`.
    pub fn put_text(&mut self, text: &str) -> Result<Result<TextRefView, String>, Gap> {
        Ok(block_on(self.texts.put(text))
            .map(|r| TextRefView {
                id: r.id,
                digest: r.digest,
            })
            .map_err(|e| e.to_string()))
    }

    /// `TextStore::get`.
    pub fn get_text(&self, r: &TextRefView) -> Result<Result<TextGot, String>, Gap> {
        let r = TextRef {
            id: r.id,
            digest: r.digest,
        };
        Ok(block_on(self.texts.get(&r))
            .map(|got| match got {
                TextLookup::Text(t) => TextGot::Text(t),
                TextLookup::NoText(_) => TextGot::Erased,
            })
            .map_err(|e| e.to_string()))
    }
}

/// Ends `store` as a crash or stop of the cell process does: its memory
/// is lost and its connections close.
pub fn stop(store: Store) {
    drop(store);
}

// ---------------------------------------------------------------------------
// Adapter types.

/// A checkpoint: its ledger sequence and its opened state.
pub type Checkpoint = (Seq, Vec<u8>);

/// The side effects of one append (design section 5.3 step 6), as
/// `fstp_cell_core::driver::SideEffects` carries them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Side {
    /// A consumed step-up challenge id.
    pub stepup_consumed: Option<[u8; 16]>,
    /// The last microsecond at which the batch may commit under its
    /// step-up.
    pub stepup_fresh_until: Option<i64>,
    /// Ended session ids.
    pub sessions_ended: Vec<[u8; 16]>,
}

/// A text reference: the text id and its salted digest (ADR-007).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextRefView {
    /// The text id.
    pub id: [u8; 16],
    /// HMAC-SHA-256 of the text under its salt.
    pub digest: [u8; 32],
}

/// How a text reference resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextGot {
    /// The text.
    Text(String),
    /// The text is erased or under erasure. It names no text.
    Erased,
}

// ---------------------------------------------------------------------------
// The test record.

/// A test record: a small closed kind and a text over `[A-Za-z0-9-]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rec {
    /// A kind code.
    pub kind: u8,
    /// The text, from the alphabet `[A-Za-z0-9-]`.
    pub text: String,
}

impl Rec {
    /// A record. Characters outside the alphabet become `-`.
    pub fn new(kind: u8, text: &str) -> Rec {
        let text = text
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        Rec { kind, text }
    }

    /// The record of its one spelling, if `b` is one.
    fn parse(b: &[u8]) -> Option<Rec> {
        let s = std::str::from_utf8(b).ok()?;
        let rest = s.strip_prefix("{\"k\":")?;
        let (kind, rest) = rest.split_once(",\"t\":\"")?;
        let text = rest.strip_suffix("\"}")?;
        let kind: u8 = kind.parse().ok()?;
        let r = Rec {
            kind,
            text: text.to_owned(),
        };
        (r.canonical() == b).then_some(r)
    }
}

impl Canonical for Rec {
    fn canonical(&self) -> Vec<u8> {
        format!("{{\"k\":{},\"t\":\"{}\"}}", self.kind, self.text).into_bytes()
    }
}

/// A random record.
pub fn rec(g: &mut fstp_prop::Gen) -> Rec {
    const ALPHABET: &[u8] = b"ABCxyz019-";
    let n = g.usize_in(0..=12);
    let text: String = (0..n).map(|_| char::from(*g.pick(ALPHABET))).collect();
    Rec::new(g.u8_in(0..=3), &text)
}

// ---------------------------------------------------------------------------
// Bytes, randomness and canaries.

/// Lowercase hex.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Uppercase hex.
pub fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// The bytes of lowercase or uppercase hex.
pub fn unhex(s: &str) -> Vec<u8> {
    let s = s.as_bytes();
    assert!(s.len().is_multiple_of(2), "odd hex length");
    s.chunks(2)
        .map(|p| {
            let d = |c: u8| match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("not hex: {c}"),
            };
            d(p[0]) * 16 + d(p[1])
        })
        .collect()
}

/// The text form of a uuid.
pub fn uuid_text(b: &[u8; 16]) -> String {
    let h = hex(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// A bytea literal for psql.
pub fn bytea(b: &[u8]) -> String {
    format!("'\\x{}'::bytea", hex(b))
}

/// 16 fresh bytes: SHA-256 of the process id, the clock and a counter.
/// They only need to differ between tests.
pub fn fresh16() -> [u8; 16] {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut input = Vec::new();
    input.extend_from_slice(&std::process::id().to_be_bytes());
    input.extend_from_slice(&t.to_be_bytes());
    input.extend_from_slice(&n.to_be_bytes());
    let h = fstp_crypto::sha256(&input);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h[..16]);
    out
}

/// A canary `CNRY-<cell>-<kind>-<32 hex>` (design section 14.1). It uses
/// only the record alphabet.
pub fn canary(cell_hex: &str, kind: &str) -> String {
    format!("CNRY-{cell_hex}-{kind}-{}", hex(&fresh16()))
}

/// Whether `haystack` holds `canary` raw, or as lowercase or uppercase
/// hex of its bytes (a `bytea` column in a dump).
pub fn holds_canary(haystack: &[u8], canary: &str) -> bool {
    let forms = [
        canary.as_bytes().to_vec(),
        hex(canary.as_bytes()).into_bytes(),
        hex_upper(canary.as_bytes()).into_bytes(),
    ];
    forms
        .iter()
        .any(|f| haystack.windows(f.len()).any(|w| w == f.as_slice()))
}

// ---------------------------------------------------------------------------
// The reference schema.

/// The reference application schema of `tests/reference/app.sql`,
/// written from design sections 4.1, 4.2 and 7.1 by the W2e test author.
/// It runs the harness, the predicates and their teeth before the
/// production migrations exist. It is never a stand-in for them: every
/// production test provisions through [`app_migrations`].
pub const REFERENCE_APP: &[Migration] = &[Migration::new(
    1,
    "reference_app",
    include_str!("../reference/app.sql"),
)];

// ---------------------------------------------------------------------------
// The reference role plan.

/// The role plan of the application database, written from design section
/// 4.1 by the W2e test author.
pub mod reference {
    /// The tables of the application database (design section 4.2).
    pub const APP_TABLES: [&str; 18] = [
        "ledger.command",
        "ledger.entry",
        "audit.chain",
        "audit.anchor",
        "blob.text",
        "keystore.root",
        "keystore.group_key",
        "keystore.data_key",
        "keystore.erasure_intent",
        "auth.session",
        "auth.challenge",
        "auth.sign_count",
        "auth.token",
        "auth_log.stepup_consumed",
        "auth_log.session_end",
        "ops.outbox",
        "ops.checkpoint",
        "ops.licence_state",
    ];

    /// The tables whose triggers refuse UPDATE, DELETE and TRUNCATE for
    /// every role, the owner included (ADR-007 "Database link trigger").
    pub const APPEND_ONLY: [&str; 4] = [
        "ledger.entry",
        "audit.chain",
        "auth_log.stepup_consumed",
        "auth_log.session_end",
    ];

    /// The role suffixes of the application database (design section 4.1).
    pub const SUFFIXES: [&str; 5] = ["migrator", "writer", "app", "keys", "auditor"];

    const SI: &[&str] = &["SELECT", "INSERT"];
    const S: &[&str] = &["SELECT"];
    const FULL: &[&str] = &["SELECT", "INSERT", "UPDATE", "DELETE"];
    const SD: &[&str] = &["SELECT", "DELETE"];

    /// The schema of `schema.table`.
    pub fn schema_of(object: &str) -> &str {
        object.split_once('.').map_or(object, |(s, _)| s)
    }

    /// The privileges design section 4.1 gives the role `suffix` on the
    /// application table `object`, in the `apply_grant` grammar's order.
    ///
    /// Readings: "full rights" are the four privileges of the grammar.
    /// "The stored ledger rows" of the auditor are `ledger.command` and
    /// `ledger.entry`. The `keys` role's DELETE on `blob` rows of completed
    /// erasures is a table grant on `blob.text` with SELECT, since a
    /// DELETE by id reads the id column and the grammar has no row or
    /// column grants. The migrator owns every schema and holds no grant.
    pub fn privileges(suffix: &str, object: &str) -> &'static [&'static str] {
        let schema = schema_of(object);
        match (suffix, schema) {
            ("writer", "ledger" | "auth_log") => SI,
            ("writer", "audit") if matches!(object, "audit.chain" | "audit.anchor") => SI,
            ("writer", "ops") if object == "ops.outbox" => SI,
            ("app", "ledger" | "audit" | "auth_log") => S,
            ("app", "auth") => FULL,
            ("app", "ops") if object == "ops.outbox" => S,
            ("app", "ops") => FULL,
            ("app", "blob") => SI,
            ("keys", "keystore") => FULL,
            ("keys", "blob") => SD,
            ("auditor", "audit" | "ledger") => S,
            _ => &[],
        }
    }

    /// Every grant row of the plan: `(suffix, object, privileges)`, in
    /// table order, then role order.
    pub fn plan() -> Vec<(&'static str, &'static str, &'static [&'static str])> {
        let mut out = Vec::new();
        for object in APP_TABLES {
            for suffix in SUFFIXES {
                let p = privileges(suffix, object);
                if !p.is_empty() {
                    out.push((suffix, object, p));
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// The server and the cell database.

/// One runtime per test binary.
pub fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(4).unwrap())
}

/// Runs `f` on the test runtime.
pub fn block_on<F: Future>(f: F) -> F::Output {
    rt().block_on(f)
}

/// The application cluster of this test binary: a named server with its
/// own cluster CA and the subject OU `application` (design section 1.3).
pub fn app_server() -> &'static PgServer {
    PgServer::shared_named("app", "application").unwrap_or_else(|e| panic!("{e}"))
}

/// A refused SQL statement: its SQLSTATE and psql's error text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqlError {
    /// The SQLSTATE, when psql printed one.
    pub state: Option<String>,
    /// The error text.
    pub text: String,
}

/// The SQLSTATE in a verbose psql error, `ERROR:  XXXXX: ...`.
fn sqlstate_of(text: &str) -> Option<String> {
    let at = text.find("ERROR:  ")?;
    let code = text.get(at + 8..at + 13)?;
    let colon = text.get(at + 13..at + 14)?;
    (colon == ":" && code.bytes().all(|b| b.is_ascii_alphanumeric())).then(|| code.to_owned())
}

/// One application database `c_<cell>` with its five login roles,
/// migrated and granted. Dropping it drops the database and the roles.
pub struct CellDb {
    /// The cluster.
    pub server: &'static PgServer,
    /// The cell id.
    pub cell: [u8; 16],
    /// The cell id in lowercase hex.
    pub hex: String,
    /// `c_<hex>`.
    pub dbname: String,
    /// The login of each role, by suffix.
    pub logins: BTreeMap<&'static str, RoleLogin>,
}

impl fmt::Debug for CellDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CellDb")
            .field("dbname", &self.dbname)
            .finish_non_exhaustive()
    }
}

impl CellDb {
    /// Provisions a fresh cell database: the five roles of design section
    /// 4.1 with client certificates, the database owned by the migrator,
    /// the application migrations applied by the migrator, the placement
    /// row, and every reference grant through `fstp_meta.apply_grant`.
    ///
    /// The migrations seam is read first, so a refusal costs no database.
    pub fn provision() -> Result<CellDb, Gap> {
        let migrations = app_migrations()?;
        Ok(CellDb::provision_with(migrations))
    }

    /// As [`CellDb::provision`], over `migrations` in place of the
    /// production set. The harness self-tests and the teeth use
    /// [`REFERENCE_APP`].
    pub fn provision_with(migrations: &'static [Migration]) -> CellDb {
        let db = CellDb::bare();
        db.migrate(migrations);
        db.place();
        db.grant_plan();
        db
    }

    /// The roles and the database, with nothing migrated.
    fn bare() -> CellDb {
        let server = app_server();
        let cell = fresh16();
        let hex = hex(&cell);
        let dbname = format!("c_{hex}");
        let mut logins = BTreeMap::new();
        for suffix in reference::SUFFIXES {
            let login = server
                .create_login_role(&format!("c_{hex}_{suffix}"))
                .unwrap_or_else(|e| panic!("{e}"));
            logins.insert(suffix, login);
        }
        let db = CellDb {
            server,
            cell,
            hex,
            dbname,
            logins,
        };
        let roles: Vec<String> = reference::SUFFIXES.iter().map(|s| db.role(s)).collect();
        let roles: Vec<&str> = roles.iter().map(String::as_str).collect();
        server
            .create_database_for(&db.dbname, &roles)
            .unwrap_or_else(|e| panic!("{e}"));
        server
            .psql(
                "postgres",
                &format!(
                    "ALTER DATABASE {} OWNER TO {};",
                    db.dbname,
                    db.role("migrator")
                ),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        db
    }

    /// Applies `migrations` as the migrator.
    fn migrate(&self, migrations: &'static [Migration]) {
        let set = MigrationSet::new(migrations).unwrap_or_else(|e| panic!("{e}"));
        let mut c = self.connect("migrator");
        block_on(set.apply(&mut c)).unwrap_or_else(|e| panic!("the application migrations: {e}"));
    }

    /// The placement row that provisioning writes (design section 4.1,
    /// `fstp_meta.placement`, kind 1 for an application database).
    fn place(&self) {
        let cluster = fresh16();
        self.psql(&format!(
            "INSERT INTO fstp_meta.placement (cell_id, cluster_id, kind) VALUES ({}, {}, 1);",
            bytea(&self.cell),
            bytea(&cluster)
        ))
        .unwrap_or_else(|e| panic!("the placement row: {e:?}"));
    }

    /// Calls `fstp_meta.apply_grant` once per reference row, as the
    /// migrator, with `fstp.cell` set to this cell (design section 4.1).
    fn grant_plan(&self) {
        let mut c = self.connect("migrator");
        block_on(c.query_one(
            "SELECT pg_catalog.set_config('fstp.cell', $1, false)",
            &[&self.hex.as_str()],
        ))
        .unwrap_or_else(|e| panic!("set fstp.cell: {e}"));
        for (suffix, object, privs) in reference::plan() {
            let privs = privs.join(", ");
            block_on(c.execute(
                "SELECT fstp_meta.apply_grant($1, $2, $3)",
                &[&privs.as_str(), &object, &suffix],
            ))
            .unwrap_or_else(|e| panic!("apply_grant({privs}, {object}, {suffix}): {e}"));
        }
    }

    /// The role name `c_<cell>_<suffix>`.
    pub fn role(&self, suffix: &str) -> String {
        format!("c_{}_{suffix}", self.hex)
    }

    /// The `fstp-pgwire` configuration of the role `suffix`: its client
    /// certificate and password, trusting the cluster CA.
    pub fn config(&self, suffix: &str) -> Config {
        let login = self
            .logins
            .get(suffix)
            .unwrap_or_else(|| panic!("no role {suffix}"));
        let p = login.conn_params(self.server, &self.dbname);
        let tls = ClientTls::new(p.server_ca_pem, p.client_cert_pem, p.client_key_pem)
            .unwrap_or_else(|e| panic!("{e}"));
        Config::new(
            p.host.clone(),
            p.port,
            p.user.as_str(),
            Password::new(p.password.as_str()).unwrap_or_else(|e| panic!("{e}")),
            p.dbname.clone(),
            tls,
        )
        .unwrap_or_else(|e| panic!("{e}"))
        .connect_timeout(Some(Duration::from_secs(20)))
    }

    /// A connection as the role `suffix`.
    pub fn connect(&self, suffix: &str) -> Client<TokioRuntime> {
        block_on(Client::connect(rt(), &self.config(suffix)))
            .unwrap_or_else(|e| panic!("connect as {suffix}: {e}"))
    }

    /// Runs `sql` with psql as the superuser, with verbose errors.
    pub fn psql(&self, sql: &str) -> Result<String, SqlError> {
        let script = format!("\\set VERBOSITY verbose\n{sql}");
        self.server.psql(&self.dbname, &script).map_err(|e| {
            let text = e.to_string();
            SqlError {
                state: sqlstate_of(&text),
                text,
            }
        })
    }

    /// Runs `sql` as the role `suffix`, through `SET ROLE` in a superuser
    /// session. Privilege checks then apply to that role alone.
    pub fn psql_as(&self, suffix: &str, sql: &str) -> Result<String, SqlError> {
        self.psql(&format!("SET ROLE {};\n{sql}", self.role(suffix)))
    }

    /// The SQLSTATE of `sql` run as `suffix`, or `None` if it succeeded.
    pub fn state_as(&self, suffix: &str, sql: &str) -> Option<String> {
        match self.psql_as(suffix, sql) {
            Ok(_) => None,
            Err(e) => Some(
                e.state
                    .unwrap_or_else(|| format!("no SQLSTATE in {}", e.text)),
            ),
        }
    }

    /// One `bigint` or `count(*)` as the superuser.
    pub fn count(&self, sql: &str) -> u64 {
        self.psql(sql)
            .unwrap_or_else(|e| panic!("{sql}: {e:?}"))
            .parse()
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
    }

    /// The rows of each append-protected and append-written table.
    pub fn row_counts(&self) -> BTreeMap<&'static str, u64> {
        let mut out = BTreeMap::new();
        for t in [
            "ledger.command",
            "ledger.entry",
            "audit.chain",
            "audit.anchor",
            "auth_log.stepup_consumed",
            "auth_log.session_end",
            "ops.outbox",
        ] {
            out.insert(t, self.count(&format!("SELECT count(*) FROM {t};")));
        }
        out
    }

    /// The data of the whole database, as `pg_dump --data-only` writes it.
    pub fn dump(&self) -> Vec<u8> {
        self.server
            .dump_data(&self.dbname)
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// The cell id as `fstp-audit` names it.
    pub fn cell_id(&self) -> CellId {
        CellId(self.cell)
    }

    /// The stored ledger rows, in sequence order.
    pub fn ledger_rows(&self) -> Vec<StoredEntry> {
        let out = self
            .psql(
                "SELECT seq || '|' || at || '|' || encode(command, 'hex') || '|' || schema \
                 || '|' || key_ix || '|' || encode(body, 'hex') FROM ledger.entry ORDER BY seq;",
            )
            .unwrap_or_else(|e| panic!("{e:?}"));
        out.lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let f: Vec<&str> = l.split('|').collect();
                let mut command = [0u8; 16];
                command.copy_from_slice(&unhex(f[2]));
                StoredEntry {
                    seq: f[0].parse().unwrap(),
                    at: f[1].parse().unwrap(),
                    command,
                    schema: f[3].parse().unwrap(),
                    key_ix: u32::from_be_bytes(f[4].parse::<i32>().unwrap().to_be_bytes()),
                    body: unhex(f[5]),
                }
            })
            .collect()
    }

    /// The stored chain rows with their links, in row order.
    pub fn chain_rows(&self) -> Vec<StoredRow> {
        let out = self
            .psql(
                "SELECT n || '|' || at || '|' || kind || '|' || coalesce(ledger_seq::text, '') \
                 || '|' || encode(stored_hash, 'hex') || '|' || encode(coalesce(body, ''::bytea), 'hex') \
                 || '|' || encode(link, 'hex') FROM audit.chain ORDER BY n;",
            )
            .unwrap_or_else(|e| panic!("{e:?}"));
        out.lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let f: Vec<&str> = l.split('|').collect();
                let kind = match f[2] {
                    "1" => RowKind::Ledger {
                        seq: f[3].parse().unwrap(),
                    },
                    "2" => RowKind::Event { body: unhex(f[5]) },
                    other => panic!("chain row kind {other}"),
                };
                let mut stored_hash = [0u8; 32];
                stored_hash.copy_from_slice(&unhex(f[4]));
                let mut link = [0u8; 32];
                link.copy_from_slice(&unhex(f[6]));
                StoredRow {
                    row: ChainRow {
                        n: f[0].parse().unwrap(),
                        at: f[1].parse().unwrap(),
                        kind,
                        stored_hash,
                    },
                    link: Link(link),
                }
            })
            .collect()
    }

    /// The rows of `audit.anchor` as `fstp-audit` reads them, in row
    /// order: each anchor with its decoded receipt.
    pub fn audit_anchor_rows(&self) -> Vec<fstp_audit::anchor::AnchorRow> {
        let out = self
            .psql(
                "SELECT n || '|' || encode(link, 'hex') || '|' || at || '|' \
                 || encode(signature, 'hex') || '|' || encode(receipt, 'hex') \
                 FROM audit.anchor ORDER BY n;",
            )
            .unwrap_or_else(|e| panic!("{e:?}"));
        out.lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let f: Vec<&str> = l.split('|').collect();
                let mut link = [0u8; 32];
                link.copy_from_slice(&unhex(f[1]));
                fstp_audit::anchor::AnchorRow {
                    anchor: Anchor {
                        cell: self.cell_id(),
                        chain: ChainId::App,
                        n: f[0].parse().unwrap(),
                        link: Link(link),
                        at: f[2].parse().unwrap(),
                        signature: unhex(f[3]),
                    },
                    receipt: fstp_audit::anchor::decode_receipt(&unhex(f[4]))
                        .unwrap_or_else(|e| panic!("a stored receipt: {e}")),
                }
            })
            .collect()
    }

    /// The rows of `ops.outbox`, in id order.
    pub fn outbox_rows(&self) -> Vec<OutboxStored> {
        let out = self
            .psql(
                "SELECT encode(uuid_send(id), 'hex') || '|' || kind || '|' || encode(idem, 'hex') \
                 || '|' || encode(uuid_send(dek), 'hex') || '|' || encode(body, 'hex') \
                 FROM ops.outbox ORDER BY id;",
            )
            .unwrap_or_else(|e| panic!("{e:?}"));
        out.lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let f: Vec<&str> = l.split('|').collect();
                let mut id = [0u8; 16];
                id.copy_from_slice(&unhex(f[0]));
                let mut dek = [0u8; 16];
                dek.copy_from_slice(&unhex(f[3]));
                OutboxStored {
                    id,
                    kind: f[1].parse().unwrap(),
                    idem: unhex(f[2]),
                    dek,
                    body: unhex(f[4]),
                }
            })
            .collect()
    }

    /// The anchor rows: `(n, link, receipt bytes)`, in row order.
    pub fn anchor_rows(&self) -> Vec<(u64, Link, Vec<u8>)> {
        let out = self
            .psql(
                "SELECT n || '|' || encode(link, 'hex') || '|' || encode(receipt, 'hex') \
                 FROM audit.anchor ORDER BY n;",
            )
            .unwrap_or_else(|e| panic!("{e:?}"));
        out.lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let f: Vec<&str> = l.split('|').collect();
                let mut link = [0u8; 32];
                link.copy_from_slice(&unhex(f[1]));
                (f[0].parse().unwrap(), Link(link), unhex(f[2]))
            })
            .collect()
    }
}

impl Drop for CellDb {
    fn drop(&mut self) {
        let mut sql = format!("DROP DATABASE IF EXISTS {} WITH (FORCE);\n", self.dbname);
        for suffix in reference::SUFFIXES {
            sql.push_str(&format!("DROP ROLE IF EXISTS {};\n", self.role(suffix)));
        }
        // A failed cleanup must not hide the test's own outcome.
        let _ = self.server.psql("postgres", &sql);
    }
}

/// Checks that `rows` and `ledger` form a chain that `fstp-audit`
/// recomputes: rows numbered 1, 2, 3 and so on, one kind 1 row per
/// ledger entry in sequence order, and every stored hash and link equal
/// to the `fstp-audit` value (I-24, design section 7.1).
pub fn recompute_chain(
    cell: CellId,
    rows: &[StoredRow],
    ledger: &[StoredEntry],
) -> Result<(), String> {
    let mut prev = fstp_audit::chain::genesis(cell, ChainId::App);
    let mut seqs = Vec::new();
    for (i, r) in rows.iter().enumerate() {
        let want_n = u64::try_from(i).map_err(|e| e.to_string())? + 1;
        if r.row.n != want_n {
            return Err(format!("row {i} has n {}, not {want_n}", r.row.n));
        }
        let entry = match &r.row.kind {
            RowKind::Ledger { seq } => {
                seqs.push(*seq);
                Some(
                    ledger
                        .iter()
                        .find(|e| e.seq == *seq)
                        .ok_or(format!("row {want_n} names no ledger entry {seq}"))?,
                )
            }
            RowKind::Event { .. } => None,
        };
        let sh = fstp_audit::chain::stored_hash(r.row.at, &r.row.kind, entry)
            .map_err(|e| format!("row {want_n}: {e}"))?;
        if sh != r.row.stored_hash {
            return Err(format!("row {want_n}: stored hash differs from fstp-audit"));
        }
        let link = fstp_audit::chain::link_of(&prev, cell, ChainId::App, want_n, &sh);
        if link != r.link {
            return Err(format!("row {want_n}: link differs from fstp-audit"));
        }
        prev = link;
    }
    let want: Vec<u64> = ledger.iter().map(|e| e.seq).collect();
    if seqs != want {
        return Err(format!(
            "kind 1 rows name {seqs:?}, the ledger holds {want:?}"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The witness.

/// How the fake witness answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Records and answers.
    Accept,
    /// Refuses the message. A refused message changes nothing.
    Refuse,
    /// The message or its answer is lost. Nothing is recorded.
    Unreachable,
}

/// A message the witness recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recorded {
    /// A receipted prepare of `(n, link)` after `prev`.
    Prepare {
        /// The head the prepare extends.
        prev: (u64, Link),
        /// The prospective head row.
        n: u64,
        /// The prospective head link.
        link: Link,
    },
    /// An abort.
    Abort {
        /// The row.
        n: u64,
        /// The link.
        link: Link,
    },
    /// An in-doubt record.
    InDoubtAbsent {
        /// The row.
        n: u64,
        /// The link.
        link: Link,
    },
}

#[derive(Debug)]
struct WitnessState {
    mode: Mode,
    /// In-doubt records that are lost before one is recorded.
    in_doubt_losses: u32,
    recorded: Vec<Recorded>,
    /// The log as `fstp_audit::verify` reads it.
    log: Vec<fstp_audit::witness::WitnessRecord>,
    received: u64,
    outstanding: Option<(u64, Link)>,
    receipts: Vec<Receipt>,
    seq: u64,
    wlink: Link,
}

/// A witness for one cell's App chain. It keeps one outstanding prepare,
/// refuses a prepare that neither extends nor repeats it, answers a
/// retransmit with the first receipt, and signs each receipt with a real
/// composite key (ADR-010 "Prepare, receipt, commit").
#[derive(Clone)]
pub struct FakeWitness {
    cell: CellId,
    key: Arc<CompositeSigningKey>,
    state: Arc<Mutex<WitnessState>>,
}

impl fmt::Debug for FakeWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeWitness").finish_non_exhaustive()
    }
}

impl FakeWitness {
    /// A witness for `cell` that accepts.
    pub fn new(cell: CellId) -> FakeWitness {
        let key = fstp_crypto::composite::generate().unwrap_or_else(|e| panic!("{e}"));
        FakeWitness {
            cell,
            key: Arc::new(key),
            state: Arc::new(Mutex::new(WitnessState {
                mode: Mode::Accept,
                in_doubt_losses: 0,
                recorded: Vec::new(),
                log: Vec::new(),
                received: 0,
                outstanding: None,
                receipts: Vec::new(),
                seq: 0,
                wlink: witness_genesis(cell, ChainId::App),
            })),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, WitnessState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The witness's composite public key.
    pub fn public_key(&self) -> Vec<u8> {
        self.key.public_key().to_bytes().to_vec()
    }

    /// Sets how the witness answers from now on.
    pub fn set_mode(&self, mode: Mode) {
        self.lock().mode = mode;
    }

    /// Loses the next `n` in-doubt records.
    pub fn lose_in_doubt(&self, n: u32) {
        self.lock().in_doubt_losses = n;
    }

    /// Makes `head` the outstanding prepare, as if a prepare of it had
    /// been receipted and its answer lost.
    pub fn hold_outstanding(&self, head: (u64, Link)) {
        self.lock().outstanding = Some(head);
    }

    /// The outstanding prepare.
    pub fn outstanding(&self) -> Option<(u64, Link)> {
        self.lock().outstanding
    }

    /// Every recorded message, in order.
    pub fn recorded(&self) -> Vec<Recorded> {
        self.lock().recorded.clone()
    }

    /// The witness log for this cell's App chain, as
    /// `fstp_audit::verify` reads it.
    pub fn witness_log(&self) -> Vec<fstp_audit::witness::WitnessRecord> {
        self.lock().log.clone()
    }

    /// How many messages reached the witness, recorded or not.
    pub fn received(&self) -> u64 {
        self.lock().received
    }

    /// The receipts given, in order.
    pub fn receipts(&self) -> Vec<Receipt> {
        self.lock().receipts.clone()
    }

    fn on_prepare(&self, p: &Prepare) -> Result<Receipt, WitnessFault> {
        let mut st = self.lock();
        st.received += 1;
        match st.mode {
            Mode::Unreachable => return Err(WitnessFault::Unreachable),
            Mode::Refuse => return Err(WitnessFault::Refused),
            Mode::Accept => {}
        }
        let head = (p.anchor.n, p.anchor.link);
        let shaped = p.check_shape().is_ok()
            && p.anchor.cell == self.cell
            && p.anchor.chain == ChainId::App
            && p.recomputed_head() == Some(head);
        if !shaped {
            return Err(WitnessFault::Refused);
        }
        if let Some(open) = st.outstanding {
            if open == head {
                let first = st
                    .receipts
                    .iter()
                    .rev()
                    .find(|r| (r.fields.n, r.fields.link) == head)
                    .cloned();
                return first.ok_or(WitnessFault::Refused);
            }
            if p.prev != open {
                return Err(WitnessFault::Refused);
            }
        }
        st.seq += 1;
        let seq = st.seq;
        st.wlink = witness_link(
            &st.wlink,
            self.cell,
            ChainId::App,
            RecordKind::Prepare,
            seq,
            head.0,
            &head.1,
        );
        let fields = ReceiptFields {
            n: head.0,
            link: head.1,
            witness_seq: seq,
            witness_link: st.wlink,
            received_at: p.anchor.at,
        };
        let msg = receipt_message(self.cell, ChainId::App, &fields);
        let signature = self
            .key
            .sign_with_context(&msg, fstp_audit::anchor::RECEIPT_CONTEXT)
            .map_err(|_| WitnessFault::Refused)?
            .to_bytes()
            .to_vec();
        let receipt = Receipt {
            cell: self.cell,
            chain: ChainId::App,
            fields,
            signature,
        };
        st.outstanding = Some(head);
        st.recorded.push(Recorded::Prepare {
            prev: p.prev,
            n: head.0,
            link: head.1,
        });
        st.log.push(fstp_audit::witness::WitnessRecord::Prepare(
            fstp_audit::anchor::AnchorRow {
                anchor: p.anchor.clone(),
                receipt: receipt.clone(),
            },
        ));
        st.receipts.push(receipt.clone());
        Ok(receipt)
    }

    fn on_withdraw(&self, head: (u64, Link), in_doubt: bool) -> Result<(), WitnessFault> {
        let mut st = self.lock();
        st.received += 1;
        match st.mode {
            Mode::Unreachable => return Err(WitnessFault::Unreachable),
            Mode::Refuse => return Err(WitnessFault::Refused),
            Mode::Accept => {}
        }
        if in_doubt && st.in_doubt_losses > 0 {
            st.in_doubt_losses -= 1;
            return Err(WitnessFault::Unreachable);
        }
        if st.outstanding != Some(head) {
            return Err(WitnessFault::UnknownPrepare);
        }
        st.outstanding = None;
        let (n, link) = head;
        st.recorded.push(if in_doubt {
            Recorded::InDoubtAbsent { n, link }
        } else {
            Recorded::Abort { n, link }
        });
        st.log.push(if in_doubt {
            fstp_audit::witness::WitnessRecord::InDoubtAbsent { n, link }
        } else {
            fstp_audit::witness::WitnessRecord::Abort { n, link }
        });
        Ok(())
    }
}

impl PrepareWitness for FakeWitness {
    fn prepare(&self, p: &Prepare) -> impl Future<Output = Result<Receipt, WitnessFault>> + Send {
        ready(self.on_prepare(p))
    }

    fn abort(&self, head: (u64, Link)) -> impl Future<Output = Result<(), WitnessFault>> + Send {
        ready(self.on_withdraw(head, false))
    }

    fn in_doubt_absent(
        &self,
        head: (u64, Link),
    ) -> impl Future<Output = Result<(), WitnessFault>> + Send {
        ready(self.on_withdraw(head, true))
    }
}

// ---------------------------------------------------------------------------
// Catalogue introspection.

/// The user tables of the database and their columns in order:
/// `(schema, table) -> [(column, type)]`.
pub fn columns(db: &CellDb) -> BTreeMap<(String, String), Vec<(String, String)>> {
    let out = db
        .psql(
            "SELECT n.nspname || '|' || c.relname || '|' || a.attname || '|' \
             || pg_catalog.format_type(a.atttypid, a.atttypmod) \
             FROM pg_catalog.pg_attribute a \
             JOIN pg_catalog.pg_class c ON c.oid = a.attrelid \
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
             WHERE c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped \
             AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') \
             ORDER BY n.nspname, c.relname, a.attnum;",
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut map: BTreeMap<(String, String), Vec<(String, String)>> = BTreeMap::new();
    for l in out.lines().filter(|l| !l.is_empty()) {
        let f: Vec<&str> = l.splitn(4, '|').collect();
        map.entry((f[0].to_owned(), f[1].to_owned()))
            .or_default()
            .push((f[2].to_owned(), f[3].to_owned()));
    }
    map
}

/// Every table privilege a role other than the table owner holds, as
/// `(grantee, schema.table, privilege)`. PUBLIC appears as `PUBLIC`.
pub fn table_grants(db: &CellDb) -> BTreeSet<(String, String, String)> {
    let out = db
        .psql(
            "SELECT coalesce(r.rolname, 'PUBLIC') || '|' || n.nspname || '.' || c.relname \
             || '|' || a.privilege_type \
             FROM pg_catalog.pg_class c \
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
             CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a \
             LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee \
             WHERE a.grantee <> c.relowner \
             AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') \
             ORDER BY 1;",
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
    out.lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.splitn(3, '|').collect();
            (f[0].to_owned(), f[1].to_owned(), f[2].to_owned())
        })
        .collect()
}

/// Every column privilege a role other than the table owner holds, as
/// `(grantee, schema.table.column, privilege)`.
pub fn column_grants(db: &CellDb) -> BTreeSet<(String, String, String)> {
    let out = db
        .psql(
            "SELECT coalesce(r.rolname, 'PUBLIC') || '|' || n.nspname || '.' || c.relname \
             || '.' || att.attname || '|' || a.privilege_type \
             FROM pg_catalog.pg_attribute att \
             JOIN pg_catalog.pg_class c ON c.oid = att.attrelid \
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
             CROSS JOIN LATERAL pg_catalog.aclexplode(att.attacl) a \
             LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee \
             WHERE a.grantee <> c.relowner \
             AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') \
             ORDER BY 1;",
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
    out.lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.splitn(3, '|').collect();
            (f[0].to_owned(), f[1].to_owned(), f[2].to_owned())
        })
        .collect()
}

/// Every schema privilege a role other than the schema owner holds, as
/// `(grantee, schema, privilege)`, for the schemas the migrations made.
pub fn schema_grants(db: &CellDb) -> BTreeSet<(String, String, String)> {
    let out = db
        .psql(
            "SELECT coalesce(r.rolname, 'PUBLIC') || '|' || n.nspname || '|' || a.privilege_type \
             FROM pg_catalog.pg_namespace n \
             CROSS JOIN LATERAL pg_catalog.aclexplode(n.nspacl) a \
             LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee \
             WHERE a.grantee <> n.nspowner \
             AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast', 'public') \
             AND n.nspname NOT LIKE 'pg_temp%' AND n.nspname NOT LIKE 'pg_toast_temp%' \
             ORDER BY 1;",
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
    out.lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.splitn(3, '|').collect();
            (f[0].to_owned(), f[1].to_owned(), f[2].to_owned())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Direct writes as the writer role, for the schema tests.

/// The SQL that inserts a ledger command row and its entries, as the
/// writer would (design section 4.2). `entries` are `(seq, body)`.
pub fn insert_entries_sql(command: &[u8; 16], at: i64, entries: &[StoredEntry]) -> String {
    let first = entries.first().map_or(0, |e| e.seq);
    let last = entries.last().map_or(0, |e| e.seq);
    let mut sql = format!(
        "INSERT INTO ledger.command (command, first_seq, last_seq, at) VALUES ({}, {first}, {last}, {at});\n",
        bytea(command)
    );
    for e in entries {
        sql.push_str(&format!(
            "INSERT INTO ledger.entry (seq, at, command, schema, key_ix, body) VALUES ({}, {}, {}, {}, {}, {});\n",
            e.seq,
            e.at,
            bytea(&e.command),
            e.schema,
            i32::from_be_bytes(e.key_ix.to_be_bytes()),
            bytea(&e.body)
        ));
    }
    sql
}

/// The SQL that inserts one chain row with the link column `link`.
pub fn insert_chain_sql(row: &ChainRow, link: &Link) -> String {
    let (kind, seq, body) = match &row.kind {
        RowKind::Ledger { seq } => (1, seq.to_string(), "NULL".to_owned()),
        RowKind::Event { body } => (2, "NULL".to_owned(), bytea(body)),
    };
    format!(
        "INSERT INTO audit.chain (n, at, kind, ledger_seq, stored_hash, body, link) VALUES ({}, {}, {kind}, {seq}, {}, {body}, {});\n",
        row.n,
        row.at,
        bytea(&row.stored_hash),
        bytea(&link.0)
    )
}
