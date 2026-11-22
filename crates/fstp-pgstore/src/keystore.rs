//! The keystore tables of the App chain (ADR-004, decided by Daniel on
//! 2026-11-20; migration `0011_keystore.sql`). Lane L3 `prod/keystore-pg`.
//!
//! [`KeystoreTables`] reads and writes the rows of one cell's keystore
//! over the `c_<cell>_keys` role only (I-82). It moves bytes and holds no
//! key: every row it sees is wrapped by custody, sealed under a seal key
//! or a group key, or a public value (I-80). The cell's keystore
//! (`fstp_cell::tasks::erasure::Keystore`) decides what the rows hold and
//! opens them.
//!
//! [`KeystoreTables::apply`] writes one batch of [`KeystoreChanges`] in
//! one transaction, so a step of an erasure is durable whole or not at
//! all (design section 3.5 step 4). [`KeystoreTables::load`] reads every
//! row back.

use std::future::Future;
use std::pin::Pin;

use fstp_pgwire::{Client, Row, ToSql, Transaction, Uuid};
use fstp_rt::Runtime;

use crate::error::StoreFault;
use crate::pool::{Pool, Role};

/// The chain code of the App chain (`fstp_keys::Chain::App`).
pub const APP_CHAIN: i16 = 1;

/// The `keystore.root.state` of a live root.
pub const ROOT_LIVE: i16 = 1;
/// The `keystore.root.state` of a destroyed root.
pub const ROOT_DESTROYED: i16 = 2;
/// The `keystore.root.state` of a root created for a batch not yet
/// committed.
pub const ROOT_PENDING: i16 = 3;

/// The `keystore.group_key.state` and `keystore.data_key.state` of a
/// stored row. The keystore keeps no other state in them.
const ROW_STORED: i16 = 1;

/// The chain row: the sealed chain state and the keystore's own fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainRow {
    /// The epoch whose seal key seals `state`.
    pub epoch: u64,
    /// The sealed chain state, `nonce || ciphertext`.
    pub state: Vec<u8>,
    /// The `Lookup` keyed digest group, once one exists.
    pub lookup_group: Option<[u8; 16]>,
    /// The text group that new login emails join.
    pub login_group: Option<[u8; 16]>,
    /// The request id of the start-up unwrap whose key record is owed.
    pub startup_unwrap: Option<[u8; 16]>,
}

/// What a root row says of its root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootStatus {
    /// The root serves its epoch.
    Live,
    /// The root was created for a batch not yet committed.
    Pending,
    /// The root was destroyed. The digest of the custody receipt.
    Destroyed([u8; 32]),
}

/// One `keystore.root` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootRow {
    /// The epoch.
    pub epoch: u64,
    /// The custody backend code.
    pub backend: i16,
    /// The custody handle.
    pub handle: Vec<u8>,
    /// The seal key wrapped under the root, empty while pending.
    pub wrapped: Vec<u8>,
    /// The status.
    pub status: RootStatus,
}

/// One `keystore.group_key` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKeyRow {
    /// The group.
    pub group: [u8; 16],
    /// The generation.
    pub generation: u32,
    /// The purpose code.
    pub purpose: u8,
    /// The group public key.
    pub public_key: Vec<u8>,
    /// The group secret sealed under the seal key of `epoch`,
    /// `nonce || ciphertext`.
    pub sealed_secret: Vec<u8>,
    /// The epoch of the seal key.
    pub epoch: u64,
}

/// One `keystore.data_key` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataKeyRow {
    /// The data key id.
    pub id: [u8; 16],
    /// The group.
    pub group: [u8; 16],
    /// The generation.
    pub generation: u32,
    /// The key sealed to its group key (FSK1).
    pub sealed: Vec<u8>,
}

/// One `keystore.text` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextRow {
    /// The text id.
    pub id: [u8; 16],
    /// The data key id.
    pub dek: [u8; 16],
    /// The generation of the blob's seal context.
    pub generation: u32,
    /// The sealed blob (FSB1).
    pub envelope: Vec<u8>,
}

/// One `keystore.signer` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerRow {
    /// The purpose code.
    pub purpose: u8,
    /// The generation.
    pub generation: u32,
    /// The composite public key.
    pub public_key: Vec<u8>,
    /// When the generation was created, in microseconds.
    pub created_at: i64,
    /// The epoch and the sealed secret of the current generation. `None`
    /// for a replaced generation, whose secret is dropped.
    pub sealed: Option<(u64, Vec<u8>)>,
}

/// One `keystore.login_digest` row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoginDigestRow {
    /// The keyed digest.
    pub digest: [u8; 32],
    /// The account.
    pub account: [u8; 16],
}

/// One `keystore.login_text` row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoginTextRow {
    /// The account.
    pub account: [u8; 16],
    /// The text that holds its login email.
    pub text: [u8; 16],
}

/// One `keystore.display_name` row (SA-11 amendment, lane L26).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayNameRow {
    /// The account.
    pub account: [u8; 16],
    /// The text that holds its display name.
    pub text: [u8; 16],
    /// The keyed fingerprint of the normalised name.
    pub fingerprint: [u8; 32],
}

/// Every row of one keystore, each table in key order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeystoreRows {
    /// The chain row, `None` on a keystore never written.
    pub chain: Option<ChainRow>,
    /// The roots, by epoch.
    pub roots: Vec<RootRow>,
    /// The group rows, by group and generation.
    pub groups: Vec<GroupKeyRow>,
    /// The data keys, by id.
    pub keys: Vec<DataKeyRow>,
    /// The texts, by id.
    pub texts: Vec<TextRow>,
    /// The signing keys, by purpose and generation.
    pub signers: Vec<SignerRow>,
    /// The login digests, by digest.
    pub digests: Vec<LoginDigestRow>,
    /// The login texts, by account.
    pub logins: Vec<LoginTextRow>,
    /// The display names, by account (lane L26).
    pub displays: Vec<DisplayNameRow>,
    /// The texts whose erasure request joined the chain state, by id.
    pub requested: Vec<[u8; 16]>,
}

/// One change to a table: a row written whole, or a key deleted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change<K, R> {
    /// The row, inserted or replacing the row of its key.
    Put(R),
    /// The row of this key, deleted if present.
    Delete(K),
}

/// One batch of changes, written in one transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeystoreChanges {
    /// The chain row, written whole when present.
    pub chain: Option<ChainRow>,
    /// Root rows by epoch.
    pub roots: Vec<Change<u64, RootRow>>,
    /// Group rows by group and generation.
    pub groups: Vec<Change<([u8; 16], u32), GroupKeyRow>>,
    /// Data key rows by id.
    pub keys: Vec<Change<[u8; 16], DataKeyRow>>,
    /// Text rows by id.
    pub texts: Vec<Change<[u8; 16], TextRow>>,
    /// Signer rows by purpose and generation.
    pub signers: Vec<Change<(u8, u32), SignerRow>>,
    /// Login digest rows by digest.
    pub digests: Vec<Change<[u8; 32], LoginDigestRow>>,
    /// Login text rows by account.
    pub logins: Vec<Change<[u8; 16], LoginTextRow>>,
    /// Display name rows by account (lane L26).
    pub displays: Vec<Change<[u8; 16], DisplayNameRow>>,
    /// Erasure request rows by text.
    pub requested: Vec<Change<[u8; 16], [u8; 16]>>,
}

impl KeystoreChanges {
    /// Whether the batch changes nothing.
    pub fn is_empty(&self) -> bool {
        self.chain.is_none()
            && self.roots.is_empty()
            && self.groups.is_empty()
            && self.keys.is_empty()
            && self.texts.is_empty()
            && self.signers.is_empty()
            && self.digests.is_empty()
            && self.logins.is_empty()
            && self.displays.is_empty()
            && self.requested.is_empty()
    }
}

const CHAIN_PUT: &str = "INSERT INTO keystore.chain (chain, epoch, state, lookup_group, \
     login_group, startup_unwrap) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (chain) DO UPDATE \
     SET epoch = EXCLUDED.epoch, state = EXCLUDED.state, lookup_group = EXCLUDED.lookup_group, \
     login_group = EXCLUDED.login_group, startup_unwrap = EXCLUDED.startup_unwrap";
const CHAIN_GET: &str = "SELECT epoch, state, lookup_group, login_group, startup_unwrap \
     FROM keystore.chain WHERE chain = $1";

const ROOT_PUT: &str = "INSERT INTO keystore.root (chain, epoch, backend, handle, \
     wrapped_seal_key, state, created_at, destroyed_at, receipt_digest) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (chain, epoch) DO UPDATE \
     SET backend = EXCLUDED.backend, handle = EXCLUDED.handle, \
     wrapped_seal_key = EXCLUDED.wrapped_seal_key, state = EXCLUDED.state, \
     destroyed_at = COALESCE(keystore.root.destroyed_at, EXCLUDED.destroyed_at), \
     receipt_digest = EXCLUDED.receipt_digest";
const ROOT_DEL: &str = "DELETE FROM keystore.root WHERE chain = $1 AND epoch = $2";
const ROOT_ALL: &str = "SELECT epoch, backend, handle, wrapped_seal_key, state, receipt_digest \
     FROM keystore.root WHERE chain = $1 ORDER BY epoch";

const GROUP_PUT: &str = "INSERT INTO keystore.group_key (chain, purpose, group_id, generation, \
     public_key, sealed_secret, epoch, state) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
     ON CONFLICT (group_id, generation) DO UPDATE SET chain = EXCLUDED.chain, \
     purpose = EXCLUDED.purpose, public_key = EXCLUDED.public_key, \
     sealed_secret = EXCLUDED.sealed_secret, epoch = EXCLUDED.epoch, state = EXCLUDED.state";
const GROUP_DEL: &str = "DELETE FROM keystore.group_key WHERE group_id = $1 AND generation = $2";
const GROUP_ALL: &str = "SELECT group_id, generation, purpose, public_key, sealed_secret, epoch \
     FROM keystore.group_key WHERE chain = $1 ORDER BY group_id, generation";

const KEY_PUT: &str = "INSERT INTO keystore.data_key (id, group_id, generation, sealed, state) \
     VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO UPDATE SET group_id = EXCLUDED.group_id, \
     generation = EXCLUDED.generation, sealed = EXCLUDED.sealed, state = EXCLUDED.state";
const KEY_DEL: &str = "DELETE FROM keystore.data_key WHERE id = $1";
const KEY_ALL: &str = "SELECT id, group_id, generation, sealed FROM keystore.data_key ORDER BY id";

const TEXT_PUT: &str = "INSERT INTO keystore.text (id, dek, generation, envelope) \
     VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO UPDATE SET dek = EXCLUDED.dek, \
     generation = EXCLUDED.generation, envelope = EXCLUDED.envelope";
const TEXT_DEL: &str = "DELETE FROM keystore.text WHERE id = $1";
const TEXT_ALL: &str = "SELECT id, dek, generation, envelope FROM keystore.text ORDER BY id";

const SIGNER_PUT: &str = "INSERT INTO keystore.signer (purpose, generation, public_key, \
     created_at, epoch, sealed_secret) VALUES ($1, $2, $3, $4, $5, $6) \
     ON CONFLICT (purpose, generation) DO UPDATE SET public_key = EXCLUDED.public_key, \
     created_at = EXCLUDED.created_at, epoch = EXCLUDED.epoch, \
     sealed_secret = EXCLUDED.sealed_secret";
const SIGNER_DEL: &str = "DELETE FROM keystore.signer WHERE purpose = $1 AND generation = $2";
const SIGNER_ALL: &str = "SELECT purpose, generation, public_key, created_at, epoch, \
     sealed_secret FROM keystore.signer ORDER BY purpose, generation";

const DIGEST_PUT: &str = "INSERT INTO keystore.login_digest (digest, account) VALUES ($1, $2) \
     ON CONFLICT (digest) DO UPDATE SET account = EXCLUDED.account";
const DIGEST_DEL: &str = "DELETE FROM keystore.login_digest WHERE digest = $1";
const DIGEST_ALL: &str = "SELECT digest, account FROM keystore.login_digest ORDER BY digest";

const LOGIN_PUT: &str = "INSERT INTO keystore.login_text (account, text_id) VALUES ($1, $2) \
     ON CONFLICT (account) DO UPDATE SET text_id = EXCLUDED.text_id";
const LOGIN_DEL: &str = "DELETE FROM keystore.login_text WHERE account = $1";
const LOGIN_ALL: &str = "SELECT account, text_id FROM keystore.login_text ORDER BY account";

const DISPLAY_PUT: &str = "INSERT INTO keystore.display_name (account, text_id, fingerprint) \
     VALUES ($1, $2, $3) ON CONFLICT (account) DO UPDATE SET text_id = EXCLUDED.text_id, \
     fingerprint = EXCLUDED.fingerprint";
const DISPLAY_DEL: &str = "DELETE FROM keystore.display_name WHERE account = $1";
const DISPLAY_ALL: &str =
    "SELECT account, text_id, fingerprint FROM keystore.display_name ORDER BY account";

const REQUEST_PUT: &str =
    "INSERT INTO keystore.erasure_request (text_id) VALUES ($1) ON CONFLICT DO NOTHING";
const REQUEST_DEL: &str = "DELETE FROM keystore.erasure_request WHERE text_id = $1";
const REQUEST_ALL: &str = "SELECT text_id FROM keystore.erasure_request ORDER BY text_id";

/// The future of one statement, built in a frame of its own and kept on the
/// heap (lane L26). The batch write and the load run one statement per
/// row kind, so each statement's future would otherwise take its own slot
/// in their frames: half a megabyte in a debug build, on the thread that
/// runs a cell's start-up. Each statement goes through [`exec`], [`rows`]
/// or [`row_opt`] instead.
type Stmt<'a, T> = Pin<Box<dyn Future<Output = Result<T, fstp_pgwire::Error>> + Send + 'a>>;

/// The parameters of one statement.
type Params<'a> = &'a [&'a (dyn ToSql + Sync)];

/// `Transaction::execute` as a [`Stmt`].
#[inline(never)]
fn exec<'a, 'b: 'a, R: Runtime>(
    tx: &'a mut Transaction<'b, R>,
    sql: &'static str,
    params: Params<'a>,
) -> Stmt<'a, u64> {
    Box::pin(tx.execute(sql, params))
}

/// `Client::query` as a [`Stmt`].
#[inline(never)]
fn rows<'a, R: Runtime>(
    client: &'a mut Client<R>,
    sql: &'static str,
    params: Params<'a>,
) -> Stmt<'a, Vec<Row>> {
    Box::pin(client.query(sql, params))
}

/// `Client::query_opt` as a [`Stmt`].
#[inline(never)]
fn row_opt<'a, R: Runtime>(
    client: &'a mut Client<R>,
    sql: &'static str,
    params: Params<'a>,
) -> Stmt<'a, Option<Row>> {
    Box::pin(client.query_opt(sql, params))
}

fn corrupt() -> StoreFault {
    StoreFault::Corrupt("a keystore row outside its constraints")
}

fn uuid(b: [u8; 16]) -> Uuid {
    Uuid::from_bytes(b)
}

fn i64_of(n: u64) -> Result<i64, StoreFault> {
    i64::try_from(n).map_err(|_| StoreFault::Refused("a keystore epoch past i64"))
}

fn i32_of(n: u32) -> Result<i32, StoreFault> {
    i32::try_from(n).map_err(|_| StoreFault::Refused("a keystore generation past i32"))
}

fn u64_of(n: i64) -> Result<u64, StoreFault> {
    u64::try_from(n).map_err(|_| corrupt())
}

fn u32_of(n: i32) -> Result<u32, StoreFault> {
    u32::try_from(n).map_err(|_| corrupt())
}

fn u8_of(n: i16) -> Result<u8, StoreFault> {
    u8::try_from(n).map_err(|_| corrupt())
}

fn bytes32(v: &[u8]) -> Result<[u8; 32], StoreFault> {
    <[u8; 32]>::try_from(v).map_err(|_| corrupt())
}

fn id(row: &fstp_pgwire::Row, ix: usize) -> Result<[u8; 16], StoreFault> {
    let u: Uuid = row.get(ix)?;
    Ok(*u.as_bytes())
}

fn opt_id(row: &fstp_pgwire::Row, ix: usize) -> Result<Option<[u8; 16]>, StoreFault> {
    let u: Option<Uuid> = row.get(ix)?;
    Ok(u.map(|u| *u.as_bytes()))
}

/// The keystore tables of one cell over its keys role (module
/// documentation).
pub struct KeystoreTables<R: Runtime> {
    pool: Pool<R>,
    clock: crate::store::Clock,
}

impl<R: Runtime> std::fmt::Debug for KeystoreTables<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeystoreTables").finish_non_exhaustive()
    }
}

impl<R: Runtime> KeystoreTables<R> {
    /// The tables over `pool`, which must serve `c_<cell>_keys` (I-82).
    ///
    /// # Errors
    ///
    /// [`StoreFault::WrongRole`] for a pool of another role.
    pub fn new(pool: Pool<R>) -> Result<KeystoreTables<R>, StoreFault> {
        if pool.role() != Role::Keys {
            return Err(StoreFault::WrongRole);
        }
        Ok(KeystoreTables {
            pool,
            clock: std::sync::Arc::new(crate::store::system_clock),
        })
    }

    /// The tables with `clock` for the times a root row records.
    #[must_use]
    pub fn with_clock(mut self, clock: crate::store::Clock) -> KeystoreTables<R> {
        self.clock = clock;
        self
    }

    /// The cell.
    pub fn cell(&self) -> [u8; 16] {
        self.pool.cell()
    }

    /// Every row of the keystore. A keystore never written has no chain
    /// row and no other row.
    ///
    /// # Errors
    ///
    /// A pool or database fault, or a row outside its constraints. Rows
    /// without a chain row are refused as [`StoreFault::Corrupt`].
    pub async fn load(&self) -> Result<KeystoreRows, StoreFault> {
        let mut client = self.pool.get().await?;
        // A client that failed is dropped, never returned to the pool.
        let rows = load_rows(&mut client).await?;
        client.release();
        let other = !(rows.roots.is_empty()
            && rows.groups.is_empty()
            && rows.keys.is_empty()
            && rows.texts.is_empty()
            && rows.signers.is_empty()
            && rows.digests.is_empty()
            && rows.logins.is_empty()
            && rows.requested.is_empty()
            && rows.displays.is_empty());
        if rows.chain.is_none() && other {
            return Err(StoreFault::Corrupt("keystore rows without a chain row"));
        }
        Ok(rows)
    }

    /// Writes `changes` in one transaction.
    ///
    /// # Errors
    ///
    /// A pool or database fault. Nothing is written then.
    pub async fn apply(&self, changes: &KeystoreChanges) -> Result<(), StoreFault> {
        if changes.is_empty() {
            return Ok(());
        }
        let now = (self.clock)().unwrap_or(0);
        let mut client = self.pool.get().await?;
        write_changes(&mut client, changes, now).await?;
        client.release();
        Ok(())
    }
}

async fn load_rows<R: Runtime>(
    client: &mut crate::pool::Pooled<R>,
) -> Result<KeystoreRows, StoreFault> {
    let mut out = KeystoreRows::default();
    if let Some(r) = row_opt(client, CHAIN_GET, &[&APP_CHAIN]).await? {
        let epoch: i64 = r.get(0)?;
        out.chain = Some(ChainRow {
            epoch: u64_of(epoch)?,
            state: r.get(1)?,
            lookup_group: opt_id(&r, 2)?,
            login_group: opt_id(&r, 3)?,
            startup_unwrap: opt_id(&r, 4)?,
        });
    }
    for r in rows(client, ROOT_ALL, &[&APP_CHAIN]).await? {
        let epoch: i64 = r.get(0)?;
        let state: i16 = r.get(4)?;
        let digest: Option<Vec<u8>> = r.get(5)?;
        let status = match (state, digest) {
            (ROOT_LIVE, None) => RootStatus::Live,
            (ROOT_PENDING, None) => RootStatus::Pending,
            (ROOT_DESTROYED, Some(d)) => RootStatus::Destroyed(bytes32(&d)?),
            _ => return Err(corrupt()),
        };
        out.roots.push(RootRow {
            epoch: u64_of(epoch)?,
            backend: r.get(1)?,
            handle: r.get(2)?,
            wrapped: r.get(3)?,
            status,
        });
    }
    for r in rows(client, GROUP_ALL, &[&APP_CHAIN]).await? {
        let generation: i32 = r.get(1)?;
        let purpose: i16 = r.get(2)?;
        let epoch: i64 = r.get(5)?;
        out.groups.push(GroupKeyRow {
            group: id(&r, 0)?,
            generation: u32_of(generation)?,
            purpose: u8_of(purpose)?,
            public_key: r.get(3)?,
            sealed_secret: r.get(4)?,
            epoch: u64_of(epoch)?,
        });
    }
    for r in rows(client, KEY_ALL, &[]).await? {
        let generation: i32 = r.get(2)?;
        out.keys.push(DataKeyRow {
            id: id(&r, 0)?,
            group: id(&r, 1)?,
            generation: u32_of(generation)?,
            sealed: r.get(3)?,
        });
    }
    for r in rows(client, TEXT_ALL, &[]).await? {
        let generation: i32 = r.get(2)?;
        out.texts.push(TextRow {
            id: id(&r, 0)?,
            dek: id(&r, 1)?,
            generation: u32_of(generation)?,
            envelope: r.get(3)?,
        });
    }
    for r in rows(client, SIGNER_ALL, &[]).await? {
        let purpose: i16 = r.get(0)?;
        let generation: i32 = r.get(1)?;
        let epoch: Option<i64> = r.get(4)?;
        let sealed: Option<Vec<u8>> = r.get(5)?;
        let sealed = match (epoch, sealed) {
            (Some(e), Some(s)) => Some((u64_of(e)?, s)),
            (None, None) => None,
            _ => return Err(corrupt()),
        };
        out.signers.push(SignerRow {
            purpose: u8_of(purpose)?,
            generation: u32_of(generation)?,
            public_key: r.get(2)?,
            created_at: r.get(3)?,
            sealed,
        });
    }
    for r in rows(client, DIGEST_ALL, &[]).await? {
        let digest: Vec<u8> = r.get(0)?;
        out.digests.push(LoginDigestRow {
            digest: bytes32(&digest)?,
            account: id(&r, 1)?,
        });
    }
    for r in rows(client, LOGIN_ALL, &[]).await? {
        out.logins.push(LoginTextRow {
            account: id(&r, 0)?,
            text: id(&r, 1)?,
        });
    }
    for r in rows(client, REQUEST_ALL, &[]).await? {
        out.requested.push(id(&r, 0)?);
    }
    for r in rows(client, DISPLAY_ALL, &[]).await? {
        let fingerprint: Vec<u8> = r.get(2)?;
        out.displays.push(DisplayNameRow {
            account: id(&r, 0)?,
            text: id(&r, 1)?,
            fingerprint: bytes32(&fingerprint)?,
        });
    }
    Ok(out)
}

async fn write_changes<R: Runtime>(
    client: &mut crate::pool::Pooled<R>,
    c: &KeystoreChanges,
    now: i64,
) -> Result<(), StoreFault> {
    let mut tx = client.transaction().await?;
    if let Some(ch) = &c.chain {
        exec(
            &mut tx,
            CHAIN_PUT,
            &[
                &APP_CHAIN,
                &i64_of(ch.epoch)?,
                &ch.state,
                &ch.lookup_group.map(uuid),
                &ch.login_group.map(uuid),
                &ch.startup_unwrap.map(uuid),
            ],
        )
        .await?;
    }
    for change in &c.roots {
        match change {
            Change::Put(r) => {
                let (state, destroyed_at, digest) = match r.status {
                    RootStatus::Live => (ROOT_LIVE, None, None),
                    RootStatus::Pending => (ROOT_PENDING, None, None),
                    RootStatus::Destroyed(d) => (ROOT_DESTROYED, Some(now), Some(d.to_vec())),
                };
                exec(
                    &mut tx,
                    ROOT_PUT,
                    &[
                        &APP_CHAIN,
                        &i64_of(r.epoch)?,
                        &r.backend,
                        &r.handle,
                        &r.wrapped,
                        &state,
                        &now,
                        &destroyed_at,
                        &digest,
                    ],
                )
                .await?;
            }
            Change::Delete(e) => {
                exec(&mut tx, ROOT_DEL, &[&APP_CHAIN, &i64_of(*e)?]).await?;
            }
        }
    }
    for change in &c.groups {
        match change {
            Change::Put(g) => {
                exec(
                    &mut tx,
                    GROUP_PUT,
                    &[
                        &APP_CHAIN,
                        &i16::from(g.purpose),
                        &uuid(g.group),
                        &i32_of(g.generation)?,
                        &g.public_key,
                        &g.sealed_secret,
                        &i64_of(g.epoch)?,
                        &ROW_STORED,
                    ],
                )
                .await?;
            }
            Change::Delete((g, generation)) => {
                exec(&mut tx, GROUP_DEL, &[&uuid(*g), &i32_of(*generation)?]).await?;
            }
        }
    }
    for change in &c.keys {
        match change {
            Change::Put(k) => {
                exec(
                    &mut tx,
                    KEY_PUT,
                    &[
                        &uuid(k.id),
                        &uuid(k.group),
                        &i32_of(k.generation)?,
                        &k.sealed,
                        &ROW_STORED,
                    ],
                )
                .await?;
            }
            Change::Delete(k) => {
                exec(&mut tx, KEY_DEL, &[&uuid(*k)]).await?;
            }
        }
    }
    for change in &c.texts {
        match change {
            Change::Put(t) => {
                exec(
                    &mut tx,
                    TEXT_PUT,
                    &[
                        &uuid(t.id),
                        &uuid(t.dek),
                        &i32_of(t.generation)?,
                        &t.envelope,
                    ],
                )
                .await?;
            }
            Change::Delete(t) => {
                exec(&mut tx, TEXT_DEL, &[&uuid(*t)]).await?;
            }
        }
    }
    for change in &c.signers {
        match change {
            Change::Put(s) => {
                let (epoch, sealed) = match &s.sealed {
                    Some((e, b)) => (Some(i64_of(*e)?), Some(b.clone())),
                    None => (None, None),
                };
                exec(
                    &mut tx,
                    SIGNER_PUT,
                    &[
                        &i16::from(s.purpose),
                        &i32_of(s.generation)?,
                        &s.public_key,
                        &s.created_at,
                        &epoch,
                        &sealed,
                    ],
                )
                .await?;
            }
            Change::Delete((p, generation)) => {
                exec(
                    &mut tx,
                    SIGNER_DEL,
                    &[&i16::from(*p), &i32_of(*generation)?],
                )
                .await?;
            }
        }
    }
    for change in &c.digests {
        match change {
            Change::Put(d) => {
                exec(&mut tx, DIGEST_PUT, &[&d.digest.to_vec(), &uuid(d.account)]).await?;
            }
            Change::Delete(d) => {
                exec(&mut tx, DIGEST_DEL, &[&d.to_vec()]).await?;
            }
        }
    }
    for change in &c.logins {
        match change {
            Change::Put(l) => {
                exec(&mut tx, LOGIN_PUT, &[&uuid(l.account), &uuid(l.text)]).await?;
            }
            Change::Delete(a) => {
                exec(&mut tx, LOGIN_DEL, &[&uuid(*a)]).await?;
            }
        }
    }
    // Deletes first, so a fingerprint a deleted row held is free for a
    // row put in the same batch (the UNIQUE constraint, lane L26).
    for change in &c.displays {
        if let Change::Delete(a) = change {
            exec(&mut tx, DISPLAY_DEL, &[&uuid(*a)]).await?;
        }
    }
    for change in &c.displays {
        if let Change::Put(d) = change {
            exec(
                &mut tx,
                DISPLAY_PUT,
                &[&uuid(d.account), &uuid(d.text), &d.fingerprint.to_vec()],
            )
            .await?;
        }
    }
    for change in &c.requested {
        match change {
            Change::Put(t) => {
                exec(&mut tx, REQUEST_PUT, &[&uuid(*t)]).await?;
            }
            Change::Delete(t) => {
                exec(&mut tx, REQUEST_DEL, &[&uuid(*t)]).await?;
            }
        }
    }
    tx.commit().await?;
    Ok(())
}
