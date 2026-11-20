//! The `mcp.*` rows of the authorisation server (migration
//! `0010_mcp.sql`, ADR-013 amendment of 2026-11-20, lane L2).
//!
//! [`McpStore`] reads the durable records back at start and writes the
//! journal of one endpoint call in one transaction:
//!
//! 1. each new client's registration metadata goes to a sealed text first
//!    ([`MetaTexts`]), and its row names that text;
//! 2. then, in one transaction: client inserts, family upserts that
//!    replace only a lower version, refresh hash inserts, family drops and
//!    client drops, in that order. A drop deletes the dependent rows by
//!    the foreign keys.
//!
//! No row holds a token, a code, a consent handle or client text. A
//! client whose metadata text is gone, erased or unknown, is deleted with
//! its families at load, which fails closed. A text that cannot be opened
//! for now fails the load.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};

use fstp_oauth::{
    Account, Change, ClientNumber, ClientRecord, FamilyRecord, LoginMethod, Records, RefreshHash,
    ScopeSet,
};
use fstp_pgstore::Pool;
use fstp_rt::Runtime;

/// Why the store failed. It names no row and no value (R-NF-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McpFault {
    /// The database or the text store did not answer, or refused.
    Unavailable,
    /// A stored row is outside the shape of `0010_mcp.sql`.
    Corrupt,
}

/// The future of a store call.
pub type McpFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, McpFault>> + Send + 'a>>;

/// Where the durable records of the authorisation server live.
pub trait McpStore: Send + Sync + 'static {
    /// Every durable record.
    fn load(&self) -> McpFuture<'_, Records>;
    /// Writes the changes of one call, all or none.
    fn write(&self, changes: Vec<Change>) -> McpFuture<'_, ()>;
}

/// Why a metadata text did not open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextFault {
    /// The text is erased or unknown, for good.
    Gone,
    /// The text store did not answer.
    Unavailable,
}

/// The future of a text call.
pub type TextFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, TextFault>> + Send + 'a>>;

/// The sealed texts that hold client metadata.
pub trait MetaTexts: Send + Sync + 'static {
    /// Stores `bytes` as text `id`.
    fn put(&self, id: [u8; 16], bytes: Vec<u8>) -> TextFuture<'_, ()>;
    /// Opens text `id`.
    fn open(&self, id: [u8; 16]) -> TextFuture<'_, Vec<u8>>;
}

/// The text group of the authorisation server's client metadata.
/// Interim, pending Daniel: one fixed group, since a client belongs to no
/// data subject.
pub const MCP_TEXT_GROUP: [u8; 16] = *b"fstp-oauth-meta\0";

/// [`MetaTexts`] over the cell's keystore owner, in [`MCP_TEXT_GROUP`].
#[derive(Clone, Debug)]
pub struct ErasureTexts {
    keys: crate::tasks::erasure::ErasureHandle,
}

impl ErasureTexts {
    /// The texts of `keys`. The group is added on first use.
    pub fn new(keys: crate::tasks::erasure::ErasureHandle) -> ErasureTexts {
        ErasureTexts { keys }
    }
}

impl MetaTexts for ErasureTexts {
    fn put(&self, id: [u8; 16], bytes: Vec<u8>) -> TextFuture<'_, ()> {
        Box::pin(async move {
            if self
                .keys
                .put_text(MCP_TEXT_GROUP, id, bytes.clone())
                .await
                .is_ok()
            {
                return Ok(());
            }
            // The group does not exist yet: add it, then store once more.
            // A failed add (the group exists) leaves the second put to
            // report.
            let _ = self.keys.add_group(MCP_TEXT_GROUP).await;
            self.keys
                .put_text(MCP_TEXT_GROUP, id, bytes)
                .await
                .map_err(|_| TextFault::Unavailable)
        })
    }

    fn open(&self, id: [u8; 16]) -> TextFuture<'_, Vec<u8>> {
        Box::pin(async move {
            use crate::tasks::erasure::OpenRefusal;
            match self.keys.open_text(id).await {
                Ok(p) => Ok(p.to_vec()),
                Err(OpenRefusal::Erased | OpenRefusal::Unknown) => Err(TextFault::Gone),
                Err(OpenRefusal::Keys) => Err(TextFault::Unavailable),
            }
        })
    }
}

/// [`MetaTexts`] in process memory, for tests and the memory backend.
#[derive(Debug, Default)]
pub struct MemoryTexts {
    texts: Mutex<BTreeMap<[u8; 16], Vec<u8>>>,
}

impl MetaTexts for MemoryTexts {
    fn put(&self, id: [u8; 16], bytes: Vec<u8>) -> TextFuture<'_, ()> {
        self.texts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, bytes);
        Box::pin(std::future::ready(Ok(())))
    }

    fn open(&self, id: [u8; 16]) -> TextFuture<'_, Vec<u8>> {
        let t = self
            .texts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .cloned()
            .ok_or(TextFault::Gone);
        Box::pin(std::future::ready(t))
    }
}

/// The `mcp.family.method` code of a login method.
const fn method_code(m: LoginMethod) -> i16 {
    match m {
        LoginMethod::Passkey => 1,
        LoginMethod::MagicLink => 2,
        LoginMethod::Opaque => 3,
        LoginMethod::EudiWallet => 4,
    }
}

fn method_of(code: i16) -> Option<LoginMethod> {
    [
        LoginMethod::Passkey,
        LoginMethod::MagicLink,
        LoginMethod::Opaque,
        LoginMethod::EudiWallet,
    ]
    .into_iter()
    .find(|m| method_code(*m) == code)
}

/// The 16 bytes of a `client_id`, or `None` for one the server never
/// issues.
fn client_id_bytes(id: &str) -> Option<[u8; 16]> {
    let raw = fstp_oauth::decode_base64url(id.as_bytes()).ok()?;
    <[u8; 16]>::try_from(raw.as_bytes()).ok()
}

fn int8(v: u64) -> Result<i64, McpFault> {
    i64::try_from(v).map_err(|_| McpFault::Corrupt)
}

fn uint8(v: i64) -> Result<u64, McpFault> {
    u64::try_from(v).map_err(|_| McpFault::Corrupt)
}

/// The stored family `f` as row values.
struct FamilyRow {
    id: i64,
    client: i64,
    account: Vec<u8>,
    scopes: i32,
    start: i64,
    end: i64,
    current: Vec<u8>,
    refreshes: i32,
    revoked: bool,
    method: i16,
    version: i64,
}

impl FamilyRow {
    fn of(f: &FamilyRecord) -> Result<FamilyRow, McpFault> {
        Ok(FamilyRow {
            id: int8(f.id)?,
            client: int8(f.client.raw())?,
            account: f.account.raw().to_be_bytes().to_vec(),
            scopes: i32::from(f.scopes.bits()),
            start: f.start,
            end: f.end,
            current: f.current.to_vec(),
            refreshes: i32::try_from(f.refreshes).map_err(|_| McpFault::Corrupt)?,
            revoked: f.revoked,
            method: method_code(f.method),
            version: int8(f.version)?,
        })
    }
}

/// The store over the cell's `c_<cell>_app` pool.
pub struct PgMcpStore<R: Runtime> {
    pool: Pool<R>,
    texts: Arc<dyn MetaTexts>,
}

impl<R: Runtime> std::fmt::Debug for PgMcpStore<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgMcpStore").finish_non_exhaustive()
    }
}

impl<R: Runtime> PgMcpStore<R> {
    /// The store over `pool`, with client metadata in `texts`.
    ///
    /// # Errors
    ///
    /// [`McpFault::Unavailable`] for a pool of another role than `app`.
    pub fn new(pool: Pool<R>, texts: Arc<dyn MetaTexts>) -> Result<PgMcpStore<R>, McpFault> {
        if pool.role() != fstp_pgstore::Role::App {
            return Err(McpFault::Unavailable);
        }
        Ok(PgMcpStore { pool, texts })
    }

    async fn load_rows(&self) -> Result<Records, McpFault> {
        let mut c = self.pool.get().await.map_err(|_| McpFault::Unavailable)?;
        let clients = c
            .query(
                "SELECT number, client_id, metadata_text, registered_at FROM mcp.client ORDER BY number",
                &[],
            )
            .await
            .map_err(|_| McpFault::Unavailable)?;
        let mut out = Records::default();
        let mut gone: Vec<i64> = Vec::new();
        for row in &clients {
            let number: i64 = row.get(0).map_err(|_| McpFault::Corrupt)?;
            let id: Vec<u8> = row.get(1).map_err(|_| McpFault::Corrupt)?;
            let text: Vec<u8> = row.get(2).map_err(|_| McpFault::Corrupt)?;
            let registered: i64 = row.get(3).map_err(|_| McpFault::Corrupt)?;
            let text = <[u8; 16]>::try_from(text.as_slice()).map_err(|_| McpFault::Corrupt)?;
            let metadata = match self.texts.open(text).await {
                Ok(m) => m,
                Err(TextFault::Gone) => {
                    gone.push(number);
                    continue;
                }
                Err(TextFault::Unavailable) => return Err(McpFault::Unavailable),
            };
            out.clients.push(ClientRecord {
                number: ClientNumber::from_raw(uint8(number)?),
                client_id: fstp_oauth::encode_base64url(&id),
                metadata,
                registered,
            });
        }
        for number in gone {
            c.execute("DELETE FROM mcp.client WHERE number = $1", &[&number])
                .await
                .map_err(|_| McpFault::Unavailable)?;
        }
        let families = c
            .query(
                "SELECT id, client, account, scopes, started_at, ends_at, current_hash, refreshes, revoked, method, version \
                 FROM mcp.family ORDER BY id",
                &[],
            )
            .await
            .map_err(|_| McpFault::Unavailable)?;
        for row in &families {
            let get_i64 = |i: usize| row.get::<i64>(i).map_err(|_| McpFault::Corrupt);
            let account: Vec<u8> = row.get(2).map_err(|_| McpFault::Corrupt)?;
            let account =
                <[u8; 16]>::try_from(account.as_slice()).map_err(|_| McpFault::Corrupt)?;
            let scopes: i32 = row.get(3).map_err(|_| McpFault::Corrupt)?;
            let scopes = u16::try_from(scopes)
                .ok()
                .and_then(ScopeSet::from_bits)
                .ok_or(McpFault::Corrupt)?;
            let current: Vec<u8> = row.get(6).map_err(|_| McpFault::Corrupt)?;
            let refreshes: i32 = row.get(7).map_err(|_| McpFault::Corrupt)?;
            let revoked: bool = row.get(8).map_err(|_| McpFault::Corrupt)?;
            let method: i16 = row.get(9).map_err(|_| McpFault::Corrupt)?;
            out.families.push(FamilyRecord {
                id: uint8(get_i64(0)?)?,
                client: ClientNumber::from_raw(uint8(get_i64(1)?)?),
                account: Account::from_raw(u128::from_be_bytes(account)),
                scopes,
                start: get_i64(4)?,
                end: get_i64(5)?,
                current: <[u8; 32]>::try_from(current.as_slice()).map_err(|_| McpFault::Corrupt)?,
                refreshes: u32::try_from(refreshes).map_err(|_| McpFault::Corrupt)?,
                revoked,
                method: method_of(method).ok_or(McpFault::Corrupt)?,
                version: uint8(get_i64(10)?)?,
            });
        }
        let refresh = c
            .query("SELECT hash, family FROM mcp.refresh", &[])
            .await
            .map_err(|_| McpFault::Unavailable)?;
        c.release();
        for row in &refresh {
            let hash: Vec<u8> = row.get(0).map_err(|_| McpFault::Corrupt)?;
            let family: i64 = row.get(1).map_err(|_| McpFault::Corrupt)?;
            out.refresh.push(RefreshHash {
                hash: <[u8; 32]>::try_from(hash.as_slice()).map_err(|_| McpFault::Corrupt)?,
                family: uint8(family)?,
            });
        }
        Ok(out)
    }

    async fn write_rows(&self, changes: Vec<Change>) -> Result<(), McpFault> {
        if changes.is_empty() {
            return Ok(());
        }
        let mut clients = Vec::new();
        let mut families: BTreeMap<u64, FamilyRecord> = BTreeMap::new();
        let mut refresh = Vec::new();
        let mut family_drops = Vec::new();
        let mut client_drops = Vec::new();
        for c in changes {
            match c {
                Change::Client(r) => clients.push(r),
                Change::Family(f) => {
                    let newer = families
                        .get(&f.id)
                        .is_none_or(|old| old.version < f.version);
                    if newer {
                        families.insert(f.id, f);
                    }
                }
                Change::Refresh(h) => refresh.push(h),
                Change::FamilyDropped(f) => family_drops.push(f),
                Change::ClientDropped(n) => client_drops.push(n),
            }
        }
        // The texts first: a row never names a text that was not stored.
        let mut client_rows = Vec::with_capacity(clients.len());
        for r in clients {
            let id = client_id_bytes(&r.client_id).ok_or(McpFault::Corrupt)?;
            let text = fstp_crypto::random_array::<16>().map_err(|_| McpFault::Unavailable)?;
            self.texts
                .put(text, r.metadata.clone())
                .await
                .map_err(|_| McpFault::Unavailable)?;
            client_rows.push((int8(r.number.raw())?, id, text, r.registered));
        }
        let family_rows = families
            .values()
            .map(FamilyRow::of)
            .collect::<Result<Vec<_>, _>>()?;
        let mut c = self.pool.get().await.map_err(|_| McpFault::Unavailable)?;
        let mut tx = c.transaction().await.map_err(|_| McpFault::Unavailable)?;
        let fail = |_| McpFault::Unavailable;
        for (number, id, text, registered) in &client_rows {
            tx.execute(
                "INSERT INTO mcp.client (number, client_id, metadata_text, registered_at) VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (number) DO NOTHING",
                &[number, &id.to_vec(), &text.to_vec(), registered],
            )
            .await
            .map_err(fail)?;
        }
        for f in &family_rows {
            tx.execute(
                "INSERT INTO mcp.family (id, client, account, scopes, started_at, ends_at, current_hash, refreshes, revoked, method, version) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
                 ON CONFLICT (id) DO UPDATE SET current_hash = EXCLUDED.current_hash, refreshes = EXCLUDED.refreshes, \
                 revoked = EXCLUDED.revoked, version = EXCLUDED.version WHERE mcp.family.version < EXCLUDED.version",
                &[
                    &f.id,
                    &f.client,
                    &f.account,
                    &f.scopes,
                    &f.start,
                    &f.end,
                    &f.current,
                    &f.refreshes,
                    &f.revoked,
                    &f.method,
                    &f.version,
                ],
            )
            .await
            .map_err(fail)?;
        }
        for h in &refresh {
            tx.execute(
                "INSERT INTO mcp.refresh (hash, family) VALUES ($1, $2) ON CONFLICT (hash) DO NOTHING",
                &[&h.hash.to_vec(), &int8(h.family)?],
            )
            .await
            .map_err(fail)?;
        }
        for f in &family_drops {
            tx.execute("DELETE FROM mcp.family WHERE id = $1", &[&int8(*f)?])
                .await
                .map_err(fail)?;
        }
        for n in &client_drops {
            tx.execute(
                "DELETE FROM mcp.client WHERE number = $1",
                &[&int8(n.raw())?],
            )
            .await
            .map_err(fail)?;
        }
        tx.commit().await.map_err(fail)?;
        c.release();
        Ok(())
    }
}

impl<R: Runtime> McpStore for PgMcpStore<R> {
    fn load(&self) -> McpFuture<'_, Records> {
        Box::pin(self.load_rows())
    }

    fn write(&self, changes: Vec<Change>) -> McpFuture<'_, ()> {
        Box::pin(self.write_rows(changes))
    }
}

/// The store in process memory, with the row rules of the tables: a
/// client inserts once, a family replaces a lower version only, a drop
/// deletes the dependent rows. Tests and the memory backend use it.
#[derive(Debug, Default)]
pub struct MemoryMcpStore {
    rows: Mutex<MemoryRows>,
}

#[derive(Debug, Default)]
struct MemoryRows {
    clients: BTreeMap<u64, ClientRecord>,
    families: BTreeMap<u64, FamilyRecord>,
    refresh: BTreeMap<[u8; 32], u64>,
    /// When set, every write fails, as a database that went away.
    failing: bool,
}

impl MemoryMcpStore {
    /// Makes every later write fail, or succeed again.
    pub fn set_failing(&self, failing: bool) {
        self.lock().failing = failing;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryRows> {
        self.rows.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The stored records.
    pub fn records(&self) -> Records {
        let rows = self.lock();
        Records {
            clients: rows.clients.values().cloned().collect(),
            families: rows.families.values().cloned().collect(),
            refresh: rows
                .refresh
                .iter()
                .map(|(hash, family)| RefreshHash {
                    hash: *hash,
                    family: *family,
                })
                .collect(),
        }
    }
}

impl MemoryRows {
    fn drop_family(&mut self, f: u64) {
        self.families.remove(&f);
        self.refresh.retain(|_, fam| *fam != f);
    }
}

impl McpStore for MemoryMcpStore {
    fn load(&self) -> McpFuture<'_, Records> {
        Box::pin(std::future::ready(Ok(self.records())))
    }

    fn write(&self, changes: Vec<Change>) -> McpFuture<'_, ()> {
        let mut rows = self.lock();
        if rows.failing {
            return Box::pin(std::future::ready(Err(McpFault::Unavailable)));
        }
        for c in changes {
            match c {
                Change::Client(r) => {
                    rows.clients.entry(r.number.raw()).or_insert(r);
                }
                Change::Family(f) => {
                    let newer = rows
                        .families
                        .get(&f.id)
                        .is_none_or(|old| old.version < f.version);
                    if newer {
                        rows.families.insert(f.id, f);
                    }
                }
                Change::Refresh(h) => {
                    rows.refresh.entry(h.hash).or_insert(h.family);
                }
                Change::FamilyDropped(f) => rows.drop_family(f),
                Change::ClientDropped(n) => {
                    rows.clients.remove(&n.raw());
                    let gone: Vec<u64> = rows
                        .families
                        .values()
                        .filter(|f| f.client == n)
                        .map(|f| f.id)
                        .collect();
                    for f in gone {
                        rows.drop_family(f);
                    }
                }
            }
        }
        Box::pin(std::future::ready(Ok(())))
    }
}
