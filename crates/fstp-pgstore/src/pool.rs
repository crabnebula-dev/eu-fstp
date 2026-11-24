//! Per-role pools of one cell (M3 design section 4.7, ADR-005, I-82).
//!
//! A [`Pool`] serves one role of one cell and keeps at most its size of
//! clients. It refuses a configuration that names another cell's role or
//! database before it opens any connection. Every new connection then
//! checks, on the server, that its session runs as `c_<cell>_<role>` in
//! `c_<cell>`. So no pool serves two cells, and a process belongs to one
//! cell.
//!
//! A caller waits for a free client when all are in use. A connection that
//! breaks is dropped, and its place is reopened on the next request.
//!
//! # Reconnect (ADR-005 record of lane m10/store-reconnect)
//!
//! A restart of the cluster ends every session, idle ones included. So
//! [`Pool::get`] pings an idle client ([`fstp_pgwire::Client::ping`], one
//! round trip that runs no statement) before it hands it out. A client
//! that fails the ping is dropped and the next idle one is tried, then a
//! new connection with the full start: TLS with the server check, login
//! and the I-82 identity check. The pool never repeats a statement or a
//! transaction: a client is only ever replaced between two uses.
//!
//! A failed connect starts a backoff of [`RECONNECT_FIRST`], doubled after
//! each further failure up to [`RECONNECT_MAX`]. Until it ends, a call that
//! needs a new connection fails at once with the last connect error, so a
//! cluster that is down costs no caller a connect timeout. A connect that
//! succeeds ends the backoff.

use std::fmt;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use fstp_pgwire::{Client, Config};
use fstp_rt::Runtime;

use crate::error::DbFault;

/// The most clients one pool may keep.
pub const MAX_POOL_CLIENTS: usize = 64;

/// The backoff after the first failed connect (module documentation).
pub const RECONNECT_FIRST: Duration = Duration::from_millis(100);

/// The longest backoff between two connect attempts (module
/// documentation).
pub const RECONNECT_MAX: Duration = Duration::from_secs(2);

/// The connect backoff of a pool (module documentation).
#[derive(Debug, Default)]
struct Backoff {
    /// No connect is tried before this instant.
    until: Option<Instant>,
    /// The wait after the next failure.
    next: Duration,
    /// The error the calls fail with until then.
    last: Option<PoolError>,
}

impl Backoff {
    /// The error to fail with now, if the backoff still runs.
    fn waiting(&self, now: Instant) -> Option<PoolError> {
        match (self.until, &self.last) {
            (Some(until), Some(e)) if now < until => Some(e.clone()),
            _ => None,
        }
    }

    /// Records a failed connect at `now`.
    fn failed(&mut self, now: Instant, e: PoolError) {
        let wait = if self.next.is_zero() {
            RECONNECT_FIRST
        } else {
            self.next
        };
        self.until = now.checked_add(wait);
        self.next = wait.saturating_mul(2).min(RECONNECT_MAX);
        self.last = Some(e);
    }

    /// Ends the backoff after a connect that succeeded.
    fn succeeded(&mut self) {
        *self = Backoff::default();
    }
}

/// A login role of a cell's application database (design section 4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// `c_<cell>_migrator`: owns every schema.
    Migrator,
    /// `c_<cell>_writer`: INSERT and SELECT on the ledger, the chain, the
    /// anchors, `auth_log` and the outbox.
    Writer,
    /// `c_<cell>_app`: operational rows, texts and checkpoints.
    App,
    /// `c_<cell>_keys`: the keystore.
    Keys,
    /// `c_<cell>_auditor`: reads the chain and the stored ledger rows.
    Auditor,
}

impl Role {
    /// Every role.
    pub const ALL: [Role; 5] = [
        Role::Migrator,
        Role::Writer,
        Role::App,
        Role::Keys,
        Role::Auditor,
    ];

    /// The role name suffix, as `fstp_meta.apply_grant` takes it.
    pub const fn suffix(self) -> &'static str {
        match self {
            Role::Migrator => "migrator",
            Role::Writer => "writer",
            Role::App => "app",
            Role::Keys => "keys",
            Role::Auditor => "auditor",
        }
    }
}

fn hex(b: &[u8; 16]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(32);
    for x in b {
        for nibble in [x >> 4, x & 0x0f] {
            if let Some(d) = DIGITS.get(usize::from(nibble)) {
                s.push(char::from(*d));
            }
        }
    }
    s
}

/// The application database of `cell`: `c_<cell>`, with the cell id in
/// 32 lowercase hex digits.
pub fn database_name(cell: &[u8; 16]) -> String {
    format!("c_{}", hex(cell))
}

/// The login role `c_<cell>_<suffix>` of `cell`.
pub fn role_name(cell: &[u8; 16], role: Role) -> String {
    format!("c_{}_{}", hex(cell), role.suffix())
}

/// Why a pool refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoolError {
    /// The configuration names a role or database other than this cell's
    /// role (I-82). Nothing was opened.
    ForeignRole,
    /// The size is 0 or above [`MAX_POOL_CLIENTS`].
    SizeOutOfRange,
    /// A connection failed.
    Connect(DbFault),
    /// The server reports a session user or database other than the
    /// pool's (I-82). The connection was closed.
    IdentityMismatch,
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoolError::ForeignRole => f.write_str("the configuration names another cell's role"),
            PoolError::SizeOutOfRange => f.write_str("pool size out of range"),
            PoolError::Connect(e) => write!(f, "connect: {e}"),
            PoolError::IdentityMismatch => {
                f.write_str("the session runs as another role or database")
            }
        }
    }
}

impl std::error::Error for PoolError {}

struct State<R: Runtime> {
    idle: Vec<Client<R>>,
    open: usize,
    waiters: Vec<Waker>,
}

struct Inner<R: Runtime> {
    rt: R,
    cell: [u8; 16],
    role: Role,
    config: Config,
    max: usize,
    state: Mutex<State<R>>,
    backoff: Mutex<Backoff>,
}

impl<R: Runtime> Inner<R> {
    fn lock(&self) -> MutexGuard<'_, State<R>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn backoff(&self) -> MutexGuard<'_, Backoff> {
        self.backoff.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Frees one place and wakes every waiter, which then compete again.
    fn release(&self, client: Option<Client<R>>) {
        let waiters = {
            let mut st = self.lock();
            match client {
                Some(c) => st.idle.push(c),
                None => st.open = st.open.saturating_sub(1),
            }
            std::mem::take(&mut st.waiters)
        };
        for w in waiters {
            w.wake();
        }
    }
}

/// The clients of one role of one cell. Cheap to clone: clones share the
/// clients.
pub struct Pool<R: Runtime> {
    inner: Arc<Inner<R>>,
}

impl<R: Runtime> Clone for Pool<R> {
    fn clone(&self) -> Pool<R> {
        Pool {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<R: Runtime> fmt::Debug for Pool<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool")
            .field("role", &self.inner.role)
            .field("max", &self.inner.max)
            .finish_non_exhaustive()
    }
}

impl<R: Runtime> Pool<R> {
    /// Opens a pool of at most `max_clients` clients for `role` of `cell`
    /// over `config`, and connects its first client.
    ///
    /// # Errors
    ///
    /// - [`PoolError::ForeignRole`] when `config` names another user than
    ///   `c_<cell>_<role>` or another database than `c_<cell>`, before
    ///   any connection is made;
    /// - [`PoolError::SizeOutOfRange`];
    /// - [`PoolError::Connect`] or [`PoolError::IdentityMismatch`] from
    ///   the first connection.
    pub async fn open(
        rt: R,
        cell: [u8; 16],
        role: Role,
        config: Config,
        max_clients: usize,
    ) -> Result<Pool<R>, PoolError> {
        if config.user() != role_name(&cell, role) || config.dbname() != database_name(&cell) {
            return Err(PoolError::ForeignRole);
        }
        if max_clients == 0 || max_clients > MAX_POOL_CLIENTS {
            return Err(PoolError::SizeOutOfRange);
        }
        let inner = Arc::new(Inner {
            rt,
            cell,
            role,
            config,
            max: max_clients,
            state: Mutex::new(State {
                idle: Vec::new(),
                open: 1,
                waiters: Vec::new(),
            }),
            backoff: Mutex::new(Backoff::default()),
        });
        let first = connect(&inner).await;
        match first {
            Ok(c) => inner.lock().idle.push(c),
            Err(e) => return Err(e),
        }
        Ok(Pool { inner })
    }

    /// The cell the pool serves.
    pub fn cell(&self) -> [u8; 16] {
        self.inner.cell
    }

    /// The role the pool serves.
    pub fn role(&self) -> Role {
        self.inner.role
    }

    /// The most clients the pool keeps.
    pub fn max_clients(&self) -> usize {
        self.inner.max
    }

    /// The runtime the pool's clients run on.
    pub fn runtime(&self) -> &R {
        &self.inner.rt
    }

    /// A client, waiting while every client is in use. An idle client
    /// answers a ping first; one the server ended is dropped and replaced
    /// (module documentation, "Reconnect").
    ///
    /// # Errors
    ///
    /// [`PoolError::Connect`] or [`PoolError::IdentityMismatch`] when a new
    /// connection is needed and fails, or while the backoff after such a
    /// failure runs.
    pub async fn get(&self) -> Result<Pooled<R>, PoolError> {
        loop {
            let slot = Acquire { inner: &self.inner }.await;
            match slot {
                Some(client) => {
                    let mut pooled = Pooled::new(&self.inner, client);
                    if pooled.client.ping().await.is_ok() {
                        return Ok(pooled);
                    }
                    // The session is gone. Dropping it frees its place,
                    // and the next round takes another idle client or
                    // connects.
                    drop(pooled);
                }
                None => {
                    // The place is reserved. The guard frees it if the
                    // connect fails or this future is dropped.
                    let guard = Reserved {
                        inner: &self.inner,
                        armed: true,
                    };
                    let client = reconnect(&self.inner).await?;
                    guard.defuse();
                    return Ok(Pooled::new(&self.inner, client));
                }
            }
        }
    }
}

/// A new client in place of one that broke or was never opened, under the
/// backoff of the module documentation.
async fn reconnect<R: Runtime>(inner: &Inner<R>) -> Result<Client<R>, PoolError> {
    if let Some(e) = inner.backoff().waiting(Instant::now()) {
        return Err(e);
    }
    match connect(inner).await {
        Ok(c) => {
            inner.backoff().succeeded();
            Ok(c)
        }
        Err(e) => {
            inner.backoff().failed(Instant::now(), e.clone());
            Err(e)
        }
    }
}

/// Connects one client and checks its session identity on the server.
async fn connect<R: Runtime>(inner: &Inner<R>) -> Result<Client<R>, PoolError> {
    let mut client = Client::connect(&inner.rt, &inner.config)
        .await
        .map_err(|e| PoolError::Connect(DbFault::from(e)))?;
    let row = client
        .query_one(
            "SELECT pg_catalog.current_user()::pg_catalog.text, \
             pg_catalog.current_database()::pg_catalog.text",
            &[],
        )
        .await
        .map_err(|e| PoolError::Connect(DbFault::from(e)))?;
    let user: String = row
        .get(0)
        .map_err(|e| PoolError::Connect(DbFault::from(e)))?;
    let db: String = row
        .get(1)
        .map_err(|e| PoolError::Connect(DbFault::from(e)))?;
    if user != role_name(&inner.cell, inner.role) || db != database_name(&inner.cell) {
        // The identity is wrong either way; a failed close changes nothing.
        let _ = client.close().await;
        return Err(PoolError::IdentityMismatch);
    }
    Ok(client)
}

/// Waits for an idle client, or for a free place (`None`).
struct Acquire<'a, R: Runtime> {
    inner: &'a Inner<R>,
}

impl<R: Runtime> Future for Acquire<'_, R> {
    type Output = Option<Client<R>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Client<R>>> {
        let mut st = self.inner.lock();
        if let Some(c) = st.idle.pop() {
            return Poll::Ready(Some(c));
        }
        if st.open < self.inner.max {
            st.open = st.open.saturating_add(1);
            return Poll::Ready(None);
        }
        if !st.waiters.iter().any(|w| w.will_wake(cx.waker())) {
            st.waiters.push(cx.waker().clone());
        }
        Poll::Pending
    }
}

/// A reserved place for a client that is still connecting.
struct Reserved<'a, R: Runtime> {
    inner: &'a Inner<R>,
    armed: bool,
}

impl<R: Runtime> Reserved<'_, R> {
    fn defuse(mut self) {
        self.armed = false;
    }
}

impl<R: Runtime> Drop for Reserved<'_, R> {
    fn drop(&mut self) {
        if self.armed {
            self.inner.release(None);
        }
    }
}

/// A client taken from a pool. [`Pooled::release`] gives it back. A
/// client dropped without it is closed and its place freed, so an early
/// return never leaves a connection in an unknown state.
pub struct Pooled<R: Runtime> {
    client: Client<R>,
    place: Place<R>,
}

/// One place of a pool, freed on drop unless the client went back.
struct Place<R: Runtime> {
    inner: Arc<Inner<R>>,
    armed: bool,
}

impl<R: Runtime> Drop for Place<R> {
    fn drop(&mut self) {
        if self.armed {
            self.inner.release(None);
        }
    }
}

impl<R: Runtime> Pooled<R> {
    fn new(inner: &Arc<Inner<R>>, client: Client<R>) -> Pooled<R> {
        Pooled {
            client,
            place: Place {
                inner: Arc::clone(inner),
                armed: true,
            },
        }
    }

    /// Gives the client back to its pool. A broken connection, or one
    /// with a transaction still open, is closed instead and its place
    /// freed.
    pub fn release(self) {
        let Pooled { client, mut place } = self;
        if client.is_broken() || client.transaction_status() != fstp_pgwire::TransactionStatus::Idle
        {
            return;
        }
        place.armed = false;
        place.inner.release(Some(client));
    }
}

impl<R: Runtime> fmt::Debug for Pooled<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pooled").finish_non_exhaustive()
    }
}

impl<R: Runtime> Deref for Pooled<R> {
    type Target = Client<R>;

    fn deref(&self) -> &Client<R> {
        &self.client
    }
}

impl<R: Runtime> DerefMut for Pooled<R> {
    fn deref_mut(&mut self) -> &mut Client<R> {
        &mut self.client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-005 record of lane m10/store-reconnect, row "Backoff": the
    /// wait after a failed connect starts at [`RECONNECT_FIRST`], doubles
    /// up to [`RECONNECT_MAX`], fails calls with the last error while it
    /// runs, and ends with a connect that succeeds.
    #[test]
    fn adr005_reconnect_backoff_is_bounded_and_ends_on_success() {
        let fault = PoolError::Connect(DbFault {
            kind: fstp_pgwire::ErrorKind::Io,
            sqlstate: None,
        });
        let t0 = Instant::now();
        let mut b = Backoff::default();
        assert_eq!(b.waiting(t0), None);
        let mut waits = Vec::new();
        for _ in 0..8 {
            b.failed(t0, fault.clone());
            let until = b.until.unwrap_or(t0);
            waits.push(until.duration_since(t0));
            assert_eq!(b.waiting(t0), Some(fault.clone()));
            assert_eq!(b.waiting(until), None);
        }
        assert_eq!(
            waits,
            [100, 200, 400, 800, 1600, 2000, 2000, 2000].map(Duration::from_millis)
        );
        b.succeeded();
        assert_eq!(b.waiting(t0), None);
        b.failed(t0, fault);
        assert_eq!(b.until.map(|u| u.duration_since(t0)), Some(RECONNECT_FIRST));
    }
}
