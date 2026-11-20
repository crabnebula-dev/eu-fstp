//! The production authorisation server of the cell (ADR-013 amendment of
//! 2026-11-20, `docs/handoff/production-mcp-design.md` section 3.4, lane
//! L2).
//!
//! [`AuthServer`] holds one `fstp-oauth` server over the cell's durable
//! `mcp.*` rows ([`store`]):
//!
//! - every call that changes a durable record writes the journal of that
//!   call in one transaction before its reply is sent. A failed write
//!   answers 503 and reloads the server from the rows before the next
//!   call, which drops the records held in memory only, as a restart does;
//! - every grant is judged against the account's last completed recovery
//!   in the cell's state (I-79, H-21): a code issued, or a family started,
//!   at or before it is refused. Each load also revokes every stored
//!   family the check refuses;
//! - the four OAuth endpoints and the consent denial are served by
//!   [`routes`], through the front's mount ([`Mount`]);
//! - the API core's `Tokens` port is [`tokens::CellTokens`] over the same
//!   server.
//!
//! The server never learns an identity attribute (I-86). It knows an
//! account by its raw id.
//!
//! Composition hooks (lane L2, kept small for lanes L1 and L4): the cell
//! start builds the server ([`AuthServer::start`]), mounts its routes on
//! the front (`crate::http::front::Front::mount_oauth`) and gives it to
//! the route backend for the recovery route (`set_agent_grants`). L1's
//! composition plugs [`tokens::CellTokens`] into its `CellPorts`.

pub mod routes;
pub mod store;
pub mod tokens;

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fstp_cell_core::CellState;
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_http::{Request, Response};
use fstp_oauth::{Account, AuthorizationServer, Config, GrantGuard};

use crate::engine::CommitClock;
use store::{McpFault, McpStore};

/// How often the server drops records that can no longer change an
/// answer (`AuthorizationServer::purge`): every ten minutes.
const PURGE_EVERY_US: i64 = 600_000_000;

/// The state of the cell after its last commit.
pub type StateView = Arc<dyn Fn() -> Arc<CellState> + Send + Sync>;

/// The configuration of the cell's authorisation server: the issuer is
/// the cell origin `https://{host}`, the one resource `{origin}/mcp`, and
/// P-71 and P-72 the cell defaults (ADR-013 amendment, "Lifetimes").
///
/// # Errors
///
/// When `fstp-oauth` refuses the host.
pub fn config_for(host: &str) -> Result<Config, fstp_oauth::OauthError> {
    let origin = format!("https://{host}");
    let cfg = Config::new(
        &origin,
        &format!("{origin}/mcp"),
        fstp_auth::SessionLifetimes::DEFAULT.absolute_us,
        fstp_auth::stepup::P71_DEFAULT_US,
    );
    AuthorizationServer::new(cfg.clone())?;
    Ok(cfg)
}

/// The guard of the accounts' last completed recoveries (I-79).
struct RecoveryGuard(Arc<CellState>);

impl GrantGuard for RecoveryGuard {
    fn refused(&self, account: Account, since: i64) -> bool {
        self.0.auth().ended_by_recovery(
            AccountId::from_raw(account.raw()),
            Timestamp::from_micros(since),
        )
    }
}

/// The server in memory, or none when it must be loaded from the rows.
struct Slot {
    server: Option<AuthorizationServer>,
    last_purge: i64,
}

/// The cell's authorisation server (module documentation).
pub struct AuthServer {
    cfg: Config,
    slot: Mutex<Slot>,
    store: Arc<dyn McpStore>,
    state: StateView,
    clock: CommitClock,
}

impl std::fmt::Debug for AuthServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthServer")
            .field("issuer", &self.cfg.issuer)
            .finish_non_exhaustive()
    }
}

impl AuthServer {
    /// The server of `cfg` over `store`, loaded from its rows. `state`
    /// gives the cell's state after its last commit, and `clock` the cell
    /// clock.
    ///
    /// # Errors
    ///
    /// When the rows cannot be read or the sweep cannot be written.
    pub async fn start(
        cfg: Config,
        store: Arc<dyn McpStore>,
        state: StateView,
        clock: CommitClock,
    ) -> Result<Arc<AuthServer>, McpFault> {
        let s = Arc::new(AuthServer {
            cfg,
            slot: Mutex::new(Slot {
                server: None,
                last_purge: i64::MIN,
            }),
            store,
            state,
            clock,
        });
        s.ensure_loaded().await?;
        Ok(s)
    }

    /// The configuration, which the metadata documents name.
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// The cell clock, microseconds.
    pub fn now(&self) -> i64 {
        (self.clock)()
    }

    fn lock(&self) -> MutexGuard<'_, Slot> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn guard(&self) -> RecoveryGuard {
        RecoveryGuard((self.state)())
    }

    /// Loads the server from the rows when it holds none, and revokes
    /// every family the recovery check refuses (H-21).
    async fn ensure_loaded(&self) -> Result<(), McpFault> {
        if self.lock().server.is_some() {
            return Ok(());
        }
        let records = self.store.load().await?;
        let restored = AuthorizationServer::restore(self.cfg.clone(), records)
            .map_err(|_| McpFault::Corrupt)?;
        let mut server = restored.server;
        server.revoke_refused(&self.guard());
        self.store.write(server.take_changes()).await?;
        let mut slot = self.lock();
        if slot.server.is_none() {
            slot.server = Some(server);
        }
        Ok(())
    }

    /// Runs `f` on the server and writes the changes it made before it
    /// returns (module documentation). A failed write drops the server,
    /// so the next call loads it from the rows.
    ///
    /// # Errors
    ///
    /// When the server cannot be loaded, or the changes not written.
    pub async fn call<T>(
        &self,
        f: impl FnOnce(&mut AuthorizationServer, &dyn GrantGuard, i64) -> T,
    ) -> Result<T, McpFault> {
        self.ensure_loaded().await?;
        let guard = self.guard();
        let now = self.now();
        let (out, changes) = {
            let mut slot = self.lock();
            let purge = now.saturating_sub(slot.last_purge) >= PURGE_EVERY_US;
            if purge {
                slot.last_purge = now;
            }
            let Some(server) = slot.server.as_mut() else {
                return Err(McpFault::Unavailable);
            };
            if purge {
                server.purge(now);
            }
            let out = f(server, &guard, now);
            (out, server.take_changes())
        };
        if let Err(e) = self.store.write(changes).await {
            self.lock().server = None;
            return Err(e);
        }
        Ok(out)
    }

    /// Reads the server with `f`, after loading it if need be. Nothing is
    /// written.
    ///
    /// # Errors
    ///
    /// When the server cannot be loaded.
    pub async fn read<T>(
        &self,
        f: impl FnOnce(&AuthorizationServer, &dyn GrantGuard, i64) -> T,
    ) -> Result<T, McpFault> {
        self.ensure_loaded().await?;
        let guard = self.guard();
        let now = self.now();
        let slot = self.lock();
        let server = slot.server.as_ref().ok_or(McpFault::Unavailable)?;
        Ok(f(server, &guard, now))
    }

    /// Ends every agent grant of `account` at once, durably: every family
    /// and every unredeemed code (I-79, H-21, issue 6 M5). The recovery
    /// route calls it after the completion commits. Returns how many
    /// families it revoked.
    ///
    /// # Errors
    ///
    /// When the server cannot be loaded or the revocation not written.
    /// The recovery check still refuses every older grant.
    pub async fn revoke_all_agents(&self, account: AccountId) -> Result<usize, McpFault> {
        self.call(|s, _, now| s.revoke_all_agents(Account::from_raw(account.raw()), now))
            .await
    }
}

/// The future of a mounted route.
pub type MountFuture<'a> = Pin<Box<dyn Future<Output = Response> + Send + 'a>>;

/// What the cell front hands every request below `/oauth` to (lane L2
/// hook, `crate::http::front::Front::mount_oauth`).
pub trait Mount: Send + Sync + 'static {
    /// Serves one request below `/oauth`.
    fn serve(&self, req: Request) -> MountFuture<'_>;
}

/// The routes of an [`AuthServer`] on the cell origin `origin`.
#[derive(Clone, Debug)]
pub struct OauthRoutes {
    server: Arc<AuthServer>,
    origin: String,
}

impl OauthRoutes {
    /// The routes of `server`, whose pages and form posts belong to the
    /// cell origin `https://{host}`.
    pub fn new(server: Arc<AuthServer>, host: &str) -> OauthRoutes {
        OauthRoutes {
            server,
            origin: format!("https://{host}"),
        }
    }
}

impl Mount for OauthRoutes {
    fn serve(&self, req: Request) -> MountFuture<'_> {
        Box::pin(routes::serve(&self.server, &self.origin, req))
    }
}

/// Whether `path` lies below `/oauth`.
pub fn is_route(path: &str) -> bool {
    path == "/oauth" || path.starts_with("/oauth/")
}

/// What the recovery route revokes through (lane L2 hook, H-21).
pub trait AgentGrants: Send + Sync + 'static {
    /// Ends every agent grant of `account` (issue 6 M5).
    fn revoke_all_agents(
        &self,
        account: AccountId,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

impl AgentGrants for AuthServer {
    fn revoke_all_agents(
        &self,
        account: AccountId,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            // A failed write leaves the recovery check, which refuses
            // every grant older than the recovery on every call.
            let _ = AuthServer::revoke_all_agents(self, account).await;
        })
    }
}

/// Lane L2 hook of `crate::process::start`: the authorisation server of a
/// serving cell on `host`, over its `app` pool, with client metadata in
/// the keystore owner `keys`, judged against the state of `engine`, on
/// the cell clock.
///
/// # Errors
///
/// [`crate::CellError::Config`] for a host `fstp-oauth` refuses, and
/// [`crate::CellError::Store`] when the rows cannot be read.
pub async fn start_pg<R: fstp_rt::Runtime>(
    pool: fstp_pgstore::Pool<R>,
    keys: crate::tasks::erasure::ErasureHandle,
    engine: crate::engine::CellEngine,
    clock: CommitClock,
    host: &str,
) -> Result<Arc<AuthServer>, crate::CellError> {
    let cfg = config_for(host)
        .map_err(|_| crate::CellError::Config(crate::config::ConfigError::Invalid("host")))?;
    let store_err = |_| crate::CellError::Store(fstp_ledger::StoreError::Unavailable);
    let texts: Arc<dyn store::MetaTexts> = Arc::new(store::ErasureTexts::new(keys));
    let store = store::PgMcpStore::new(pool, texts).map_err(store_err)?;
    let state: StateView = Arc::new(move || engine.state());
    AuthServer::start(cfg, Arc::new(store), state, clock)
        .await
        .map_err(store_err)
}

#[cfg(test)]
mod tests;
