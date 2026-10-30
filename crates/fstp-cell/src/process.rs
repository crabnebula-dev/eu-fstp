//! A serving cell over its PostgreSQL database: the start path that a
//! world, and later the binary, runs (design sections 2.3, 5.3, 7.2 and
//! 9.2). Lane int5.
//!
//! [`start`] runs, in order:
//!
//! 1. It opens the `c_<cell>_writer` and `c_<cell>_app` pools (design
//!    section 4.7) and reads the placement marker as the app role (I-83).
//! 2. It builds the record store over the writer pool, with the ledger
//!    keys, the App chain's `Anchor` key, the witness client of the App
//!    chain over [`crate::witness::link::TlsWitnessLink`] and the pinned
//!    witness receipt keys (ADR-010 "Keys").
//! 3. On a first start, with no keystore held, it creates epoch 0 of the
//!    App key chain through custody (design section 9.2 step 8). Each
//!    custody call is recorded first, through an engine over the same
//!    store, so the genesis entries are anchored like every other entry.
//! 4. It runs `crate::engine::startup::start_pg`: custody, the open
//!    prepare, the replay, the chain against the witness log, and the
//!    three listeners.
//! 5. It serves the listeners: the tunnel listener through
//!    [`crate::http::tunnel::TunnelListener`] and the cell's front, the
//!    loopback health listener over plain HTTP, and the internal listener
//!    over mutual TLS. The internal listener has no route in M3 (design
//!    section 8.7), so it answers 404.
//!
//! [`RunningCell::issue_first_admin_invitation`] is step 10 of design
//! section 9.2: the cell draws the first admin's token, as two halves on a
//! SaaS cell (Q35), and records the invitation's digest through the system
//! task `Provisioning`. The halves leave the cell only in its return
//! value, which the caller hands to the two staff channels.
//!
//! What the caller still hands in, reported to Daniel and the lead: the
//! ledger keys, the `Anchor` key and the CredLookup key, which the
//! keystore groups of design section 3.5 do not give yet. The keystore
//! itself is held in memory by its owner (`crate::tasks::erasure`). The
//! outbox data keys are held in process memory ([`MemoryOutboxKeys`]).
//!
//! Open I-83 seam, reported to Daniel and the lead: design section 9.2
//! has the start check the placement marker, the database server's
//! certificate OU and the registration of its SPKI. Only the marker is
//! read from the database here. `fstp_pgwire::Client` does not expose the
//! server's leaf certificate, so the OU and the SPKI registration are
//! [`CellProcessParts::server_ou`] and
//! [`CellProcessParts::registered_spki`], which the caller asserts. A world
//! passes the kind of the cluster it connected to. The fix is to expose
//! the leaf from `fstp_pgwire` (lead-owned) and derive both here.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use fstp_audit::{CellId, ChainId, CompositeSigningKey};
use fstp_cell_core::gate;
use fstp_crypto::aead;
use fstp_custody::Custody;
use fstp_keys::{DekId, ObjectId};
use fstp_pgstore::{KeyFuture, LedgerKeys, OutboxKey, OutboxKeys, Pool, Role, StoreFault};
use fstp_rt::{Runtime, Shutdown};

use crate::CellError;
use crate::config::Mode;
use crate::engine::pg::PgCellStore;
use crate::engine::startup::{
    ClusterRole, DatabaseView, ListenerKind, PgStartParts, StartRefusal, start_pg,
};
use crate::engine::{CellEngine, VaultClient};
use crate::http::front::{Front, FrontConfig, StderrLog};
use crate::http::tunnel::{TunnelListener, TunnelTls};
use crate::routes::pg::PgBackend;
use crate::tasks::erasure::{ErasureHandle, ErasureRunner, Keystore};
use crate::witness::WitnessClient;
use crate::witness::link::{TlsWitnessLink, WitnessEndpoint};

/// The size of each pool.
pub const POOL_CLIENTS: usize = 4;

/// The keys the caller hands in (module documentation).
pub struct CellKeys {
    /// The App chain's composite `Anchor` key (design section 3.9).
    pub anchor: CompositeSigningKey,
    /// The ledger data key generations.
    pub ledger: Arc<LedgerKeys>,
    /// The CredLookup key of the sign count rows.
    pub cred_lookup: [u8; 32],
}

/// Where the cell's listeners bind. Port 0 picks a free port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Listen {
    /// The tunnel port from the edge.
    pub tunnel: SocketAddr,
    /// The internal mutual TLS port.
    pub internal: SocketAddr,
    /// The loopback health port.
    pub health: SocketAddr,
}

/// What a serving cell starts from.
pub struct CellProcessParts<C, V> {
    /// The cell.
    pub cell: [u8; 16],
    /// The deployment mode.
    pub mode: Mode,
    /// The cell host: the relying party id and the origin host.
    pub host: String,
    /// The `c_<cell>_writer` login.
    pub writer: fstp_pgwire::Config,
    /// The `c_<cell>_app` login.
    pub app: fstp_pgwire::Config,
    /// The kind the database server's certificate OU names. A caller
    /// claim, not read from the session: see "Open I-83 seam" in the
    /// module documentation.
    pub server_ou: ClusterRole,
    /// The kind the server's SPKI is registered for. A caller claim, like
    /// [`CellProcessParts::server_ou`].
    pub registered_spki: ClusterRole,
    /// The App chain's custody backend.
    pub custody: C,
    /// The keystore of the App chain, or `None` on a first start.
    pub keystore: Option<Keystore>,
    /// The keys of module documentation.
    pub keys: CellKeys,
    /// The witness of the App chain.
    pub witness: WitnessEndpoint,
    /// The pinned witness receipt keys, encoded.
    pub witness_keys: Vec<Vec<u8>>,
    /// The vault client.
    pub vault: V,
    /// The tunnel listener's TLS.
    pub tunnel_tls: TunnelTls,
    /// The internal listener's server configuration, with client
    /// authentication against the cell CA.
    pub internal_tls: Arc<fstp_tls::ServerConfig>,
    /// The compiled auth pages the front serves, if any.
    pub pages: Option<crate::http::pages::Pages>,
    /// Where to bind.
    pub listen: Listen,
}

/// The first admin's token as the cell drew it (design section 8.3).
#[derive(Clone, PartialEq, Eq)]
pub struct FirstAdminToken {
    /// The first half, or the one token of a self-hosted cell.
    pub first: [u8; 32],
    /// The second half on a SaaS cell.
    pub second: Option<[u8; 32]>,
}

impl std::fmt::Debug for FirstAdminToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A credential: the debug form never shows it.
        f.write_str("FirstAdminToken(..)")
    }
}

/// A serving cell.
pub struct RunningCell<R: Runtime> {
    rt: R,
    cell: [u8; 16],
    mode: Mode,
    engine: CellEngine,
    backend: Arc<PgBackend<R>>,
    shutdown: Shutdown,
    servers: Vec<fstp_http::ServerHandle<R>>,
    bound: Listen,
    erasure: ErasureHandle,
    app: Pool<R>,
    reader: PgCellStore<R, WitnessClient<TlsWitnessLink<R>>>,
}

impl<R: Runtime> std::fmt::Debug for RunningCell<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunningCell")
            .field("bound", &self.bound)
            .finish_non_exhaustive()
    }
}

/// The outbox data keys, held in process memory for the life of the
/// process. A key seals one row (`fstp_pgstore::OutboxKey`).
#[derive(Default)]
pub struct MemoryOutboxKeys {
    keys: Mutex<OutboxKeyMap>,
}

/// The outbox data keys by data key id and row.
type OutboxKeyMap = BTreeMap<([u8; 16], [u8; 16]), [u8; aead::KEY_LEN]>;

impl MemoryOutboxKeys {
    fn keys(&self) -> MutexGuard<'_, OutboxKeyMap> {
        self.keys.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl OutboxKeys for MemoryOutboxKeys {
    fn create(&self, row: ObjectId) -> KeyFuture<'_, OutboxKey> {
        let made = (|| {
            let mut bytes = [0u8; aead::KEY_LEN];
            fstp_crypto::random_bytes(&mut bytes).map_err(|_| StoreFault::SealRefused)?;
            let dek = fstp_crypto::random_array::<16>().map_err(|_| StoreFault::SealRefused)?;
            let key = aead::Key::from_bytes(&bytes).map_err(|_| StoreFault::SealRefused)?;
            self.keys().insert((dek, row.0), bytes);
            Ok(OutboxKey {
                dek: DekId(dek),
                key,
            })
        })();
        Box::pin(std::future::ready(made))
    }

    fn open(&self, dek: DekId, row: ObjectId) -> KeyFuture<'_, Option<OutboxKey>> {
        let found = self.keys().get(&(dek.0, row.0)).copied();
        let opened = match found {
            None => Ok(None),
            Some(bytes) => aead::Key::from_bytes(&bytes)
                .map(|key| Some(OutboxKey { dek, key }))
                .map_err(|_| StoreFault::OpenFailed),
        };
        Box::pin(std::future::ready(opened))
    }
}

fn store_err<E>(_: E) -> CellError {
    CellError::Store(fstp_ledger::StoreError::Unavailable)
}

/// The configuration bytes of `cell` in `mode` (`crate::config`).
fn config_bytes(cell: [u8; 16], mode: Mode) -> Vec<u8> {
    let hex: String = cell.iter().map(|b| format!("{b:02x}")).collect();
    let mode = match mode {
        Mode::Saas => "saas",
        Mode::SelfHosted => "self_hosted",
    };
    format!("{{\"cell\":\"{hex}\",\"mode\":\"{mode}\",\"version\":\"0.3.0\"}}").into_bytes()
}

/// The placement marker of the cell database, read as the app role.
async fn placement_marker<R: Runtime>(app: &Pool<R>) -> Result<u8, CellError> {
    let mut c = app.get().await.map_err(store_err)?;
    let rows = c
        .query("SELECT kind FROM fstp_meta.placement", &[])
        .await
        .map_err(store_err)?;
    c.release();
    let [row] = rows.as_slice() else {
        return Err(CellError::Config(crate::config::ConfigError::Invalid(
            "placement",
        )));
    };
    let kind: i16 = row.get(0).map_err(store_err)?;
    u8::try_from(kind).map_err(store_err)
}

fn refusal(r: StartRefusal) -> CellError {
    match r {
        StartRefusal::Config(c) => CellError::Config(c),
        StartRefusal::ChainTamper => CellError::ChainTamper,
        StartRefusal::Witness | StartRefusal::WitnessPins => {
            CellError::Witness(fstp_audit::anchorer::WitnessFault::Unreachable)
        }
        StartRefusal::Placement => {
            CellError::Config(crate::config::ConfigError::Invalid("placement"))
        }
        StartRefusal::Custody => CellError::Keys("custody"),
        StartRefusal::KeyRecord => CellError::Keys("key record"),
        StartRefusal::Store => CellError::Store(fstp_ledger::StoreError::Unavailable),
        StartRefusal::Listen => CellError::Io(std::io::ErrorKind::AddrNotAvailable),
    }
}

/// A 404 for every request: the internal listener has no route in M3.
struct NoRoute;

impl fstp_http::Handler for NoRoute {
    async fn handle(&self, _req: fstp_http::Request) -> fstp_http::Response {
        fstp_http::Response::new(fstp_http::StatusCode::NOT_FOUND)
    }
}

/// Starts the cell of `parts` on `rt` (module documentation).
///
/// # Errors
///
/// The first step that fails, as a [`CellError`].
pub async fn start<R, C, V>(
    rt: &R,
    parts: CellProcessParts<C, V>,
) -> Result<RunningCell<R>, CellError>
where
    R: Runtime,
    C: Custody + Clone + Send + Sync + 'static,
    V: VaultClient + Clone,
{
    let CellProcessParts {
        cell,
        mode,
        host,
        writer,
        app,
        server_ou,
        registered_spki,
        custody,
        keystore,
        keys,
        witness,
        witness_keys,
        vault,
        tunnel_tls,
        internal_tls,
        pages,
        listen,
    } = parts;
    let reader_pool = Pool::open(rt.clone(), cell, Role::Writer, writer.clone(), 1)
        .await
        .map_err(store_err)?;
    let writer_pool = Pool::open(rt.clone(), cell, Role::Writer, writer, POOL_CLIENTS)
        .await
        .map_err(store_err)?;
    let app_pool = Pool::open(rt.clone(), cell, Role::App, app, POOL_CLIENTS)
        .await
        .map_err(store_err)?;
    let marker = placement_marker(&app_pool).await?;
    let anchor_key = keys.anchor.public_key().to_bytes().to_vec();
    let link = TlsWitnessLink::new(rt.clone(), witness.clone(), CellId(cell), ChainId::App);
    let client = WitnessClient::new(link, CellId(cell), ChainId::App, witness.ca_digest);
    let reader_link = TlsWitnessLink::new(rt.clone(), witness.clone(), CellId(cell), ChainId::App);
    let reader_client =
        WitnessClient::new(reader_link, CellId(cell), ChainId::App, witness.ca_digest);
    let signer: Arc<dyn fstp_pgstore::AnchorSigner> = Arc::new(keys.anchor);
    // A second store over its own pool reads the ledger for the caller. It
    // never appends, so its witness client sends nothing.
    let reader = PgCellStore::new(
        reader_pool,
        Arc::clone(&keys.ledger),
        Arc::clone(&signer),
        reader_client,
        witness_keys.clone(),
        Arc::new(MemoryOutboxKeys::default()),
    )
    .map_err(store_err)?;
    let store = PgCellStore::new(
        writer_pool,
        Arc::clone(&keys.ledger),
        signer,
        client,
        witness_keys,
        Arc::new(MemoryOutboxKeys::default()),
    )
    .map_err(store_err)?;
    let (store, keystore) = match keystore {
        Some(k) => (store, k),
        None => genesis(rt, store, vault.clone(), custody.clone(), cell).await?,
    };
    let database = DatabaseView {
        marker,
        server_ou,
        registered_spki,
    };
    let started = start_pg(
        rt,
        PgStartParts {
            config: config_bytes(cell, mode),
            database,
            custody,
            keystore,
            store,
            anchor_key,
            vault,
            crabnebula: None::<NoCrabNebula>,
            licence: None,
            listen: [
                (ListenerKind::Tunnel, listen.tunnel),
                (ListenerKind::Internal, listen.internal),
                (ListenerKind::Health, listen.health),
            ],
        },
        &mut |_| {},
    )
    .await
    .map_err(refusal)?;
    let backend = Arc::new(
        PgBackend::new(started.engine.clone(), app_pool.clone(), keys.cred_lookup)
            .map_err(store_err)?,
    );
    let front_cfg = FrontConfig {
        cell,
        host: host.clone(),
        enabled: fstp_auth::EnabledMethods::default(),
    };
    let log = Arc::new(StderrLog);
    let front = match pages {
        #[cfg(feature = "dev-pages")]
        Some(p) => Front::with_pages(front_cfg, p, Arc::clone(&backend), log),
        #[cfg(not(feature = "dev-pages"))]
        Some(_) => {
            return Err(CellError::NotImplemented(
                "the auth pages need the dev-pages feature",
            ));
        }
        None => Front::new(front_cfg, Arc::clone(&backend), log),
    }
    .map_err(|_| CellError::Config(crate::config::ConfigError::Invalid("host")))?;
    let mut servers = Vec::with_capacity(3);
    let mut bound = listen;
    let fstp_cell_shutdown = started.shutdown.clone();
    for (kind, l) in started.listeners {
        let local = fstp_rt::Listener::local_addr(&l).map_err(|e| CellError::Io(e.kind()))?;
        let server = match kind {
            ListenerKind::Tunnel => {
                bound.tunnel = local;
                let tunnel = TunnelListener::new(
                    rt,
                    l,
                    tunnel_tls.clone(),
                    host.clone(),
                    fstp_cell_shutdown.signal(),
                )
                .map_err(|e| CellError::Io(e.kind()))?;
                fstp_http::Server::new(rt.clone(), http_config(None), front.tunnel_handler())
                    .serve(tunnel)
            }
            ListenerKind::Health => {
                bound.health = local;
                fstp_http::Server::new(rt.clone(), http_config(None), front.health_handler())
                    .serve(l)
            }
            ListenerKind::Internal => {
                bound.internal = local;
                let tls = (*internal_tls).clone();
                fstp_http::Server::new(rt.clone(), http_config(Some(tls)), NoRoute).serve(l)
            }
        }
        .map_err(|e| CellError::Io(e.kind()))?;
        servers.push(server);
    }
    Ok(RunningCell {
        rt: rt.clone(),
        cell,
        mode,
        engine: started.engine,
        backend,
        shutdown: started.shutdown,
        servers,
        bound,
        erasure: started.erasure,
        app: app_pool,
        reader,
    })
}

/// The HTTP settings of a listener, with `tls` when the listener
/// terminates TLS itself.
fn http_config(tls: Option<fstp_tls::ServerConfig>) -> fstp_http::ServerConfig {
    fstp_http::ServerConfig {
        tls,
        limits: fstp_http::Limits {
            max_body_bytes: 1 << 20,
            ..fstp_http::Limits::default()
        },
        ..fstp_http::ServerConfig::default()
    }
}

/// The CrabNebula transport of a cell that has none: a SaaS cell never
/// reaches CrabNebula (B12). It is never handed to a start, and every
/// call would fail as unreachable.
struct NoCrabNebula;

impl crate::egress::CnTransport for NoCrabNebula {
    fn exchange(
        &self,
        _host: &'static str,
        _request: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, crate::egress::CnFault>> + Send {
        std::future::ready(Err(crate::egress::CnFault::Unreachable))
    }
}

/// Step 3 of the module documentation: epoch 0 of the App key chain,
/// with each custody call recorded through an engine over `store`.
async fn genesis<R, C, V>(
    rt: &R,
    store: PgCellStore<R, WitnessClient<TlsWitnessLink<R>>>,
    vault: V,
    custody: C,
    cell: [u8; 16],
) -> Result<(PgCellStore<R, WitnessClient<TlsWitnessLink<R>>>, Keystore), CellError>
where
    R: Runtime,
    C: Custody + Send + Sync + 'static,
    V: VaultClient,
{
    let shutdown = Shutdown::new();
    let (engine, task) =
        CellEngine::start(rt, store, vault, &shutdown, crate::engine::DEFAULT_QUEUE)
            .await
            .map_err(store_err)?;
    let runner = ErasureRunner::genesis(custody, engine.clone(), cell).await;
    // The engine ends once its last handle drops, and gives the store back.
    let keystore = runner.map(|r| r.keystore().clone());
    drop(engine);
    let store = task.await.map_err(store_err)?;
    Ok((store, keystore?))
}

impl<R: Runtime> RunningCell<R> {
    /// The cell.
    pub fn cell(&self) -> [u8; 16] {
        self.cell
    }

    /// Where the listeners are bound.
    pub fn bound(&self) -> Listen {
        self.bound
    }

    /// The engine.
    pub fn engine(&self) -> &CellEngine {
        &self.engine
    }

    /// The route backend.
    pub fn backend(&self) -> &Arc<PgBackend<R>> {
        &self.backend
    }

    /// The erasure task's handle.
    pub fn erasure(&self) -> &ErasureHandle {
        &self.erasure
    }

    /// Every committed ledger entry, decrypted, in sequence order. It reads
    /// through a store of its own, so it never waits for the engine.
    ///
    /// # Errors
    ///
    /// [`CellError::Store`] when the store cannot be read or an entry does
    /// not open.
    pub async fn ledger(
        &self,
    ) -> Result<Vec<fstp_ledger::Entry<fstp_cell_core::CellRecord>>, CellError> {
        crate::engine::read_after(&self.reader, fstp_ledger::Seq::ZERO)
            .await
            .map_err(CellError::Store)
    }

    /// The app pool, for reads of the operational rows.
    pub fn app_pool(&self) -> &Pool<R> {
        &self.app
    }

    /// Design section 9.2 step 10 (module documentation): draws the first
    /// admin's token and records its invitation for a new account.
    ///
    /// # Errors
    ///
    /// [`CellError::Keys`] when no random value is available, and
    /// [`CellError::Store`] when the gate or the engine refuses, for
    /// example while a first-admin invitation is open or a first admin
    /// enrolled.
    pub async fn issue_first_admin_invitation(&self) -> Result<FirstAdminToken, CellError> {
        use fstp_auth::ceremony::{split_token_digest, token_digest};
        use fstp_auth::codec::Token;
        let rnd = || fstp_crypto::random_array::<32>().map_err(|_| CellError::Keys("token"));
        let first = rnd()?;
        let second = rnd()?;
        let ids = fstp_crypto::random_array::<16>().map_err(|_| CellError::Keys("ids"))?;
        let invitation = fstp_crypto::random_array::<16>().map_err(|_| CellError::Keys("ids"))?;
        let suffix = fstp_crypto::random_array::<8>().map_err(|_| CellError::Keys("ids"))?;
        let account = fstp_domain::id::AccountId::from_raw(u128::from_be_bytes(ids));
        let (digest, second, deployment) = match self.mode {
            Mode::Saas => (
                split_token_digest(&Token(first), &Token(second)),
                Some(second),
                fstp_auth::recovery::Deployment::Saas,
            ),
            Mode::SelfHosted => (
                token_digest(&Token(first)),
                None,
                fstp_auth::recovery::Deployment::SelfHosted,
            ),
        };
        let now = fstp_domain::time::Timestamp::from_micros(crate::tasks::system_now());
        let admitted = gate::admit_first_admin_invitation(
            &self.engine.state(),
            invitation,
            account,
            digest,
            deployment,
            fstp_cell_core::system_command_id(suffix),
            now,
        )
        .map_err(store_err)?;
        self.engine.execute(admitted).await.map_err(store_err)?;
        Ok(FirstAdminToken { first, second })
    }

    /// Stops the listeners and the tasks, and waits up to `deadline` for
    /// them to drain.
    ///
    /// # Errors
    ///
    /// [`CellError::Io`] when something was still running at the deadline.
    pub async fn shutdown(self, deadline: Duration) -> Result<(), CellError> {
        let mut timed_out = false;
        for s in &self.servers {
            if s.shutdown(deadline).await.is_err() {
                timed_out = true;
            }
        }
        drop(self.backend);
        drop(self.engine);
        if self.shutdown.shutdown(&self.rt, deadline).await.is_err() {
            timed_out = true;
        }
        if timed_out {
            Err(CellError::Io(std::io::ErrorKind::TimedOut))
        } else {
            Ok(())
        }
    }
}
