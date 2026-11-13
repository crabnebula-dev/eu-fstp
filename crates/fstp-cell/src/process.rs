//! A serving cell over its PostgreSQL database: the start path that a
//! world, and later the binary, runs (design sections 2.3, 5.3, 7.2 and
//! 9.2). Lane int5.
//!
//! [`start`] runs, in order:
//!
//! 1. It opens the `c_<cell>_writer` and `c_<cell>_app` pools (design
//!    section 4.7) and runs the I-83 start check of design section 9.2
//!    before anything else touches the database, custody or the witness
//!    ([`check_database`]). It reads the placement marker as the app
//!    role. It takes the server certificate OU and the SPKI from the leaf
//!    certificate that each connection of each pool verified
//!    ([`fstp_pgwire::Client::server_certificate_der`]), through the
//!    server check of every pool configuration
//!    ([`application_server_check`]). The cell refuses
//!    anything but an application database on a server whose OU is
//!    `application` and whose SPKI digest the control plane registered
//!    for an application cluster only.
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
//! The caller hands in no claim about its database server. It hands in
//! the registration set ([`CellProcessParts::registered_servers`]): each
//! cluster's server SPKI digest and kind, as the control plane recorded
//! them at cluster registration (`cp.cluster` `kind` and `server_spki`).
//! The OU and the SPKI come from the live connections only. The SPKI and
//! the first subject OU are read by `fstp_witness::peer::read_cert`, the
//! in-house fuzzed DER reader of the witness's sender check. Every
//! subject OU is read by `fstp_pgwire::x509::subject_organizational_units`,
//! fuzzed as well. A subject with more than one OU names no cluster kind.
//!
//! A pool opens later connections over the same configuration, for
//! example after one broke. So the OU and SPKI check does not run only at
//! start: [`start`] adds it to the writer and app configurations as a
//! [`fstp_pgwire::ServerCheck`] ([`application_server_check`]). Every
//! connection of every pool, the app pool of the route backend included,
//! then runs it before its startup message.

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
    ClusterRole, DatabaseView, ListenerKind, PgStartParts, StartRefusal, accepts_database, start_pg,
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
    /// The control plane's registration of cluster server keys (module
    /// documentation). The start check looks up each live server's SPKI
    /// digest here ([`check_database`]).
    pub registered_servers: Vec<RegisteredSpki>,
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
    clock: crate::engine::CommitClock,
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

/// The subject OU of an application cluster's server certificate (design
/// sections 1.3 and 4.1), as `fstp_pki::cert::ClusterKindOu::Application`
/// spells it. The cell does not depend on `fstp-pki`.
pub const APPLICATION_OU: &str = "application";

/// The subject OU of a vault cluster's server certificate, as
/// `fstp_pki::cert::ClusterKindOu::Vault` spells it.
pub const VAULT_OU: &str = "vault";

/// One cluster server key as the control plane registered it (design
/// section 9.2): the SHA-256 digest of the server certificate's
/// SubjectPublicKeyInfo DER, and the kind of the cluster it was
/// registered for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisteredSpki {
    /// SHA-256 over the SubjectPublicKeyInfo DER, tag and length included.
    pub digest: [u8; 32],
    /// The kind of the cluster the key was registered for.
    pub role: ClusterRole,
}

/// The kind that the subject OU of the server certificate `cert_der`
/// names. The subject must hold exactly one OU, and it must be
/// [`APPLICATION_OU`] or [`VAULT_OU`]. A certificate that does not read,
/// a subject without an OU or with two, and any other OU name
/// [`ClusterRole::Other`].
///
/// Both in-house readers must agree on the OU: the first subject OU of
/// `fstp_witness::peer::read_cert` and the only one that
/// `fstp_pgwire::x509::subject_organizational_units` lists.
#[must_use]
pub fn server_ou_role(cert_der: &[u8]) -> ClusterRole {
    let Ok(cert) = fstp_witness::peer::read_cert(cert_der) else {
        return ClusterRole::Other;
    };
    let Ok(ous) = fstp_pgwire::x509::subject_organizational_units(cert_der) else {
        return ClusterRole::Other;
    };
    let [ou] = ous.as_slice() else {
        return ClusterRole::Other;
    };
    if cert.names.subject_ou.as_deref() != Some(*ou) {
        return ClusterRole::Other;
    }
    if *ou == APPLICATION_OU.as_bytes() {
        ClusterRole::Application
    } else if *ou == VAULT_OU.as_bytes() {
        ClusterRole::Vault
    } else {
        ClusterRole::Other
    }
}

/// Whether the server certificate `cert_der` is that of an application
/// cluster: its OU names one ([`server_ou_role`]) and `registered` gives
/// its SPKI that kind only ([`registered_role`]).
#[must_use]
pub fn is_application_server(cert_der: &[u8], registered: &[RegisteredSpki]) -> bool {
    server_ou_role(cert_der) == ClusterRole::Application
        && registered_role(cert_der, registered) == ClusterRole::Application
}

/// The server check that [`start`] adds to the writer and app
/// configurations: it accepts a server only when
/// [`is_application_server`] holds for its verified leaf under
/// `registered`. Every connection of a pool over such a configuration
/// runs it, so a pool that reconnects later is held to the I-83 server
/// check of design section 9.2 too. A refused connection fails with
/// [`fstp_pgwire::ErrorKind::ServerRefused`].
#[must_use]
pub fn application_server_check(registered: &[RegisteredSpki]) -> fstp_pgwire::ServerCheck {
    let registered = registered.to_vec();
    fstp_pgwire::ServerCheck::new(move |der: &[u8]| is_application_server(der, &registered))
}

/// The SHA-256 digest of the SubjectPublicKeyInfo of the certificate
/// `cert_der`, or `None` when the certificate does not read.
#[must_use]
pub fn server_spki_digest(cert_der: &[u8]) -> Option<[u8; 32]> {
    fstp_witness::peer::read_cert(cert_der)
        .ok()
        .map(|c| fstp_crypto::sha256(c.spki))
}

/// The kind that `registered` gives the SPKI of the server certificate
/// `cert_der`. It is the one kind every registration of that digest
/// names. A key with no registration, a key registered for two kinds, or
/// a certificate that does not read names [`ClusterRole::Other`], so the
/// start check refuses it.
#[must_use]
pub fn registered_role(cert_der: &[u8], registered: &[RegisteredSpki]) -> ClusterRole {
    let Some(digest) = server_spki_digest(cert_der) else {
        return ClusterRole::Other;
    };
    let mut roles = registered
        .iter()
        .filter(|r| r.digest == digest)
        .map(|r| r.role);
    match roles.next() {
        Some(first) if roles.all(|r| r == first) => first,
        _ => ClusterRole::Other,
    }
}

/// The I-83 start check of design section 9.2 over the live connection
/// `client`: the placement marker it reads, and the OU and the SPKI of
/// the leaf certificate its server presented, checked against
/// `registered`. Returns the view it accepted.
///
/// It is the only place a [`DatabaseView`] is built, so the view that
/// `crate::engine::startup::start_pg` checks again always comes from a
/// live connection (I-83).
///
/// # Errors
///
/// The refusal of [`StartRefusal::Placement`] when the view is not that
/// of an application database on an application cluster
/// (`crate::engine::startup::accepts_database`). [`CellError::Store`]
/// or [`CellError::Config`] when the marker does not read.
pub async fn check_database<R: Runtime>(
    client: &mut fstp_pgwire::Client<R>,
    registered: &[RegisteredSpki],
) -> Result<DatabaseView, CellError> {
    let marker = placement_marker(client).await?;
    let cert_der = client.server_certificate_der();
    let view = DatabaseView::new(
        marker,
        server_ou_role(cert_der),
        registered_role(cert_der, registered),
    );
    if !accepts_database(&view) {
        return Err(refusal(StartRefusal::Placement));
    }
    Ok(view)
}

/// The error of a pool step. A connection that the server check of
/// [`application_server_check`] refused is the I-83 placement refusal.
/// Any other failure is a store error.
fn pool_err(e: fstp_pgstore::PoolError) -> CellError {
    match e {
        fstp_pgstore::PoolError::Connect(fstp_pgstore::DbFault {
            kind: fstp_pgwire::ErrorKind::ServerRefused,
            ..
        }) => refusal(StartRefusal::Placement),
        other => store_err(other),
    }
}

/// The placement marker of the cell database, read over `client`.
async fn placement_marker<R: Runtime>(
    client: &mut fstp_pgwire::Client<R>,
) -> Result<u8, CellError> {
    let rows = client
        .query("SELECT kind FROM fstp_meta.placement", &[])
        .await
        .map_err(store_err)?;
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

/// Starts the cell of `parts` on `rt` (module documentation), with the
/// production [`StartOptions`].
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
    start_with(rt, parts, StartOptions::default()).await
}

/// What a caller may set beyond [`CellProcessParts`]. The default is the
/// production cell: the system clock and [`crate::shell::ProductionShell`].
#[derive(Clone)]
pub struct StartOptions {
    /// The cell clock: the route backend's instants, the store's commit
    /// instant, the first admin's invitation and the timeline and erasure
    /// tasks all read it. A test world passes a clock it can move, so its
    /// tests set the cell's time (lane F-CYCLE2).
    pub clock: crate::engine::CommitClock,
    /// The creator shell the command route reads its facts from
    /// ([`crate::shell`]).
    pub creator_shell: Arc<dyn crate::shell::CreatorShell>,
    /// The proof mail port of self-registration, magic links and recovery
    /// email proofs ([`crate::mail`]).
    pub proof_mail: Arc<dyn crate::mail::ProofMail>,
    /// The pinned control-plane key of recovery operator tickets, encoded
    /// (design section 8.5). `None` refuses every ticket, as a cell does
    /// until provisioning hands it the key (Interim, pending Daniel).
    pub operator_key: Option<Vec<u8>>,
    /// The login methods the tenant enables (P-70). Passkeys are always
    /// enabled. The default enables nothing more, so magic links are off
    /// until the tenant's setting is handed in (lane m3/login-m2http,
    /// Interim, pending Daniel: no record carries P-70 yet).
    pub login_methods: fstp_auth::EnabledMethods,
}

impl Default for StartOptions {
    fn default() -> StartOptions {
        StartOptions {
            clock: crate::engine::system_commit_clock(),
            creator_shell: Arc::new(crate::shell::ProductionShell),
            proof_mail: Arc::new(crate::mail::NoProofMail),
            operator_key: None,
            login_methods: fstp_auth::EnabledMethods::default(),
        }
    }
}

impl std::fmt::Debug for StartOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartOptions").finish_non_exhaustive()
    }
}

/// [`start`] with the options `options` ([`StartOptions`]).
///
/// # Errors
///
/// The first step that fails, as a [`CellError`].
pub async fn start_with<R, C, V>(
    rt: &R,
    parts: CellProcessParts<C, V>,
    options: StartOptions,
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
        registered_servers,
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
    let StartOptions {
        clock,
        creator_shell,
        proof_mail,
        operator_key,
        login_methods,
    } = options;
    // I-83 first: nothing below runs against a database that fails it.
    // Every connection of the three pools, now and later, checks the
    // server's OU and SPKI before its startup message.
    let server_check = application_server_check(&registered_servers);
    let writer = writer.server_check(server_check.clone());
    let app = app.server_check(server_check);
    let reader_pool = Pool::open(rt.clone(), cell, Role::Writer, writer.clone(), 1)
        .await
        .map_err(pool_err)?;
    let writer_pool = Pool::open(rt.clone(), cell, Role::Writer, writer, POOL_CLIENTS)
        .await
        .map_err(pool_err)?;
    let app_pool = Pool::open(rt.clone(), cell, Role::App, app, POOL_CLIENTS)
        .await
        .map_err(pool_err)?;
    // The placement marker, and the view `start_pg` checks again.
    let database = {
        let mut c = app_pool.get().await.map_err(pool_err)?;
        let checked = check_database(&mut c, &registered_servers).await;
        c.release();
        checked?
    };
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
    let store_clock = Arc::clone(&clock);
    let store = PgCellStore::from_store(
        store
            .into_inner()
            .with_clock(Arc::new(move || Some(store_clock()))),
    );
    let (store, keystore) = match keystore {
        Some(k) => (store, k),
        None => {
            genesis(
                rt,
                store,
                vault.clone(),
                custody.clone(),
                cell,
                Arc::clone(&clock),
            )
            .await?
        }
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
            clock: Arc::clone(&clock),
        },
        &mut |_| {},
    )
    .await
    .map_err(refusal)?;
    let backend = Arc::new(
        PgBackend::new(started.engine.clone(), app_pool.clone(), keys.cred_lookup)
            .map_err(store_err)?
            .with_clock(Arc::clone(&clock))
            .with_shell(creator_shell)
            .with_proof_mail(proof_mail)
            .with_login_index(started.erasure.clone())
            .with_mode(match mode {
                Mode::Saas => fstp_auth::recovery::Deployment::Saas,
                Mode::SelfHosted => fstp_auth::recovery::Deployment::SelfHosted,
            })
            .with_operator_key(operator_key),
    );
    // The timeline reads `auth.session` through the route backend for
    // `EndSessionsAtBindingEnd` (design sections 4.2 and 5.1).
    let _ = started
        .sessions
        .set(Arc::new(crate::tasks::timeline::BackendSessions(
            Arc::clone(&backend),
        )));
    let front_cfg = FrontConfig {
        cell,
        host: host.clone(),
        enabled: login_methods,
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
        clock,
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
    clock: crate::engine::CommitClock,
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
    let engine = engine.with_clock(clock);
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
        let now = fstp_domain::time::Timestamp::from_micros((self.clock)());
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

    /// Keeps `email` as the login email of the first admin's invitation,
    /// whose token digest is `digest`. The enrolment binds it to the new
    /// account through the keyed index (design section 4.2). Interim,
    /// pending Daniel (lane m3/login-m2http): provisioning names the
    /// tenant contact's address here, and design section 9.2 step 10
    /// names no address.
    pub fn note_first_admin_email(&self, digest: [u8; 32], email: String) {
        self.backend.note_first_admin_email(digest, email);
    }

    /// The contract port's fact `event` of `contract` on `proposal` (M5
    /// design section 4.1), as the system task
    /// `fstp_cell_core::SystemTask::ContractPort`.
    ///
    /// Interim (lane F-CYCLE3): the cell runs no contract signature route
    /// yet, so nothing in a serving cell calls this. A test world calls it
    /// in process to stand for a completed signature, and its claims say
    /// so. The gate admits only `ContractFact` under this task, and the
    /// domain decides it with every guard of its row.
    ///
    /// # Errors
    ///
    /// [`CellError::Keys`] when no random value is available, and
    /// [`CellError::Store`] when the gate or the engine refuses.
    pub async fn contract_fact(
        &self,
        proposal: fstp_domain::id::ProposalId,
        contract: fstp_domain::id::ContractId,
        event: fstp_domain::command::ContractEvent,
    ) -> Result<(), CellError> {
        let suffix = fstp_crypto::random_array::<8>().map_err(|_| CellError::Keys("ids"))?;
        let now = fstp_domain::time::Timestamp::from_micros((self.clock)());
        let action = gate::Action::Command(fstp_cell_core::CellCommand::Engine(
            fstp_engine::Command::Core(fstp_domain::Command::ContractFact {
                proposal,
                contract,
                event,
            }),
        ));
        let admitted = gate::admit_system(
            &self.engine.state(),
            action,
            fstp_cell_core::SystemTask::ContractPort,
            fstp_cell_core::system_command_id(suffix),
            now,
        )
        .map_err(store_err)?;
        self.engine.execute(admitted).await.map_err(store_err)?;
        Ok(())
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
