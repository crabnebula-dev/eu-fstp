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
//! 3. It loads the keystore of the App chain from its tables over the
//!    `c_<cell>_keys` login (ADR-004, decided by Daniel on 2026-11-20,
//!    lane L3). On a first start, with no keystore rows and an empty
//!    ledger, it creates epoch 0 of the App key chain through custody
//!    (design section 9.2 step 8) and writes it to the tables. Each
//!    custody call is recorded first, through an engine over the same
//!    store, so the genesis entries are anchored like every other entry.
//!    No keystore rows beside a ledger that is not empty is refused.
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
//! itself lives in its tables (`crate::tasks::erasure::tables`). The
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
    /// The vault ticket key: purpose `Ticket` on the App chain, Ed25519
    /// (ADR-004, design section 6.5). The vault pins its public key.
    /// Interim, pending Daniel (lane m3/cell-routes): it is handed in by
    /// the caller, as the `Anchor` key is, until the keystore creates and
    /// rotates it. `None` leaves the ticket routes at 501.
    pub ticket: Option<Arc<fstp_crypto::sig::Ed25519SigningKey>>,
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
    /// The `c_<cell>_keys` login of the keystore tables (ADR-004, decided
    /// by Daniel on 2026-11-20). The keystore is loaded from them at each
    /// start, and created there on a first start (lane L3).
    pub keystore: fstp_pgwire::Config,
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
    release: crate::tasks::release::ReleaseView,
    /// Lane L2: the authorisation server (`crate::oauth`).
    oauth: Arc<crate::oauth::AuthServer>,
    /// The ledger key generations, which also seal the API core's rows
    /// (ADR-026).
    ledger_keys: Arc<LedgerKeys>,
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

// ---- Lane L5 `prod/api-ports` (ADR-026 record of lane L5): the relay
// the API core's ports deliver through (`crate::api::mail`).
pub use crate::api::mail::{Relay, RelayFuture, StagedMail};

/// The relay of [`StartOptions::api_relay`].
pub type ApiRelay = std::sync::Arc<dyn Relay>;
// ---- End of lane L5's block.

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
    /// The cell's start option for the login methods (P-70). Passkeys are
    /// always enabled. The default enables nothing more, so magic links are
    /// off unless this option enables them. Since Daniel's decision of
    /// 2026-11-15 (late, ADR-008) it is the default only: a tenant admin's
    /// `SetLoginPolicy` turns magic links on or off, and its choice wins
    /// (`fstp_cell_core::tenant::TenantLoginPolicy::enabled_methods`).
    pub login_methods: fstp_auth::EnabledMethods,
    /// The control plane link of a SaaS cell ([`crate::control`]). With
    /// one, the cell sends its heartbeats there. Interim, pending Daniel
    /// (lane F-ISO): the control plane runs no listener yet (lane F-CP),
    /// so the production default is `None`, and a test world passes the
    /// world's control plane.
    pub control_plane: Option<crate::control::ControlPlaneEndpoint>,
    /// A test's fault point on the cell's record store
    /// ([`fstp_pgstore::FaultPoint`], lane F-ERASE). Production sets none.
    pub fault_point: Option<fstp_pgstore::FaultPoint>,
    /// The transport to the CrabNebula services (design section 10.1).
    /// With one, a self-hosted cell starts its licence refresh and update
    /// check in the background (`crate::tasks::release`, I-38, I-39). A
    /// SaaS cell never builds a call, with or without one (B12).
    ///
    /// Interim, pending Daniel: Q34 is open, so the production default is
    /// `None` and no cell process builds `crate::egress::TlsCnTransport`
    /// yet. A test world passes its CrabNebula stand-in.
    pub crabnebula: Option<crate::egress::SharedCnTransport>,
    /// The licence token the cell holds, with its pinned key set (design
    /// section 10.2, Q41). Interim, pending Daniel: the sealed licence
    /// store of `fstp-cell licence import` is not built, so the caller
    /// hands the imported token in. Without one only the update check
    /// runs.
    pub licence: Option<crate::tasks::release::LicenceHold>,
    /// The clock of the licence refresh and the update check, or `None`
    /// to run them on [`StartOptions::clock`], as production does. A test
    /// world passes a clock it moves ahead of the cell's, so a call falls
    /// due without moving the cell's own time, which would end its
    /// sessions (P-72).
    pub release_clock: Option<crate::engine::CommitClock>,
    /// The rate limits of the public auth routes and of `PutText`
    /// (ADR-024). The default holds the interim values. A test world
    /// passes wider ones, since all its clients share one loopback
    /// address and so one peer key.
    pub auth_limits: crate::routes::AuthLimits,
    /// The organisation port of ADR-021 for a ledger that holds no
    /// tenant part (`crate::public::OrganisationPort`). The production
    /// default answers "not active", so the public pages answer "not
    /// published yet" until the ledger records the activation. A test
    /// world from before the tenant part sets it active, and says so.
    pub organisation: crate::public::OrganisationPort,
    /// The compiled journey UI (`web/dist/app`, loaded with
    /// `fstp_web::load_dir`). With it, the cell mounts the web adapter over
    /// its own `ApiCore` (ADR-026). `None` serves the cell table only.
    pub web_assets: Option<fstp_web::AssetSet>,
    // ---- Lane L5 `prod/api-ports` (ADR-026 record of lane L5).
    /// The relay the API core's ports deliver their mail through, such
    /// as a programme role invitation. `None` refuses each invitation
    /// before it records anything. Lane L4's configured relay plugs in
    /// here at merge. A test world passes one of its own.
    pub api_relay: Option<ApiRelay>,
    // ---- End of lane L5's block.
    /// The keystore snapshot writer of the App chain and the directory of
    /// its status file, when the configuration names an object store
    /// (ADR-012 records of lanes L17 and L27). `None` keeps step 5's
    /// in-memory copy and takes no daily snapshot.
    pub keystore_snapshots: Option<(fstp_backup::Snapshots, std::path::PathBuf)>,
    /// The onboarding probes of the API core's `Prober` port (ADR-026
    /// record of lane L18): the relay's greeting and a saved sending
    /// domain. `None` fails every probe (Q5).
    pub tenant_prober: Option<Arc<dyn crate::shell::probe::TenantProbe>>,
    /// The host status file of the tenant admins' System page (ADR-028
    /// record of lane L20), which `fstp-admin` writes. `None` shows the
    /// page's host rows as not configured.
    pub host_status: Option<std::path::PathBuf>,
    /// The forge client of the payment checks runner (ADR-026 section of
    /// lane `m10/checks-runner`, ADR-009 amendment of 2026-11-24). With
    /// one, the cell runs `crate::tasks::checks` in the background, and
    /// it records the submission and acceptance runs of each payment
    /// request (I-32). `fstp_cell::run` always passes one, built from the
    /// configuration's forge allowlist. The default is `None`, so a test
    /// world keeps playing the payment port in process
    /// ([`RunningCell::payment_checks`]).
    pub checks: Option<crate::egress::SharedForge>,
    /// Test only (ADR-026 amendment of 2026-11-23, M10 F-039, F-040):
    /// `true` serves the wide form of `POST /api/v1/commands`, as a test
    /// world drives its cycle through it. The field exists only with the
    /// test-only feature `wide-commands`. The default is `false`.
    #[cfg(feature = "wide-commands")]
    pub wide_commands: bool,
}

impl Default for StartOptions {
    fn default() -> StartOptions {
        StartOptions {
            clock: crate::engine::system_commit_clock(),
            creator_shell: Arc::new(crate::shell::ProductionShell),
            proof_mail: Arc::new(crate::mail::NoProofMail),
            operator_key: None,
            login_methods: fstp_auth::EnabledMethods::default(),
            control_plane: None,
            fault_point: None,
            crabnebula: None,
            licence: None,
            release_clock: None,
            auth_limits: crate::routes::AuthLimits::default(),
            organisation: crate::public::OrganisationPort::default(),
            web_assets: None,
            api_relay: None,
            keystore_snapshots: None,
            tenant_prober: None,
            host_status: None,
            checks: None,
            #[cfg(feature = "wide-commands")]
            wide_commands: false,
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
        control_plane,
        fault_point,
        crabnebula,
        licence,
        release_clock,
        auth_limits,
        organisation,
        web_assets,
        api_relay,
        keystore_snapshots,
        tenant_prober,
        host_status,
        checks,
        #[cfg(feature = "wide-commands")]
        wide_commands,
    } = options;
    if control_plane.is_some() {
        crate::control::allowed(mode).map_err(CellError::Egress)?;
    }
    // Lane L26: the pools, the stores and the keystore open in a phase of
    // their own ([`open_phase`]), so its values never share a frame with
    // the rest of the start-up.
    let Opened {
        app_pool,
        reader,
        store,
        keystore,
        database,
        anchor_key,
    } = open_phase(
        rt,
        OpenInputs {
            cell,
            writer,
            app,
            keystore,
            registered_servers,
            anchor: keys.anchor,
            ledger: Arc::clone(&keys.ledger),
            witness,
            witness_keys,
            custody: custody.clone(),
            vault: vault.clone(),
            clock: Arc::clone(&clock),
            fault_point,
            keystore_snapshots,
        },
    )
    .await?;
    // The API core asks the vault through a clone of the engine's client.
    let api_vault = vault.clone();
    let mut report = |_| {};
    let started = step(|| {
        start_pg(
            rt,
            PgStartParts {
                config: config_bytes(cell, mode),
                database,
                custody,
                keystore,
                store,
                anchor_key,
                vault,
                crabnebula,
                licence,
                listen: [
                    (ListenerKind::Tunnel, listen.tunnel),
                    (ListenerKind::Internal, listen.internal),
                    (ListenerKind::Health, listen.health),
                ],
                clock: Arc::clone(&clock),
                release_clock,
            },
            &mut report,
        )
    })
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
            .with_operator_key(operator_key)
            .with_ticket_key(keys.ticket),
    );
    // ADR-032: the anonymous draft store, shared by the draft routes and
    // the claim of the API core, and its hourly sweep.
    let drafts: Arc<dyn fstp_api_core::anon::AnonymousDrafts> =
        Arc::new(crate::tasks::drafts::PgAnonymousDrafts::new(
            fstp_pgstore::ApiStore::new(app_pool.clone(), Arc::clone(&keys.ledger))
                .map_err(store_err)?,
        ));
    let _ = backend.set_anonymous_drafts(Arc::clone(&drafts));
    {
        let signal = started.shutdown.signal();
        let clock = crate::tasks::FnClock::new(rt.clone(), Arc::clone(&clock));
        let drafts = Arc::clone(&drafts);
        drop(rt.spawn(async move {
            crate::tasks::drafts::run(&clock, drafts, &signal).await;
            drop(signal);
        }));
    }
    // ADR-007 (Daniel, 2026-11-23, decision 1b; lane L39): the hourly
    // retention sweep of stored documents. With today's rule table it
    // erases nothing (`crate::tasks::retention`).
    {
        let signal = started.shutdown.signal();
        let clock = crate::tasks::FnClock::new(rt.clone(), Arc::clone(&clock));
        let store = fstp_pgstore::ApiStore::new(app_pool.clone(), Arc::clone(&keys.ledger))
            .map_err(store_err)?;
        let erasure = started.erasure.clone();
        drop(rt.spawn(async move {
            crate::tasks::retention::run(&clock, store, erasure, &signal).await;
            drop(signal);
        }));
    }
    // ADR-026 section of lane `m10/checks-runner` (I-32, R-PR-02): the
    // checks runner of payment requests, over the configured forge client.
    if let Some(forge) = checks {
        let signal = started.shutdown.signal();
        let clock = crate::tasks::FnClock::new(rt.clone(), Arc::clone(&clock));
        let engine = started.engine.clone();
        let texts = crate::tasks::checks::ErasureTexts(started.erasure.clone());
        drop(rt.spawn(async move {
            crate::tasks::checks::run(&clock, &engine, &forge, &texts, &signal).await;
            drop(signal);
        }));
    }
    // The public text class lives in memory, as the text store it copies
    // from does, so a start copies the texts of every published call
    // again (`crate::public`).
    step(|| backend.copy_public_texts()).await;
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
        limits: auth_limits,
        organisation,
        #[cfg(feature = "wide-commands")]
        wide_commands,
    };
    // Lane L2 hook (ADR-013 amendment of 2026-11-20): the authorisation
    // server over the `mcp` rows, its `/oauth` routes on the front, and its
    // grants for the recovery route (H-21).
    let oauth = step(|| {
        crate::oauth::start_pg(
            app_pool.clone(),
            started.erasure.clone(),
            started.engine.clone(),
            Arc::clone(&clock),
            &host,
        )
    })
    .await?;
    let log = Arc::new(StderrLog);
    // ADR-026: with the compiled journey UI, the cell mounts the web
    // adapter over one ApiCore of its own ports behind its table. The
    // auth pages are served by every build (D2).
    let front = match web_assets {
        Some(assets) => {
            let parts = crate::api::ApiParts {
                cell,
                engine: started.engine.clone(),
                backend: Arc::clone(&backend),
                store: fstp_pgstore::ApiStore::new(app_pool.clone(), Arc::clone(&keys.ledger))
                    .map_err(store_err)?,
                vault: api_vault,
                erasure: started.erasure.clone(),
                organisation,
                // Lane L5: the invitation mail and its delivery.
                host: host.clone(),
                app: app_pool.clone(),
                relay: api_relay,
                prober: tenant_prober,
                rt: rt.clone(),
                host_status,
                // Lane L6's shell facts, fresh in the request, as the
                // cell's command route reads them (ADR-027, wave 2 merge).
                facts: Some(Arc::new(crate::api::facts::FreshFacts(Arc::clone(
                    &backend,
                )))),
            };
            let web = web_router(parts, &oauth, &host, assets)?;
            Front::with_web(front_cfg, pages, web, Arc::clone(&backend), log)
        }
        None => match pages {
            Some(p) => Front::with_pages(front_cfg, p, Arc::clone(&backend), log),
            None => Front::new(front_cfg, Arc::clone(&backend), log),
        },
    }
    .map_err(|_| CellError::Config(crate::config::ConfigError::Invalid("host")))?;
    let _ = backend.set_agent_grants(Arc::clone(&oauth) as Arc<dyn crate::oauth::AgentGrants>);
    let _ = front.mount_oauth(Arc::new(crate::oauth::OauthRoutes::new(
        Arc::clone(&oauth),
        &host,
    )));
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
    // B4, I-19: a SaaS cell reports its heartbeat to the control plane
    // through the closed protocol only. A self-hosted cell never does.
    if let Some(endpoint) = control_plane {
        drop(rt.spawn(crate::control::heartbeat_task(
            rt.clone(),
            endpoint,
            cell,
            started.shutdown.signal(),
        )));
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
        release: started.release,
        app: app_pool,
        reader,
        oauth,
        ledger_keys: Arc::clone(&keys.ledger),
    })
}

/// What the first phase of the start-up opens (lane L26).
struct Opened<R: Runtime> {
    app_pool: Pool<R>,
    reader: PgCellStore<R, WitnessClient<TlsWitnessLink<R>>>,
    store: PgCellStore<R, WitnessClient<TlsWitnessLink<R>>>,
    keystore: Keystore,
    database: DatabaseView,
    anchor_key: Vec<u8>,
}

/// What the first phase of the start-up takes (lane L26).
struct OpenInputs<C, V> {
    cell: [u8; 16],
    writer: fstp_pgwire::Config,
    app: fstp_pgwire::Config,
    keystore: fstp_pgwire::Config,
    registered_servers: Vec<RegisteredSpki>,
    anchor: CompositeSigningKey,
    ledger: Arc<LedgerKeys>,
    witness: WitnessEndpoint,
    witness_keys: Vec<Vec<u8>>,
    custody: C,
    vault: V,
    clock: crate::engine::CommitClock,
    fault_point: Option<fstp_pgstore::FaultPoint>,
    keystore_snapshots: Option<(fstp_backup::Snapshots, std::path::PathBuf)>,
}

/// [`open_phase_inner`] as a [`Step`]: its future is built here and kept on
/// the heap (lane L26).
#[inline(never)]
fn open_phase<'a, R, C, V>(
    rt: &'a R,
    inputs: OpenInputs<C, V>,
) -> Step<'a, Result<Opened<R>, CellError>>
where
    R: Runtime,
    C: Custody + Clone + Send + Sync + 'static,
    V: VaultClient + Clone + 'a,
{
    Box::pin(open_phase_inner(rt, inputs))
}

/// The first phase of [`start_with`]: the I-83 check of every pool, the
/// placement marker, the ledger stores, and the keystore, loaded from its
/// tables or created on a first start (lane L3).
async fn open_phase_inner<R, C, V>(rt: &R, inputs: OpenInputs<C, V>) -> Result<Opened<R>, CellError>
where
    R: Runtime,
    C: Custody + Clone + Send + Sync + 'static,
    V: VaultClient + Clone,
{
    let OpenInputs {
        cell,
        writer,
        app,
        keystore,
        registered_servers,
        anchor,
        ledger,
        witness,
        witness_keys,
        custody,
        vault,
        clock,
        fault_point,
        keystore_snapshots,
    } = inputs;
    // I-83 first: nothing below runs against a database that fails it.
    // Every connection of the three pools, now and later, checks the
    // server's OU and SPKI before its startup message.
    let server_check = application_server_check(&registered_servers);
    let writer = writer.server_check(server_check.clone());
    // Lane L3: the keys login checks its server as the other two do.
    let keystore = keystore.server_check(server_check.clone());
    let app = app.server_check(server_check);
    let reader_pool = step(|| Pool::open(rt.clone(), cell, Role::Writer, writer.clone(), 1))
        .await
        .map_err(pool_err)?;
    let writer_pool = step(|| Pool::open(rt.clone(), cell, Role::Writer, writer, POOL_CLIENTS))
        .await
        .map_err(pool_err)?;
    let app_pool = step(|| Pool::open(rt.clone(), cell, Role::App, app, POOL_CLIENTS))
        .await
        .map_err(pool_err)?;
    // The placement marker, and the view `start_pg` checks again.
    let database = {
        let mut c = app_pool.get().await.map_err(pool_err)?;
        let checked = step(|| check_database(&mut c, &registered_servers)).await;
        c.release();
        checked?
    };
    let anchor_key = anchor.public_key().to_bytes().to_vec();
    let link = TlsWitnessLink::new(rt.clone(), witness.clone(), CellId(cell), ChainId::App);
    let client = WitnessClient::new(link, CellId(cell), ChainId::App, witness.ca_digest);
    let reader_link = TlsWitnessLink::new(rt.clone(), witness.clone(), CellId(cell), ChainId::App);
    let reader_client =
        WitnessClient::new(reader_link, CellId(cell), ChainId::App, witness.ca_digest);
    let signer: Arc<dyn fstp_pgstore::AnchorSigner> = Arc::new(anchor);
    // A second store over its own pool reads the ledger for the caller. It
    // never appends, so its witness client sends nothing.
    let reader = PgCellStore::new(
        reader_pool,
        Arc::clone(&ledger),
        Arc::clone(&signer),
        reader_client,
        witness_keys.clone(),
        Arc::new(MemoryOutboxKeys::default()),
    )
    .map_err(store_err)?;
    let store = PgCellStore::new(
        writer_pool,
        Arc::clone(&ledger),
        signer,
        client,
        witness_keys,
        Arc::new(MemoryOutboxKeys::default()),
    )
    .map_err(store_err)?;
    let store_clock = Arc::clone(&clock);
    let mut inner = store
        .into_inner()
        .with_clock(Arc::new(move || Some(store_clock())));
    if let Some(f) = fault_point {
        inner = inner.with_fault_point(f);
    }
    let store = PgCellStore::from_store(inner);
    // ---- Lane L3 `prod/keystore-pg`: the keystore load (ADR-004, decided
    // by Daniel on 2026-11-20). The keystore lives in its tables and is
    // written through `c_<cell>_keys` only (I-82). A start loads it. Genesis
    // runs only on an empty ledger with no keystore rows. Either way the
    // keystore handed on comes from the tables, its chain state sealed
    // until the start-up opens it under `S(e)`.
    let keys_pool = step(|| Pool::open(rt.clone(), cell, Role::Keys, keystore, 2))
        .await
        .map_err(pool_err)?;
    let tables = Arc::new(
        fstp_pgstore::KeystoreTables::new(keys_pool)
            .map_err(store_err)?
            .with_clock(Arc::new({
                let clock = Arc::clone(&clock);
                move || Some(clock())
            })),
    );
    let sink: Arc<dyn crate::tasks::erasure::KeystoreSink> = tables.clone();
    let mut rows = step(|| tables.load()).await.map_err(store_err)?;
    let store = if rows.chain.is_none() {
        if !step(|| ledger_is_empty(&app_pool)).await? {
            // The ledger names key records of a keystore these tables do
            // not hold. A fresh epoch 0 would leave every stored text
            // unreadable, so the start refuses.
            return Err(CellError::Keys(
                "the keystore tables are empty but the ledger is not",
            ));
        }
        let store = step(|| {
            genesis(
                rt,
                store,
                vault,
                custody,
                cell,
                Arc::clone(&clock),
                Arc::clone(&sink),
            )
        })
        .await?;
        rows = step(|| tables.load()).await.map_err(store_err)?;
        store
    } else {
        store
    };
    let keystore = Keystore::from_rows(cell, rows, sink)?;
    // ADR-012 record of lane L17: step 5 takes its snapshots through the
    // object store, when one is configured.
    let keystore = match keystore_snapshots {
        Some((s, dir)) => keystore.with_snapshots(s, Some(dir)),
        None => keystore,
    };
    Ok(Opened {
        app_pool,
        reader,
        store,
        keystore,
        database,
        anchor_key,
    })
}

/// The web adapter over one `ApiCore` of the cell's ports `parts` (ADR-026),
/// with the token store of `oauth` (ADR-013 amendment of 2026-11-20). A
/// function of its own (lane L26), so the composition's values live in its
/// frame and never in the start-up's.
#[inline(never)]
fn web_router<R, V>(
    parts: crate::api::ApiParts<R, V>,
    oauth: &Arc<crate::oauth::AuthServer>,
    host: &str,
    assets: fstp_web::AssetSet,
) -> Result<fstp_web::WebRouter, CellError>
where
    R: Runtime,
    V: VaultClient + Clone,
{
    // Lane L2's token store over the same authorisation server.
    let tokens = crate::oauth::tokens::CellTokens::new(Arc::clone(oauth));
    let core = crate::api::compose(parts, tokens);
    let origin = fstp_web::parse_origin_header(format!("https://{host}").as_bytes())
        .map_err(|_| CellError::Config(crate::config::ConfigError::Invalid("host")))?;
    // One issuer and resource for the metadata documents and the server
    // that issues the tokens (ADR-013 amendment).
    let web_cfg = fstp_web::WebConfig::new(origin, assets).with_oauth(oauth.config().clone());
    fstp_web::router(Arc::new(core), web_cfg)
        .map_err(|_| CellError::NotImplemented("the web adapter refused its configuration"))
}

/// A step of the start-up whose future is built in a frame of its own and
/// kept on the heap (lane L26). The start-up awaits its large steps through
/// one, so its own state and its poll frame hold a box, never the step's
/// future. A debug build then keeps the thread that runs the start-up, a
/// test thread in the celltest world, well inside its stack.
pub(crate) type Step<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Builds the future of `make` in this function's own frame and keeps it on
/// the heap, as a [`Step`] (lane L26).
#[inline(never)]
pub(crate) fn step<'a, T, F>(make: impl FnOnce() -> F) -> Step<'a, T>
where
    F: std::future::Future<Output = T> + Send + 'a,
{
    Box::pin(make())
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

/// Whether the cell's ledger holds no entry, read as the app role, which
/// holds SELECT on the ledger (lane L3).
async fn ledger_is_empty<R: Runtime>(app: &Pool<R>) -> Result<bool, CellError> {
    const SQL: &str = "SELECT NOT EXISTS (SELECT 1 FROM ledger.entry)";
    let mut c = app.get().await.map_err(pool_err)?;
    let row = c
        .query_one(SQL, &[])
        .await
        .map_err(|_| CellError::Keys("the ledger head read"))?;
    let empty: bool = row
        .get(0)
        .map_err(|_| CellError::Keys("the ledger head read"))?;
    c.release();
    Ok(empty)
}

/// Step 3 of the module documentation: epoch 0 of the App key chain,
/// with each custody call recorded through an engine over `store`. The
/// keystore is written whole to `sink` before the engine stops (lane L3).
async fn genesis<R, C, V>(
    rt: &R,
    store: PgCellStore<R, WitnessClient<TlsWitnessLink<R>>>,
    vault: V,
    custody: C,
    cell: [u8; 16],
    clock: crate::engine::CommitClock,
    sink: Arc<dyn crate::tasks::erasure::KeystoreSink>,
) -> Result<PgCellStore<R, WitnessClient<TlsWitnessLink<R>>>, CellError>
where
    R: Runtime,
    C: Custody + Send + Sync + 'static,
    V: VaultClient,
{
    let shutdown = Shutdown::new();
    let (engine, task) =
        step(|| CellEngine::start(rt, store, vault, &shutdown, crate::engine::DEFAULT_QUEUE))
            .await
            .map_err(store_err)?;
    let engine = engine.with_clock(clock);
    let written = match step(|| ErasureRunner::genesis(custody, engine.clone(), cell)).await {
        Ok(mut runner) => step(|| runner.persist_to(sink)).await,
        Err(e) => Err(e),
    };
    // The engine ends once its last handle drops, and gives the store back.
    drop(engine);
    let store = task.await.map_err(store_err)?;
    written?;
    Ok(store)
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

    /// The admin view of the licence refresh and the update check: each
    /// attempt with its time and outcome, and the licence token held
    /// (design section 10.3). It holds no handle to the task, so nothing
    /// waits for a call through it (I-39).
    pub fn release(&self) -> &crate::tasks::release::ReleaseView {
        &self.release
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

    /// Lane L2: the cell's authorisation server (`crate::oauth`). L1's
    /// composition builds its `Tokens` port from it
    /// (`crate::oauth::tokens::CellTokens`).
    pub fn oauth(&self) -> &Arc<crate::oauth::AuthServer> {
        &self.oauth
    }

    /// The API core's tables over the app pool, sealing under the cell's
    /// ledger key generations (ADR-026), for a test that reads them.
    ///
    /// # Errors
    ///
    /// [`CellError::Store`] for a pool of another role.
    pub fn api_store(&self) -> Result<fstp_pgstore::ApiStore<R>, CellError> {
        fstp_pgstore::ApiStore::new(self.app.clone(), Arc::clone(&self.ledger_keys))
            .map_err(|e| CellError::Store(fstp_ledger::StoreError::from(e)))
    }

    /// The ledger key generations of the process (ADR-026).
    pub fn ledger_keys(&self) -> &Arc<LedgerKeys> {
        &self.ledger_keys
    }

    /// The app pool, for reads of the operational rows.
    pub fn app_pool(&self) -> &Pool<R> {
        &self.app
    }

    /// Every row of the App chain, with the stored ledger rows and the
    /// anchors, read through the cell's own reading store (ADR-010). The
    /// kind 2 rows are the audit events (ADR-010 amendment of 2026-11-20).
    ///
    /// # Errors
    ///
    /// [`CellError::Store`] when the store cannot be read.
    pub async fn chain_rows(&self) -> Result<fstp_pgstore::ChainRows, CellError> {
        self.reader
            .inner()
            .read_chain_rows()
            .await
            .map_err(|e| CellError::Store(fstp_ledger::StoreError::from(e)))
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
        self.first_admin_invitation(None).await
    }

    /// The cell's deployment mode, as the auth rules name it.
    fn deployment(&self) -> fstp_auth::recovery::Deployment {
        match self.mode {
            Mode::Saas => fstp_auth::recovery::Deployment::Saas,
            Mode::SelfHosted => fstp_auth::recovery::Deployment::SelfHosted,
        }
    }

    /// `fstp-cell provision-tenant` (ADR-026 "Tenant provisioning",
    /// decided by Daniel on 2026-11-21): records `TenantProvisioned` as
    /// the system task `Provisioning`, with the agreement versions
    /// `agreements`. The first admin is the cell's own first admin,
    /// enrolled or invited, or else a new random account, which the
    /// first-admin invitation then invites (ADR-026 record of lane L12).
    /// The first admin's account is returned.
    ///
    /// # Errors
    ///
    /// [`CellError::Keys`] when no random value is available, and
    /// [`CellError::Store`] when the gate or the engine refuses, for
    /// example on a ledger that holds a tenant part.
    pub async fn provision_tenant(
        &self,
        agreements: Option<fstp_engine::AgreementVersions>,
    ) -> Result<fstp_domain::id::AccountId, CellError> {
        let now = fstp_domain::time::Timestamp::from_micros((self.clock)());
        let state = self.engine.state();
        if state.engine().tenant.provisioning().is_some() {
            return Err(store_err(()));
        }
        let first_admin = match state.auth().first_admin_account(now) {
            Some(a) => a,
            None => {
                let ids = fstp_crypto::random_array::<16>().map_err(|_| CellError::Keys("ids"))?;
                fstp_domain::id::AccountId::from_raw(u128::from_be_bytes(ids))
            }
        };
        let suffix = fstp_crypto::random_array::<8>().map_err(|_| CellError::Keys("ids"))?;
        let admitted = gate::admit_tenant_provisioning(
            &state,
            first_admin,
            agreements,
            self.deployment(),
            fstp_cell_core::system_command_id(suffix),
            now,
        )
        .map_err(store_err)?;
        self.engine.execute(admitted).await.map_err(store_err)?;
        Ok(first_admin)
    }

    /// [`RunningCell::issue_first_admin_invitation`], with the first
    /// admin's login email `email`, if any (`fstp-cell first-admin
    /// --email`, ADR-026 "First admin email", decided by Daniel on
    /// 2026-11-21).
    ///
    /// The invited account is the tenant part's first admin when the
    /// ledger holds one, else a new random account. The address is bound
    /// to that account in the login email index before the invitation is
    /// recorded: sealed and fingerprinted under the `Lookup` key, as every
    /// login email is. The routes give an address of an account that never
    /// enrolled no magic link and no recovery (ADR-026 record of lane
    /// L12), so the address alone opens nothing before the enrolment.
    ///
    /// # Errors
    ///
    /// As [`RunningCell::issue_first_admin_invitation`]. A cell with an
    /// open first-admin invitation or an enrolled first admin, and an
    /// address that is another account's login email, are refused before
    /// anything is recorded.
    pub async fn first_admin_invitation(
        &self,
        email: Option<&str>,
    ) -> Result<FirstAdminToken, CellError> {
        use fstp_auth::ceremony::{split_token_digest, token_digest};
        use fstp_auth::codec::Token;
        let rnd = || fstp_crypto::random_array::<32>().map_err(|_| CellError::Keys("token"));
        let first = rnd()?;
        let second = rnd()?;
        let ids = fstp_crypto::random_array::<16>().map_err(|_| CellError::Keys("ids"))?;
        let invitation = fstp_crypto::random_array::<16>().map_err(|_| CellError::Keys("ids"))?;
        let suffix = fstp_crypto::random_array::<8>().map_err(|_| CellError::Keys("ids"))?;
        let state = self.engine.state();
        let account = match state.engine().tenant.provisioning() {
            Some(p) => p.first_admin,
            None => fstp_domain::id::AccountId::from_raw(u128::from_be_bytes(ids)),
        };
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
        if let Some(email) = email {
            // The provisioning rule of the decider, checked before the
            // address is bound, so a refused invitation binds nothing.
            if state.auth().any_first_admin() || state.auth().first_admin_invitation_open(now) {
                return Err(store_err(()));
            }
            match self
                .erasure
                .set_login_email(account, email.to_owned())
                .await?
            {
                crate::tasks::erasure::LoginEmailSet::Set => {}
                crate::tasks::erasure::LoginEmailSet::Taken => {
                    return Err(CellError::Config(crate::config::ConfigError::Invalid(
                        "email",
                    )));
                }
            }
        }
        let admitted = gate::admit_first_admin_invitation(
            &state,
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

    /// Records the checks runner's `RecordChecks` of `request` (M5 design
    /// section 4.2, R-PR-02, I-32) as the system task
    /// `fstp_cell_core::SystemTask::PaymentPort`. The gate admits only
    /// `RecordChecks` under this task, and the domain decides it with
    /// every guard of its row.
    ///
    /// Since lane `m10/checks-runner` the production cell records these
    /// runs itself (`crate::tasks::checks`, ADR-026). A test world, whose
    /// start options set no forge client, still calls this in process, as
    /// it plays the contract port ([`RunningCell::contract_fact`]).
    ///
    /// # Errors
    ///
    /// [`CellError::Keys`] when no random value is available, and
    /// [`CellError::Store`] when the gate or the engine refuses.
    pub async fn payment_checks(
        &self,
        request: fstp_domain::id::RequestId,
        phase: fstp_domain::payment::CheckPhase,
        results: Vec<fstp_domain::payment::CheckResult>,
        snapshot: fstp_domain::id::ContentDigest,
    ) -> Result<(), CellError> {
        let suffix = fstp_crypto::random_array::<8>().map_err(|_| CellError::Keys("ids"))?;
        let now = fstp_domain::time::Timestamp::from_micros((self.clock)());
        let action = gate::Action::Command(fstp_cell_core::CellCommand::Engine(
            fstp_engine::Command::Core(fstp_domain::Command::RecordChecks {
                request,
                phase,
                results,
                snapshot,
            }),
        ));
        let admitted = gate::admit_system(
            &self.engine.state(),
            action,
            fstp_cell_core::SystemTask::PaymentPort,
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

/// The compiled journey UI a cell mounts, as `fstp_web` takes it.
pub use fstp_web::{AssetSet as WebAssets, load_dir as load_web_assets};

/// A one-module stub of the journey UI, for a test cell that drives the
/// API core and needs no browser UI (ADR-026). Its shell loads one empty
/// module.
///
/// # Errors
///
/// The asset set's refusal, which a fixed set never meets.
pub fn stub_web_assets() -> Result<WebAssets, fstp_web::AssetError> {
    WebAssets::from_files("main.js", &[("main.js", b"export {};\n".as_slice())])
}
