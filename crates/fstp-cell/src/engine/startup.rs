//! The start-up path of a cell (design sections 3.4, 5.5, 7.2
//! "Start-up", 10.2; I-24, I-39, I-80).
//!
//! [`start`] runs it over the in-memory anchoring store, and [`start_pg`]
//! over the PostgreSQL record store ([`PgCellStore`], design section 5.3).
//! Both run the phases below in the same order ([`StartStore`]).
//!
//! The order:
//!
//! 1. The configuration decodes ([`crate::config::decode`]), and the
//!    database passes the I-83 placement check ([`accepts_database`]).
//!    That check runs on [`start_pg`] only, over the [`DatabaseView`]
//!    that `crate::process::check_database` read from a live connection.
//!    The in-memory store of [`start`] is on no cluster.
//! 2. The current seal key `S(e)` of the App chain is unwrapped through
//!    custody, then the group secrets are opened under it (I-80). The
//!    ledger is sealed under those keys, so both come first.
//! 3. The witness reports its open prepare, if any, and the cell resolves
//!    it from its chain: a present row committed, and a missing one is
//!    recorded as `InDoubtAbsent` at the witness (I-24). The cell then
//!    raises `PossibleDeletion` to tenant admins and the auditor view for
//!    every `InDoubtAbsent` record the witness log holds, before the chain
//!    is verified (design section 7.2 "In doubt", ADR-010). The store
//!    holds the alert durably before the witness forgets the prepare
//!    (`fstp_audit::anchorer`), and every raise is keyed by `(n, link)`.
//!    So a crash between the record and the raise loses no alert, and an
//!    alert row that was deleted is raised again at the next start.
//! 4. The engine replays the ledger (design section 5.5).
//! 5. The chain verifies against the witness log (`fstp_audit::verify`).
//!    A chain that fails keeps the cell from serving.
//! 6. The listeners bind: the tunnel port, the internal mTLS port and the
//!    loopback health port (design section 2.3).
//! 7. The system tasks start, each a participant of the cell's
//!    [`Shutdown`] (ADR-002), in every mode:
//!    - the timeline ([`crate::tasks::timeline::run`]), which issues the
//!      due system commands, such as scheduled role ends;
//!    - the erasure task ([`crate::tasks::erasure::task`]), which owns the
//!      runner and runs each batch once its request is in the ledger
//!      (design section 3.5).
//!
//!    A self-hosted cell also starts its licence refresh and update
//!    check. They run in the background, so start never waits for them
//!    (I-39). A cell without a licence token runs the update check only,
//!    until the first token is imported (design section 10.2, Q41).
//! 8. `Started` is logged.
//!
//! Each phase is reported as it completes.

use std::future::Future;
use std::net::SocketAddr;

use fstp_audit::anchorer::Resolution;
use fstp_audit::verify::ChainView;
use fstp_audit::witness::WitnessRecord;
use fstp_audit::{CellId, ChainId};
use fstp_custody::Custody;
use fstp_obs::LogEvent;
use fstp_rt::{Listener as _, Runtime, Shutdown};

use super::pg::PgCellStore;
use super::{CellEngine, CellStore, VaultClient};
use crate::config::{CellConfig, Mode};
use crate::egress::{CnClient, CnTransport};
use crate::tasks::erasure::{self, ErasureHandle, ErasureRunner, Keystore};
use crate::tasks::release::{self, LicenceHold, ReleaseSettings, ReleaseView};
use crate::tasks::{SystemClock, timeline};
use crate::witness::store::{AnchoredStore, ChainRead, Database, Resolved, StoreKeys};
use crate::witness::{WitnessClient, WitnessLink};

/// The kind of a database cluster, as the start check reads it from the
/// placement marker, the server certificate OU and the registered SPKI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClusterRole {
    /// An application cluster.
    Application,
    /// A vault cluster.
    Vault,
    /// Any other cluster, or an unknown kind.
    Other,
}

/// What the cell sees of its database at start (design section 9.2).
///
/// Its fields are private, and only `crate::process::check_database`
/// builds one: from the placement marker it reads over a live
/// connection, and the OU and SPKI registration of the server certificate
/// that connection verified. So a caller of [`start_pg`] cannot claim a
/// placement that no connection showed (I-83).
///
/// I-83: outside this crate, a view cannot be written down.
///
/// ```compile_fail
/// use fstp_cell::engine::startup::{APPLICATION_MARKER, ClusterRole, DatabaseView};
/// let _ = DatabaseView {
///     marker: APPLICATION_MARKER,
///     server_ou: ClusterRole::Application,
///     registered_spki: ClusterRole::Application,
/// };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatabaseView {
    /// `fstp_meta.placement.kind`: 1 application, 2 vault.
    marker: u8,
    /// The kind named by the server certificate's subject OU.
    server_ou: ClusterRole,
    /// The kind the server SPKI is registered for at the control plane.
    registered_spki: ClusterRole,
}

impl DatabaseView {
    /// The view of a database whose placement marker is `marker`, on a
    /// server whose certificate OU names `server_ou` and whose SPKI is
    /// registered for `registered_spki`. Only
    /// `crate::process::check_database` calls it.
    pub(crate) const fn new(
        marker: u8,
        server_ou: ClusterRole,
        registered_spki: ClusterRole,
    ) -> DatabaseView {
        DatabaseView {
            marker,
            server_ou,
            registered_spki,
        }
    }

    /// `fstp_meta.placement.kind`: 1 application, 2 vault.
    #[must_use]
    pub const fn marker(&self) -> u8 {
        self.marker
    }

    /// The kind named by the server certificate's subject OU.
    #[must_use]
    pub const fn server_ou(&self) -> ClusterRole {
        self.server_ou
    }

    /// The kind the server SPKI is registered for at the control plane.
    #[must_use]
    pub const fn registered_spki(&self) -> ClusterRole {
        self.registered_spki
    }
}

/// The placement marker of an application database (design section 4.2).
pub const APPLICATION_MARKER: u8 = 1;

/// The I-83 start check of design section 9.2: the cell accepts its
/// database only when the placement marker, the server certificate OU
/// and the registered SPKI all name an application cluster. It refuses a
/// vault cluster, and any mix.
pub fn accepts_database(db: &DatabaseView) -> bool {
    db.marker == APPLICATION_MARKER
        && db.server_ou == ClusterRole::Application
        && db.registered_spki == ClusterRole::Application
}

/// A listener of the cell (design section 2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ListenerKind {
    /// The tunnel port from the edge.
    Tunnel,
    /// The internal mTLS port for the vault.
    Internal,
    /// The loopback health port.
    Health,
}

/// A start-up phase, reported when it completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartPhase {
    /// The configuration decoded.
    ConfigDecoded,
    /// `S(e)` of the App chain was unwrapped through custody.
    SealKeyUnwrapped,
    /// The group secrets were opened under `S(e)`.
    GroupSecretsOpened,
    /// An in-doubt prepare was resolved: its row exists.
    InDoubtCommitted,
    /// `PossibleDeletion` was raised to tenant admins and the auditor view
    /// for every `InDoubtAbsent` record of the witness log.
    PossibleDeletionRaised,
    /// The witness recorded `InDoubtAbsent` for an in-doubt prepare whose
    /// row is missing.
    InDoubtAbsentRecorded,
    /// The ledger was replayed into `CellState`.
    LedgerReplayed,
    /// The chain verified against the witness.
    ChainVerified,
    /// A listener was bound and accepts connections.
    Listening(ListenerKind),
    /// `LogEvent::Started` was logged.
    Started,
}

/// Why start-up stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartRefusal {
    /// The configuration was refused.
    Config(crate::config::ConfigError),
    /// The database is not on an application cluster (I-83, design
    /// section 9.2).
    Placement,
    /// Custody could not unwrap the seal key, or a group secret did not
    /// open.
    Custody,
    /// The witness could not be reached, so no open prepare could be
    /// resolved and the chain cannot be verified.
    Witness,
    /// The pinned witness receipt keys are empty or do not decode
    /// (ADR-010 "Keys", I-90). Nothing reached the witness.
    WitnessPins,
    /// The store could not be read, or the ledger does not fold.
    Store,
    /// The chain did not verify against the witness.
    ChainTamper,
    /// A listener could not be bound.
    Listen,
    /// A key record could not be written after the replay.
    KeyRecord,
}

/// The parts a cell starts from over the in-memory anchoring store.
///
/// They carry no [`DatabaseView`]. The in-memory store is not on a
/// cluster, so it has no placement marker or server certificate to check.
/// The I-83 start check runs on [`start_pg`], the path over a cluster.
pub struct StartParts<C, D, L, V, T> {
    /// The configuration bytes.
    pub config: Vec<u8>,
    /// The App chain's custody backend.
    pub custody: C,
    /// The App chain's keystore.
    pub keystore: Keystore,
    /// The cell database.
    pub db: D,
    /// The witness client of the App chain.
    pub witness: WitnessClient<L>,
    /// The anchor and ledger keys of the store, and the pinned witness
    /// receipt keys. The store checks each new receipt under those pins
    /// before COMMIT, and the start-up verification checks every stored
    /// receipt under the same set (ADR-010 "Keys", I-24).
    pub keys: StoreKeys,
    /// The vault client.
    pub vault: V,
    /// The transport to the CrabNebula services of a self-hosted cell.
    pub crabnebula: Option<T>,
    /// The licence token a self-hosted cell holds.
    pub licence: Option<LicenceHold>,
    /// Where to bind each listener. Port 0 picks a free port.
    pub listen: [(ListenerKind, SocketAddr); 3],
}

/// The parts a cell starts from over its PostgreSQL database (design
/// section 5.3): the parts of [`StartParts`], with the record store in
/// place of the database, the witness client and the store keys.
pub struct PgStartParts<C, R: Runtime, L, V, T> {
    /// The configuration bytes.
    pub config: Vec<u8>,
    /// What the cell reads of its database before it uses it (I-83).
    /// Only `crate::process::check_database` builds one, from a live
    /// connection to the database.
    pub database: DatabaseView,
    /// The App chain's custody backend.
    pub custody: C,
    /// The App chain's keystore.
    pub keystore: Keystore,
    /// The record store over the cell database's writer role, with its
    /// ledger keys, anchor signer, pinned witness receipt keys and the
    /// witness client of the App chain. Its cell must be the configured
    /// cell.
    pub store: PgCellStore<R, WitnessClient<L>>,
    /// The App chain's composite `Anchor` public key, encoded. The
    /// start-up verification checks every stored anchor under it.
    pub anchor_key: Vec<u8>,
    /// The vault client.
    pub vault: V,
    /// The transport to the CrabNebula services of a self-hosted cell.
    pub crabnebula: Option<T>,
    /// The licence token a self-hosted cell holds.
    pub licence: Option<LicenceHold>,
    /// Where to bind each listener. Port 0 picks a free port.
    pub listen: [(ListenerKind, SocketAddr); 3],
}

/// A started cell over the store `S`.
pub struct StartedCell<R: Runtime, S> {
    /// The configuration.
    pub config: CellConfig,
    /// The engine.
    pub engine: CellEngine,
    /// The cell's shutdown. Every task joins it.
    pub shutdown: Shutdown,
    /// The bound listeners. The routes of lane W3a agent one accept on
    /// them.
    pub listeners: Vec<(ListenerKind, R::TcpListener)>,
    /// The handle on the erasure task, which owns the erasure runner.
    pub erasure: ErasureHandle,
    /// The admin view of the licence and update calls.
    pub release: ReleaseView,
    /// The engine task, which gives the store back once it ends.
    pub engine_task: fstp_rt::JoinHandle<S>,
}

/// What the start-up path needs of a cell's anchoring store, beyond the
/// engine's [`CellStore`] (ADR-010 "Start-up", design section 7.2).
pub trait StartStore: CellStore {
    /// Learns the witness's open prepare and resolves it from the chain
    /// before the cell serves: a present row committed, and a missing one
    /// raises `PossibleDeletion` and is recorded as `InDoubtAbsent`.
    fn resolve_open_prepare(
        &mut self,
    ) -> impl Future<Output = Result<Resolved, StartRefusal>> + Send;

    /// The witness log of the App chain.
    fn witness_log(&self) -> impl Future<Output = Result<Vec<WitnessRecord>, StartRefusal>> + Send;

    /// The chain as stored, for the start-up verification.
    fn stored_chain(&self) -> impl Future<Output = Result<ChainRead, StartRefusal>> + Send;

    /// The pinned witness receipt keys. The start-up verification checks
    /// every stored receipt under the set the store checks new ones with.
    fn pinned_witness_keys(&self) -> Vec<Vec<u8>>;

    /// Raises `PossibleDeletion` for each of `heads`, durably and keyed by
    /// `(n, link)`, so a head raised before changes nothing.
    fn raise_possible_deletions(
        &mut self,
        heads: &[(u64, fstp_audit::Link)],
    ) -> impl Future<Output = Result<(), StartRefusal>> + Send;
}

impl<D: Database, L: WitnessLink> StartStore for AnchoredStore<D, WitnessClient<L>> {
    async fn resolve_open_prepare(&mut self) -> Result<Resolved, StartRefusal> {
        self.start().await.map_err(|_| StartRefusal::Witness)
    }

    async fn witness_log(&self) -> Result<Vec<WitnessRecord>, StartRefusal> {
        self.witness()
            .log()
            .await
            .map_err(|_| StartRefusal::Witness)
    }

    async fn stored_chain(&self) -> Result<ChainRead, StartRefusal> {
        Ok(self.db().read_chain())
    }

    fn pinned_witness_keys(&self) -> Vec<Vec<u8>> {
        self.witness_keys().to_vec()
    }

    async fn raise_possible_deletions(
        &mut self,
        heads: &[(u64, fstp_audit::Link)],
    ) -> Result<(), StartRefusal> {
        AnchoredStore::raise_possible_deletions(self, heads)
            .await
            .map_err(|_| StartRefusal::Store)
    }
}

impl<R: Runtime, L: WitnessLink> StartStore for PgCellStore<R, WitnessClient<L>> {
    async fn resolve_open_prepare(&mut self) -> Result<Resolved, StartRefusal> {
        let open = self
            .inner()
            .witness()
            .outstanding()
            .await
            .map_err(|_| StartRefusal::Witness)?;
        let Some(head) = open else {
            return Ok(Resolved::Nothing);
        };
        match self.inner_mut().resolve_in_doubt(head).await {
            Ok(Resolution::Committed) => Ok(Resolved::Committed),
            Ok(Resolution::AbsentRaisePossibleDeletion) => Ok(Resolved::AbsentRecorded),
            Err(_) => Err(StartRefusal::Witness),
        }
    }

    async fn witness_log(&self) -> Result<Vec<WitnessRecord>, StartRefusal> {
        self.inner()
            .witness()
            .log()
            .await
            .map_err(|_| StartRefusal::Witness)
    }

    async fn stored_chain(&self) -> Result<ChainRead, StartRefusal> {
        let c = self
            .inner()
            .read_chain_rows()
            .await
            .map_err(|_| StartRefusal::Store)?;
        Ok(ChainRead {
            rows: c.rows,
            stored: c.stored,
            anchors: c.anchors,
        })
    }

    fn pinned_witness_keys(&self) -> Vec<Vec<u8>> {
        self.inner().witness_keys().to_vec()
    }

    async fn raise_possible_deletions(
        &mut self,
        heads: &[(u64, fstp_audit::Link)],
    ) -> Result<(), StartRefusal> {
        self.inner_mut()
            .raise_possible_deletions(heads)
            .await
            .map_err(|_| StartRefusal::Store)
    }
}

/// The `InDoubtAbsent` records of the witness log, as `(n, link)`, in
/// witness order. Each one is a possible deletion the cell must raise
/// (design section 7.2 "In doubt", `fstp_audit::verify` lists the same
/// set as `possible_deletions`).
fn in_doubt_absent(log: &[WitnessRecord]) -> Vec<(u64, fstp_audit::Link)> {
    log.iter()
        .filter_map(|w| match w {
            WitnessRecord::InDoubtAbsent { n, link } => Some((*n, *link)),
            WitnessRecord::Prepare(_) | WitnessRecord::Abort { .. } => None,
        })
        .collect()
}

/// The parts every start path shares, after its store parts are taken.
struct Common<C, V, T> {
    config: Vec<u8>,
    /// The checked view of a database on a cluster, or `None` for the
    /// in-memory store, which is on none.
    database: Option<DatabaseView>,
    custody: C,
    keystore: Keystore,
    vault: V,
    crabnebula: Option<T>,
    licence: Option<LicenceHold>,
    listen: [(ListenerKind, SocketAddr); 3],
}

/// Starts a cell from `parts` over the in-memory anchoring store and
/// reports each phase to `report`.
///
/// # Errors
///
/// The first [`StartRefusal`]. No listener is bound and `Started` is not
/// logged before every earlier phase completed.
pub async fn start<R, C, D, L, V, T>(
    rt: &R,
    parts: StartParts<C, D, L, V, T>,
    report: &mut (dyn FnMut(StartPhase) + Send),
) -> Result<StartedCell<R, AnchoredStore<D, WitnessClient<L>>>, StartRefusal>
where
    R: Runtime,
    C: Custody,
    D: Database,
    L: WitnessLink,
    V: VaultClient,
    T: CnTransport,
{
    let StartParts {
        config,
        custody,
        keystore,
        db,
        witness,
        keys,
        vault,
        crabnebula,
        licence,
        listen,
    } = parts;
    let anchor_key = keys.anchor.public_key().to_bytes().to_vec();
    let common = Common {
        config,
        database: None,
        custody,
        keystore,
        vault,
        crabnebula,
        licence,
        listen,
    };
    // ADR-010 "Keys", I-90: a pin set that accepts no receipt is refused
    // when the store is built, before any prepare reaches the witness.
    let open = move |cell: [u8; 16]| {
        AnchoredStore::new(db, witness, cell, keys).map_err(|_| StartRefusal::WitnessPins)
    };
    start_with(rt, common, anchor_key, open, report).await
}

/// Starts a cell from `parts` over its PostgreSQL record store
/// ([`PgCellStore`], design section 5.3) and reports each phase to
/// `report`. The phases and their order are those of [`start`].
///
/// # Errors
///
/// The first [`StartRefusal`]. A store whose cell is not the configured
/// cell is refused as a configuration that names another cell.
pub async fn start_pg<R, C, L, V, T>(
    rt: &R,
    parts: PgStartParts<C, R, L, V, T>,
    report: &mut (dyn FnMut(StartPhase) + Send),
) -> Result<StartedCell<R, PgCellStore<R, WitnessClient<L>>>, StartRefusal>
where
    R: Runtime,
    C: Custody,
    L: WitnessLink,
    V: VaultClient,
    T: CnTransport,
{
    let PgStartParts {
        config,
        database,
        custody,
        keystore,
        store,
        anchor_key,
        vault,
        crabnebula,
        licence,
        listen,
    } = parts;
    let common = Common {
        config,
        database: Some(database),
        custody,
        keystore,
        vault,
        crabnebula,
        licence,
        listen,
    };
    let open = move |cell: [u8; 16]| {
        if store.inner().cell() == cell {
            Ok(store)
        } else {
            Err(StartRefusal::Config(crate::config::ConfigError::Invalid(
                "cell",
            )))
        }
    };
    start_with(rt, common, anchor_key, open, report).await
}

/// The start-up path of [`start`] and [`start_pg`] over the store that
/// `open` gives for the configured cell.
async fn start_with<R, C, V, T, S>(
    rt: &R,
    parts: Common<C, V, T>,
    anchor_key: Vec<u8>,
    open: impl FnOnce([u8; 16]) -> Result<S, StartRefusal>,
    report: &mut (dyn FnMut(StartPhase) + Send),
) -> Result<StartedCell<R, S>, StartRefusal>
where
    R: Runtime,
    C: Custody,
    V: VaultClient,
    T: CnTransport,
    S: StartStore,
{
    let config = crate::config::decode(&parts.config).map_err(StartRefusal::Config)?;
    // The licence the refresh names: the configured one, or else the one
    // of the token held. A token for another licence than the configured
    // one is refused, so the cell never refreshes a licence it was not
    // given (design section 10.2).
    let licence = match (config.licence, parts.licence.as_ref()) {
        (Some(c), Some(h)) if c != h.token.licence => {
            return Err(StartRefusal::Config(crate::config::ConfigError::Invalid(
                "licence",
            )));
        }
        (Some(c), _) => Some(c),
        (None, h) => h.map(|h| h.token.licence),
    };
    report(StartPhase::ConfigDecoded);
    if let Some(database) = &parts.database
        && !accepts_database(database)
    {
        return Err(StartRefusal::Placement);
    }
    let seal = parts
        .keystore
        .unwrap_current(&parts.custody)
        .await
        .map_err(|_| StartRefusal::Custody)?;
    report(StartPhase::SealKeyUnwrapped);
    let groups = parts
        .keystore
        .open_groups(&seal)
        .map_err(|_| StartRefusal::Custody)?;
    report(StartPhase::GroupSecretsOpened);
    let cell = config.cell.0;
    let mut store = open(cell)?;
    let witness_keys = store.pinned_witness_keys();
    match store.resolve_open_prepare().await? {
        Resolved::Nothing => {}
        Resolved::Committed => report(StartPhase::InDoubtCommitted),
        Resolved::AbsentRecorded => report(StartPhase::InDoubtAbsentRecorded),
    }
    let log = store.witness_log().await?;
    let in_doubt = in_doubt_absent(&log);
    if !in_doubt.is_empty() {
        store.raise_possible_deletions(&in_doubt).await?;
        report(StartPhase::PossibleDeletionRaised);
    }
    let chain = store.stored_chain().await?;
    let shutdown = Shutdown::new();
    let (engine, engine_task) =
        CellEngine::start(rt, store, parts.vault, &shutdown, super::DEFAULT_QUEUE)
            .await
            .map_err(|_| StartRefusal::Store)?;
    report(StartPhase::LedgerReplayed);
    let view = ChainView {
        cell: CellId(cell),
        chain: ChainId::App,
        rows: &chain.rows,
        ledger: &chain.stored,
        anchors: &chain.anchors,
        witness: &log,
        anchor_keys: std::slice::from_ref(&anchor_key),
        witness_keys: &witness_keys,
    };
    if fstp_audit::verify::verify(&view).is_err() {
        shutdown.trigger();
        return Err(StartRefusal::ChainTamper);
    }
    report(StartPhase::ChainVerified);
    let mut listeners = Vec::with_capacity(parts.listen.len());
    for (kind, addr) in parts.listen {
        let l = rt.bind_tcp(addr).await.map_err(|_| StartRefusal::Listen)?;
        if l.local_addr().is_err() {
            return Err(StartRefusal::Listen);
        }
        listeners.push((kind, l));
        report(StartPhase::Listening(kind));
    }
    let runner =
        ErasureRunner::from_open(parts.custody, engine.clone(), parts.keystore, seal, groups)
            .await
            .map_err(|_| StartRefusal::KeyRecord)?;
    // The timeline: scheduled role ends and every other due system
    // command (design sections 5.1 and 8.2).
    {
        let signal = shutdown.signal();
        let clock = SystemClock::new(rt.clone());
        let engine = engine.clone();
        drop(rt.spawn(async move {
            timeline::run(&clock, &engine, &signal).await;
            drop(signal);
        }));
    }
    // M6 lane L6-API: the dispatcher starts only once the tenant set a mail
    // relay and the cell holds its App chain `Lookup` key
    // (`crate::tasks::dispatch::start_plan`). Seam: the cell holds no
    // `Lookup` key yet, nor the app pool and cell secret store that its
    // delivery log, outbox source and mail egress need, so none starts.
    // The erasure task (design section 3.5).
    let (erasure, erasure_task) =
        erasure::task(runner, SystemClock::new(rt.clone()), shutdown.signal());
    drop(rt.spawn(erasure_task));
    let view = ReleaseView::default();
    if let (Mode::SelfHosted, Some(transport)) = (config.mode, parts.crabnebula) {
        let client = CnClient::new(config.mode, transport);
        let settings = ReleaseSettings {
            licence,
            version: config.version,
            channel: fstp_release::egress::Channel::Stable,
        };
        let signal = shutdown.signal();
        let clock = SystemClock::new(rt.clone());
        let task_view = view.clone();
        let hold = parts.licence;
        let mode = config.mode;
        drop(rt.spawn(async move {
            release::run(&clock, &client, mode, settings, hold, &task_view, &signal).await;
        }));
    }
    let _ = fstp_obs::log_to_stderr(&LogEvent::Started);
    report(StartPhase::Started);
    Ok(StartedCell {
        config,
        engine,
        shutdown,
        listeners,
        erasure,
        release: view,
        engine_task,
    })
}
