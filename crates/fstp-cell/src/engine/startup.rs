//! The start-up path of a cell (design sections 3.4, 5.5, 7.2
//! "Start-up", 10.2; I-24, I-39, I-80).
//!
//! The order:
//!
//! 1. The configuration decodes ([`crate::config::decode`]), and the
//!    database passes the I-83 placement check ([`accepts_database`]).
//! 2. The current seal key `S(e)` of the App chain is unwrapped through
//!    custody, then the group secrets are opened under it (I-80). The
//!    ledger is sealed under those keys, so both come first.
//! 3. The witness reports its open prepare, if any, and the cell resolves
//!    it from its chain: a present row committed, a missing one raises
//!    `PossibleDeletion` and is recorded as `InDoubtAbsent` (I-24).
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

use std::net::SocketAddr;

use fstp_audit::verify::ChainView;
use fstp_audit::{CellId, ChainId};
use fstp_custody::Custody;
use fstp_obs::LogEvent;
use fstp_rt::{Listener as _, Runtime, Shutdown};

use super::{CellEngine, VaultClient};
use crate::config::{CellConfig, Mode};
use crate::egress::{CnClient, CnTransport};
use crate::tasks::erasure::{self, ErasureHandle, ErasureRunner, Keystore};
use crate::tasks::release::{self, LicenceHold, ReleaseSettings, ReleaseView};
use crate::tasks::{SystemClock, timeline};
use crate::witness::store::{AnchoredStore, Database, Resolved, StoreKeys};
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatabaseView {
    /// `fstp_meta.placement.kind`: 1 application, 2 vault.
    pub marker: u8,
    /// The kind named by the server certificate's subject OU.
    pub server_ou: ClusterRole,
    /// The kind the server SPKI is registered for at the control plane.
    pub registered_spki: ClusterRole,
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
    /// `PossibleDeletion` was raised for an in-doubt prepare whose row is
    /// missing.
    PossibleDeletionRaised,
    /// The witness recorded `InDoubtAbsent` for it.
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

/// The parts a cell starts from.
pub struct StartParts<C, D, L, V, T> {
    /// The configuration bytes.
    pub config: Vec<u8>,
    /// What the cell reads of its database before it uses it (I-83).
    pub database: DatabaseView,
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

/// A started cell.
pub struct StartedCell<R: Runtime, D, L> {
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
    pub engine_task: fstp_rt::JoinHandle<AnchoredStore<D, WitnessClient<L>>>,
}

/// Starts a cell from `parts` and reports each phase to `report`.
///
/// # Errors
///
/// The first [`StartRefusal`]. No listener is bound and `Started` is not
/// logged before every earlier phase completed.
pub async fn start<R, C, D, L, V, T>(
    rt: &R,
    parts: StartParts<C, D, L, V, T>,
    report: &mut (dyn FnMut(StartPhase) + Send),
) -> Result<StartedCell<R, D, L>, StartRefusal>
where
    R: Runtime,
    C: Custody,
    D: Database,
    L: WitnessLink,
    V: VaultClient,
    T: CnTransport,
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
    if !accepts_database(&parts.database) {
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
    let anchor_key = parts.keys.anchor.public_key().to_bytes().to_vec();
    // ADR-010 "Keys", I-90: a pin set that accepts no receipt is refused
    // here, before any prepare reaches the witness.
    let mut store = AnchoredStore::new(parts.db, parts.witness, cell, parts.keys)
        .map_err(|_| StartRefusal::WitnessPins)?;
    let witness_keys = store.witness_keys().to_vec();
    match store.start().await.map_err(|_| StartRefusal::Witness)? {
        Resolved::Nothing => {}
        Resolved::Committed => report(StartPhase::InDoubtCommitted),
        Resolved::AbsentRecorded => {
            // The anchorer core raises the alert before the witness
            // forgets the prepare (fstp_audit::anchorer, W2g reading).
            report(StartPhase::PossibleDeletionRaised);
            report(StartPhase::InDoubtAbsentRecorded);
        }
    }
    let log = store
        .witness()
        .log()
        .await
        .map_err(|_| StartRefusal::Witness)?;
    let chain = store.db().read_chain();
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
