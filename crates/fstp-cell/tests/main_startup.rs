//! Start-up of a cell: configuration decode, keys, ledger replay, chain
//! verification against the witness, then the listeners (M3 design
//! sections 2.3, 3.4, 5.5, 7.2 "Start-up", 10.2 and 10.3; I-24, I-38,
//! I-39, I-80).
//!
//! Lane W3a (agent two, test author) wrote these tests before `main` and
//! the start-up path. Each test starts a cell through [`start_cell`] or
//! decodes a configuration through [`decode_config`]. Both seams refuse
//! with `NotImplemented` until the start-up path exists, so each test is
//! red for that reason only. The production agent replaces the seam
//! bodies with calls into `fstp_cell` and leaves the assertions alone.
//!
//! [`start_cell`] runs the start-up path over in-memory parts: a
//! `MemStore` ledger, a scripted vault, a custody simulator, a scripted
//! witness and, for a self-hosted cell, scripted CrabNebula services. It
//! reports each start-up phase as it completes, in order.
//!
//! The design fixes these orders:
//!
//! - Section 3.4: the cell unwraps its current seal key `S(e)` through
//!   custody, then opens its group secrets. The ledger is sealed under
//!   those keys (section 5.3 step 4), so both come before the replay.
//! - Section 5.5: the engine replays the ledger at start.
//! - Section 7.2: the cell verifies its chain against the witness before
//!   it serves requests, and resolves any in-doubt prepare first.
//! - Section 10.2: neither cell start nor any request waits for the
//!   licence refresh.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fstp_audit::anchor::AnchorRow;
use fstp_audit::anchorer::{CommitOutcome, WitnessFault};
use fstp_audit::witness::WitnessRecord;
use fstp_audit::{CellId, ChainId, CompositeSigningKey, Link};
use fstp_cell::config::{ConfigError, Mode};
use fstp_cell::egress::{CnFault, CnTransport};
use fstp_cell::engine::startup::{
    APPLICATION_MARKER, ClusterRole, DatabaseView, ListenerKind, StartParts, StartPhase,
    StartRefusal as ProdRefusal,
};
use fstp_cell::engine::{CellEngine, VaultClient};
use fstp_cell::tasks::erasure::ErasureRunner;
use fstp_cell::witness::store::{
    AnchoredStore, ChainRead, Database, MemDatabase, StoreKeys, Tables, Transaction,
};
use fstp_cell::witness::{WitnessClient, WitnessLink, WitnessMessage, WitnessReply};
use fstp_cell_core::driver::VaultFault;
use fstp_cell_core::gate::{self, Action, Admitted};
use fstp_cell_core::{CellCommand, CellState, KeyCommand, SystemTask, system_command_id};
use fstp_crypto::{aead, composite};
use fstp_custody::{
    Aad, BackendId, Custody, CustodyError, CustodyHandle, DestroyReceipt, EcdsaSignature, Refusal,
    RootLabel, RootRef, SealKey, SignKeyRef, UsageCursor, UsagePage, WrappedSealKey,
};
use fstp_domain::id::VaultEpoch;
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::time::Timestamp;
use fstp_keys::envelope::DataKey;
use fstp_ledger::{Seq, StoreError};
use fstp_rt::Shutdown;
use fstp_rt::tokio::TokioRuntime;
use fstp_witness::{ChainWitness, Sender, sign_receipt};

/// A listener of the cell (design section 2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Listener {
    /// The tunnel port from the edge.
    Tunnel,
    /// The internal mTLS port for the vault.
    Internal,
    /// The loopback health port.
    Health,
}

/// A start-up phase, reported when it completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// The configuration decoded.
    ConfigDecoded,
    /// `S(e)` of the App chain was unwrapped through custody.
    SealKeyUnwrapped,
    /// The group secrets were opened under `S(e)`.
    GroupSecretsOpened,
    /// The ledger was replayed into `CellState`.
    LedgerReplayed,
    /// An in-doubt prepare was resolved: its row exists, so it committed.
    InDoubtCommitted,
    /// An in-doubt prepare was resolved: its row is missing, so the cell
    /// sent `InDoubtAbsent` and the witness recorded it.
    InDoubtAbsentRecorded,
    /// `PossibleDeletion` was raised to tenant admins and the auditor
    /// view.
    PossibleDeletionRaised,
    /// The chain verified against the witness.
    ChainVerified,
    /// A listener was bound and accepts connections.
    Listening(Listener),
    /// A licence refresh completed (self-hosted only).
    LicenceRefreshed,
    /// `LogEvent::Started` was logged.
    Started,
}

/// Why start-up stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StartRefusal {
    /// The chain did not verify against the witness.
    ChainTamper,
    /// Custody could not unwrap the seal key.
    Custody,
    /// Any other cause.
    #[allow(
        dead_code,
        reason = "only the seam builds it, once the production path exists"
    )]
    Other,
}

/// A fault in one of the in-memory parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// Every part behaves.
    None,
    /// One committed row of the ledger was changed after its receipt.
    ChainTampered,
    /// The witness holds a prepare for the head's successor whose commit
    /// outcome is unknown. `present` says whether the row exists.
    InDoubt {
        /// Whether row `n` with the prepared link exists.
        present: bool,
    },
    /// Custody refuses every unwrap.
    CustodyUnavailable,
    /// The CrabNebula licence and update services accept the connection
    /// and never answer.
    CrabNebulaHangs,
}

/// What a start-up did.
#[derive(Debug)]
struct Trace {
    phases: Vec<Phase>,
    outcome: Result<(), StartRefusal>,
}

/// The cell of these tests.
const CELL: [u8; 16] = [0x3C; 16];
/// The SPKI digest of the pinned witness CA.
const WITNESS_CA: [u8; 32] = [0x11; 32];
/// The licence of the self-hosted cell.
const LICENCE_HEX: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The configuration of a cell in `mode`.
fn config_bytes(mode: Mode, intermediary: bool) -> Vec<u8> {
    let mut members = vec![
        format!("\"cell\":\"{}\"", hex(&CELL)),
        "\"version\":\"0.3.0\"".to_owned(),
    ];
    match mode {
        Mode::Saas => members.push("\"mode\":\"saas\"".to_owned()),
        Mode::SelfHosted => {
            members.push("\"mode\":\"self_hosted\"".to_owned());
            members.push(format!("\"licence\":\"{LICENCE_HEX}\""));
        }
    }
    if intermediary {
        members.push("\"eudi_relying_party\":\"intermediary\"".to_owned());
    }
    format!("{{{}}}", members.join(",")).into_bytes()
}

/// An in-memory custody backend: roots never leave it.
#[derive(Default)]
struct SimCustody {
    roots: Mutex<BTreeMap<Vec<u8>, [u8; 32]>>,
    next: Mutex<u64>,
    refuse_unwrap: AtomicBool,
}

#[derive(Clone, Default)]
struct Custodian(Arc<SimCustody>);

impl Custody for Custodian {
    fn create_root(
        &self,
        label: RootLabel,
    ) -> impl Future<Output = Result<RootRef, CustodyError>> + Send {
        let mut key = [0u8; 32];
        let r = fstp_crypto::random_bytes(&mut key).map_err(CustodyError::Crypto);
        let handle = {
            let mut n = lock(&self.0.next);
            *n += 1;
            n.to_be_bytes().to_vec()
        };
        lock(&self.0.roots).insert(handle.clone(), key);
        std::future::ready(r.map(|()| RootRef {
            backend: BackendId::Simulator,
            cell: label.cell,
            chain: label.chain,
            epoch: label.epoch,
            handle: CustodyHandle(handle),
        }))
    }

    fn wrap(
        &self,
        root: &RootRef,
        key: &SealKey,
        aad: &Aad,
    ) -> impl Future<Output = Result<WrappedSealKey, CustodyError>> + Send {
        let r = (|| {
            let rk = *lock(&self.0.roots)
                .get(&root.handle.0)
                .ok_or(CustodyError::Refused(Refusal::UnknownRoot))?;
            let k = aead::Key::from_bytes(&rk).map_err(CustodyError::Crypto)?;
            let s = aead::seal(&k, &aad.0, key.expose()).map_err(CustodyError::Crypto)?;
            let mut out = s.nonce.to_vec();
            out.extend_from_slice(&s.body);
            Ok(WrappedSealKey(out))
        })();
        std::future::ready(r)
    }

    fn unwrap(
        &self,
        root: &RootRef,
        w: &WrappedSealKey,
        aad: &Aad,
    ) -> impl Future<Output = Result<SealKey, CustodyError>> + Send {
        let r = (|| {
            if self.0.refuse_unwrap.load(Ordering::Acquire) {
                return Err(CustodyError::Transport("custody unavailable"));
            }
            let rk = *lock(&self.0.roots)
                .get(&root.handle.0)
                .ok_or(CustodyError::Refused(Refusal::UnknownRoot))?;
            let k = aead::Key::from_bytes(&rk).map_err(CustodyError::Crypto)?;
            let (nonce, body) = w.0.split_at(aead::NONCE_LEN);
            let nonce: [u8; aead::NONCE_LEN] = nonce.try_into().unwrap();
            let pt = aead::open(&k, &nonce, &aad.0, body)
                .map_err(|_| CustodyError::Refused(Refusal::UnwrapFailed))?;
            let bytes: [u8; 32] = pt.as_slice().try_into().unwrap();
            Ok(SealKey::from_bytes(bytes))
        })();
        std::future::ready(r)
    }

    fn destroy(
        &self,
        root: &RootRef,
    ) -> impl Future<Output = Result<DestroyReceipt, CustodyError>> + Send {
        let gone = lock(&self.0.roots).remove(&root.handle.0).is_some();
        std::future::ready(if gone {
            Ok(DestroyReceipt(root.handle.0.clone()))
        } else {
            Err(CustodyError::Refused(Refusal::UnknownRoot))
        })
    }

    fn sign(
        &self,
        _key: &SignKeyRef,
        _digest: &[u8; 32],
    ) -> impl Future<Output = Result<EcdsaSignature, CustodyError>> + Send {
        std::future::ready(Err(CustodyError::Refused(Refusal::NoSignKey)))
    }

    fn usage_since(
        &self,
        _root: &RootRef,
        _cursor: UsageCursor,
    ) -> impl Future<Output = Result<UsagePage, CustodyError>> + Send {
        std::future::ready(Ok(UsagePage::default()))
    }
}

/// A vault at the genesis epoch: key commands ask no query.
struct GenesisVault;

impl VaultClient for GenesisVault {
    fn epoch(&self) -> impl Future<Output = Result<VaultEpoch, VaultFault>> + Send {
        std::future::ready(Ok(VaultEpoch::GENESIS))
    }

    fn ask(
        &self,
        _queries: &[Query],
        _reaction_for: Option<VaultEpoch>,
        _at: Timestamp,
    ) -> impl Future<Output = Result<Answers, VaultFault>> + Send {
        std::future::ready(Err(VaultFault::Unavailable))
    }

    fn ack(
        &self,
        _epoch: VaultEpoch,
        _seq: Seq,
        _link: [u8; 32],
    ) -> impl Future<Output = Result<(), VaultFault>> + Send {
        std::future::ready(Ok(()))
    }
}

/// The scripted witness: the witness core of `fstp-witness`, with its log.
struct WitnessPeer {
    core: Mutex<ChainWitness>,
    key: CompositeSigningKey,
    log: Mutex<Vec<WitnessRecord>>,
}

#[derive(Clone)]
struct Peer(Arc<WitnessPeer>);

impl WitnessLink for Peer {
    fn peer_issuer(&self) -> impl Future<Output = Result<[u8; 32], WitnessFault>> + Send {
        std::future::ready(Ok(WITNESS_CA))
    }

    fn send(
        &self,
        message: WitnessMessage,
    ) -> impl Future<Output = Result<WitnessReply, WitnessFault>> + Send {
        let sender = Sender::writer(CellId(CELL), ChainId::App);
        let mut core = lock(&self.0.core);
        let reply = match message {
            WitnessMessage::Prepare(p) => match core.prepare(sender, &p, p.anchor.at) {
                Err(_) => WitnessReply::Refused,
                Ok(fields) => {
                    match sign_receipt(&self.0.key, CellId(CELL), ChainId::App, &fields) {
                        Err(_) => WitnessReply::Refused,
                        Ok(receipt) => {
                            lock(&self.0.log).push(WitnessRecord::Prepare(AnchorRow {
                                anchor: p.anchor.clone(),
                                receipt: receipt.clone(),
                            }));
                            WitnessReply::Receipt(receipt)
                        }
                    }
                }
            },
            WitnessMessage::Abort { n, link } => match core.abort(sender, n, &link) {
                Ok(_) => {
                    lock(&self.0.log).push(WitnessRecord::Abort { n, link });
                    WitnessReply::Recorded
                }
                Err(_) => WitnessReply::UnknownPrepare,
            },
            WitnessMessage::InDoubtAbsent { n, link } => {
                match core.in_doubt_absent(sender, n, &link) {
                    Ok(_) => {
                        lock(&self.0.log).push(WitnessRecord::InDoubtAbsent { n, link });
                        WitnessReply::Recorded
                    }
                    Err(_) => WitnessReply::UnknownPrepare,
                }
            }
        };
        std::future::ready(Ok(reply))
    }

    fn outstanding(
        &self,
        _cell: CellId,
        _chain: ChainId,
    ) -> impl Future<Output = Result<Option<(u64, Link)>, WitnessFault>> + Send {
        std::future::ready(Ok(lock(&self.0.core).state().outstanding))
    }

    fn log(
        &self,
        _cell: CellId,
        _chain: ChainId,
    ) -> impl Future<Output = Result<Vec<WitnessRecord>, WitnessFault>> + Send {
        std::future::ready(Ok(lock(&self.0.log).clone()))
    }
}

/// The cell database, with the next COMMIT's outcome and a tampered read.
struct Db {
    inner: MemDatabase,
    next_unknown: Option<bool>,
    tamper: bool,
}

impl Database for Db {
    fn tables(&self) -> &Tables {
        self.inner.tables()
    }

    fn commit(&mut self, tx: Transaction) -> impl Future<Output = CommitOutcome> + Send {
        let outcome = match self.next_unknown.take() {
            Some(committed) => {
                if committed {
                    let _ = self.inner.apply(tx);
                }
                CommitOutcome::Unknown
            }
            None => self.inner.apply(tx),
        };
        std::future::ready(outcome)
    }

    fn raise_possible_deletion(
        &mut self,
        head: (u64, Link),
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.inner.raise_possible_deletion(head)
    }

    fn read_chain(&self) -> ChainRead {
        let mut c = self.inner.read_chain();
        if self.tamper
            && let Some(b) = c.stored.first_mut().and_then(|e| e.body.last_mut())
        {
            *b ^= 1;
        }
        c
    }
}

/// A CrabNebula service that accepts and never answers.
struct Hangs;

impl CnTransport for Hangs {
    fn exchange(
        &self,
        _host: &'static str,
        _request: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, CnFault>> + Send {
        std::future::pending()
    }
}

fn phase_of(p: StartPhase) -> Phase {
    match p {
        StartPhase::ConfigDecoded => Phase::ConfigDecoded,
        StartPhase::SealKeyUnwrapped => Phase::SealKeyUnwrapped,
        StartPhase::GroupSecretsOpened => Phase::GroupSecretsOpened,
        StartPhase::InDoubtCommitted => Phase::InDoubtCommitted,
        StartPhase::PossibleDeletionRaised => Phase::PossibleDeletionRaised,
        StartPhase::InDoubtAbsentRecorded => Phase::InDoubtAbsentRecorded,
        StartPhase::LedgerReplayed => Phase::LedgerReplayed,
        StartPhase::ChainVerified => Phase::ChainVerified,
        StartPhase::Listening(ListenerKind::Tunnel) => Phase::Listening(Listener::Tunnel),
        StartPhase::Listening(ListenerKind::Internal) => Phase::Listening(Listener::Internal),
        StartPhase::Listening(ListenerKind::Health) => Phase::Listening(Listener::Health),
        StartPhase::Started => Phase::Started,
    }
}

fn key_command(n: u8) -> Admitted {
    let s = CellState::genesis();
    gate::admit_system(
        &s,
        Action::Command(CellCommand::Key(KeyCommand::RecordKeyOp {
            op: format!("{{\"n\":{n}}}").into_bytes(),
        })),
        SystemTask::ErasureRunner,
        system_command_id([b's', b't', b'a', b'r', b't', b'-', b'0', n]),
        Timestamp::from_micros(1_800_000_000_000_000),
    )
    .unwrap()
}

/// Seam: runs the start-up path of a cell in `mode` over in-memory parts
/// with `fault`, records each phase as it completes, and stops at
/// `LogEvent::Started` or at the first refusal. The ledger holds two
/// committed entries, each with its receipt, before the start.
fn start_cell(mode: Mode, fault: Fault) -> Result<Trace, &'static str> {
    let rt = TokioRuntime::new_multi_thread(2).map_err(|_| "no runtime")?;
    let rt2 = rt.clone();
    rt.block_on(async move {
        let peer = Peer(Arc::new(WitnessPeer {
            core: Mutex::new(ChainWitness::genesis(CellId(CELL), ChainId::App)),
            key: composite::generate().map_err(|_| "no witness key")?,
            log: Mutex::new(Vec::new()),
        }));
        let witness_key = vec![peer.0.key.public_key().to_bytes().to_vec()];
        let client =
            |p: &Peer| WitnessClient::new(p.clone(), CellId(CELL), ChainId::App, WITNESS_CA);
        let custody = Custodian::default();
        let keys = StoreKeys {
            anchor: composite::generate().map_err(|_| "no anchor key")?,
            ledger: DataKey::generate().map_err(|_| "no ledger key")?,
        };
        // Before the start: genesis of the key chain, whose two custody
        // calls are the two committed entries, each with its receipt.
        let db = Db {
            inner: MemDatabase::new(),
            next_unknown: None,
            tamper: false,
        };
        let mut store = AnchoredStore::new(db, client(&peer), CELL, keys);
        store
            .start()
            .await
            .map_err(|_| "the witness did not answer")?;
        let shutdown = Shutdown::new();
        let (engine, task) = CellEngine::start(&rt2, store, GenesisVault, &shutdown, 8)
            .await
            .map_err(|_| "the setup engine did not start")?;
        let mut runner = ErasureRunner::genesis(custody.clone(), engine.clone(), CELL)
            .await
            .map_err(|_| "the key chain did not start")?;
        runner.add_group([0x47; 16]).map_err(|_| "no group")?;
        let keystore = runner.keystore().clone();
        drop(runner);
        if engine.state().head().raw() != 2 {
            return Err("the setup did not commit two entries");
        }
        drop(engine);
        let mut store = task.await.map_err(|_| "the setup engine failed")?;
        if let Fault::InDoubt { present } = fault {
            // A third append whose COMMIT outcome is lost: the witness
            // holds its prepare, and the row exists only if `present`.
            let (mut db, w, keys) = store.into_parts();
            db.next_unknown = Some(present);
            store = AnchoredStore::new(db, w, CELL, keys);
            let shutdown = Shutdown::new();
            let (engine, task) = CellEngine::start(&rt2, store, GenesisVault, &shutdown, 8)
                .await
                .map_err(|_| "the setup engine did not start again")?;
            let _ = engine.execute(key_command(3)).await;
            drop(engine);
            store = task.await.map_err(|_| "the setup engine failed")?;
        }
        let (mut db, _, keys) = store.into_parts();
        db.tamper = fault == Fault::ChainTampered;
        if fault == Fault::CustodyUnavailable {
            custody.0.refuse_unwrap.store(true, Ordering::Release);
        }
        let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
        let parts = StartParts {
            config: config_bytes(mode, false),
            database: DatabaseView {
                marker: APPLICATION_MARKER,
                server_ou: ClusterRole::Application,
                registered_spki: ClusterRole::Application,
            },
            custody,
            keystore,
            db,
            witness: client(&peer),
            keys,
            witness_keys: witness_key,
            vault: GenesisVault,
            crabnebula: (mode == Mode::SelfHosted).then_some(Hangs),
            licence: None,
            listen: [
                (ListenerKind::Tunnel, loopback),
                (ListenerKind::Internal, loopback),
                (ListenerKind::Health, loopback),
            ],
        };
        let mut phases = Vec::new();
        let outcome = {
            let mut report = |p: StartPhase| phases.push(phase_of(p));
            fstp_cell::engine::startup::start(&rt2, parts, &mut report).await
        };
        let outcome = match outcome {
            Ok(cell) => {
                cell.shutdown.trigger();
                drop(cell);
                Ok(())
            }
            Err(ProdRefusal::ChainTamper) => Err(StartRefusal::ChainTamper),
            Err(ProdRefusal::Custody) => Err(StartRefusal::Custody),
            Err(_) => Err(StartRefusal::Other),
        };
        Ok(Trace { phases, outcome })
    })
}

/// Seam: writes a configuration of `shape` in the cell's configuration
/// format, with every other member valid, and decodes it with the cell's
/// decoder.
fn decode_config(shape: ConfigShape) -> Result<Result<Mode, ConfigRefusal>, &'static str> {
    Ok(
        match fstp_cell::config::decode(&config_bytes(shape.mode, shape.intermediary)) {
            Ok(c) => Ok(c.mode),
            Err(ConfigError::IntermediaryWhenSelfHosted) => {
                Err(ConfigRefusal::IntermediaryWhenSelfHosted)
            }
            Err(_) => Err(ConfigRefusal::Other),
        },
    )
}

/// What a configuration says, as far as these tests need.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConfigShape {
    mode: Mode,
    /// P-45 intermediary mode (`eudi-wallet.md`).
    intermediary: bool,
}

/// Why a configuration was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfigRefusal {
    /// A self-hosted build refuses P-45 intermediary mode.
    IntermediaryWhenSelfHosted,
    /// Any other cause.
    #[allow(
        dead_code,
        reason = "only the seam builds it, once the production path exists"
    )]
    Other,
}

fn position(t: &Trace, p: Phase) -> Option<usize> {
    t.phases.iter().position(|q| *q == p)
}

fn first_listener(t: &Trace) -> Option<usize> {
    t.phases
        .iter()
        .position(|q| matches!(q, Phase::Listening(_)))
}

/// Whether the phases `want` occur in `t`, each after the one before.
fn in_order(t: &Trace, want: &[Phase]) -> bool {
    let mut from = 0;
    for p in want {
        match t.phases[from..].iter().position(|q| q == p) {
            Some(i) => from += i + 1,
            None => return false,
        }
    }
    true
}

/// I-24, design section 7.2 ("Start-up"): the cell resolves an in-doubt
/// prepare and verifies its chain against the witness before any listener
/// accepts a connection.
#[test]
fn i24_cell_resolves_in_doubt_and_verifies_its_chain_before_any_listener() {
    let t =
        start_cell(Mode::Saas, Fault::InDoubt { present: true }).unwrap_or_else(|e| panic!("{e}"));
    let resolved = position(&t, Phase::InDoubtCommitted);
    let verified = position(&t, Phase::ChainVerified);
    let listening = first_listener(&t);
    let ok = t.outcome.is_ok()
        && matches!((resolved, verified, listening), (Some(r), Some(v), Some(l)) if r < v && v < l)
        && t.phases.last() == Some(&Phase::Started);
    assert!(ok, "{t:?}");
}

/// I-24, design section 7.2 ("In doubt"): a prepared link whose row is
/// missing at start is recorded as `InDoubtAbsent` at the witness and
/// raised as `PossibleDeletion`, both before the chain is verified. That
/// alert is the detection, so the cell then serves.
#[test]
fn i24_cell_start_raises_possible_deletion_for_a_missing_in_doubt_row() {
    let t =
        start_cell(Mode::Saas, Fault::InDoubt { present: false }).unwrap_or_else(|e| panic!("{e}"));
    let ok = t.outcome.is_ok()
        && in_order(
            &t,
            &[
                Phase::InDoubtAbsentRecorded,
                Phase::PossibleDeletionRaised,
                Phase::ChainVerified,
                Phase::Started,
            ],
        )
        && position(&t, Phase::InDoubtCommitted).is_none();
    assert!(ok, "{t:?}");
}

/// I-24, design section 7.2: a chain that fails verification against the
/// witness keeps the cell from serving. No listener is bound and
/// `Started` is never logged.
#[test]
fn i24_cell_refuses_to_serve_when_its_chain_fails_verification() {
    let t = start_cell(Mode::Saas, Fault::ChainTampered).unwrap_or_else(|e| panic!("{e}"));
    let ok = t.outcome == Err(StartRefusal::ChainTamper)
        && first_listener(&t).is_none()
        && position(&t, Phase::Started).is_none()
        && position(&t, Phase::ChainVerified).is_none();
    assert!(ok, "{t:?}");
}

/// I-80, design section 3.4: the cell unwraps its seal key through
/// custody and opens its group secrets before it replays the ledger,
/// which is sealed under them. Start-up then reaches every listener.
#[test]
fn i80_cell_unwraps_its_seal_key_through_custody_before_it_replays_the_ledger() {
    let t = start_cell(Mode::Saas, Fault::None).unwrap_or_else(|e| panic!("{e}"));
    let ok = t.outcome.is_ok()
        && in_order(
            &t,
            &[
                Phase::ConfigDecoded,
                Phase::SealKeyUnwrapped,
                Phase::GroupSecretsOpened,
                Phase::LedgerReplayed,
                Phase::ChainVerified,
            ],
        )
        && [Listener::Tunnel, Listener::Internal, Listener::Health]
            .iter()
            .all(|l| position(&t, Phase::Listening(*l)).is_some())
        && t.phases.last() == Some(&Phase::Started);
    assert!(ok, "{t:?}");
}

/// I-80, design section 3.4: without custody the cell cannot unwrap its
/// seal key, so it never reads the ledger and never serves.
#[test]
fn i80_cell_refuses_to_start_without_custody() {
    let t = start_cell(Mode::Saas, Fault::CustodyUnavailable).unwrap_or_else(|e| panic!("{e}"));
    let ok = t.outcome == Err(StartRefusal::Custody)
        && position(&t, Phase::LedgerReplayed).is_none()
        && first_listener(&t).is_none()
        && position(&t, Phase::Started).is_none();
    assert!(ok, "{t:?}");
}

/// I-39, design section 10.2: a self-hosted cell starts and serves while
/// the CrabNebula services never answer. No licence refresh comes before
/// `Started`.
#[test]
fn i39_cell_start_never_waits_for_the_licence_service() {
    let t = start_cell(Mode::SelfHosted, Fault::CrabNebulaHangs).unwrap_or_else(|e| panic!("{e}"));
    let ok = t.outcome.is_ok()
        && t.phases.last() == Some(&Phase::Started)
        && position(&t, Phase::LicenceRefreshed).is_none();
    assert!(ok, "{t:?}");
}

/// I-38, design section 10.3 (`eudi-wallet.md`): a self-hosted build
/// refuses P-45 intermediary mode at configuration decode.
#[test]
fn i38_cell_config_decode_refuses_intermediary_mode_when_self_hosted() {
    let got = decode_config(ConfigShape {
        mode: Mode::SelfHosted,
        intermediary: true,
    })
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got, Err(ConfigRefusal::IntermediaryWhenSelfHosted));
}

/// Design sections 1.2 and 10.3: a valid self-hosted configuration
/// without intermediary mode decodes, so the refusal above is about
/// intermediary mode and nothing else.
#[test]
fn i38_cell_config_decode_accepts_a_self_hosted_cell_without_intermediary_mode() {
    let got = decode_config(ConfigShape {
        mode: Mode::SelfHosted,
        intermediary: false,
    })
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got, Ok(Mode::SelfHosted));
}

/// The order helper itself: it needs every phase, each after the one
/// before. This checks the predicate the tests above rest on.
#[test]
fn i24_in_order_predicate_needs_each_phase_after_the_one_before() {
    let t = Trace {
        phases: vec![
            Phase::ChainVerified,
            Phase::InDoubtCommitted,
            Phase::Started,
        ],
        outcome: Ok(()),
    };
    let ok = in_order(&t, &[Phase::ChainVerified, Phase::Started])
        && !in_order(&t, &[Phase::InDoubtCommitted, Phase::ChainVerified])
        && !in_order(&t, &[Phase::LedgerReplayed]);
    assert!(ok, "the order predicate is wrong");
}
