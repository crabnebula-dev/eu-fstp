//! The witness service: its listener over mutual TLS, its PostgreSQL
//! store and its receipts (I-24, ADR-010 "Witnesses", design sections 1.3
//! and 7.2). Lane int5.
//!
//! [`serve`] runs the service on one runtime through `fstp-rt` until its
//! [`WitnessHandle`] shuts it down. [`serve_local`] runs the same service
//! for a self-hosted install over the append-only file store of
//! [`crate::file_store::FileStore`] instead of a database (lane F-SELF,
//! ADR-010 "Self-hosted witness"). Step 1 then opens and loads that store:
//!
//! 1. It connects to its database as `witness_service`, checks the
//!    placement marker (kind 4, I-83) and loads the registered cell CAs
//!    and anchor key histories.
//! 2. It binds its listener. Each connection runs a TLS 1.3 handshake
//!    that requires a client certificate from a registered cell CA. The
//!    sender is the certificate's issuing cell and its OU
//!    ([`crate::peer::sender_of`]). A connection whose certificate names
//!    no chain writer is closed before it is read.
//! 3. Each frame is one request ([`crate::wire`]). A prepare is checked
//!    under the chain's anchor key history (I-90), then run through the
//!    witness core ([`crate::ChainWitness`]) on a copy of the chain's
//!    state. A new record is stored first. Only then does the copy replace
//!    the state, and only then does the receipt leave the witness.
//! 4. On shutdown the listener closes, every connection ends after the
//!    frame it serves, and the drain waits for them.
//!
//! What is not built here, reported to Daniel and the lead:
//!
//! - The copy of each record to an object-lock bucket at a second
//!   provider (ADR-010 "Witnesses"). The provider waits on Q25.
//! - The receipt key's custody entry (ADR-010 "Keys", open point 6).
//!   [`WitnessParts::receipt_key`] is handed in by the caller.
//! - Restore declarations from the control plane (ADR-012, interim).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use fstp_audit::anchor::AnchorRow;
use fstp_audit::witness::{Prepare, RecordKind, WitnessRecord};
use fstp_audit::{CellId, ChainId, CompositeSigningKey, Link};
use fstp_pgwire::Client;
use fstp_rt::{
    DrainTimeout, IoExt as _, JoinHandle, Listener as _, Runtime, Shutdown, ShutdownSignal,
};

use crate::WitnessError;
use crate::chain_witness::{ChainWitness, Refusal, Sender, accepts_sender};
use crate::file_store::FileStore;
use crate::lock::AsyncMutex;
use crate::message::WitnessMessage;
use crate::peer::{PinnedCa, sender_of};
use crate::receipt::{check_anchor_signature, sign_receipt};
use crate::store::{self, LoadedChain, StoreError};
use crate::wire::{
    LogPage, MAX_LOG_RECORDS, WireReply, WireRequest, decode_request, encode_reply, read_frame,
    write_frame,
};

/// The placement marker of a witness database (I-83).
pub const WITNESS_MARKER: i16 = 4;

/// How long a TLS handshake may take.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a connection may wait for its next frame.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// What the witness starts from.
pub struct WitnessParts {
    /// The `witness_service` login to the witness database.
    pub db: fstp_pgwire::Config,
    /// The composite receipt key.
    pub receipt_key: CompositeSigningKey,
    /// The witness server certificate chain from the control-plane CA,
    /// PEM, leaf first.
    pub server_chain_pem: Vec<u8>,
    /// Its private key, PEM.
    pub server_key_pem: Vec<u8>,
    /// Where to listen. Port 0 picks a free port.
    pub listen: SocketAddr,
}

impl std::fmt::Debug for WitnessParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessParts")
            .field("listen", &self.listen)
            .finish_non_exhaustive()
    }
}

/// One chain as the service holds it.
#[derive(Clone)]
struct Chain {
    core: ChainWitness,
    log: Vec<WitnessRecord>,
}

/// Where the witness keeps its records: the PostgreSQL database of a SaaS
/// witness, or the append-only file store of a local witness.
#[allow(
    clippy::large_enum_variant,
    reason = "one store per witness process, never moved after start"
)]
enum Backend<R: Runtime> {
    /// The `witness_service` login and its connection, once open.
    Pg {
        db: fstp_pgwire::Config,
        client: Option<Client<R>>,
    },
    /// The file store of a self-hosted install (ADR-010 "Self-hosted
    /// witness").
    File(FileStore),
    /// No store: the placeholder that `AsyncMutex` needs as a default.
    /// Every operation refuses.
    Closed,
}

impl<R: Runtime> Backend<R> {
    /// The database client, connecting first if needed.
    async fn client<'a>(
        rt: &R,
        db: &fstp_pgwire::Config,
        client: &'a mut Option<Client<R>>,
    ) -> Result<&'a mut Client<R>, StoreError> {
        if client.is_none() {
            let c = Client::connect(rt, db)
                .await
                .map_err(|_| StoreError::Unavailable("connect"))?;
            *client = Some(c);
        }
        client.as_mut().ok_or(StoreError::Unavailable("connect"))
    }

    /// Drops the database connection after a failure, so the next use
    /// opens another. A file store keeps nothing open.
    fn reset(&mut self) {
        if let Backend::Pg { client, .. } = self {
            *client = None;
        }
    }

    async fn load_chain(
        &mut self,
        rt: &R,
        cell: CellId,
        chain: ChainId,
    ) -> Result<LoadedChain, StoreError> {
        match self {
            Backend::Pg { db, client } => {
                let c = Self::client(rt, db, client).await?;
                store::load_chain(c, cell, chain).await
            }
            Backend::File(f) => f.load_chain(cell, chain),
            Backend::Closed => Err(CLOSED),
        }
    }

    async fn load_registry(&mut self, rt: &R) -> Result<Vec<store::RegisteredCell>, StoreError> {
        match self {
            Backend::Pg { db, client } => {
                let c = Self::client(rt, db, client).await?;
                store::load_registry(c).await
            }
            Backend::File(f) => f.load_registry(),
            Backend::Closed => Err(CLOSED),
        }
    }

    async fn insert_prepare(
        &mut self,
        rt: &R,
        p: &Prepare,
        row: &AnchorRow,
    ) -> Result<(), StoreError> {
        match self {
            Backend::Pg { db, client } => {
                let c = Self::client(rt, db, client).await?;
                store::insert_prepare(c, row).await
            }
            Backend::File(f) => f.append_prepare(p, row),
            Backend::Closed => Err(CLOSED),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "each argument is one field of the record"
    )]
    async fn insert_withdrawal(
        &mut self,
        rt: &R,
        message: &WitnessMessage,
        kind: RecordKind,
        n: u64,
        link: &Link,
        at: i64,
        w: &crate::chain_witness::Withdrawal,
    ) -> Result<(), StoreError> {
        match self {
            Backend::Pg { db, client } => {
                let (cell, chain) = match message {
                    WitnessMessage::Abort { cell, chain, .. }
                    | WitnessMessage::InDoubtAbsent { cell, chain, .. } => (*cell, *chain),
                    WitnessMessage::Prepare(_) => return Err(StoreError::Corrupt("withdrawal")),
                };
                let c = Self::client(rt, db, client).await?;
                store::insert_withdrawal(c, cell, chain, kind, n, link, at, w).await
            }
            Backend::File(f) => f.append_withdrawal(message, at, w),
            Backend::Closed => Err(CLOSED),
        }
    }

    async fn register(
        &mut self,
        rt: &R,
        cell: CellId,
        ca_cert_der: &[u8],
        anchor_keys: &[(ChainId, Vec<u8>)],
        at: i64,
    ) -> Result<(), StoreError> {
        match self {
            Backend::Pg { db, client } => {
                let c = Self::client(rt, db, client).await?;
                store::register_cell(c, cell, ca_cert_der, at).await?;
                for (chain, key) in anchor_keys {
                    store::register_anchor_key(c, cell, *chain, key, at).await?;
                }
                Ok(())
            }
            Backend::File(f) => {
                f.register_cell(cell, ca_cert_der, at)?;
                for (chain, key) in anchor_keys {
                    f.register_anchor_key(cell, *chain, key, at)?;
                }
                Ok(())
            }
            Backend::Closed => Err(CLOSED),
        }
    }
}

/// The refusal of the placeholder store.
const CLOSED: StoreError = StoreError::Unavailable("closed");

/// What the service holds under its async lock: its store and the chains
/// loaded so far.
struct Core<R: Runtime> {
    backend: Backend<R>,
    chains: BTreeMap<(CellId, u8), Chain>,
}

impl<R: Runtime> Default for Core<R> {
    fn default() -> Self {
        Core {
            backend: Backend::Closed,
            chains: BTreeMap::new(),
        }
    }
}

/// One registered cell, as the service pins it.
#[derive(Clone)]
struct Registered {
    ca_cert_pem: Vec<u8>,
    pin: PinnedCa,
    keys: BTreeMap<u8, Vec<Vec<u8>>>,
}

struct Shared<R: Runtime> {
    rt: R,
    receipt_key: CompositeSigningKey,
    server_chain_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    core: AsyncMutex<Core<R>>,
    cells: Mutex<BTreeMap<CellId, Registered>>,
    tls: Mutex<Option<Arc<fstp_tls::ServerConfig>>>,
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// UTC microseconds now.
fn now_us() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0)
}

fn store_err(e: StoreError) -> WitnessError {
    WitnessError::Store(e)
}

impl<R: Runtime> Shared<R> {
    /// Rebuilds the TLS configuration over the registered cell CAs.
    fn rebuild_tls(&self) -> Result<(), WitnessError> {
        let roots: Vec<u8> = locked(&self.cells)
            .values()
            .flat_map(|r| r.ca_cert_pem.iter().copied())
            .collect();
        let config = if roots.is_empty() {
            None
        } else {
            let cfg = fstp_tls::ServerConfig::builder(&self.server_chain_pem, &self.server_key_pem)
                .require_client_auth(&roots)
                .build()
                .map_err(|_| WitnessError::Tls)?;
            Some(Arc::new(cfg))
        };
        *locked(&self.tls) = config;
        Ok(())
    }

    /// Adds `cell` to the pinned set, in memory.
    fn pin(
        &self,
        cell: CellId,
        ca_cert_der: &[u8],
        keys: BTreeMap<u8, Vec<Vec<u8>>>,
    ) -> Result<(), WitnessError> {
        let pin = PinnedCa::from_ca_der(cell, ca_cert_der).map_err(|_| WitnessError::BadCa)?;
        let pem = fstp_pki::pem::encode(fstp_pki::pem::PemLabel::Certificate, ca_cert_der)
            .map_err(|_| WitnessError::BadCa)?;
        locked(&self.cells).insert(
            cell,
            Registered {
                ca_cert_pem: pem.into_bytes(),
                pin,
                keys,
            },
        );
        Ok(())
    }

    fn pins(&self) -> Vec<PinnedCa> {
        locked(&self.cells)
            .values()
            .map(|r| r.pin.clone())
            .collect()
    }

    fn anchor_keys(&self, cell: CellId, chain: ChainId) -> Vec<Vec<u8>> {
        locked(&self.cells)
            .get(&cell)
            .and_then(|r| r.keys.get(&chain.byte()).cloned())
            .unwrap_or_default()
    }

    /// The chain `(cell, chain)`, loaded from the store on first use.
    async fn chain<'a>(
        &self,
        core: &'a mut Core<R>,
        cell: CellId,
        chain: ChainId,
    ) -> Result<&'a mut Chain, StoreError> {
        let key = (cell, chain.byte());
        if !core.chains.contains_key(&key) {
            let LoadedChain { state, held, log } =
                match core.backend.load_chain(&self.rt, cell, chain).await {
                    Ok(l) => l,
                    Err(e) => {
                        if matches!(e, StoreError::Unavailable(_)) {
                            core.backend.reset();
                        }
                        return Err(e);
                    }
                };
            core.chains.insert(
                key,
                Chain {
                    core: ChainWitness::resume_holding(cell, chain, state, held),
                    log,
                },
            );
        }
        core.chains
            .get_mut(&key)
            .ok_or(StoreError::Unavailable("chain"))
    }

    async fn prepare(&self, sender: Sender, p: Prepare) -> WireReply {
        let (cell, chain) = (p.anchor.cell, p.anchor.chain);
        if !accepts_sender(sender, cell, chain) {
            return WireReply::Refused;
        }
        // I-90: both halves under a key of the chain's anchor key history.
        if check_anchor_signature(&p.anchor, &self.anchor_keys(cell, chain)).is_err() {
            return WireReply::Refused;
        }
        let mut core = self.core.lock().await;
        let Ok(state) = self.chain(&mut core, cell, chain).await else {
            return WireReply::Refused;
        };
        let before = state.core.state().seq;
        let mut next = state.core.clone();
        let Ok(fields) = next.prepare(sender, &p, now_us()) else {
            return WireReply::Refused;
        };
        if fields.witness_seq == before {
            // A retransmit of the outstanding prepare: its stored receipt.
            return match state.log.iter().rev().find_map(|r| match r {
                WitnessRecord::Prepare(row) if row.receipt.fields.witness_seq == before => {
                    Some(row.receipt.clone())
                }
                _ => None,
            }) {
                Some(rc) => WireReply::Receipt(rc),
                None => WireReply::Refused,
            };
        }
        let Ok(receipt) = sign_receipt(&self.receipt_key, cell, chain, &fields) else {
            return WireReply::Refused;
        };
        let row = AnchorRow {
            anchor: p.anchor.clone(),
            receipt: receipt.clone(),
        };
        let stored = core.backend.insert_prepare(&self.rt, &p, &row).await;
        if stored.is_err() {
            // Nothing was stored, so nothing changes. The chain is read
            // again from the store on its next use.
            core.backend.reset();
            core.chains.remove(&(cell, chain.byte()));
            return WireReply::Refused;
        }
        if let Some(state) = core.chains.get_mut(&(cell, chain.byte())) {
            state.core = next;
            state.log.push(WitnessRecord::Prepare(row));
        }
        WireReply::Receipt(receipt)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the sender, the chain, the record kind and the head"
    )]
    async fn withdraw(
        &self,
        sender: Sender,
        cell: CellId,
        chain: ChainId,
        kind: RecordKind,
        n: u64,
        link: Link,
    ) -> WireReply {
        // The witness core checks the sender again. This check comes first so
        // that no other cell's chain is even loaded for it.
        if !accepts_sender(sender, cell, chain) {
            return WireReply::Refused;
        }
        let mut core = self.core.lock().await;
        let Ok(state) = self.chain(&mut core, cell, chain).await else {
            return WireReply::Refused;
        };
        let mut next = state.core.clone();
        let done = match kind {
            RecordKind::Abort => next.abort(sender, n, &link),
            _ => next.in_doubt_absent(sender, n, &link),
        };
        let w = match done {
            Ok(w) => w,
            Err(Refusal::UnknownPrepare) => return WireReply::UnknownPrepare,
            Err(_) => return WireReply::Refused,
        };
        let at = now_us();
        let message = match kind {
            RecordKind::Abort => WitnessMessage::Abort {
                cell,
                chain,
                n,
                link,
            },
            _ => WitnessMessage::InDoubtAbsent {
                cell,
                chain,
                n,
                link,
            },
        };
        let stored = core
            .backend
            .insert_withdrawal(&self.rt, &message, kind, n, &link, at, &w)
            .await;
        if stored.is_err() {
            core.backend.reset();
            core.chains.remove(&(cell, chain.byte()));
            return WireReply::Refused;
        }
        if let Some(state) = core.chains.get_mut(&(cell, chain.byte())) {
            state.core = next;
            state.log.push(match kind {
                RecordKind::Abort => WitnessRecord::Abort { n, link },
                _ => WitnessRecord::InDoubtAbsent { n, link },
            });
        }
        WireReply::Recorded
    }

    /// The page of `cell`'s `chain` log after its first `after` records: at
    /// most [`MAX_LOG_RECORDS`] records, and whether more follow. A client
    /// that holds more records than the log is refused.
    async fn log_page(
        &self,
        sender: Sender,
        cell: CellId,
        chain: ChainId,
        after: u64,
    ) -> WireReply {
        if !accepts_sender(sender, cell, chain) {
            return WireReply::Refused;
        }
        let Ok(start) = usize::try_from(after) else {
            return WireReply::Refused;
        };
        let mut core = self.core.lock().await;
        let Ok(c) = self.chain(&mut core, cell, chain).await else {
            return WireReply::Refused;
        };
        let Some(rest) = c.log.get(start..) else {
            return WireReply::Refused;
        };
        let (page, more) = match rest.split_at_checked(MAX_LOG_RECORDS) {
            Some((page, tail)) => (page, !tail.is_empty()),
            None => (rest, false),
        };
        WireReply::Log(LogPage {
            records: page.to_vec(),
            more,
        })
    }

    async fn handle(&self, sender: Sender, req: WireRequest) -> WireReply {
        match req {
            WireRequest::Message(WitnessMessage::Prepare(p)) => self.prepare(sender, p).await,
            WireRequest::Message(WitnessMessage::Abort {
                cell,
                chain,
                n,
                link,
            }) => {
                self.withdraw(sender, cell, chain, RecordKind::Abort, n, link)
                    .await
            }
            WireRequest::Message(WitnessMessage::InDoubtAbsent {
                cell,
                chain,
                n,
                link,
            }) => {
                self.withdraw(sender, cell, chain, RecordKind::InDoubtAbsent, n, link)
                    .await
            }
            WireRequest::Outstanding { cell, chain } => {
                if !accepts_sender(sender, cell, chain) {
                    return WireReply::Refused;
                }
                let mut core = self.core.lock().await;
                match self.chain(&mut core, cell, chain).await {
                    Ok(c) => WireReply::Outstanding(c.core.state().outstanding),
                    Err(_) => WireReply::Refused,
                }
            }
            WireRequest::Log { cell, chain } => self.log_page(sender, cell, chain, 0).await,
            WireRequest::LogAfter { cell, chain, after } => {
                self.log_page(sender, cell, chain, after).await
            }
        }
    }
}

/// A running witness.
pub struct WitnessHandle<R: Runtime> {
    shared: Arc<Shared<R>>,
    local_addr: SocketAddr,
    shutdown: Shutdown,
    accept: JoinHandle<()>,
}

impl<R: Runtime> std::fmt::Debug for WitnessHandle<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessHandle")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl<R: Runtime> WitnessHandle<R> {
    /// Where the witness listens.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The encoded composite public key of the receipt key, which cells pin
    /// (ADR-010 "Keys").
    pub fn receipt_public_key(&self) -> Vec<u8> {
        self.shared.receipt_key.public_key().to_bytes().to_vec()
    }

    /// Pins every cell of the registry as the database holds it now, and
    /// rebuilds the TLS configuration of new connections over their CAs.
    /// Provisioning writes the registry as `witness_migrator`
    /// ([`crate::store::registration_sql`]) and then calls this, so the
    /// service role needs only SELECT on the registry tables.
    ///
    /// # Errors
    ///
    /// [`WitnessError::Store`] when the registry cannot be read, and
    /// [`WitnessError::BadCa`] for a CA certificate that does not read.
    pub async fn reload_registry(&self) -> Result<(), WitnessError> {
        {
            let mut core = self.shared.core.lock().await;
            let all = match core.backend.load_registry(&self.shared.rt).await {
                Ok(all) => all,
                Err(e) => {
                    core.backend.reset();
                    return Err(store_err(e));
                }
            };
            for r in &all {
                self.shared.pin(r.cell, &r.ca_cert, keys_of(r))?;
            }
        }
        self.shared.rebuild_tls()
    }

    /// Registers `cell` (design section 9.2, ADR-010 "Witnesses"): its CA
    /// certificate `ca_cert_der` and the anchor public key of each of its
    /// chains. The registration is stored first, then pinned, and the TLS
    /// configuration of new connections trusts the CA. The service's own
    /// login writes the rows, so this needs INSERT on the registry tables.
    /// The world grants `witness_service` no such right, and registers
    /// through [`WitnessHandle::reload_registry`].
    ///
    /// # Errors
    ///
    /// [`WitnessError::Store`] when the registration cannot be stored, or
    /// names another CA for a registered cell, and [`WitnessError::BadCa`]
    /// for a certificate without a subjectKeyIdentifier.
    pub async fn register_cell(
        &self,
        cell: CellId,
        ca_cert_der: &[u8],
        anchor_keys: &[(ChainId, Vec<u8>)],
    ) -> Result<(), WitnessError> {
        let at = now_us();
        {
            let mut core = self.shared.core.lock().await;
            let rt = &self.shared.rt;
            let registered = core
                .backend
                .register(rt, cell, ca_cert_der, anchor_keys, at)
                .await;
            if let Err(e) = registered {
                core.backend.reset();
                return Err(store_err(e));
            }
            let all = core.backend.load_registry(rt).await.map_err(store_err)?;
            let mine = all.into_iter().find(|r| r.cell == cell);
            let keys = mine.map(|r| keys_of(&r)).unwrap_or_default();
            self.shared.pin(cell, ca_cert_der, keys)?;
        }
        self.shared.rebuild_tls()
    }

    /// Stops accepting, lets every connection finish its frame, and waits
    /// up to `deadline` for them.
    ///
    /// # Errors
    ///
    /// [`DrainTimeout`] when connections were still open at the deadline.
    /// They are aborted then.
    pub async fn shutdown(&self, deadline: Duration) -> Result<(), DrainTimeout> {
        let res = self.shutdown.shutdown(&self.shared.rt, deadline).await;
        if res.is_err() {
            self.accept.abort();
        }
        res
    }

    /// Starts the shutdown without waiting.
    pub fn trigger_shutdown(&self) {
        self.shutdown.trigger();
    }
}

fn keys_of(r: &store::RegisteredCell) -> BTreeMap<u8, Vec<Vec<u8>>> {
    let mut keys = BTreeMap::new();
    keys.insert(ChainId::App.byte(), r.app_keys.clone());
    keys.insert(ChainId::Vault.byte(), r.vault_keys.clone());
    keys
}

/// Starts the witness from `parts` on `rt` (module documentation).
///
/// # Errors
///
/// [`WitnessError::Store`] when the database cannot be reached, its
/// placement marker is not a witness database's, or its registry does not
/// load. [`WitnessError::Io`] when the listener cannot be bound.
pub async fn serve<R: Runtime>(
    rt: R,
    parts: WitnessParts,
) -> Result<WitnessHandle<R>, WitnessError> {
    let WitnessParts {
        db,
        receipt_key,
        server_chain_pem,
        server_key_pem,
        listen,
    } = parts;
    let mut client = Client::connect(&rt, &db)
        .await
        .map_err(|_| WitnessError::Store(StoreError::Unavailable("connect")))?;
    if store::placement_kind(&mut client)
        .await
        .map_err(store_err)?
        != WITNESS_MARKER
    {
        return Err(WitnessError::Store(StoreError::Corrupt(
            "not a witness database (I-83)",
        )));
    }
    let registry = store::load_registry(&mut client).await.map_err(store_err)?;
    let backend = Backend::Pg {
        db,
        client: Some(client),
    };
    start(
        rt,
        backend,
        registry,
        receipt_key,
        server_chain_pem,
        server_key_pem,
        listen,
    )
    .await
}

/// What a local witness of a self-hosted install starts from (ADR-010
/// "Self-hosted witness").
pub struct LocalWitnessParts {
    /// The directory of its append-only file store. Only the witness's
    /// OS user may read and write it.
    pub dir: PathBuf,
    /// The composite receipt key, from the witness's own `fstp-keyd`
    /// entry (ADR-004 part 2, "Self-hosted witness receipt key").
    pub receipt_key: CompositeSigningKey,
    /// The witness server certificate chain from the install CA, PEM,
    /// leaf first.
    pub server_chain_pem: Vec<u8>,
    /// Its private key, PEM.
    pub server_key_pem: Vec<u8>,
    /// Where to listen. Port 0 picks a free port.
    pub listen: SocketAddr,
}

impl std::fmt::Debug for LocalWitnessParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalWitnessParts")
            .field("listen", &self.listen)
            .finish_non_exhaustive()
    }
}

/// Starts the local witness of a self-hosted install from `parts` on
/// `rt`. It runs the same listener, sender rule, anchor check and
/// receipts as [`serve`], over the file store in
/// [`LocalWitnessParts::dir`] ([`FileStore`]). It loads every file of the
/// store first, so a store with a missing, changed or cut record never
/// serves.
///
/// Scope (ADR-010 open point 7): a root user on the node can rewrite the
/// store and the cell's database together, which the local witness does
/// not detect.
///
/// # Errors
///
/// [`WitnessError::Store`] when the store does not open or load, and
/// [`WitnessError::Io`] when the listener cannot be bound.
pub async fn serve_local<R: Runtime>(
    rt: R,
    parts: LocalWitnessParts,
) -> Result<WitnessHandle<R>, WitnessError> {
    let LocalWitnessParts {
        dir,
        receipt_key,
        server_chain_pem,
        server_key_pem,
        listen,
    } = parts;
    let files = FileStore::open(&dir).map_err(store_err)?;
    let registry = files.load_registry().map_err(store_err)?;
    start(
        rt,
        Backend::File(files),
        registry,
        receipt_key,
        server_chain_pem,
        server_key_pem,
        listen,
    )
    .await
}

/// Pins `registry`, binds the listener and runs the accept loop.
async fn start<R: Runtime>(
    rt: R,
    backend: Backend<R>,
    registry: Vec<store::RegisteredCell>,
    receipt_key: CompositeSigningKey,
    server_chain_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    listen: SocketAddr,
) -> Result<WitnessHandle<R>, WitnessError> {
    let shared = Arc::new(Shared {
        rt: rt.clone(),
        receipt_key,
        server_chain_pem,
        server_key_pem,
        core: AsyncMutex::new(Core {
            backend,
            chains: BTreeMap::new(),
        }),
        cells: Mutex::new(BTreeMap::new()),
        tls: Mutex::new(None),
    });
    for r in &registry {
        shared.pin(r.cell, &r.ca_cert, keys_of(r))?;
    }
    shared.rebuild_tls()?;
    let listener = rt
        .bind_tcp(listen)
        .await
        .map_err(|e| WitnessError::Io(e.kind()))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| WitnessError::Io(e.kind()))?;
    let shutdown = Shutdown::new();
    let accept = rt.spawn(accept_loop(
        Arc::clone(&shared),
        listener,
        shutdown.signal(),
    ));
    Ok(WitnessHandle {
        shared,
        local_addr,
        shutdown,
        accept,
    })
}

async fn accept_loop<R: Runtime>(
    shared: Arc<Shared<R>>,
    mut listener: R::TcpListener,
    signal: ShutdownSignal,
) {
    loop {
        let Some(accepted) = signal.run_until(listener.accept()).await else {
            break;
        };
        let Ok((tcp, _peer)) = accepted else {
            // A failed accept, such as a full descriptor table, is retried
            // after a pause so the loop never spins.
            shared.rt.sleep(Duration::from_millis(50)).await;
            continue;
        };
        let conn_shared = Arc::clone(&shared);
        let conn_signal = signal.clone();
        drop(shared.rt.spawn(async move {
            connection(conn_shared, tcp, conn_signal).await;
        }));
    }
}

/// Serves one connection until it closes, fails, idles out or the witness
/// shuts down.
async fn connection<R: Runtime>(shared: Arc<Shared<R>>, tcp: R::Tcp, signal: ShutdownSignal) {
    let Some(config) = locked(&shared.tls).clone() else {
        return;
    };
    let handshake = fstp_rt::timeout(
        &shared.rt,
        HANDSHAKE_TIMEOUT,
        fstp_tls::accept(&config, tcp),
    );
    let Ok(Ok(mut stream)) = handshake.await else {
        return;
    };
    let Some(sender) = stream
        .peer_end_entity_der()
        .and_then(|der| sender_of(der, &shared.pins()))
    else {
        return;
    };
    loop {
        let read = fstp_rt::timeout(&shared.rt, IDLE_TIMEOUT, read_frame(&mut stream));
        let Some(frame) = signal.run_until(read).await else {
            break;
        };
        let Ok(Ok(Some(bytes))) = frame else {
            break;
        };
        let reply = match decode_request(&bytes) {
            Ok(req) => shared.handle(sender, req).await,
            Err(_) => WireReply::Refused,
        };
        let Ok(out) = encode_reply(&reply) else {
            break;
        };
        if write_frame(&mut stream, &out).await.is_err() {
            break;
        }
    }
    let _ = stream.shutdown().await;
}
