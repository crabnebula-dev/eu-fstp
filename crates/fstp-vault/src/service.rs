//! The vault service: its two listeners over mutual TLS, its database
//! and its sans-IO core (design sections 6.1 to 6.3, ADR-009, ADR-010).
//! Lane int5.
//!
//! [`serve`] runs the service on one runtime through `fstp-rt` until its
//! [`VaultHandle`] shuts it down:
//!
//! 1. It connects to `v_<cell>` as `v_<cell>_vault` and runs the I-83
//!    start check of design section 9.2 over that connection
//!    ([`check_database`]). It reads the placement marker, and takes the
//!    server certificate OU and the SPKI from the leaf certificate the
//!    server presented ([`fstp_pgwire::Client::server_certificate_der`]).
//!    It refuses anything but a vault database on a server whose OU is
//!    `vault` and whose SPKI digest the control plane registered for a
//!    vault cluster only (`crate::start::accepts_database`).
//! 2. It loads the vault from its rows (`crate::store::load`).
//! 3. It serves the internal listener: mutual TLS with the cell CA as the
//!    only root, so only the cell's own `cell-app` certificate reaches the
//!    four internal routes (design section 6.1).
//! 4. It serves the vault origin through the edge tunnel: the edge's
//!    tunnel TLS, the tunnel header for `id.<cell host>`, then the
//!    browser's TLS for that host (ADR-009).
//!
//! Every call runs on a copy of the vault. The call's journal is what the
//! database must record before the vault answers (`crate::origin`).
//!
//! Daniel decided ADR-010 open point 5 on 2026-11-13 (m3-finish Q-C):
//! each committed fact batch and each identity release or read is a kind
//! 1 row of the vault chain. A call whose journal is not empty commits its
//! rows, its one kind 1 row and its anchor in one transaction, after the
//! witness receipted the row's link (`crate::chain`, lane F-VCHAIN). Only
//! then is it answered and the copy kept. Without a chain writer
//! ([`VaultParts::chain`] is `None`), or when the witness or the database
//! fails, such a call is refused with 503 and the copy is dropped. Calls
//! with an empty journal, such as the epoch read, are always answered.
//!
//! The caller hands in no claim about its database server. It hands in
//! the registration set ([`VaultParts::registered_servers`]): each
//! cluster's server SPKI digest and kind, as the control plane recorded
//! them at cluster registration (`cp.cluster` `kind` and `server_spki`).
//! The OU and the SPKI come from the live connection only. The SPKI and
//! the first subject OU are read by `fstp_witness::peer::read_cert`, the
//! in-house fuzzed DER reader that also reads the `cell-app` OU of the
//! internal listener. Every subject OU is read by
//! `fstp_pgwire::x509::subject_organizational_units`, fuzzed as well. A
//! subject with more than one OU names no cluster kind.
//!
//! The vault opens one database connection. [`serve`] also adds the
//! same OU and SPKI check to its configuration as a
//! [`fstp_pgwire::ServerCheck`] ([`vault_server_check`]). So the
//! connection, and any cancel connection opened for it later, refuses a
//! server that fails it before the startup message.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Poll, Waker};
use std::time::Duration;

use fstp_edge::{TUNNEL_HEADER_LEN, decode_tunnel_header};
use fstp_pgwire::Client;
use fstp_rt::{IoExt as _, Listener, Runtime, Shutdown, ShutdownSignal};
use fstp_tls::TlsStream;
use fstp_witness::lock::AsyncMutex;

use crate::VaultError;
use crate::chain::{VaultChain, VaultChainParts};
use crate::origin::JournalEntry;
use crate::origin::{INTERNAL_ROUTES, Vault};
use crate::start::{ClusterRole, DatabaseView, accepts_database, placement_marker};
use crate::store::{Sealer, load};

/// How long the two handshakes and the tunnel header may take.
pub const TUNNEL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The subject OU of the cell's `cell-app` client certificate, the only
/// peer of the internal listener (design section 6.1).
pub const CELL_APP_OU: &str = "cell-app";

/// The largest request body either listener takes.
pub const MAX_BODY: u64 = 256 * 1024;

/// The subject OU of a vault cluster's server certificate (design
/// sections 1.3 and 4.1). It is `fstp_pki::cert::ClusterKindOu::Vault`,
/// spelt out because the vault does not depend on `fstp-pki`.
pub const VAULT_OU: &str = "vault";

/// The subject OU of an application cluster's server certificate, as
/// `fstp_pki::cert::ClusterKindOu::Application` spells it.
pub const APPLICATION_OU: &str = "application";

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
/// [`VAULT_OU`] or [`APPLICATION_OU`]. A certificate that does not read,
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
    if *ou == VAULT_OU.as_bytes() {
        ClusterRole::Vault
    } else if *ou == APPLICATION_OU.as_bytes() {
        ClusterRole::Application
    } else {
        ClusterRole::Other
    }
}

/// Whether the server certificate `cert_der` is that of a vault cluster:
/// its OU names one ([`server_ou_role`]) and `registered` gives its SPKI
/// that kind only ([`registered_role`]).
#[must_use]
pub fn is_vault_server(cert_der: &[u8], registered: &[RegisteredSpki]) -> bool {
    server_ou_role(cert_der) == ClusterRole::Vault
        && registered_role(cert_der, registered) == ClusterRole::Vault
}

/// The server check that [`serve`] adds to the vault database
/// configuration: it accepts a server only when [`is_vault_server`]
/// holds for its verified leaf under `registered`. Every connection and
/// cancel connection over the configuration runs it before anything is
/// sent past the TLS handshake. A refused connection fails with
/// [`fstp_pgwire::ErrorKind::ServerRefused`].
#[must_use]
pub fn vault_server_check(registered: &[RegisteredSpki]) -> fstp_pgwire::ServerCheck {
    let registered = registered.to_vec();
    fstp_pgwire::ServerCheck::new(move |der: &[u8]| is_vault_server(der, &registered))
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

/// What the vault sees of its database: the placement marker `marker`
/// read over a connection, and the OU and the SPKI registration of the
/// server certificate `cert_der` that the same connection verified.
#[must_use]
pub fn database_view(marker: u8, cert_der: &[u8], registered: &[RegisteredSpki]) -> DatabaseView {
    DatabaseView {
        marker,
        server_ou: server_ou_role(cert_der),
        registered_spki: registered_role(cert_der, registered),
    }
}

/// The I-83 start check of design section 9.2 over the live connection
/// `client`: the placement marker it reads, and the OU and the SPKI of
/// the leaf certificate its server presented, checked against
/// `registered`. Returns the view it accepted.
///
/// # Errors
///
/// [`VaultError::Malformed`] when the view is not that of a vault
/// database on a vault cluster (`crate::start::accepts_database`), and
/// the errors of [`placement_marker`].
pub async fn check_database<R: Runtime>(
    client: &mut Client<R>,
    registered: &[RegisteredSpki],
) -> Result<DatabaseView, VaultError> {
    let marker = placement_marker(client).await?;
    let view = database_view(marker, client.server_certificate_der(), registered);
    if !accepts_database(&view) {
        return Err(VaultError::Malformed("not a vault database (I-83)"));
    }
    Ok(view)
}

/// What the vault starts from.
pub struct VaultParts {
    /// The cell.
    pub cell: [u8; 16],
    /// The `v_<cell>_vault` login.
    pub db: fstp_pgwire::Config,
    /// The control plane's registration of cluster server keys (module
    /// documentation). The start check looks up the live server's SPKI
    /// digest here ([`check_database`]).
    pub registered_servers: Vec<RegisteredSpki>,
    /// Seals and opens the stored values.
    pub sealer: Arc<dyn Sealer>,
    /// The cell's ticket public keys, current and next.
    pub ticket_keys: Vec<[u8; 32]>,
    /// The internal listener's configuration, with client authentication
    /// against the cell CA.
    pub internal_tls: fstp_tls::ServerConfig,
    /// The tunnel configuration: the vault's tunnel certificate, with
    /// client authentication against the edge's CA.
    pub tunnel_tls: Arc<fstp_tls::ServerConfig>,
    /// The vault origin's configuration: the certificate of `id.<host>`.
    pub origin_tls: Arc<fstp_tls::ServerConfig>,
    /// The vault origin host, `id.<cell host>`.
    pub origin_host: String,
    /// Where the internal listener binds.
    pub internal_listen: SocketAddr,
    /// Where the tunnel listener binds.
    pub origin_listen: SocketAddr,
    /// The vault chain writer: the Vault chain's anchor key and the
    /// witness (ADR-010, open point 5). `None` runs no writer, so every
    /// call that would write is refused with 503 and reads are served
    /// (ADR-010 "Witness unavailable").
    pub chain: Option<VaultChainParts>,
}

impl std::fmt::Debug for VaultParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultParts")
            .field("origin_host", &self.origin_host)
            .finish_non_exhaustive()
    }
}

/// The vault under its async lock, with its store when the chain writer
/// runs.
struct Held<R: Runtime> {
    vault: Vault,
    store: Option<Persist<R>>,
}

impl<R: Runtime> Default for Held<R> {
    fn default() -> Self {
        Held {
            vault: Vault::default(),
            store: None,
        }
    }
}

/// What persists a call: the database login, its connection once open,
/// the sealer and the vault chain writer (`crate::chain`).
struct Persist<R: Runtime> {
    rt: R,
    db: fstp_pgwire::Config,
    client: Option<Client<R>>,
    sealer: Arc<dyn Sealer>,
    chain: VaultChain<R>,
}

impl<R: Runtime> Persist<R> {
    /// Commits `journal` with its chain row, anchored at the witness. A
    /// failed database connection is dropped, and the next call opens
    /// another, with the same I-83 server check.
    async fn commit(&mut self, journal: &[JournalEntry], now: i64) -> Result<(), VaultError> {
        if self.client.is_none() {
            let c = Client::connect(&self.rt, &self.db)
                .await
                .map_err(|_| VaultError::Unavailable("the vault database"))?;
            self.client = Some(c);
        }
        let Some(client) = self.client.as_mut() else {
            return Err(VaultError::Unavailable("the vault database"));
        };
        let done = self
            .chain
            .commit(client, self.sealer.as_ref(), journal, now)
            .await;
        if matches!(done, Err(VaultError::Unavailable(_))) {
            self.client = None;
        }
        done
    }
}

/// One call's result.
struct Answer {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

struct Shared<R: Runtime> {
    held: AsyncMutex<Held<R>>,
}

fn now_us() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0)
}

impl<R: Runtime> Shared<R> {
    /// Runs `call` on a copy of the vault at `now`. A call with an empty
    /// journal keeps the copy and is answered. A call with a journal is
    /// answered only once its rows, its kind 1 chain row and its anchor
    /// committed (`crate::chain`). Without a chain writer, or when the
    /// witness or the database fails, it is refused with 503 and the copy
    /// is dropped, so memory never runs ahead of the database.
    async fn run(&self, now: i64, call: impl FnOnce(&mut Vault) -> Answer) -> Answer {
        let mut held = self.held.lock().await;
        let mut next = held.vault.clone();
        let answer = call(&mut next);
        let journal = next.take_journal();
        if journal.is_empty() {
            held.vault = next;
            return answer;
        }
        let committed = match held.store.as_mut() {
            Some(p) => p.commit(&journal, now).await.is_ok(),
            None => false,
        };
        if !committed {
            return Answer {
                status: 503,
                headers: vec![("content-type", "text/plain; charset=utf-8".to_owned())],
                body: Vec::new(),
            };
        }
        held.vault = next;
        answer
    }
}

fn response(a: Answer) -> fstp_http::Response {
    let status = fstp_http::StatusCode::from_u16(a.status)
        .unwrap_or(fstp_http::StatusCode::INTERNAL_SERVER_ERROR);
    let mut resp = fstp_http::Response::new(status);
    resp.body = a.body;
    for (name, value) in a.headers {
        let _ = resp.headers.try_insert(name, value);
    }
    resp
}

/// The internal listener's handler.
struct Internal<R: Runtime>(Arc<Shared<R>>);

impl<R: Runtime> fstp_http::Handler for Internal<R> {
    async fn handle(&self, req: fstp_http::Request) -> fstp_http::Response {
        let path = req.target.path().to_owned();
        let known = INTERNAL_ROUTES.iter().any(|r| r.path == path);
        if !known {
            return fstp_http::Response::new(fstp_http::StatusCode::NOT_FOUND);
        }
        if req.method != fstp_http::Method::POST {
            return fstp_http::Response::new(fstp_http::StatusCode::METHOD_NOT_ALLOWED);
        }
        // The TLS layer verified the client certificate under the cell CA.
        // Only its `cell-app` certificate reaches the routes (design
        // section 6.1): the cell CA issues other certificates too, such as
        // `cell-witness`.
        let cell_app = req
            .client_certificate_der()
            .and_then(|der| fstp_witness::peer::read_cert_names(der).ok())
            .and_then(|n| n.subject_ou)
            .is_some_and(|ou| ou == CELL_APP_OU.as_bytes());
        if !cell_app {
            return fstp_http::Response::new(fstp_http::StatusCode::FORBIDDEN);
        }
        let now = now_us();
        let body = req.body;
        let a = self
            .0
            .run(now, |v| Answer {
                status: 200,
                headers: vec![("content-type", "application/json".to_owned())],
                body: v.internal_bytes(&body, now),
            })
            .await;
        response(a)
    }
}

/// The vault origin's handler.
struct Origin<R: Runtime>(Arc<Shared<R>>);

impl<R: Runtime> fstp_http::Handler for Origin<R> {
    async fn handle(&self, req: fstp_http::Request) -> fstp_http::Response {
        let now = now_us();
        let method = req.method.as_str().to_owned();
        let path = req.target.path().to_owned();
        let body = req.body;
        let a = self
            .0
            .run(now, |v| {
                let r = v.origin(&method, &path, &body, now);
                Answer {
                    status: r.status,
                    headers: r.headers,
                    body: r.body,
                }
            })
            .await;
        response(a)
    }
}

/// How many finished tunnel connections may wait for the HTTP server. A
/// connection that finds the queue full is closed.
const TUNNEL_QUEUE: usize = 64;

type OriginStream<R> = TlsStream<TlsStream<<R as Runtime>::Tcp>>;

/// The finished connections of a tunnel listener, and the waker of its
/// `accept`. `fstp-rt` has no channel and no third-party crate may be
/// added, so this queue is in-house over `std::sync::Mutex`.
struct ReadyQueue<T> {
    items: VecDeque<T>,
    closed: bool,
    waker: Option<Waker>,
}

type Ready<R> = Arc<Mutex<ReadyQueue<(OriginStream<R>, SocketAddr)>>>;

fn queue<T>(m: &Mutex<ReadyQueue<T>>) -> MutexGuard<'_, ReadyQueue<T>> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Adds `item` to `ready` and wakes `accept`. A closed or full queue
/// refuses it, which drops and so closes the connection.
fn push_ready<T>(ready: &Mutex<ReadyQueue<T>>, item: T) {
    let waker = {
        let mut q = queue(ready);
        if q.closed || q.items.len() >= TUNNEL_QUEUE {
            return;
        }
        q.items.push_back(item);
        q.waker.take()
    };
    if let Some(w) = waker {
        w.wake();
    }
}

/// Closes `ready` and wakes `accept`.
fn close_ready<T>(ready: &Mutex<ReadyQueue<T>>) {
    let waker = {
        let mut q = queue(ready);
        q.closed = true;
        q.waker.take()
    };
    if let Some(w) = waker {
        w.wake();
    }
}

/// The vault origin's tunnel listener: the edge's tunnel TLS, the tunnel
/// header, then the browser's TLS for the origin host (ADR-009 "Edge and
/// tunnel"). A connection that fails a step is closed before an HTTP byte
/// is read.
///
/// The vault origin is public through the edge. So, as in
/// `fstp_cell::http::tunnel`, one accept task takes the TCP connections,
/// and each connection's handshakes run in a task of their own under
/// [`TUNNEL_HANDSHAKE_TIMEOUT`]. A peer that stalls holds only its own
/// task, never the next peer. `accept` yields the finished connections.
struct TunnelListener<R: Runtime> {
    ready: Ready<R>,
    local: SocketAddr,
}

impl<R: Runtime> TunnelListener<R> {
    /// Accepts tunnel connections for `host` on `tcp` until `signal` shuts
    /// the listener down.
    fn new(
        rt: &R,
        tcp: R::TcpListener,
        tunnel: Arc<fstp_tls::ServerConfig>,
        origin: Arc<fstp_tls::ServerConfig>,
        host: String,
        signal: ShutdownSignal,
    ) -> std::io::Result<TunnelListener<R>> {
        let local = tcp.local_addr()?;
        let ready: Ready<R> = Arc::new(Mutex::new(ReadyQueue {
            items: VecDeque::new(),
            closed: false,
            waker: None,
        }));
        let task_ready = Arc::clone(&ready);
        let task_rt = rt.clone();
        drop(rt.spawn(async move {
            let mut tcp = tcp;
            loop {
                let Some(accepted) = signal.run_until(tcp.accept()).await else {
                    break;
                };
                let Ok((conn, _peer)) = accepted else {
                    // A failed accept, such as a full descriptor table, is
                    // retried after a pause so the loop never spins.
                    task_rt.sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let ready = Arc::clone(&task_ready);
                let (tunnel, origin, host) =
                    (Arc::clone(&tunnel), Arc::clone(&origin), host.clone());
                let hs_rt = task_rt.clone();
                drop(task_rt.spawn(async move {
                    let shake = tunnel_handshake::<R>(conn, &tunnel, &origin, &host);
                    if let Ok(Some(done)) =
                        fstp_rt::timeout(&hs_rt, TUNNEL_HANDSHAKE_TIMEOUT, shake).await
                    {
                        push_ready(&ready, done);
                    }
                }));
            }
            close_ready(&task_ready);
        }));
        Ok(TunnelListener { ready, local })
    }
}

impl<R: Runtime> Drop for TunnelListener<R> {
    fn drop(&mut self) {
        // Handshakes still running drop their connections from now on.
        let mut q = queue(&self.ready);
        q.closed = true;
        q.items.clear();
    }
}

async fn tunnel_handshake<R: Runtime>(
    tcp: R::Tcp,
    tunnel: &fstp_tls::ServerConfig,
    origin: &fstp_tls::ServerConfig,
    host: &str,
) -> Option<(OriginStream<R>, SocketAddr)> {
    let mut t = fstp_tls::accept(tunnel, tcp).await.ok()?;
    let mut header = [0u8; TUNNEL_HEADER_LEN];
    t.read_exact(&mut header).await.ok()?;
    let h = decode_tunnel_header(&header).ok()?;
    if !h.host.as_str().eq_ignore_ascii_case(host) {
        return None;
    }
    let inner = fstp_tls::accept(origin, t).await.ok()?;
    if !inner.sni().is_some_and(|s| s.eq_ignore_ascii_case(host)) {
        return None;
    }
    Some((inner, SocketAddr::new(h.client_ip(), h.port)))
}

impl<R: Runtime> Listener for TunnelListener<R> {
    type Conn = OriginStream<R>;

    async fn accept(&mut self) -> std::io::Result<(Self::Conn, SocketAddr)> {
        std::future::poll_fn(|cx| {
            let mut q = queue(&self.ready);
            if let Some(done) = q.items.pop_front() {
                return Poll::Ready(Ok(done));
            }
            if q.closed {
                return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::NotConnected)));
            }
            q.waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local)
    }
}

/// A running vault.
pub struct VaultHandle<R: Runtime> {
    rt: R,
    internal: fstp_http::ServerHandle<R>,
    origin: fstp_http::ServerHandle<R>,
    /// Stops the tunnel listener's accept task.
    tunnel: Shutdown,
}

impl<R: Runtime> std::fmt::Debug for VaultHandle<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultHandle")
            .field("internal", &self.internal.local_addr())
            .field("origin", &self.origin.local_addr())
            .finish()
    }
}

impl<R: Runtime> VaultHandle<R> {
    /// Where the internal listener is bound.
    pub fn internal_addr(&self) -> SocketAddr {
        self.internal.local_addr()
    }

    /// Where the tunnel listener of the vault origin is bound.
    pub fn origin_addr(&self) -> SocketAddr {
        self.origin.local_addr()
    }

    /// Stops both listeners and waits up to `deadline` for their
    /// connections.
    ///
    /// # Errors
    ///
    /// [`VaultError::Unavailable`] when a connection was still open at the
    /// deadline.
    pub async fn shutdown(&self, deadline: Duration) -> Result<(), VaultError> {
        // The tunnel accept task stops taking connections first.
        self.tunnel.trigger();
        let a = self.internal.shutdown(deadline).await;
        let b = self.origin.shutdown(deadline).await;
        let c = self.tunnel.shutdown(&self.rt, deadline).await;
        if a.is_err() || b.is_err() || c.is_err() {
            return Err(VaultError::Unavailable("the drain"));
        }
        Ok(())
    }
}

fn http_config(tls: Option<fstp_tls::ServerConfig>) -> fstp_http::ServerConfig {
    fstp_http::ServerConfig {
        tls,
        limits: fstp_http::Limits {
            max_body_bytes: MAX_BODY,
            ..fstp_http::Limits::default()
        },
        ..fstp_http::ServerConfig::default()
    }
}

/// Starts the vault of `parts` on `rt` (module documentation).
///
/// # Errors
///
/// [`VaultError::Unavailable`] when the database cannot be reached or a
/// listener cannot be bound, and [`VaultError::Malformed`] for a database
/// that is not this vault's, or rows that do not load.
pub async fn serve<R: Runtime>(rt: R, parts: VaultParts) -> Result<VaultHandle<R>, VaultError> {
    let VaultParts {
        cell,
        db,
        registered_servers,
        sealer,
        ticket_keys,
        internal_tls,
        tunnel_tls,
        origin_tls,
        origin_host,
        internal_listen,
        origin_listen,
        chain,
    } = parts;
    // The server check runs on this connection and on any cancel
    // connection before anything passes the TLS handshake (I-83).
    let db = db.server_check(vault_server_check(&registered_servers));
    let mut client: Client<R> = Client::connect(&rt, &db).await.map_err(|e| {
        if e.kind() == fstp_pgwire::ErrorKind::ServerRefused {
            VaultError::Malformed("not a vault database (I-83)")
        } else {
            VaultError::Unavailable("the vault database")
        }
    })?;
    check_database(&mut client, &registered_servers).await?;
    let vault = load(&mut client, sealer.as_ref(), cell, &ticket_keys).await?;
    // ADR-010 "Start-up": the vault verifies its chain against the
    // witness before it serves.
    let store = match chain {
        Some(parts) => Some(Persist {
            rt: rt.clone(),
            chain: VaultChain::open(rt.clone(), cell, parts, &mut client).await?,
            db,
            client: Some(client),
            sealer,
        }),
        None => None,
    };
    let shared = Arc::new(Shared {
        held: AsyncMutex::new(Held { vault, store }),
    });
    let internal_tcp = rt
        .bind_tcp(internal_listen)
        .await
        .map_err(|_| VaultError::Unavailable("the internal listener"))?;
    let internal = fstp_http::Server::new(
        rt.clone(),
        http_config(Some(internal_tls)),
        Internal(Arc::clone(&shared)),
    )
    .serve(internal_tcp)
    .map_err(|_| VaultError::Unavailable("the internal listener"))?;
    let origin_tcp = rt
        .bind_tcp(origin_listen)
        .await
        .map_err(|_| VaultError::Unavailable("the tunnel listener"))?;
    let tunnel_shutdown = Shutdown::new();
    let tunnel = TunnelListener::new(
        &rt,
        origin_tcp,
        tunnel_tls,
        origin_tls,
        origin_host,
        tunnel_shutdown.signal(),
    )
    .map_err(|_| VaultError::Unavailable("the tunnel listener"))?;
    let origin = fstp_http::Server::new(rt.clone(), http_config(None), Origin(shared))
        .serve(tunnel)
        .map_err(|_| VaultError::Unavailable("the tunnel listener"))?;
    Ok(VaultHandle {
        rt,
        internal,
        origin,
        tunnel: tunnel_shutdown,
    })
}

/// Seals the vault's stored values under one AES-256-GCM data key, and
/// digests queries under an HMAC key (`crate::store::Sealer`). Each sealed
/// value is `nonce (12) || ciphertext || tag`. Both keys are the vault
/// chain's, handed in by the caller until the vault keystore gives them
/// (design section 3.5).
pub struct AeadSealer {
    dek: [u8; 16],
    key: fstp_crypto::aead::Key,
    digest_key: [u8; 32],
}

impl std::fmt::Debug for AeadSealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadSealer").finish_non_exhaustive()
    }
}

impl AeadSealer {
    /// A sealer with the data key `key` of id `dek` and the digest key
    /// `digest_key`.
    pub fn new(dek: [u8; 16], key: fstp_crypto::aead::Key, digest_key: [u8; 32]) -> AeadSealer {
        AeadSealer {
            dek,
            key,
            digest_key,
        }
    }
}

impl Sealer for AeadSealer {
    fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<crate::store::SealedValue, VaultError> {
        let s = fstp_crypto::aead::seal(&self.key, aad, plain)
            .map_err(|_| VaultError::Unavailable("sealing"))?;
        let mut bytes = s.nonce.to_vec();
        bytes.extend_from_slice(&s.body);
        Ok(crate::store::SealedValue {
            dek: self.dek,
            bytes,
        })
    }

    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, VaultError> {
        let bad = VaultError::Malformed("a sealed value");
        let (nonce, body) = sealed
            .split_at_checked(fstp_crypto::aead::NONCE_LEN)
            .ok_or(bad)?;
        let nonce: [u8; fstp_crypto::aead::NONCE_LEN] = nonce.try_into().map_err(|_| bad)?;
        fstp_crypto::aead::open(&self.key, &nonce, aad, body)
            .map(|p| p.to_vec())
            .map_err(|_| bad)
    }

    fn digest(&self, data: &[u8]) -> [u8; 32] {
        fstp_crypto::hmac_sha256(&self.digest_key, data)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// R-CR-01: a sealed value opens only under its own AAD, and a changed
    /// byte does not open.
    #[test]
    fn r_cr_01_vault_sealer_binds_its_aad() {
        let s = AeadSealer::new(
            [1; 16],
            fstp_crypto::aead::Key::generate().unwrap(),
            [2; 32],
        );
        let v = s.seal(b"aad", b"fact").unwrap();
        assert_eq!(s.open(b"aad", &v.bytes).unwrap(), b"fact");
        assert!(s.open(b"other", &v.bytes).is_err());
        let mut changed = v.bytes.clone();
        if let Some(b) = changed.last_mut() {
            *b ^= 1;
        }
        assert!(s.open(b"aad", &changed).is_err());
    }

    /// Review of lane int5, ADR-009 "Vault origin": the vault origin is
    /// public through the edge, so a peer that opens a connection and then
    /// stalls its handshake must not hold up the next peer. The cell's own
    /// tunnel listener runs each handshake in its own task for this reason
    /// (`fstp_cell::http::tunnel`). Here one silent connection is accepted
    /// first, then a complete one. The complete one must be yielded well
    /// before the silent one's 10 second handshake deadline.
    #[test]
    fn review_vault_tunnel_handshake_stall_blocks_next_peer() {
        use fstp_pgtest::certs::ClusterCa;
        use fstp_rt::tokio::TokioRuntime;

        let rt = TokioRuntime::new_multi_thread(2).unwrap();
        let edge_ca = ClusterCa::generate("review edge CA").unwrap();
        let tunnel_ca = ClusterCa::generate("review tunnel CA").unwrap();
        let origin_ca = ClusterCa::generate("review origin CA").unwrap();
        let tunnel_cert = tunnel_ca.issue_server("vault").unwrap();
        let origin_cert = origin_ca.issue_server("vault").unwrap();
        let edge_cert = edge_ca.issue_role("edge").unwrap();
        let tunnel_cfg = Arc::new(
            fstp_tls::ServerConfig::mutual(
                &tunnel_cert.cert_pem,
                &tunnel_cert.key_pem,
                edge_ca.cert_pem(),
            )
            .unwrap(),
        );
        let origin_cfg = Arc::new(
            fstp_tls::ServerConfig::new(&origin_cert.cert_pem, &origin_cert.key_pem).unwrap(),
        );
        let edge_client = fstp_tls::ClientConfig::mutual(
            tunnel_ca.cert_pem(),
            &edge_cert.cert_pem,
            &edge_cert.key_pem,
        )
        .unwrap();
        let browser = fstp_tls::ClientConfig::new(origin_ca.cert_pem()).unwrap();
        let tcp = rt
            .block_on(rt.bind_tcp(SocketAddr::from(([127, 0, 0, 1], 0))))
            .unwrap();
        let addr = tcp.local_addr().unwrap();
        let stop = fstp_rt::Shutdown::new();
        let mut listener = TunnelListener::new(
            &rt,
            tcp,
            tunnel_cfg,
            origin_cfg,
            "localhost".to_owned(),
            stop.signal(),
        )
        .unwrap();
        // The silent peer connects first and never sends a byte.
        let silent = rt.block_on(rt.connect_tcp(addr)).unwrap();
        let client_rt = rt.clone();
        let complete = rt.spawn(async move {
            client_rt.sleep(Duration::from_millis(200)).await;
            let tcp = client_rt.connect_tcp(addr).await?;
            let mut tunnel = fstp_tls::connect(&edge_client, "localhost", tcp).await?;
            let header = fstp_edge::TunnelHeader::new(
                fstp_edge::HostName::parse(b"localhost").unwrap(),
                SocketAddr::from(([192, 0, 2, 1], 4000)),
            );
            tunnel
                .write_all(&fstp_edge::encode_tunnel_header(&header))
                .await?;
            tunnel.flush().await?;
            let inner = fstp_tls::connect(&browser, "localhost", tunnel).await?;
            Ok::<_, std::io::Error>(inner)
        });
        let started = std::time::Instant::now();
        let accepted = rt.block_on(fstp_rt::timeout(
            &rt,
            Duration::from_secs(4),
            listener.accept(),
        ));
        let waited = started.elapsed();
        drop(silent);
        drop(complete);
        assert!(
            matches!(accepted, Ok(Ok(_))),
            "a complete tunnel connection waited {waited:?} behind a silent one"
        );
    }
}
