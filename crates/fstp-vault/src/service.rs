//! The vault service: its two listeners over mutual TLS, its database
//! and its sans-IO core (design sections 6.1 to 6.3, ADR-009, ADR-010).
//! Lane int5.
//!
//! [`serve`] runs the service on one runtime through `fstp-rt` until its
//! [`VaultHandle`] shuts it down:
//!
//! 1. It connects to `v_<cell>` as `v_<cell>_vault`, reads the placement
//!    marker and refuses anything but a vault database whose server
//!    certificate OU and registered SPKI both name a vault cluster (I-83,
//!    `crate::start::accepts_database`).
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
//! Reading of lane int5, reported to Daniel and the lead: ADR-010 says the
//! vault follows the prepare, receipt and commit steps for its own chain,
//! and open point 5 leaves open which vault rows become chain rows. The
//! vault chain writer is not built. So a call whose journal is not empty
//! is refused with 503, and the copy is dropped: nothing is persisted that
//! the vault chain would have to witness. Calls with an empty journal,
//! such as the epoch read, are answered. No vault fact, query log row or
//! acknowledgement is stored until the vault chain records them.
//!
//! Open I-83 seam, reported to Daniel and the lead: of the three start
//! checks of design section 9.2, only the placement marker is read from
//! the database. `fstp_pgwire::Client` does not expose the server's leaf
//! certificate, so the OU and the SPKI registration are
//! [`VaultParts::server_ou`] and [`VaultParts::registered_spki`], which
//! the caller asserts. A vault pointed at an application cluster whose
//! database carries a vault marker would start. The fix is to expose the
//! leaf from `fstp_pgwire` (lead-owned) and derive both here.

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

/// What the vault starts from.
pub struct VaultParts {
    /// The cell.
    pub cell: [u8; 16],
    /// The `v_<cell>_vault` login.
    pub db: fstp_pgwire::Config,
    /// The kind the database server's certificate OU names. A caller
    /// claim, not read from the session: see "Open I-83 seam" in the
    /// module documentation.
    pub server_ou: ClusterRole,
    /// The kind the server's SPKI is registered for. A caller claim, like
    /// [`VaultParts::server_ou`].
    pub registered_spki: ClusterRole,
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
}

impl std::fmt::Debug for VaultParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultParts")
            .field("origin_host", &self.origin_host)
            .finish_non_exhaustive()
    }
}

/// The vault under its async lock.
#[derive(Default)]
struct Held {
    vault: Vault,
}

/// One call's result.
struct Answer {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

struct Shared {
    held: AsyncMutex<Held>,
}

fn now_us() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0)
}

impl Shared {
    /// Runs `call` on a copy of the vault, and keeps the copy only when its
    /// journal is empty (module documentation).
    async fn run(&self, call: impl FnOnce(&mut Vault) -> Answer) -> Answer {
        let mut held = self.held.lock().await;
        let mut next = held.vault.clone();
        let answer = call(&mut next);
        if !next.take_journal().is_empty() {
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
struct Internal(Arc<Shared>);

impl fstp_http::Handler for Internal {
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
            .run(|v| Answer {
                status: 200,
                headers: vec![("content-type", "application/json".to_owned())],
                body: v.internal_bytes(&body, now),
            })
            .await;
        response(a)
    }
}

/// The vault origin's handler.
struct Origin(Arc<Shared>);

impl fstp_http::Handler for Origin {
    async fn handle(&self, req: fstp_http::Request) -> fstp_http::Response {
        let now = now_us();
        let method = req.method.as_str().to_owned();
        let path = req.target.path().to_owned();
        let body = req.body;
        let a = self
            .0
            .run(|v| {
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
        server_ou,
        registered_spki,
        sealer,
        ticket_keys,
        internal_tls,
        tunnel_tls,
        origin_tls,
        origin_host,
        internal_listen,
        origin_listen,
    } = parts;
    let mut client: Client<R> = Client::connect(&rt, &db)
        .await
        .map_err(|_| VaultError::Unavailable("the vault database"))?;
    let marker = placement_marker(&mut client).await?;
    let view = DatabaseView {
        marker,
        server_ou,
        registered_spki,
    };
    if !accepts_database(&view) {
        return Err(VaultError::Malformed("not a vault database (I-83)"));
    }
    let vault = load(&mut client, sealer.as_ref(), cell, &ticket_keys).await?;
    let shared = Arc::new(Shared {
        held: AsyncMutex::new(Held { vault }),
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
