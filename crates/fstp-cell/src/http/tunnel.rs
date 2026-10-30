//! The tunnel listener of a cell (design sections 1.4, 2.3 and 9.4,
//! ADR-009 "Edge and tunnel"). Lane int5.
//!
//! The edge opens a mutual TLS connection to the cell's tunnel port with
//! its tunnel certificate, writes the tunnel header, and then splices the
//! browser's bytes unchanged. So each connection runs, in order:
//!
//! 1. the tunnel handshake, which requires a client certificate from the
//!    edge's CA;
//! 2. the tunnel header (`fstp_edge::decode_tunnel_header`), whose host
//!    must be the cell host;
//! 3. the browser's own TLS handshake with the cell's origin certificate,
//!    whose SNI must equal the header's host (ADR-009 "Tunnel header
//!    host").
//!
//! A connection that fails any step is closed before an HTTP byte is
//! read. Each handshake runs in its own task under a deadline, so a slow
//! peer never holds up another. [`TunnelListener`] then yields the inner
//! stream to the HTTP server. The peer address it reports is the client
//! address of the header, which only in-memory rate limits read (Q19).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fstp_edge::{TUNNEL_HEADER_LEN, decode_tunnel_header};
use fstp_rt::{IoExt as _, Listener, Runtime, ShutdownSignal};
use fstp_tls::TlsStream;

use crate::engine::chan::{self, Receiver};

/// How long the two handshakes and the header may take together.
pub const TUNNEL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How many accepted connections may wait for the HTTP server.
const QUEUE: usize = 64;

/// The stream a tunnel connection yields: the browser's TLS inside the
/// edge's tunnel TLS.
pub type TunnelStream<R> = TlsStream<TlsStream<<R as Runtime>::Tcp>>;

/// The TLS configurations of a tunnel listener.
#[derive(Clone)]
pub struct TunnelTls {
    /// The tunnel server configuration: the cell's tunnel certificate,
    /// with client authentication against the edge's CA.
    pub tunnel: Arc<fstp_tls::ServerConfig>,
    /// The origin server configuration: the certificate of the host.
    pub origin: Arc<fstp_tls::ServerConfig>,
}

impl std::fmt::Debug for TunnelTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelTls").finish_non_exhaustive()
    }
}

/// A listener that yields the inner streams of tunnel connections.
pub struct TunnelListener<R: Runtime> {
    rx: Receiver<(TunnelStream<R>, SocketAddr)>,
    local: SocketAddr,
}

impl<R: Runtime> std::fmt::Debug for TunnelListener<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelListener")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl<R: Runtime> TunnelListener<R> {
    /// Accepts tunnel connections for `host` on `tcp`, until `signal`
    /// shuts the listener down (module documentation).
    ///
    /// # Errors
    ///
    /// The operating system error when the local address cannot be read.
    pub fn new(
        rt: &R,
        tcp: R::TcpListener,
        tls: TunnelTls,
        host: String,
        signal: ShutdownSignal,
    ) -> io::Result<TunnelListener<R>> {
        let local = tcp.local_addr()?;
        let (tx, rx) = chan::channel(QUEUE);
        let task_rt = rt.clone();
        drop(rt.spawn(async move {
            let mut tcp = tcp;
            loop {
                let Some(accepted) = signal.run_until(tcp.accept()).await else {
                    break;
                };
                let Ok((conn, _peer)) = accepted else {
                    task_rt.sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let tx = tx.clone();
                let tls = tls.clone();
                let host = host.clone();
                let hs_rt = task_rt.clone();
                drop(task_rt.spawn(async move {
                    let shake = handshake::<R>(conn, &tls, &host);
                    if let Ok(Some(ready)) =
                        fstp_rt::timeout(&hs_rt, TUNNEL_HANDSHAKE_TIMEOUT, shake).await
                    {
                        let _ = tx.send(ready).await;
                    }
                }));
            }
        }));
        Ok(TunnelListener { rx, local })
    }
}

/// Steps 1 to 3 of the module documentation, or `None` for a connection
/// that fails one.
async fn handshake<R: Runtime>(
    tcp: R::Tcp,
    tls: &TunnelTls,
    host: &str,
) -> Option<(TunnelStream<R>, SocketAddr)> {
    let mut tunnel = fstp_tls::accept(&tls.tunnel, tcp).await.ok()?;
    let mut header = [0u8; TUNNEL_HEADER_LEN];
    tunnel.read_exact(&mut header).await.ok()?;
    let h = decode_tunnel_header(&header).ok()?;
    if !h.host.as_str().eq_ignore_ascii_case(host) {
        return None;
    }
    let inner = fstp_tls::accept(&tls.origin, tunnel).await.ok()?;
    if !inner
        .sni()
        .is_some_and(|sni| sni.eq_ignore_ascii_case(host))
    {
        return None;
    }
    Some((inner, SocketAddr::new(h.client_ip(), h.port)))
}

impl<R: Runtime> Listener for TunnelListener<R> {
    type Conn = TunnelStream<R>;

    async fn accept(&mut self) -> io::Result<(Self::Conn, SocketAddr)> {
        match self.rx.recv().await {
            Some(c) => Ok(c),
            None => Err(io::Error::from(io::ErrorKind::NotConnected)),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}
