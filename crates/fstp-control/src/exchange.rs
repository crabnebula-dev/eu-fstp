//! One exchange per connection over mutual TLS (design sections 1.3 and
//! 9.1, R-NF-09).
//!
//! Interim, pending Daniel: the wire framing of the control-private links
//! is not designed. This module matches the cell side in
//! `fstp_cell::control`: the client writes one encoded message, closes its
//! sending side, and reads the reply up to the peer's close. The server
//! reads the request up to the client's close, answers once, and closes.
//! A server that refuses a request closes without a reply, so the client
//! sees a reply that does not decode.
//!
//! The server configuration requires a client certificate that chains to
//! the configured CA, so the TLS handshake refuses every other peer
//! before a byte of the request is read. The handler then sees the
//! verified leaf certificate and decides whether that peer may ask.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use fstp_rt::{IoExt, Listener, Runtime, ShutdownSignal};

/// How long the handshake and the read of one request may take.
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// How long one exchange may take on the client side, connection,
/// handshake and the peer's work included.
pub const CLIENT_TIMEOUT: Duration = Duration::from_secs(120);

/// How long the accept loop waits after an accept error before it tries
/// again, so a full descriptor table does not spin it.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// Serves exchanges on `listener` until `signal` is triggered.
///
/// Each accepted connection runs in its own task, which holds a clone of
/// `signal`, so a drain waits for exchanges in flight. A connection whose
/// handshake fails, whose request exceeds `max_request` bytes, or whose
/// handshake and read take longer than [`READ_TIMEOUT`] is closed without
/// a reply. `handler` gets the DER of the verified client certificate and
/// the request. It returns the reply, or `None` to close without one.
pub async fn serve<R, H, F>(
    rt: R,
    mut listener: R::TcpListener,
    tls: fstp_tls::ServerConfig,
    max_request: usize,
    signal: ShutdownSignal,
    handler: H,
) where
    R: Runtime,
    H: Fn(Vec<u8>, Vec<u8>) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Option<Vec<u8>>> + Send + 'static,
{
    while let Some(accepted) = signal.run_until(listener.accept()).await {
        let Ok((tcp, _peer)) = accepted else {
            rt.sleep(ACCEPT_BACKOFF).await;
            continue;
        };
        let task_signal = signal.clone();
        let task_rt = rt.clone();
        let tls = tls.clone();
        let handler = handler.clone();
        drop(rt.spawn(async move {
            let read = async {
                let mut stream = fstp_tls::accept(&tls, tcp).await?;
                let mut request = Vec::new();
                stream.read_to_end(&mut request, max_request).await?;
                Ok::<_, io::Error>((stream, request))
            };
            let Ok(Ok((mut stream, request))) =
                fstp_rt::timeout(&task_rt, READ_TIMEOUT, read).await
            else {
                drop(task_signal);
                return;
            };
            let peer = stream.peer_end_entity_der().map(<[u8]>::to_vec);
            if let Some(peer) = peer
                && let Some(reply) = handler(peer, request).await
            {
                let write = async {
                    stream.write_all(&reply).await?;
                    stream.flush().await?;
                    stream.shutdown().await
                };
                let _ = fstp_rt::timeout(&task_rt, READ_TIMEOUT, write).await;
            } else {
                let _ = fstp_rt::timeout(&task_rt, READ_TIMEOUT, stream.shutdown()).await;
            }
            drop(task_signal);
        }));
    }
}

/// One exchange from the client side: `request` to `addr`, whose
/// certificate must carry `server_name`, and the reply, at most
/// `max_reply` bytes.
///
/// # Errors
///
/// The connection, handshake or I/O error, or [`io::ErrorKind::TimedOut`]
/// after [`CLIENT_TIMEOUT`].
pub async fn request<R: Runtime>(
    rt: &R,
    addr: SocketAddr,
    server_name: &str,
    tls: &fstp_tls::ClientConfig,
    request: &[u8],
    max_reply: usize,
) -> io::Result<Vec<u8>> {
    let run = async {
        let tcp = rt.connect_tcp(addr).await?;
        let mut stream = fstp_tls::connect(tls, server_name, tcp).await?;
        stream.write_all(request).await?;
        stream.flush().await?;
        stream.shutdown().await?;
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply, max_reply).await?;
        Ok(reply)
    };
    fstp_rt::timeout(rt, CLIENT_TIMEOUT, run)
        .await
        .unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::TimedOut)))
}

/// The common names in the subject of a verified peer certificate, or
/// `None` when the certificate is not valid DER up to its subject or a
/// common name is not UTF-8.
pub fn peer_common_names(cert_der: &[u8]) -> Option<Vec<&str>> {
    fstp_pgwire::x509::subject_common_names(cert_der)
        .ok()?
        .into_iter()
        .map(|cn| std::str::from_utf8(cn).ok())
        .collect()
}

/// Whether the peer certificate names exactly one common name, `want`.
pub fn peer_is(cert_der: &[u8], want: &str) -> bool {
    matches!(peer_common_names(cert_der).as_deref(), Some([cn]) if *cn == want)
}
