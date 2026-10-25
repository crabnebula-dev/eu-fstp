//! The TLS stream adapter over any fstp-rt connection.
//!
//! [`TlsStream`] drives a rustls connection with `read_tls`, `write_tls` and
//! `process_new_packets`. Every poll either makes progress on the transport
//! or returns `Pending` with the transport's waker registered, so no path
//! spins. Each loop iteration consumes transport bytes or ends the call.

use std::fmt;
use std::future::poll_fn;
use std::io::{self, Read as _, Write as _};
use std::pin::Pin;
use std::task::{Context, Poll};

use fstp_rt::{AsyncRead, AsyncWrite, Connection};
use rustls::NamedGroup;
use rustls_pki_types::ServerName;

use crate::config::{ClientConfig, ServerConfig};
use crate::error::TlsError;

/// What the transport last did inside a [`SyncIo`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportState {
    /// No call failed or blocked.
    Ok,
    /// A call returned `Pending`, with the waker registered.
    Pending,
    /// A call returned an error.
    Failed,
}

/// Bridges the poll-based transport to the `std::io` traits that rustls
/// expects. `Pending` becomes `WouldBlock`, with the waker registered.
///
/// It records what the transport did, so the caller can tell a transport
/// error from an error that rustls produced itself.
struct SyncIo<'a, 'b, S> {
    io: &'a mut S,
    cx: &'a mut Context<'b>,
    state: TransportState,
}

impl<'a, 'b, S> SyncIo<'a, 'b, S> {
    fn new(io: &'a mut S, cx: &'a mut Context<'b>) -> Self {
        Self {
            io,
            cx,
            state: TransportState::Ok,
        }
    }

    fn track<T>(&mut self, res: Poll<io::Result<T>>) -> io::Result<T> {
        match res {
            Poll::Ready(Ok(v)) => Ok(v),
            Poll::Ready(Err(e)) => {
                self.state = TransportState::Failed;
                Err(e)
            }
            Poll::Pending => {
                self.state = TransportState::Pending;
                Err(io::ErrorKind::WouldBlock.into())
            }
        }
    }
}

impl<S: AsyncRead + Unpin> io::Read for SyncIo<'_, '_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let res = Pin::new(&mut *self.io).poll_read(self.cx, buf);
        self.track(res)
    }
}

impl<S: AsyncWrite + Unpin> io::Write for SyncIo<'_, '_, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let res = Pin::new(&mut *self.io).poll_write(self.cx, buf);
        self.track(res)
    }

    fn flush(&mut self) -> io::Result<()> {
        let res = Pin::new(&mut *self.io).poll_flush(self.cx);
        self.track(res)
    }
}

pub(crate) fn group_name(group: NamedGroup) -> &'static str {
    match group {
        NamedGroup::X25519MLKEM768 => "X25519MLKEM768",
        NamedGroup::X25519 => "X25519",
        NamedGroup::secp256r1 => "secp256r1",
        NamedGroup::secp384r1 => "secp384r1",
        other => other.as_str().unwrap_or("unknown"),
    }
}

/// A TLS 1.3 session over the transport `S`.
///
/// Created by [`connect`] or [`accept`] once the handshake has completed.
///
/// - Reading returns `Ok(0)` only after the peer sent `close_notify`. A
///   transport end of stream without it is a truncation and reads fail with
///   [`io::ErrorKind::UnexpectedEof`].
/// - Writing accepts plaintext up to rustls's bounded send buffer. When that
///   buffer is full and the transport is not writable, writes return
///   `Pending`.
/// - `poll_shutdown` sends `close_notify`, flushes, and then shuts down the
///   transport's write direction. Reading stays possible afterwards, so a
///   side can close first and still read the peer's reply (half-close).
///
/// # Invalid records after `close_notify` (decision D4)
///
/// rustls 0.23.46 marks a connection that sent `close_notify` as if it had
/// sent a fatal alert. When this side then reads an invalid record, rustls
/// queues a fatal alert through `CommonState::send_fatal_alert`. That
/// function starts with `debug_assert!(!self.sent_fatal_alert)`.
///
/// - In builds with debug assertions, such as `cargo test` and fuzz
///   builds, the assertion fails and the read panics.
/// - In release builds, the assertion is compiled out. The read fails with
///   a typed [`TlsError`] of kind [`TlsErrorKind::Protocol`], and the
///   stream stays failed. Writes are already refused after the shutdown.
///   The alert reaches the peer only if the transport still accepts it.
///
/// Half-close reads are kept on purpose (D4). Only a corrupted or hostile
/// record after this side's own `close_notify` reaches the assertion. Fuzz
/// targets avoid that order. The test
/// `d4_invalid_record_after_close_notify` pins both behaviours.
///
/// [`TlsErrorKind::Protocol`]: crate::TlsErrorKind::Protocol
///
/// # Tasks
///
/// Drive each stream from a single task. A read can also write queued TLS
/// records, so it can register the reading task's waker for transport
/// writability. Transports such as the fstp-rt duplex and TCP streams keep
/// one waker per direction. When another task writes to the same stream
/// behind a lock, its waker can be displaced, and that task may then never
/// be woken.
pub struct TlsStream<S> {
    io: S,
    conn: rustls::Connection,
    close_sent: bool,
    failed: Option<TlsError>,
}

impl<S> fmt::Debug for TlsStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsStream")
            .field("handshaking", &self.conn.is_handshaking())
            .field("close_sent", &self.close_sent)
            .field("failed", &self.failed.as_ref().map(TlsError::kind))
            .finish_non_exhaustive()
    }
}

impl<S> TlsStream<S> {
    /// The DER encoding of the peer's end-entity certificate.
    ///
    /// A client always sees the server's certificate. A server sees the
    /// client's certificate only under mutual TLS.
    #[must_use]
    pub fn peer_end_entity_der(&self) -> Option<&[u8]> {
        self.conn
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|cert| cert.as_ref())
    }

    /// The negotiated key exchange group, such as `"X25519MLKEM768"`.
    #[must_use]
    pub fn key_exchange_group(&self) -> Option<&'static str> {
        self.conn
            .negotiated_key_exchange_group()
            .map(|g| group_name(g.name()))
    }

    /// The negotiated cipher suite, such as `"TLS13_AES_256_GCM_SHA384"`.
    #[must_use]
    pub fn cipher_suite(&self) -> Option<&'static str> {
        self.conn
            .negotiated_cipher_suite()
            .map(|s| s.suite().as_str().unwrap_or("unknown"))
    }

    /// True when the negotiated protocol is TLS 1.3. It always is once the
    /// handshake completed, since this crate offers nothing else.
    #[must_use]
    pub fn is_tls13(&self) -> bool {
        self.conn.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3)
    }

    /// The negotiated ALPN protocol, if any.
    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }

    /// On the server side, the server name the client sent (SNI).
    #[must_use]
    pub fn sni(&self) -> Option<&str> {
        match &self.conn {
            rustls::Connection::Server(s) => s.server_name(),
            rustls::Connection::Client(_) => None,
        }
    }

    /// The transport.
    pub fn get_ref(&self) -> &S {
        &self.io
    }

    /// The transport, mutably. Writing to it directly corrupts the session.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.io
    }

    /// Returns the transport and drops the TLS session state.
    pub fn into_inner(self) -> S {
        self.io
    }

    /// True when this session was resumed from an earlier full handshake
    /// instead of running one (policy P2).
    ///
    /// A resumed session validated no certificate itself. It carries the
    /// peer certificate of that full handshake, which ran less than
    /// [`MAX_RESUMPTION_AGE`](crate::MAX_RESUMPTION_AGE) before it.
    #[must_use]
    pub fn is_resumed(&self) -> bool {
        self.conn.handshake_kind() == Some(rustls::HandshakeKind::Resumed)
    }

    /// Whether the handshake was full or resumed, for tests of policy P2.
    #[cfg(test)]
    pub(crate) fn handshake_kind(&self) -> Option<rustls::HandshakeKind> {
        self.conn.handshake_kind()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream<S> {
    fn new(io: S, conn: rustls::Connection) -> Self {
        Self {
            io,
            conn,
            close_sent: false,
            failed: None,
        }
    }

    fn failure(&self) -> Option<io::Error> {
        self.failed.clone().map(TlsError::into_io)
    }

    /// Reads transport bytes into rustls.
    ///
    /// Transport errors are returned as they are. An error that rustls makes
    /// itself becomes a typed [`TlsErrorKind::Protocol`] error and fails
    /// the stream. One example is a handshake message that outgrows rustls's
    /// 64 KiB handshake buffer.
    ///
    /// [`TlsErrorKind::Protocol`]: crate::TlsErrorKind::Protocol
    fn poll_read_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut adapter = SyncIo::new(&mut self.io, cx);
        let res = self.conn.read_tls(&mut adapter);
        match (res, adapter.state) {
            (Ok(n), _) => Poll::Ready(Ok(n)),
            (Err(_), TransportState::Pending) => Poll::Pending,
            (Err(e), TransportState::Failed) => Poll::Ready(Err(e)),
            (Err(e), TransportState::Ok) => {
                let err = TlsError::record_layer(&e);
                self.failed = Some(err.clone());
                Poll::Ready(Err(err.into_io()))
            }
        }
    }

    /// Writes queued TLS records to the transport. Only the transport can
    /// fail here, and its errors are returned as they are.
    fn poll_write_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut adapter = SyncIo::new(&mut self.io, cx);
        let res = self.conn.write_tls(&mut adapter);
        match (res, adapter.state) {
            (Ok(n), _) => Poll::Ready(Ok(n)),
            (Err(_), TransportState::Pending) => Poll::Pending,
            (Err(e), _) => Poll::Ready(Err(e)),
        }
    }

    /// Writes every queued TLS record. `Ready(Ok)` means the queue is empty.
    fn poll_flush_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.conn.wants_write() {
            match self.poll_write_tls(cx) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "transport accepted no TLS data",
                    )));
                }
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Processes records read so far. On failure, remembers the error and
    /// makes one attempt to send the alert that rustls queued.
    fn process(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        match self.conn.process_new_packets() {
            Ok(_) => Ok(()),
            Err(e) => {
                let err = TlsError::from_rustls(e);
                self.failed = Some(err.clone());
                // Best effort: the peer learns why, if the transport allows.
                let _ = self.poll_flush_tls(cx);
                Err(err.into_io())
            }
        }
    }

    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(e) = self.failure() {
            return Poll::Ready(Err(e));
        }
        loop {
            let flushed = self.poll_flush_tls(cx);
            if !self.conn.is_handshaking() {
                if matches!(self.conn, rustls::Connection::Server(_)) {
                    // Any remaining server output is post-handshake data,
                    // such as the session ticket (P2). Later reads, writes
                    // and the shutdown flush whatever is queued and report
                    // its errors. Waiting for it here could deadlock with
                    // a client that does not read yet.
                    return Poll::Ready(Ok(()));
                }
                // A client must deliver its final flight, or the server
                // never completes.
                return match flushed {
                    Poll::Ready(Ok(())) => Pin::new(&mut self.io).poll_flush(cx),
                    other => other,
                };
            }
            let write_blocked = match flushed {
                Poll::Ready(Ok(())) => false,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => true,
            };
            if !write_blocked && !self.conn.wants_read() {
                // Still handshaking, nothing to send and rustls reads no
                // more: the peer closed the session early.
                let err = TlsError::handshake_eof();
                self.failed = Some(err.clone());
                return Poll::Ready(Err(err.into_io()));
            }
            // Read even while a write is blocked. rustls's `wants_read` is
            // false then, which suits blocking IO. With small transport
            // buffers both peers can be writing at once, for example the
            // client's compatibility ChangeCipherSpec during the server's
            // flight. One side must read, or both wait forever.
            match self.poll_read_tls(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    let err = TlsError::handshake_eof();
                    self.failed = Some(err.clone());
                    return Poll::Ready(Err(err.into_io()));
                }
                Poll::Ready(Ok(_)) => self.process(cx)?,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            match this.conn.reader().read(buf) {
                // `Ok(0)` here means the peer sent close_notify.
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                // `UnexpectedEof`: transport EOF without close_notify.
                Err(e) => return Poll::Ready(Err(e)),
            }
            if let Some(e) = this.failure() {
                return Poll::Ready(Err(e));
            }
            // Post-handshake messages, such as a key update reply, may be
            // queued. Errors here resurface on the next write.
            let _ = this.poll_flush_tls(cx);
            match this.poll_read_tls(cx) {
                Poll::Pending => return Poll::Pending,
                // On `Ok(0)`, rustls has recorded the transport EOF and the
                // reader reports it on the next iteration.
                Poll::Ready(Ok(_)) => this.process(cx)?,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(e) = this.failure() {
            return Poll::Ready(Err(e));
        }
        if this.close_sent {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TLS stream already shut down for writing",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Drain queued records first to make room in the bounded buffer.
        let blocked = match this.poll_flush_tls(cx) {
            Poll::Ready(Ok(())) => false,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => true,
        };
        let n = this.conn.writer().write(buf)?;
        if n == 0 {
            if blocked {
                return Poll::Pending;
            }
            return Poll::Ready(Err(io::Error::other(
                "TLS send buffer accepted no data while the transport is writable",
            )));
        }
        // Push the new records out if the transport allows. The plaintext is
        // accepted either way; a transport error resurfaces on the next call.
        let _ = this.poll_flush_tls(cx);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_flush_tls(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.close_sent {
            this.conn.send_close_notify();
            this.close_sent = true;
        }
        match this.poll_flush_tls(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_shutdown(cx),
            other => other,
        }
    }
}

/// Performs a TLS 1.3 client handshake over `io` and returns the stream.
///
/// `server_name` is a DNS name or an IP address literal. The server's
/// certificate must be valid for it and chain to the configured roots. When
/// the configuration holds a client certificate, it is presented on request
/// (R-NF-09).
///
/// Under TLS 1.3 a client finishes its handshake before the server has
/// checked the client certificate. A server that rejects the certificate
/// makes the first read on the returned stream fail with an alert.
///
/// The handshake has no deadline of its own. Wrap it in
/// [`fstp_rt::timeout`] to bound it.
///
/// # Errors
///
/// Returns an [`io::Error`] that wraps a [`TlsError`] when the name is
/// invalid, the peer misbehaves or fails authentication, or the transport
/// closes early. Transport errors are returned as they are.
pub async fn connect<S: Connection>(
    cfg: &ClientConfig,
    server_name: &str,
    io: S,
) -> io::Result<TlsStream<S>> {
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|_| TlsError::config("invalid server name").into_io())?;
    let conn = rustls::ClientConnection::new(cfg.connection_config(), name)
        .map_err(|e| TlsError::config_from("client connection", e).into_io())?;
    let mut stream = TlsStream::new(io, rustls::Connection::Client(conn));
    poll_fn(|cx| stream.poll_handshake(cx)).await?;
    Ok(stream)
}

/// Performs a TLS 1.3 server handshake over `io` and returns the stream.
///
/// When the configuration requires client authentication, a client without
/// a certificate issued under the configured roots is rejected here
/// (R-NF-09).
///
/// The handshake has no deadline of its own. Wrap it in
/// [`fstp_rt::timeout`] to bound it.
///
/// # Errors
///
/// Returns an [`io::Error`] that wraps a [`TlsError`] when the peer
/// misbehaves or fails authentication, or the transport closes early.
/// Transport errors are returned as they are.
pub async fn accept<S: Connection>(cfg: &ServerConfig, io: S) -> io::Result<TlsStream<S>> {
    let conn = rustls::ServerConnection::new(cfg.connection_config())
        .map_err(|e| TlsError::config_from("server connection", e).into_io())?;
    let mut stream = TlsStream::new(io, rustls::Connection::Server(conn));
    poll_fn(|cx| stream.poll_handshake(cx)).await?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    //! Key exchange fallback tests. They build rustls configurations with a
    //! restricted group list, which only crate-internal code can do.

    use std::sync::Arc;

    use fstp_rt::duplex::duplex;
    use fstp_rt::future::{block_on, join};
    use rustls::crypto::SupportedKxGroup;
    use rustls::crypto::aws_lc_rs::kx_group;
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};

    use super::*;
    use crate::provider::crypto_provider;

    const CA: &[u8] = include_bytes!("../testdata/ca.pem");
    const SERVER: &[u8] = include_bytes!("../testdata/server.pem");
    const SERVER_KEY: &[u8] = include_bytes!("../testdata/server-key.pem");

    fn restricted_server(groups: Vec<&'static dyn SupportedKxGroup>) -> ServerConfig {
        let mut provider = (*crypto_provider()).clone();
        provider.kx_groups = groups;
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(SERVER)
            .collect::<Result<_, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_slice(SERVER_KEY).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        ServerConfig::from_rustls(cfg)
    }

    fn restricted_client(groups: Vec<&'static dyn SupportedKxGroup>) -> ClientConfig {
        let mut provider = (*crypto_provider()).clone();
        provider.kx_groups = groups;
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(CA) {
            roots.add(cert.unwrap()).unwrap();
        }
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        ClientConfig::from_rustls(cfg)
    }

    fn negotiate(client: &ClientConfig, server: &ServerConfig) -> (&'static str, &'static str) {
        let (c, s) = duplex(4096);
        let (c, s) = block_on(join(connect(client, "localhost", c), accept(server, s)));
        let c = c.unwrap();
        let s = s.unwrap();
        (
            c.key_exchange_group().unwrap(),
            s.key_exchange_group().unwrap(),
        )
    }

    #[test]
    fn our_client_falls_back_to_x25519_for_a_classical_server() {
        let client = ClientConfig::new(CA).unwrap();
        let server = restricted_server(vec![kx_group::X25519]);
        assert_eq!(negotiate(&client, &server), ("X25519", "X25519"));
    }

    /// PostgreSQL 16 offers only secp256r1 by default; the client reaches it
    /// through a HelloRetryRequest.
    #[test]
    fn our_client_reaches_a_p256_only_server() {
        let client = ClientConfig::new(CA).unwrap();
        let server = restricted_server(vec![kx_group::SECP256R1]);
        assert_eq!(negotiate(&client, &server), ("secp256r1", "secp256r1"));
    }

    #[test]
    fn our_server_accepts_a_classical_client() {
        let server = ServerConfig::new(SERVER, SERVER_KEY).unwrap();
        let client = restricted_client(vec![kx_group::X25519]);
        assert_eq!(negotiate(&client, &server), ("X25519", "X25519"));
    }

    #[test]
    fn our_endpoints_prefer_the_hybrid_group() {
        let server = ServerConfig::new(SERVER, SERVER_KEY).unwrap();
        let client = ClientConfig::new(CA).unwrap();
        assert_eq!(
            negotiate(&client, &server),
            ("X25519MLKEM768", "X25519MLKEM768")
        );
    }

    #[test]
    fn no_common_group_fails_cleanly() {
        let server = restricted_server(vec![kx_group::SECP384R1]);
        let client = restricted_client(vec![kx_group::X25519]);
        let (c, s) = duplex(4096);
        let (c, s) = block_on(join(connect(&client, "localhost", c), accept(&server, s)));
        let s_err = s.unwrap_err();
        assert_eq!(
            TlsError::from_io(&s_err).map(TlsError::kind),
            Some(crate::TlsErrorKind::NoCommonParameters)
        );
        assert!(c.is_err());
    }

    #[test]
    fn group_names_cover_unknown_values() {
        assert_eq!(group_name(NamedGroup::Unknown(0x7777)), "unknown");
        assert_eq!(group_name(NamedGroup::MLKEM768), "MLKEM768");
    }
}
