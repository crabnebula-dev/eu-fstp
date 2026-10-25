//! Integration tests for fstp-tls over real loopback TCP and over the
//! in-memory duplex.
//!
//! Tests named `r_nf_09_*` verify R-NF-09: traffic between components is
//! encrypted (TLS 1.3 with the hybrid X25519MLKEM768 group) and mutually
//! authenticated (both sides present certificates from the trusted CA).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use fstp_rt::duplex::{DuplexStream, duplex};
use fstp_rt::future::{block_on, join};
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{AsyncRead, AsyncWrite, Connection, IoExt, Listener, Runtime, timeout};
use fstp_tls::{
    CIPHER_SUITES, ClientConfig, PemLimits, ServerConfig, TlsError, TlsErrorKind, TlsStream,
    accept, connect,
};

macro_rules! testdata {
    ($name:literal) => {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/", $name)).as_slice()
    };
}

const CA: &[u8] = testdata!("ca.pem");
const SERVER: &[u8] = testdata!("server.pem");
const SERVER_KEY: &[u8] = testdata!("server-key.pem");
const CLIENT: &[u8] = testdata!("client.pem");
const CLIENT_KEY: &[u8] = testdata!("client-key.pem");
const UNTRUSTED_CA: &[u8] = testdata!("untrusted-ca.pem");
const UNTRUSTED_SERVER: &[u8] = testdata!("untrusted-server.pem");
const UNTRUSTED_SERVER_KEY: &[u8] = testdata!("untrusted-server-key.pem");
const UNTRUSTED_CLIENT: &[u8] = testdata!("untrusted-client.pem");
const UNTRUSTED_CLIENT_KEY: &[u8] = testdata!("untrusted-client-key.pem");

fn mutual_server() -> ServerConfig {
    ServerConfig::mutual(SERVER, SERVER_KEY, CA).unwrap()
}

fn mutual_client() -> ClientConfig {
    ClientConfig::mutual(CA, CLIENT, CLIENT_KEY).unwrap()
}

/// DER of the first certificate in a PEM file. A small base64 decoder keeps
/// the expected value independent of the PEM parser under test.
fn first_der(pem: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(pem).unwrap();
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    base64_decode(&body)
}

fn base64_decode(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes().filter(|c| *c != b'=') {
        let v = ALPHABET.iter().position(|a| *a == c).unwrap() as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// Deterministic xorshift generator. Not cryptographic.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next() % ((hi - lo + 1) as u64)) as usize
    }
}

fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    (0..len).map(|_| rng.next() as u8).collect()
}

fn tls_kind(e: &io::Error) -> Option<TlsErrorKind> {
    TlsError::from_io(e).map(TlsError::kind)
}

/// Handshakes both sides over a duplex pair on the current thread.
fn duplex_pair(
    client_cfg: &ClientConfig,
    server_cfg: &ServerConfig,
    name: &str,
    capacity: usize,
) -> (
    io::Result<TlsStream<DuplexStream>>,
    io::Result<TlsStream<DuplexStream>>,
) {
    let (c, s) = duplex(capacity);
    block_on(join(connect(client_cfg, name, c), accept(server_cfg, s)))
}

/// Asserts the R-NF-09 properties of an established session.
fn assert_encrypted_and_mutual<S>(client: &TlsStream<S>, server: &TlsStream<S>) {
    assert!(client.is_tls13() && server.is_tls13());
    assert_eq!(client.key_exchange_group(), Some("X25519MLKEM768"));
    assert_eq!(server.key_exchange_group(), Some("X25519MLKEM768"));
    let suite = client.cipher_suite().unwrap();
    assert!(CIPHER_SUITES.contains(&suite));
    assert_eq!(server.cipher_suite(), Some(suite));
    assert_eq!(client.peer_end_entity_der().unwrap(), first_der(SERVER));
    assert_eq!(server.peer_end_entity_der().unwrap(), first_der(CLIENT));
    assert_eq!(server.sni(), Some("localhost"));
    assert_eq!(client.sni(), None);
}

// ------------------------------------------------------------ round trips

/// R-NF-09: mutual TLS handshake and echo over real loopback TCP on tokio.
#[test]
fn r_nf_09_mutual_tls_roundtrip_over_tokio_loopback() {
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    rt.block_on(async {
        let mut listener = rt
            .bind_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server_cfg = mutual_server();
        let server = rt.spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut tls = accept(&server_cfg, tcp).await?;
            let peer = tls.peer_end_entity_der().map(<[u8]>::to_vec);
            let group = tls.key_exchange_group();
            let mut buf = [0u8; 1024];
            loop {
                let n = tls.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                tls.write_all(&buf[..n]).await?;
            }
            tls.shutdown().await?;
            io::Result::Ok((peer, group))
        });

        let tcp = rt.connect_tcp(addr).await.unwrap();
        let mut tls = connect(&mutual_client(), "localhost", tcp).await.unwrap();
        assert_eq!(tls.key_exchange_group(), Some("X25519MLKEM768"));
        assert_eq!(tls.peer_end_entity_der().unwrap(), first_der(SERVER));
        tls.write_all(b"hello over tls").await.unwrap();
        tls.flush().await.unwrap();
        let mut buf = [0u8; 14];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello over tls");
        tls.shutdown().await.unwrap();
        let mut rest = Vec::new();
        tls.read_to_end(&mut rest, 16).await.unwrap();
        assert!(rest.is_empty());

        let (peer, group) = server.await.unwrap().unwrap();
        assert_eq!(peer.unwrap(), first_der(CLIENT));
        assert_eq!(group, Some("X25519MLKEM768"));
    });
}

/// R-NF-09: the same properties over the in-memory duplex transport.
#[test]
fn r_nf_09_mutual_tls_roundtrip_over_duplex() {
    let (client, server) = duplex_pair(&mutual_client(), &mutual_server(), "localhost", 4096);
    let mut client = client.unwrap();
    let mut server = server.unwrap();
    assert_encrypted_and_mutual(&client, &server);
    block_on(async {
        let (a, b) = join(
            async {
                client.write_all(b"ping").await.unwrap();
                client.flush().await.unwrap();
                let mut buf = [0u8; 4];
                client.read_exact(&mut buf).await.unwrap();
                buf
            },
            async {
                let mut buf = [0u8; 4];
                server.read_exact(&mut buf).await.unwrap();
                server.write_all(b"pong").await.unwrap();
                server.flush().await.unwrap();
                buf
            },
        )
        .await;
        assert_eq!(&a, b"pong");
        assert_eq!(&b, b"ping");
    });
}

/// R-NF-09: the hybrid post-quantum group is negotiated between two
/// endpoints built with this crate, over a range of transport capacities.
///
/// Capacities 1 and 7 also guard against a deadlock that an early version
/// had: both peers were blocked writing during the handshake, and neither
/// read.
#[test]
fn r_nf_09_hybrid_group_negotiated_for_all_capacities() {
    for capacity in [1usize, 7, 64, 1500, 65536] {
        let (client, server) =
            duplex_pair(&mutual_client(), &mutual_server(), "localhost", capacity);
        let client = client.unwrap();
        let server = server.unwrap();
        assert_encrypted_and_mutual(&client, &server);
    }
}

/// R-NF-09: the server certificate also validates for its IP SANs.
#[test]
fn r_nf_09_ip_address_server_names() {
    for name in ["127.0.0.1", "::1"] {
        let (client, server) = duplex_pair(&mutual_client(), &mutual_server(), name, 4096);
        assert!(client.is_ok(), "{name}");
        let server = server.unwrap();
        assert_eq!(server.sni(), None, "no SNI for IP literals");
    }
}

// --------------------------------------------------------- rejections

/// R-NF-09: a client without a certificate is rejected by a mutual server.
#[test]
fn r_nf_09_missing_client_certificate_rejected() {
    let no_cert = ClientConfig::new(CA).unwrap();
    let (client, server) = duplex_pair(&no_cert, &mutual_server(), "localhost", 4096);
    let err = server.unwrap_err();
    assert_eq!(tls_kind(&err), Some(TlsErrorKind::CertificateRequired));
    // Under TLS 1.3 the client may finish first; it then learns of the
    // rejection on its first read. It never receives application data.
    match client {
        Err(e) => assert_eq!(tls_kind(&e), Some(TlsErrorKind::PeerAlert)),
        Ok(mut tls) => {
            let mut buf = [0u8; 8];
            let e = block_on(tls.read(&mut buf)).unwrap_err();
            assert_eq!(tls_kind(&e), Some(TlsErrorKind::PeerAlert));
        }
    }
}

/// R-NF-09: a client certificate from an untrusted CA is rejected.
#[test]
fn r_nf_09_untrusted_client_certificate_rejected() {
    let untrusted = ClientConfig::mutual(CA, UNTRUSTED_CLIENT, UNTRUSTED_CLIENT_KEY).unwrap();
    let (client, server) = duplex_pair(&untrusted, &mutual_server(), "localhost", 4096);
    let err = server.unwrap_err();
    assert_eq!(tls_kind(&err), Some(TlsErrorKind::UntrustedCertificate));
    if let Ok(mut tls) = client {
        let mut buf = [0u8; 8];
        let e = block_on(tls.read(&mut buf)).unwrap_err();
        assert_eq!(tls_kind(&e), Some(TlsErrorKind::PeerAlert));
    }
}

/// R-NF-09: a server whose certificate chains to an untrusted CA is
/// rejected by the client, and the server sees the client's alert.
#[test]
fn r_nf_09_untrusted_server_ca_rejected() {
    let server_cfg = ServerConfig::mutual(UNTRUSTED_SERVER, UNTRUSTED_SERVER_KEY, CA).unwrap();
    let (client, server) = duplex_pair(&mutual_client(), &server_cfg, "localhost", 4096);
    let err = client.unwrap_err();
    assert_eq!(tls_kind(&err), Some(TlsErrorKind::UntrustedCertificate));
    let err = server.unwrap_err();
    assert_eq!(tls_kind(&err), Some(TlsErrorKind::PeerAlert));

    // A client that trusts only the untrusted CA rejects the real server.
    let other_roots = ClientConfig::mutual(UNTRUSTED_CA, CLIENT, CLIENT_KEY).unwrap();
    let (client, _server) = duplex_pair(&other_roots, &mutual_server(), "localhost", 4096);
    assert_eq!(
        tls_kind(&client.unwrap_err()),
        Some(TlsErrorKind::UntrustedCertificate)
    );
}

/// R-NF-09: a certificate that is not valid for the requested name is
/// rejected.
#[test]
fn r_nf_09_hostname_mismatch_rejected() {
    for name in [
        "example.com",
        "localhost.localdomain",
        "127.0.0.2",
        "fstp-test-client",
    ] {
        let (client, server) = duplex_pair(&mutual_client(), &mutual_server(), name, 4096);
        let err = client.unwrap_err();
        assert_eq!(tls_kind(&err), Some(TlsErrorKind::NameMismatch), "{name}");
        assert_eq!(
            tls_kind(&server.unwrap_err()),
            Some(TlsErrorKind::PeerAlert),
            "{name}"
        );
    }
}

#[test]
fn invalid_server_names_are_config_errors() {
    for name in ["", "bad name", "a..b"] {
        let (c, _s) = duplex(64);
        let err = block_on(connect(&mutual_client(), name, c)).unwrap_err();
        assert_eq!(tls_kind(&err), Some(TlsErrorKind::Config), "{name:?}");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}

// ------------------------------------------------- large transfers

/// Sends `data` from `tx` to `rx` in random chunk sizes while `rx` reads
/// with random buffer sizes, then checks equality.
async fn transfer<A: Connection, B: Connection>(
    tx: &mut TlsStream<A>,
    rx: &mut TlsStream<B>,
    data: &[u8],
    seed: u64,
) {
    let send = async {
        let mut rng = Rng::new(seed);
        let mut pos = 0;
        while pos < data.len() {
            let n = rng.range(1, 70_000).min(data.len() - pos);
            tx.write_all(&data[pos..pos + n]).await.unwrap();
            pos += n;
            if rng.range(0, 9) == 0 {
                tx.flush().await.unwrap();
            }
        }
        tx.flush().await.unwrap();
    };
    let recv = async {
        let mut rng = Rng::new(seed ^ 0xFFFF);
        let mut got = Vec::with_capacity(data.len());
        let mut buf = vec![0u8; 40_000];
        while got.len() < data.len() {
            let n = rng.range(1, buf.len());
            let k = rx.read(&mut buf[..n]).await.unwrap();
            assert!(k > 0, "unexpected end of stream");
            got.extend_from_slice(&buf[..k]);
        }
        got
    };
    let ((), got) = join(send, recv).await;
    assert!(got == data, "payload mismatch");
}

#[test]
fn large_transfers_with_varied_chunks_over_duplex() {
    for (seed, capacity) in [(1u64, 1usize), (2, 333), (3, 16_384), (4, 100_000)] {
        let len = if capacity == 1 { 40_000 } else { 1_500_000 };
        let (client, server) =
            duplex_pair(&mutual_client(), &mutual_server(), "localhost", capacity);
        let mut client = client.unwrap();
        let mut server = server.unwrap();
        let up = pattern(len, seed);
        let down = pattern(len / 2, seed + 100);
        block_on(async {
            // Client to server, then server to client. The tokio test below
            // runs both directions at once.
            transfer(&mut client, &mut server, &up, seed).await;
            transfer(&mut server, &mut client, &down, seed + 1).await;
        });
    }
}

#[test]
fn large_bidirectional_transfer_over_tokio_loopback() {
    let rt = TokioRuntime::new_multi_thread(4).unwrap();
    rt.block_on(async {
        let mut listener = rt
            .bind_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server_cfg = mutual_server();
        let len = 8 * 1024 * 1024;
        let server = rt.spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = accept(&server_cfg, tcp).await.unwrap();
            // Echo everything back while reading, so both directions are
            // busy at the same time.
            let mut buf = vec![0u8; 50_000];
            let mut total = 0usize;
            loop {
                let n = tls.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                tls.write_all(&buf[..n]).await.unwrap();
                total += n;
            }
            tls.shutdown().await.unwrap();
            total
        });
        let tcp = rt.connect_tcp(addr).await.unwrap();
        let tls = connect(&mutual_client(), "localhost", tcp).await.unwrap();
        let data = pattern(len, 77);
        let (mut rd, mut wr) = split(tls);
        let expected = data.clone();
        let (sent, got) = join(
            async {
                let mut rng = Rng::new(5);
                let mut pos = 0;
                while pos < data.len() {
                    let n = rng.range(1, 100_000).min(data.len() - pos);
                    wr.write_all(&data[pos..pos + n]).await.unwrap();
                    pos += n;
                }
                wr.shutdown().await.unwrap();
                pos
            },
            async {
                let mut got = Vec::new();
                rd.read_to_end(&mut got, len + 1).await.unwrap();
                got
            },
        )
        .await;
        assert_eq!(sent, len);
        assert!(got == expected, "echo mismatch");
        assert_eq!(server.await.unwrap(), len);
    });
}

/// Shares one stream between a read half and a write half for tests.
fn split<S: Connection>(s: S) -> (Half<S>, Half<S>) {
    let shared = Arc::new(std::sync::Mutex::new(s));
    (Half(shared.clone()), Half(shared))
}

struct Half<S>(Arc<std::sync::Mutex<S>>);

impl<S: Connection> AsyncRead for Half<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_read(cx, buf)
    }
}

impl<S: Connection> AsyncWrite for Half<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_shutdown(cx)
    }
}

// ------------------------------------------------- shutdown and truncation

#[test]
fn clean_shutdown_in_both_directions() {
    let (client, server) = duplex_pair(&mutual_client(), &mutual_server(), "localhost", 4096);
    let mut client = client.unwrap();
    let mut server = server.unwrap();
    block_on(async {
        client.write_all(b"last words").await.unwrap();
        client.shutdown().await.unwrap();
        // Writing after shutdown fails.
        let err = client.write(b"more").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

        let mut got = Vec::new();
        server.read_to_end(&mut got, 64).await.unwrap();
        assert_eq!(got, b"last words");
        // End of stream after close_notify is sticky.
        let mut buf = [0u8; 4];
        assert_eq!(server.read(&mut buf).await.unwrap(), 0);

        // Half-close: the server can still answer.
        server.write_all(b"reply").await.unwrap();
        server.shutdown().await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got, 64).await.unwrap();
        assert_eq!(got, b"reply");
    });
}

/// A transport EOF without close_notify is a truncation, not a clean end.
#[test]
fn truncation_without_close_notify_is_an_error() {
    let (client, server) = duplex_pair(&mutual_client(), &mutual_server(), "localhost", 4096);
    let mut client = client.unwrap();
    let mut server = server.unwrap();
    block_on(async {
        client.write_all(b"complete record").await.unwrap();
        client.flush().await.unwrap();
        // Close the raw transport, bypassing close_notify.
        client.get_mut().shutdown().await.unwrap();

        let mut buf = [0u8; 15];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"complete record");
        let err = server.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        // The error is sticky.
        let err = server.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    });
}

/// A transport that forwards only the first `budget` bytes written after
/// arming, silently discarding the rest. It models a cut connection.
struct Cut {
    inner: DuplexStream,
    budget: Option<usize>,
}

impl AsyncRead for Cut {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Cut {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.budget {
            None => Pin::new(&mut self.inner).poll_write(cx, buf),
            Some(0) => Poll::Ready(Ok(buf.len())),
            Some(b) => {
                let n = b.min(buf.len());
                match Pin::new(&mut self.inner).poll_write(cx, &buf[..n]) {
                    Poll::Ready(Ok(k)) => {
                        self.budget = Some(b - k);
                        Poll::Ready(Ok(k))
                    }
                    other => other,
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Truncation in the middle of a record is detected as well.
#[test]
fn truncation_mid_record_is_an_error() {
    let (c, s) = duplex(4096);
    let cut = Cut {
        inner: c,
        budget: None,
    };
    let (client, server) = block_on(join(
        connect(&mutual_client(), "localhost", cut),
        accept(&mutual_server(), s),
    ));
    let mut client = client.unwrap();
    let mut server = server.unwrap();
    block_on(async {
        client.get_mut().budget = Some(10);
        client.write_all(&[0x55u8; 1000]).await.unwrap();
        client.flush().await.unwrap();
        client.get_mut().inner.shutdown().await.unwrap();
        let mut buf = [0u8; 100];
        let err = server.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    });
}

// ------------------------------------------------- handshake failures

/// A peer that closes during the handshake yields a typed error.
#[test]
fn eof_during_handshake() {
    let (c, s) = duplex(4096);
    drop(c);
    let err = block_on(accept(&mutual_server(), s)).unwrap_err();
    assert_eq!(tls_kind(&err), Some(TlsErrorKind::HandshakeEof));
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

    // The client sends its hello, then the server side disappears.
    let (c, s) = duplex(65536);
    let cfg = mutual_client();
    let res = block_on(async {
        let client = connect(&cfg, "localhost", c);
        let killer = async move {
            drop(s);
        };
        join(client, killer).await.0
    });
    let err = res.unwrap_err();
    assert!(
        tls_kind(&err) == Some(TlsErrorKind::HandshakeEof)
            || err.kind() == io::ErrorKind::BrokenPipe,
        "{err:?}"
    );
}

/// Bytes that are not TLS are rejected without a hang.
#[test]
fn garbage_from_client_is_a_protocol_error() {
    let (mut c, s) = duplex(4096);
    let res = block_on(async {
        let writer = async {
            c.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();
            c.shutdown().await.unwrap();
        };
        join(accept(&mutual_server(), s), writer).await.0
    });
    let err = res.unwrap_err();
    assert_eq!(tls_kind(&err), Some(TlsErrorKind::Protocol), "{err:?}");
}

/// A client talking to an echo server sees its own ClientHello come back.
#[test]
fn client_rejects_its_own_reflected_hello() {
    let (c, mut s) = duplex(65536);
    let res = block_on(async {
        let echo = async {
            let mut buf = [0u8; 4096];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        };
        let client = async {
            let r = connect(&mutual_client(), "localhost", c).await;
            r.map(|_| ())
        };
        join(client, echo).await.0
    });
    let err = res.unwrap_err();
    assert!(
        matches!(
            tls_kind(&err),
            Some(TlsErrorKind::Protocol) | Some(TlsErrorKind::PeerAlert)
        ),
        "{err:?}"
    );
}

/// A server with no common ALPN protocol refuses the handshake.
#[test]
fn alpn_negotiation() {
    let client = ClientConfig::builder(CA)
        .client_auth_pem(CLIENT, CLIENT_KEY)
        .alpn_protocols(&[b"h2", b"http/1.1"])
        .build()
        .unwrap();
    let server = ServerConfig::builder(SERVER, SERVER_KEY)
        .require_client_auth(CA)
        .alpn_protocols(&[b"http/1.1"])
        .build()
        .unwrap();
    let (c, s) = duplex_pair(&client, &server, "localhost", 4096);
    assert_eq!(c.unwrap().alpn(), Some(&b"http/1.1"[..]));
    assert_eq!(s.unwrap().alpn(), Some(&b"http/1.1"[..]));

    let other = ServerConfig::builder(SERVER, SERVER_KEY)
        .alpn_protocols(&[b"pgsql"])
        .build()
        .unwrap();
    let (c, s) = duplex_pair(&client, &other, "localhost", 4096);
    assert!(s.is_err());
    assert!(c.is_err());

    // Without ALPN on either side, none is reported.
    let (c, _s) = duplex_pair(&mutual_client(), &mutual_server(), "localhost", 4096);
    assert_eq!(c.unwrap().alpn(), None);
}

/// A server without client authentication does not request a certificate.
#[test]
fn server_without_client_auth() {
    let server = ServerConfig::new(SERVER, SERVER_KEY).unwrap();
    let client = ClientConfig::new(CA).unwrap();
    let (c, s) = duplex_pair(&client, &server, "localhost", 4096);
    let c = c.unwrap();
    let s = s.unwrap();
    assert!(s.peer_end_entity_der().is_none());
    assert_eq!(c.peer_end_entity_der().unwrap(), first_der(SERVER));
    // A client with a certificate is accepted too; it is just not asked.
    let (c, s) = duplex_pair(&mutual_client(), &server, "localhost", 4096);
    assert!(c.is_ok());
    assert!(s.unwrap().peer_end_entity_der().is_none());
}

// ------------------------------------------------- configuration errors

#[test]
fn configuration_errors_are_typed() {
    fn kind<T>(r: Result<T, TlsError>) -> TlsErrorKind {
        match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => e.kind(),
        }
    }
    assert_eq!(kind(ClientConfig::new(b"")), TlsErrorKind::Config);
    assert_eq!(
        kind(ClientConfig::new(b"not pem at all")),
        TlsErrorKind::Config
    );
    assert_eq!(kind(ClientConfig::new(CLIENT_KEY)), TlsErrorKind::Config);
    // Key that does not match the certificate.
    assert_eq!(
        kind(ServerConfig::new(SERVER, CLIENT_KEY)),
        TlsErrorKind::Config
    );
    assert_eq!(
        kind(ClientConfig::mutual(CA, CLIENT, SERVER_KEY)),
        TlsErrorKind::Config
    );
    // Missing key.
    assert_eq!(kind(ServerConfig::new(SERVER, b"")), TlsErrorKind::Config);
    // Limits.
    let tiny = PemLimits {
        max_input_bytes: 100,
        max_certificates: 256,
    };
    assert_eq!(
        kind(ClientConfig::builder(CA).pem_limits(tiny).build()),
        TlsErrorKind::Config
    );
    let mut two = CA.to_vec();
    two.extend_from_slice(UNTRUSTED_CA);
    let one_cert = PemLimits {
        max_input_bytes: 1 << 20,
        max_certificates: 1,
    };
    assert_eq!(
        kind(ClientConfig::builder(&two).pem_limits(one_cert).build()),
        TlsErrorKind::Config
    );
    assert!(
        ClientConfig::new(&two).is_ok(),
        "two roots are fine by default"
    );
    // ALPN bounds.
    let long = [b'x'; 256];
    assert_eq!(
        kind(ClientConfig::builder(CA).alpn_protocols(&[&long]).build()),
        TlsErrorKind::Config
    );
    assert_eq!(
        kind(ClientConfig::builder(CA).alpn_protocols(&[b""]).build()),
        TlsErrorKind::Config
    );
    let many: Vec<&[u8]> = (0..17).map(|_| b"p".as_slice()).collect();
    assert_eq!(
        kind(
            ServerConfig::builder(SERVER, SERVER_KEY)
                .alpn_protocols(&many)
                .build()
        ),
        TlsErrorKind::Config
    );
}

#[test]
fn key_material_never_appears_in_error_messages() {
    // A damaged key: keep the BEGIN line, corrupt the base64 body.
    let text = std::str::from_utf8(SERVER_KEY).unwrap();
    let damaged = text.replace('A', "*");
    let err = ServerConfig::new(SERVER, damaged.as_bytes()).unwrap_err();
    let shown = format!("{err} {err:?}");
    for line in text.lines().filter(|l| !l.starts_with("-----")) {
        assert!(!shown.contains(line), "error text leaks key material");
    }
    let debug = format!("{:?} {:?}", mutual_client(), mutual_server());
    assert!(!debug.contains("PRIVATE"));
}

// ------------------------------------------------- backpressure and polling

struct CountingWaker(AtomicBool);

impl Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// When the reader stalls, writes return `Pending` after a bounded amount
/// of buffered data, and resume once the reader drains.
#[test]
fn writes_apply_backpressure_without_spinning() {
    let (client, server) = duplex_pair(&mutual_client(), &mutual_server(), "localhost", 1024);
    let mut client = client.unwrap();
    let mut server = server.unwrap();
    let flag = Arc::new(CountingWaker(AtomicBool::new(false)));
    let waker = Waker::from(flag.clone());
    let mut cx = Context::from_waker(&waker);
    let chunk = [0xA5u8; 4096];
    let mut accepted = 0usize;
    let mut polls = 0usize;
    loop {
        polls += 1;
        assert!(polls < 10_000, "writer never blocked");
        match Pin::new(&mut client).poll_write(&mut cx, &chunk) {
            Poll::Ready(Ok(n)) => {
                assert!(n > 0);
                accepted += n;
            }
            Poll::Ready(Err(e)) => panic!("{e}"),
            Poll::Pending => break,
        }
    }
    // rustls buffers at most 64 KiB plus record overhead, and the transport
    // holds 1 KiB.
    assert!(
        accepted <= 80 * 1024,
        "accepted {accepted} bytes while stalled"
    );
    assert!(!flag.0.load(Ordering::SeqCst), "no wake-up before progress");

    // One read on the server side consumes transport bytes, even if no full
    // record arrived yet. That must wake the blocked writer.
    let mut buf = vec![0u8; 8192];
    let mut drained = 0usize;
    match Pin::new(&mut server).poll_read(&mut cx, &mut buf) {
        Poll::Ready(Ok(n)) => drained += n,
        Poll::Ready(Err(e)) => panic!("{e}"),
        Poll::Pending => {}
    }
    assert!(
        flag.0.load(Ordering::SeqCst),
        "reader progress woke the writer"
    );
    // Finish the transfer and check the byte count.
    block_on(async {
        let (_, total) = join(
            async {
                client.write_all(&chunk[..100]).await.unwrap();
                client.shutdown().await.unwrap();
            },
            async {
                let mut rest = Vec::new();
                server.read_to_end(&mut rest, 1 << 24).await.unwrap();
                drained + rest.len()
            },
        )
        .await;
        assert_eq!(total, accepted + 100);
    });
}

/// Runs both handshake futures with a scheduler that polls a future only
/// after its waker fired, and counts polls. A missing wake-up would leave
/// both futures pending; a busy loop would show as a huge poll count.
#[test]
fn handshake_wakeups_are_precise() {
    for capacity in [1usize, 100, 4096] {
        let (c, s) = duplex(capacity);
        let client_cfg = mutual_client();
        let server_cfg = mutual_server();
        let mut client = Box::pin(connect(&client_cfg, "localhost", c));
        let mut server = Box::pin(accept(&server_cfg, s));
        let cf = Arc::new(CountingWaker(AtomicBool::new(true)));
        let sf = Arc::new(CountingWaker(AtomicBool::new(true)));
        let cw = Waker::from(cf.clone());
        let sw = Waker::from(sf.clone());
        let (mut c_done, mut s_done) = (None, None);
        let mut polls = 0usize;
        while c_done.is_none() || s_done.is_none() {
            let mut progressed = false;
            if c_done.is_none() && cf.0.swap(false, Ordering::SeqCst) {
                progressed = true;
                polls += 1;
                if let Poll::Ready(r) = client.as_mut().poll(&mut Context::from_waker(&cw)) {
                    c_done = Some(r.map(|_| ()));
                }
            }
            if s_done.is_none() && sf.0.swap(false, Ordering::SeqCst) {
                progressed = true;
                polls += 1;
                if let Poll::Ready(r) = server.as_mut().poll(&mut Context::from_waker(&sw)) {
                    s_done = Some(r.map(|_| ()));
                }
            }
            assert!(progressed, "lost wake-up at capacity {capacity}");
            assert!(polls < 50_000, "busy loop at capacity {capacity}");
        }
        c_done.unwrap().unwrap();
        s_done.unwrap().unwrap();
    }
}

/// A handshake against a silent peer can be bounded with fstp-rt's timeout.
#[test]
fn handshake_timeout_with_runtime() {
    let rt = TokioRuntime::new_current_thread().unwrap();
    rt.block_on(async {
        let (c, _s) = duplex(4096);
        let res = timeout(
            &rt,
            Duration::from_millis(50),
            connect(&mutual_client(), "localhost", c),
        )
        .await;
        assert!(res.is_err(), "silent peer must not complete a handshake");
    });
}
