//! Session resumption is off on both sides (policy P2, R-NF-09).
//!
//! These tests need crate-internal access: they read the handshake kind of a
//! stream, move a server's clock, and build plain rustls peers that do
//! support resumption.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fstp_rt::IoExt;
use fstp_rt::duplex::duplex;
use fstp_rt::future::{block_on, join};
use rustls::HandshakeKind;
use rustls::time_provider::TimeProvider;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, UnixTime};

use crate::provider::crypto_provider;
use crate::{ClientConfig, ServerConfig, TlsError, TlsErrorKind, accept, connect};

const CA: &[u8] = include_bytes!("../testdata/ca.pem");
const CLIENT: &[u8] = include_bytes!("../testdata/client.pem");
const CLIENT_KEY: &[u8] = include_bytes!("../testdata/client-key.pem");
const SERVER: &[u8] = include_bytes!("../testdata/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("../testdata/server-key.pem");

/// 150 years, past the end of every test certificate's validity.
const PAST_EXPIRY_SECS: u64 = 150 * 365 * 24 * 60 * 60;

/// Real time plus an offset that the test sets.
#[derive(Debug, Default)]
struct ShiftedClock(AtomicU64);

impl TimeProvider for ShiftedClock {
    fn current_time(&self) -> Option<UnixTime> {
        let now = UnixTime::now().as_secs();
        let shifted = now.saturating_add(self.0.load(Ordering::SeqCst));
        Some(UnixTime::since_unix_epoch(Duration::from_secs(shifted)))
    }
}

/// What one completed session reports.
#[derive(Debug)]
struct Session {
    client_kind: Option<HandshakeKind>,
    server_kind: Option<HandshakeKind>,
    server_saw_client_cert: bool,
}

/// Runs a handshake and a short exchange in both directions. The exchange
/// makes the client read everything the server sent after its handshake,
/// including session tickets if the server issued any.
fn session(client: &ClientConfig, server: &ServerConfig) -> Result<Session, Option<TlsErrorKind>> {
    let kind = |e: &std::io::Error| TlsError::from_io(e).map(TlsError::kind);
    let (c, s) = duplex(1 << 16);
    let (c, s) = block_on(join(connect(client, "localhost", c), accept(server, s)));
    let mut s = s.map_err(|e| kind(&e))?;
    let mut c = c.map_err(|e| kind(&e))?;
    let (from_server, from_client) = block_on(join(
        async {
            c.write_all(b"ping").await?;
            c.shutdown().await?;
            let mut out = Vec::new();
            c.read_to_end(&mut out, 64).await?;
            Ok::<_, std::io::Error>(out)
        },
        async {
            let mut out = Vec::new();
            s.read_to_end(&mut out, 64).await?;
            s.write_all(b"pong").await?;
            s.shutdown().await?;
            Ok::<_, std::io::Error>(out)
        },
    ));
    assert_eq!(from_server.map_err(|e| kind(&e))?, b"pong");
    assert_eq!(from_client.map_err(|e| kind(&e))?, b"ping");
    Ok(Session {
        client_kind: c.handshake_kind(),
        server_kind: s.handshake_kind(),
        server_saw_client_cert: s.peer_end_entity_der().is_some(),
    })
}

/// `ServerConfig::mutual` with a clock that the test controls.
fn mutual_server_with_clock(clock: Arc<ShiftedClock>) -> ServerConfig {
    let built = ServerConfig::mutual(SERVER, SERVER_KEY, CA).unwrap();
    let mut inner = (*built.inner).clone();
    inner.time_provider = clock;
    ServerConfig {
        inner: Arc::new(inner),
    }
}

/// A plain rustls server with its default resumption support: an
/// in-memory session store and two TLS 1.3 tickets per handshake.
fn resuming_rustls_server() -> ServerConfig {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(SERVER)
        .collect::<Result<_, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(SERVER_KEY).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    assert!(cfg.send_tls13_tickets > 0, "precondition: tickets enabled");
    ServerConfig {
        inner: Arc::new(cfg),
    }
}

/// A plain rustls client with its default resumption cache.
fn resuming_rustls_client() -> ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(CA) {
        roots.add(cert.unwrap()).unwrap();
    }
    let cfg = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    ClientConfig {
        inner: Arc::new(cfg),
    }
}

/// Finding tls-resumption-skips-client-cert-revalidation, R-NF-09.
///
/// A client whose certificate has expired since its first session must be
/// rejected on every later connection. Before the fix, the server resumed
/// the earlier session from a TLS 1.3 ticket, skipped the client verifier,
/// and reported the expired certificate as the authenticated peer.
#[test]
fn review_tls_resumption_skips_client_cert_revalidation() {
    let clock = Arc::new(ShiftedClock::default());
    let server = mutual_server_with_clock(clock.clone());
    let client = ClientConfig::mutual(CA, CLIENT, CLIENT_KEY).unwrap();

    let first = session(&client, &server).expect("first session, certificate valid");
    assert!(first.server_saw_client_cert);

    clock.0.store(PAST_EXPIRY_SECS, Ordering::SeqCst);

    // A client without any earlier session is rejected: the clock works.
    let fresh = ClientConfig::mutual(CA, CLIENT, CLIENT_KEY).unwrap();
    assert_eq!(
        session(&fresh, &server).map(|_| ()),
        Err(Some(TlsErrorKind::CertificateExpired))
    );

    // The client from the first session is rejected the same way, however
    // often it reconnects.
    for attempt in 0..3 {
        let res = session(&client, &server);
        assert_eq!(
            res.as_ref().map(|_| ()),
            Err(&Some(TlsErrorKind::CertificateExpired)),
            "attempt {attempt}: {res:?}"
        );
    }
}

/// P2, R-NF-09: repeated connections between this crate's client and server
/// each run a full handshake, with and without mutual TLS.
#[test]
fn every_connection_runs_a_full_handshake() {
    let pairs = [
        (
            ClientConfig::new(CA).unwrap(),
            ServerConfig::new(SERVER, SERVER_KEY).unwrap(),
        ),
        (
            ClientConfig::mutual(CA, CLIENT, CLIENT_KEY).unwrap(),
            ServerConfig::mutual(SERVER, SERVER_KEY, CA).unwrap(),
        ),
    ];
    for (client, server) in &pairs {
        for attempt in 0..3 {
            let s = session(client, server).unwrap();
            assert_eq!(
                s.client_kind,
                Some(HandshakeKind::Full),
                "attempt {attempt}"
            );
            assert_eq!(
                s.server_kind,
                Some(HandshakeKind::Full),
                "attempt {attempt}"
            );
        }
    }
}

/// P2: the client keeps no session cache, so it runs a full handshake and
/// validates the certificate even when the server offers tickets.
#[test]
fn client_never_resumes_with_a_ticket_issuing_server() {
    let client = ClientConfig::new(CA).unwrap();
    let server = resuming_rustls_server();
    for attempt in 0..3 {
        let s = session(&client, &server).unwrap();
        assert_eq!(
            s.client_kind,
            Some(HandshakeKind::Full),
            "attempt {attempt}"
        );
    }
}

/// P2: the server issues no tickets and keeps no session store, so a
/// client that would resume still gets a full handshake.
#[test]
fn server_never_resumes_with_a_caching_client() {
    let client = resuming_rustls_client();
    let server = ServerConfig::new(SERVER, SERVER_KEY).unwrap();
    for attempt in 0..3 {
        let s = session(&client, &server).unwrap();
        assert_eq!(
            s.server_kind,
            Some(HandshakeKind::Full),
            "attempt {attempt}"
        );
    }
}

/// P2: every built server configuration carries the settings that disable
/// resumption. The client side has no getter and is covered above.
#[test]
fn built_configurations_disable_resumption() {
    for server in [
        ServerConfig::new(SERVER, SERVER_KEY).unwrap(),
        ServerConfig::mutual(SERVER, SERVER_KEY, CA).unwrap(),
    ] {
        assert_eq!(server.inner.send_tls13_tickets, 0);
        assert!(!server.inner.session_storage.can_cache());
        assert!(!server.inner.ticketer.enabled());
    }
}
