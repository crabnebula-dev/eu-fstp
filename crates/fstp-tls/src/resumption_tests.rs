//! Session resumption is bounded by the age of the full handshake (policy
//! P2, R-NF-09).
//!
//! A session can be resumed for less than one hour after the full handshake
//! that authenticated it. After that, a full handshake validates every
//! certificate again. Both sides enforce the bound on their own, and a chain
//! of resumptions never moves it.
//!
//! These tests need crate-internal access: they read the handshake kind of a
//! stream, move each side's clock, and build plain rustls peers that resume
//! without any age bound of their own. No test sleeps.

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

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;

/// 150 years, past the end of every test certificate's validity.
const PAST_EXPIRY_SECS: u64 = 150 * 365 * 24 * HOUR;

const FULL: Option<HandshakeKind> = Some(HandshakeKind::Full);
const RESUMED: Option<HandshakeKind> = Some(HandshakeKind::Resumed);

/// A frozen clock that a test moves. It starts at the real time, so the
/// test certificates are valid at offset zero.
#[derive(Debug)]
struct TestClock {
    base: u64,
    offset: AtomicU64,
}

impl TestClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            base: UnixTime::now().as_secs(),
            offset: AtomicU64::new(0),
        })
    }

    /// Sets the clock to `secs` seconds after its start.
    fn set(&self, secs: u64) {
        self.offset.store(secs, Ordering::SeqCst);
    }
}

impl TimeProvider for TestClock {
    fn current_time(&self) -> Option<UnixTime> {
        let now = self.base.saturating_add(self.offset.load(Ordering::SeqCst));
        Some(UnixTime::since_unix_epoch(Duration::from_secs(now)))
    }
}

/// What one completed session reports.
#[derive(Debug)]
struct Session {
    client_kind: Option<HandshakeKind>,
    server_kind: Option<HandshakeKind>,
    /// The client certificate as the server saw it.
    client_cert: Option<Vec<u8>>,
    /// The server certificate as the client saw it.
    server_cert: Option<Vec<u8>>,
}

impl Session {
    fn kinds(&self) -> (Option<HandshakeKind>, Option<HandshakeKind>) {
        (self.client_kind, self.server_kind)
    }
}

/// Runs a handshake and a short exchange in both directions. The exchange
/// makes the client read everything the server sent after its handshake,
/// including the session ticket.
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
        client_cert: s.peer_end_entity_der().map(<[u8]>::to_vec),
        server_cert: c.peer_end_entity_der().map(<[u8]>::to_vec),
    })
}

/// `built` with its clock replaced. The session cache stays shared.
fn server_with_clock(built: ServerConfig, clock: Arc<dyn TimeProvider>) -> ServerConfig {
    let mut inner = (*built.inner).clone();
    inner.time_provider = clock;
    ServerConfig {
        inner: Arc::new(inner),
        ..built
    }
}

/// `built` with its clock replaced. The session cache stays shared.
fn client_with_clock(built: ClientConfig, clock: Arc<dyn TimeProvider>) -> ClientConfig {
    let mut inner = (*built.inner).clone();
    inner.time_provider = clock;
    ClientConfig {
        inner: Arc::new(inner),
        ..built
    }
}

/// This crate's client and server, with or without mutual TLS, sharing one
/// clock.
fn pair(mutual: bool, clock: &Arc<TestClock>) -> (ClientConfig, ServerConfig) {
    let (client, server) = if mutual {
        (
            ClientConfig::mutual(CA, CLIENT, CLIENT_KEY).unwrap(),
            ServerConfig::mutual(SERVER, SERVER_KEY, CA).unwrap(),
        )
    } else {
        (
            ClientConfig::new(CA).unwrap(),
            ServerConfig::new(SERVER, SERVER_KEY).unwrap(),
        )
    };
    (
        client_with_clock(client, clock.clone()),
        server_with_clock(server, clock.clone()),
    )
}

/// A plain rustls server with its default resumption support: an
/// in-memory session store, two TLS 1.3 tickets per handshake, and no age
/// bound on the server side. It resumes whatever a client offers.
fn plain_rustls_server() -> ServerConfig {
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
    assert!(cfg.session_storage.can_cache(), "precondition: stateful");
    ServerConfig::from_rustls(cfg)
}

/// A plain rustls client with its default resumption cache. It offers any
/// ticket within the lifetime hint the server sent, which is 24 hours for
/// a stateful rustls server.
fn plain_rustls_client() -> ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(CA) {
        roots.add(cert.unwrap()).unwrap();
    }
    let cfg = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    ClientConfig::from_rustls(cfg)
}

/// Runs one session at each clock offset and checks the handshake kind
/// that `side` reports.
fn expect_schedule(
    client: &ClientConfig,
    server: &ServerConfig,
    clock: &TestClock,
    side: fn(&Session) -> Option<HandshakeKind>,
    schedule: &[(u64, Option<HandshakeKind>)],
) {
    for (at, want) in schedule {
        clock.set(*at);
        let s = session(client, server).unwrap();
        assert_eq!(side(&s), *want, "session at +{at}s: {s:?}");
    }
}

/// P2: a second connection within the hour resumes on both sides, with
/// and without mutual TLS. The resumed session carries both certificates
/// of the full handshake that authenticated it.
#[test]
fn p2_second_connection_within_the_hour_resumes() {
    for mutual in [false, true] {
        let clock = TestClock::new();
        let (client, server) = pair(mutual, &clock);
        let first = session(&client, &server).unwrap();
        assert_eq!(first.kinds(), (FULL, FULL), "mutual {mutual}");
        clock.set(30 * MINUTE);
        let second = session(&client, &server).unwrap();
        assert_eq!(second.kinds(), (RESUMED, RESUMED), "mutual {mutual}");
        assert_eq!(second.client_cert, first.client_cert);
        assert_eq!(second.client_cert.is_some(), mutual);
        assert_eq!(second.server_cert, first.server_cert);
        assert!(second.server_cert.is_some());
    }
}

/// P2: resumption ends one hour after the full handshake, and a chain of
/// resumptions never extends that hour. Each resumed session hands out a
/// new ticket, which keeps the time of the original full handshake.
#[test]
fn p2_a_chain_of_resumptions_never_extends_the_hour() {
    let schedule = [
        (0, FULL),
        (20 * MINUTE, RESUMED),
        (40 * MINUTE, RESUMED),
        (HOUR - 1, RESUMED),
        // The newest ticket is one second old, but its session is not.
        (HOUR, FULL),
        (HOUR + 59 * MINUTE, RESUMED),
        (2 * HOUR, FULL),
    ];
    for mutual in [false, true] {
        let clock = TestClock::new();
        let (client, server) = pair(mutual, &clock);
        for (at, want) in schedule {
            clock.set(at);
            let s = session(&client, &server).unwrap();
            assert_eq!(s.kinds(), (want, want), "mutual {mutual}, +{at}s");
        }
    }
}

/// P2: the server enforces the hour on its own. A plain rustls client
/// offers its newest ticket every time, since the lifetime hint is longer
/// than an hour. The server resumes only within the hour after the full
/// handshake.
#[test]
fn p2_server_bounds_resumption_for_a_client_without_a_bound() {
    for mutual in [false, true] {
        let clock = TestClock::new();
        let built = if mutual {
            ServerConfig::mutual(SERVER, SERVER_KEY, CA).unwrap()
        } else {
            ServerConfig::new(SERVER, SERVER_KEY).unwrap()
        };
        let server = server_with_clock(built, clock.clone());
        let client = if mutual {
            let mut roots = rustls::RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(CA) {
                roots.add(cert.unwrap()).unwrap();
            }
            let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(CLIENT)
                .collect::<Result<_, _>>()
                .unwrap();
            let key = PrivateKeyDer::from_pem_slice(CLIENT_KEY).unwrap();
            let cfg = rustls::ClientConfig::builder_with_provider(crypto_provider())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_client_auth_cert(chain, key)
                .unwrap();
            ClientConfig::from_rustls(cfg)
        } else {
            plain_rustls_client()
        };
        expect_schedule(
            &client,
            &server,
            &clock,
            |s| s.server_kind,
            &[
                (0, FULL),
                (20 * MINUTE, RESUMED),
                (HOUR - 1, RESUMED),
                (HOUR, FULL),
                (HOUR + 30 * MINUTE, RESUMED),
                (2 * HOUR, FULL),
            ],
        );
    }
}

/// P2: the client enforces the hour on its own. A plain rustls server
/// resumes any ticket it issued and hints a lifetime of 24 hours. The
/// client offers no session older than an hour, counted from the full
/// handshake, however recent the ticket.
#[test]
fn p2_client_bounds_resumption_for_a_server_without_a_bound() {
    let clock = TestClock::new();
    let client = client_with_clock(ClientConfig::new(CA).unwrap(), clock.clone());
    let server = plain_rustls_server();
    expect_schedule(
        &client,
        &server,
        &clock,
        |s| s.client_kind,
        &[
            (0, FULL),
            (20 * MINUTE, RESUMED),
            (40 * MINUTE, RESUMED),
            (HOUR - 1, RESUMED),
            (HOUR, FULL),
            (HOUR + 30 * MINUTE, RESUMED),
            (2 * HOUR, FULL),
        ],
    );
}

/// R-NF-09, P2: after the hour, a full handshake validates the client
/// certificate again, so an expired one is rejected.
///
/// The client's clock stays at the first session, so the client always
/// offers its ticket. The server's clock moves. Just past the hour the
/// server runs a full handshake and the certificate is still valid. Long
/// past its expiry, the full handshake rejects it.
#[test]
fn r_nf_09_after_the_hour_an_expired_client_certificate_is_rejected() {
    let client_clock = TestClock::new();
    let server_clock = TestClock::new();
    let client = client_with_clock(
        ClientConfig::mutual(CA, CLIENT, CLIENT_KEY).unwrap(),
        client_clock,
    );
    let server = server_with_clock(
        ServerConfig::mutual(SERVER, SERVER_KEY, CA).unwrap(),
        server_clock.clone(),
    );

    let first = session(&client, &server).unwrap();
    assert_eq!(first.kinds(), (FULL, FULL));

    server_clock.set(HOUR);
    let after_hour = session(&client, &server).unwrap();
    assert_eq!(after_hour.server_kind, FULL, "{after_hour:?}");
    assert!(after_hour.client_cert.is_some());

    server_clock.set(PAST_EXPIRY_SECS);
    for attempt in 0..3 {
        let res = session(&client, &server);
        assert_eq!(
            res.as_ref().map(|_| ()),
            Err(&Some(TlsErrorKind::CertificateExpired)),
            "attempt {attempt}: {res:?}"
        );
    }
}

/// P2: every built server configuration resumes statefully through the
/// bounded store. It sends one ticket per handshake, issues no stateless
/// tickets and accepts no early data. The shared rustls configuration
/// stores nothing by itself, so using it directly never resumes.
#[test]
fn p2_built_server_configurations_resume_only_through_the_bounded_store() {
    for server in [
        ServerConfig::new(SERVER, SERVER_KEY).unwrap(),
        ServerConfig::mutual(SERVER, SERVER_KEY, CA).unwrap(),
    ] {
        assert_eq!(server.inner.send_tls13_tickets, 1);
        assert_eq!(server.inner.max_tls13_tickets, 0);
        assert_eq!(server.inner.max_early_data_size, 0);
        assert!(!server.inner.ticketer.enabled(), "no stateless tickets");
        assert!(!server.inner.session_storage.can_cache());
        assert!(server.sessions.is_some());
        let per_connection = server.connection_config();
        assert!(per_connection.session_storage.can_cache());
        assert!(!per_connection.ticketer.enabled());
    }
    for client in [
        ClientConfig::new(CA).unwrap(),
        ClientConfig::mutual(CA, CLIENT, CLIENT_KEY).unwrap(),
    ] {
        assert!(client.sessions.is_some());
        assert!(client.inner.send_ticket_request.is_none());
    }
}

/// P2: clones of a configuration share its session cache, on both sides.
#[test]
fn p2_clones_share_the_session_cache() {
    let clock = TestClock::new();
    let (client, server) = pair(true, &clock);
    assert_eq!(session(&client, &server).unwrap().kinds(), (FULL, FULL));
    let (client2, server2) = (client.clone(), server.clone());
    assert_eq!(
        session(&client2, &server2).unwrap().kinds(),
        (RESUMED, RESUMED)
    );
    // A separately built configuration has its own, empty cache.
    let (fresh_client, _) = pair(true, &clock);
    assert_eq!(
        session(&fresh_client, &server).unwrap().kinds(),
        (FULL, FULL)
    );
}

/// P2 over real handshakes: in random schedules between this crate's
/// client and server, a session resumes exactly when the full handshake
/// that started its chain is less than an hour old.
#[test]
fn p2_random_schedules_resume_exactly_within_the_hour() {
    let cfg = fstp_prop::Config {
        cases: 12,
        ..fstp_prop::Config::default()
    };
    fstp_prop::check_with(
        "p2_random_schedules_resume_exactly_within_the_hour",
        cfg,
        |g| {
            let mutual = g.bool();
            let clock = TestClock::new();
            let (client, server) = pair(mutual, &clock);
            let mut now = 0u64;
            let mut chain_start = None;
            for step in 0..g.usize_in(1..=6) {
                let gap = match g.weighted(&[3, 2, 1]) {
                    0 => g.u64_in(0..=40 * MINUTE),
                    1 => g.u64_in(HOUR - 3..=HOUR + 3),
                    _ => g.u64_in(0..=3 * HOUR),
                };
                now = now.saturating_add(gap);
                clock.set(now);
                let s = session(&client, &server).map_err(|e| format!("step {step}: {e:?}"))?;
                let expect_resumed =
                    chain_start.is_some_and(|start| now.saturating_sub(start) < HOUR);
                let want = if expect_resumed { RESUMED } else { FULL };
                fstp_prop::prop_assert_eq!(s.kinds(), (want, want), "step {} at +{}s", step, now);
                if !expect_resumed {
                    chain_start = Some(now);
                }
            }
            Ok(())
        },
    );
}

/// Finding tls-resumption-skips-client-cert-revalidation, R-NF-09.
///
/// A client whose certificate has expired since its first session must be
/// rejected on every later connection. Before the first fix, the server
/// resumed the earlier session from a TLS 1.3 ticket without any age
/// bound, skipped the client verifier, and reported the expired
/// certificate as the authenticated peer. Policy P2 now allows resumption
/// for one hour only, so a session from long ago is never resumed.
#[test]
fn review_tls_resumption_skips_client_cert_revalidation() {
    let clock = TestClock::new();
    let server = server_with_clock(
        ServerConfig::mutual(SERVER, SERVER_KEY, CA).unwrap(),
        clock.clone(),
    );
    let client = ClientConfig::mutual(CA, CLIENT, CLIENT_KEY).unwrap();

    let first = session(&client, &server).expect("first session, certificate valid");
    assert!(first.client_cert.is_some());

    clock.set(PAST_EXPIRY_SECS);

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
