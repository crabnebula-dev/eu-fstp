//! Server authentication against the public root store (ADR-001
//! amendment of 2026-11-06, webpki-roots).
//!
//! Tests named `r_nf_09_*` verify R-NF-09 for links to external services:
//! the client always verifies the server certificate chain and host name.
//! The test CA is not a public root, so a server under it stands for a
//! server under an unknown CA. A pinned CA added on top of the public roots
//! reaches the host name check through the same verifier.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io;

use fstp_rt::duplex::{DuplexStream, duplex};
use fstp_rt::future::{block_on, join};
use fstp_tls::{ClientConfig, ServerConfig, TlsError, TlsErrorKind, TlsStream, accept, connect};

macro_rules! testdata {
    ($name:literal) => {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/", $name)).as_slice()
    };
}

const CA: &[u8] = testdata!("ca.pem");
const SERVER: &[u8] = testdata!("server.pem");
const SERVER_KEY: &[u8] = testdata!("server-key.pem");
const UNTRUSTED_SERVER: &[u8] = testdata!("untrusted-server.pem");
const UNTRUSTED_SERVER_KEY: &[u8] = testdata!("untrusted-server-key.pem");

fn tls_kind(e: &io::Error) -> Option<TlsErrorKind> {
    TlsError::from_io(e).map(TlsError::kind)
}

fn handshake(
    client_cfg: &ClientConfig,
    server_cfg: &ServerConfig,
    name: &str,
) -> (
    io::Result<TlsStream<DuplexStream>>,
    io::Result<TlsStream<DuplexStream>>,
) {
    let (c, s) = duplex(4096);
    block_on(join(connect(client_cfg, name, c), accept(server_cfg, s)))
}

/// R-NF-09: with the public roots only, a server whose certificate chains
/// to a CA outside the public root store is refused, under either test CA.
#[test]
fn r_nf_09_public_roots_refuse_unknown_ca() {
    let client = ClientConfig::public_roots().unwrap();
    for (chain, key) in [
        (SERVER, SERVER_KEY),
        (UNTRUSTED_SERVER, UNTRUSTED_SERVER_KEY),
    ] {
        let server = ServerConfig::new(chain, key).unwrap();
        let (c, s) = handshake(&client, &server, "localhost");
        assert_eq!(
            tls_kind(&c.unwrap_err()),
            Some(TlsErrorKind::UntrustedCertificate)
        );
        assert_eq!(tls_kind(&s.unwrap_err()), Some(TlsErrorKind::PeerAlert));
    }
}

/// R-NF-09: the public-root verifier checks the host name. A certificate
/// that chains to a trusted root but names another host is refused.
#[test]
fn r_nf_09_public_roots_refuse_host_name_mismatch() {
    let client = ClientConfig::public_roots_builder()
        .also_trust_pem(CA)
        .build()
        .unwrap();
    let server = ServerConfig::new(SERVER, SERVER_KEY).unwrap();
    for name in [
        "updates.fstp.crabnebula.dev",
        "api.anthropic.com",
        "example.com",
        "127.0.0.2",
    ] {
        let (c, s) = handshake(&client, &server, name);
        assert_eq!(
            tls_kind(&c.unwrap_err()),
            Some(TlsErrorKind::NameMismatch),
            "{name}"
        );
        assert_eq!(
            tls_kind(&s.unwrap_err()),
            Some(TlsErrorKind::PeerAlert),
            "{name}"
        );
    }
}

/// R-NF-09: a pinned CA on top of the public roots admits its server at
/// the matching name, so a tenant may pin a CA without losing the public
/// roots. A CA outside both is still refused.
#[test]
fn r_nf_09_public_roots_with_pinned_ca_accept_matching_name() {
    let client = ClientConfig::public_roots_builder()
        .also_trust_pem(CA)
        .build()
        .unwrap();
    let server = ServerConfig::new(SERVER, SERVER_KEY).unwrap();
    let (c, s) = handshake(&client, &server, "localhost");
    assert!(c.is_ok());
    assert!(s.is_ok());

    let other = ServerConfig::new(UNTRUSTED_SERVER, UNTRUSTED_SERVER_KEY).unwrap();
    let (c, _s) = handshake(&client, &other, "localhost");
    assert_eq!(
        tls_kind(&c.unwrap_err()),
        Some(TlsErrorKind::UntrustedCertificate)
    );
}

/// R-NF-09: the public configuration holds the compiled-in root set and
/// presents no client certificate. Invalid pinned PEM is a config error,
/// never a silent fallback to the public roots alone.
#[test]
fn r_nf_09_public_roots_config_shape() {
    let client = ClientConfig::public_roots().unwrap();
    let shown = format!("{client:?}");
    assert!(shown.contains("public_roots: true"), "{shown}");
    assert!(shown.contains("client_auth: false"), "{shown}");
    const { assert!(fstp_tls::PUBLIC_ROOT_COUNT > 100) };

    let err = ClientConfig::public_roots_builder()
        .also_trust_pem(b"not pem")
        .build()
        .unwrap_err();
    assert_eq!(err.kind(), TlsErrorKind::Config);

    let pinned = ClientConfig::new(CA).unwrap();
    assert!(format!("{pinned:?}").contains("public_roots: false"));
}
