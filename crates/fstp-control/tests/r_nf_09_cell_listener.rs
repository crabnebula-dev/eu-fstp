//! R-NF-09, I-19, I-20, design sections 1.3 and 9.1: the `CellToCp`
//! listener of `fstp-control`.
//!
//! The listener runs on a loopback port with a test control-plane CA.
//! Each exchange is framed as `fstp_cell::control::exchange` frames it:
//! one encoded `CellToCp` message, the client's close, and one encoded
//! `CpToCell` reply up to the server's close. The tests check that only a
//! cell certificate from that CA is answered, and only for its own cell.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};

use fstp_control::exchange::request;
use fstp_control::service::{CellRegistry, serve_cells};
use fstp_cp_proto::{
    CellId, CellToCp, CounterKind, CpToCell, Health, PopSig, ProductVersion, RoleName,
    ScramVerifier, SpkiDigest,
};
use fstp_pgtest::certs::ClusterCa;
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{Listener, Runtime, Shutdown};

fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(2).unwrap())
}

fn ca() -> &'static ClusterCa {
    static CA: OnceLock<ClusterCa> = OnceLock::new();
    CA.get_or_init(|| ClusterCa::generate("fstp test control plane CA").unwrap())
}

/// The listener and its registry, started once per test binary.
fn listener() -> &'static (SocketAddr, Arc<CellRegistry>) {
    static L: OnceLock<(SocketAddr, Arc<CellRegistry>)> = OnceLock::new();
    L.get_or_init(|| {
        // The harness issues server certificates with a cluster kind OU only.
        let me = ca().issue_server("control").unwrap();
        let tls =
            fstp_tls::ServerConfig::mutual(&me.cert_pem, &me.key_pem, ca().cert_pem()).unwrap();
        let l = rt()
            .block_on(rt().bind_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))))
            .unwrap();
        let addr = l.local_addr().unwrap();
        let registry = Arc::new(CellRegistry::default());
        let shutdown: &'static Shutdown = Box::leak(Box::new(Shutdown::new()));
        drop(rt().spawn(serve_cells(
            rt().clone(),
            tls,
            l,
            registry.clone(),
            shutdown.signal(),
        )));
        (addr, registry)
    })
}

fn hex(cell: CellId) -> String {
    cell.0.iter().map(|b| format!("{b:02x}")).collect()
}

/// A client that trusts the control-plane CA and presents a certificate
/// with subject CN `cn`, issued by `issuer`.
fn client(issuer: &ClusterCa, cn: &str) -> fstp_tls::ClientConfig {
    let me = issuer.issue_role(cn).unwrap();
    fstp_tls::ClientConfig::mutual(ca().cert_pem(), &me.cert_pem, &me.key_pem).unwrap()
}

fn cell_client(cell: CellId) -> fstp_tls::ClientConfig {
    client(ca(), &format!("cell_{}", hex(cell)))
}

/// One exchange. `Ok(None)` is a close without a reply.
fn exchange(tls: &fstp_tls::ClientConfig, m: &CellToCp) -> Result<Option<CpToCell>, String> {
    let frame = fstp_cp_proto::encode_cell_to_cp(m).unwrap();
    let (addr, _) = listener();
    let reply = rt()
        .block_on(request(rt(), *addr, "localhost", tls, &frame, 64 * 1024))
        .map_err(|e| format!("{e}"))?;
    if reply.is_empty() {
        return Ok(None);
    }
    fstp_cp_proto::decode_cp_to_cell(&reply)
        .map(Some)
        .map_err(|e| format!("{e:?}"))
}

fn heartbeat(cell: CellId) -> CellToCp {
    CellToCp::Heartbeat {
        cell,
        version: ProductVersion::new(0, 3, 0),
        health: Health::Ok,
    }
}

/// R-NF-09, design section 9.1: a cell's heartbeat over mutual TLS with
/// its certificate from the control-plane CA is recorded and acknowledged,
/// and so are its metering counters.
#[test]
fn r_nf_09_cell_heartbeat_is_acknowledged_over_mutual_tls() {
    let cell = CellId([0xab; 16]);
    let tls = cell_client(cell);
    assert_eq!(exchange(&tls, &heartbeat(cell)), Ok(Some(CpToCell::Ack)));
    let (_, registry) = listener();
    let seen = registry.heartbeat(cell).unwrap();
    assert_eq!(seen.version, ProductVersion::new(0, 3, 0));
    assert_eq!(seen.health, Health::Ok);
    let metering = CellToCp::Metering {
        cell,
        period: 20_000,
        counters: vec![(CounterKind::Proposals, 7)],
    };
    assert_eq!(exchange(&tls, &metering), Ok(Some(CpToCell::Ack)));
    assert_eq!(
        registry.metering(cell, 20_000),
        Some(vec![(CounterKind::Proposals, 7)])
    );
}

/// I-19, I-20: a cell cannot speak for another cell. A heartbeat or
/// metering that names another cell gets no reply and is not recorded.
#[test]
fn i20_cell_cannot_report_for_another_cell() {
    let me = CellId([0xac; 16]);
    let other = CellId([0xad; 16]);
    let tls = cell_client(me);
    assert_eq!(exchange(&tls, &heartbeat(other)), Ok(None));
    let metering = CellToCp::Metering {
        cell: other,
        period: 1,
        counters: Vec::new(),
    };
    assert_eq!(exchange(&tls, &metering), Ok(None));
    let (_, registry) = listener();
    assert!(registry.heartbeat(other).is_none());
    assert!(registry.metering(other, 1).is_none());
}

/// R-NF-09, design section 1.3: the listener answers only a cell
/// certificate from the control-plane CA. A certificate from another CA
/// with a valid cell name, no certificate at all, and the `fstp-control`
/// certificate of the same CA are all refused, and none is recorded.
#[test]
fn r_nf_09_listener_accepts_only_a_cell_certificate_from_the_control_plane_ca() {
    let cell = CellId([0xae; 16]);
    let rogue = ClusterCa::generate("rogue CA").unwrap();
    let foreign = client(&rogue, &format!("cell_{}", hex(cell)));
    let r = exchange(&foreign, &heartbeat(cell));
    assert!(matches!(r, Err(_) | Ok(None)), "{r:?}");
    let anonymous = fstp_tls::ClientConfig::new(ca().cert_pem()).unwrap();
    let r = exchange(&anonymous, &heartbeat(cell));
    assert!(matches!(r, Err(_) | Ok(None)), "{r:?}");
    let control = client(ca(), "fstp_control");
    assert_eq!(exchange(&control, &heartbeat(cell)), Ok(None));
    let (_, registry) = listener();
    assert!(registry.heartbeat(cell).is_none());
    // The positive control: the right certificate is still answered.
    let right = cell_client(cell);
    assert_eq!(exchange(&right, &heartbeat(cell)), Ok(Some(CpToCell::Ack)));
    assert!(registry.heartbeat(cell).is_some());
    let unseen = CellId([0xaf; 16]);
    let r = exchange(&foreign, &heartbeat(unseen));
    assert!(matches!(r, Err(_) | Ok(None)), "{r:?}");
    assert!(registry.heartbeat(unseen).is_none());
}

/// ADR-011, design section 9.2 step 6: a role credential is not relayed
/// yet. The listener closes without a reply rather than acknowledge a
/// credential it did not act on.
#[test]
fn adr011_role_credential_is_not_acknowledged_before_the_relay_exists() {
    let cell = CellId([0xba; 16]);
    let verifier = ScramVerifier::parse(
        b"SCRAM-SHA-256$4096:AAAAAAAAAAAAAAAAAAAAAA==$\
          AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:\
          BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=",
    )
    .unwrap();
    let m = CellToCp::RoleCredential {
        role: RoleName::App,
        spki: SpkiDigest([1; 32]),
        pop: PopSig::parse(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]).unwrap(),
        scram_verifier: verifier,
    };
    assert_eq!(exchange(&cell_client(cell), &m), Ok(None));
}
