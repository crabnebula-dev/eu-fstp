//! R-NF-09, I-19, I-20, design sections 1.3 and 9.1: the cell side of the
//! control plane link (`fstp_cell::control`) against the `CellToCp`
//! listener of `fstp-control` (`fstp_control::service::serve_cells`).
//!
//! Both sides run in this process over loopback, with a test
//! control-plane CA. The test checks that the two framings match: the
//! cell's heartbeat task reaches the listener at once on start, and the
//! listener records it. A cell whose certificate another CA issued is
//! refused.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use fstp_cell::control::{
    ControlPlaneEndpoint, ControlPlaneFault, PRODUCT_VERSION, exchange, heartbeat, heartbeat_task,
};
use fstp_control::service::{CellRegistry, serve_cells};
use fstp_cp_proto::{CellId, CpToCell};
use fstp_pgtest::certs::ClusterCa;
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{Listener, Runtime, Shutdown};

const CELL: [u8; 16] = [0xc7; 16];

fn cn(cell: [u8; 16]) -> String {
    let hex: String = cell.iter().map(|b| format!("{b:02x}")).collect();
    format!("cell_{hex}")
}

/// R-NF-09, design section 9.1: the cell's heartbeat task sends its first
/// heartbeat at start, and `fstp-control` records it under the cell its
/// certificate names. One exchange from the cell gets `Ack`.
#[test]
fn r_nf_09_cell_heartbeat_reaches_the_control_plane_listener() {
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let ca = ClusterCa::generate("fstp test control plane CA").unwrap();
    let server = ca.issue_server("control").unwrap();
    let tls =
        fstp_tls::ServerConfig::mutual(&server.cert_pem, &server.key_pem, ca.cert_pem()).unwrap();
    let listener = rt
        .block_on(rt.bind_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let registry = Arc::new(CellRegistry::default());
    let shutdown = Shutdown::new();
    let served = rt.spawn(serve_cells(
        rt.clone(),
        tls,
        listener,
        registry.clone(),
        shutdown.signal(),
    ));

    let me = ca.issue_role(&cn(CELL)).unwrap();
    let endpoint = ControlPlaneEndpoint {
        addr,
        server_name: "localhost".to_owned(),
        tls: fstp_tls::ClientConfig::mutual(ca.cert_pem(), &me.cert_pem, &me.key_pem).unwrap(),
    };
    let reply = rt.block_on(exchange(&rt, &endpoint, &heartbeat(CELL)));
    assert_eq!(reply, Ok(CpToCell::Ack));

    let other = [0xc8; 16];
    let task_shutdown = Shutdown::new();
    let task = rt.spawn(heartbeat_task(
        rt.clone(),
        endpoint.clone(),
        CELL,
        task_shutdown.signal(),
    ));
    let mut seen = false;
    for _ in 0..200 {
        if registry.heartbeat(CellId(CELL)).is_some() {
            seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    task_shutdown.trigger();
    rt.block_on(task).unwrap();
    assert!(seen, "no heartbeat was recorded");
    assert_eq!(
        registry.heartbeat(CellId(CELL)).map(|h| h.version),
        Some(PRODUCT_VERSION)
    );

    // I-20: the cell's certificate cannot report for another cell.
    let r = rt.block_on(exchange(&rt, &endpoint, &heartbeat(other)));
    assert_eq!(r, Err(ControlPlaneFault::Reply));
    assert!(registry.heartbeat(CellId(other)).is_none());

    // R-NF-09: a certificate from another CA is refused.
    let rogue = ClusterCa::generate("rogue CA").unwrap();
    let forged = rogue.issue_role(&cn(other)).unwrap();
    let forged_endpoint = ControlPlaneEndpoint {
        tls: fstp_tls::ClientConfig::mutual(ca.cert_pem(), &forged.cert_pem, &forged.key_pem)
            .unwrap(),
        ..endpoint
    };
    let r = rt.block_on(exchange(&rt, &forged_endpoint, &heartbeat(other)));
    assert!(r.is_err(), "{r:?}");
    assert!(registry.heartbeat(CellId(other)).is_none());

    shutdown.trigger();
    rt.block_on(served).unwrap();
}
