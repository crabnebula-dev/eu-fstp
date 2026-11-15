//! R-SW-02, design section 3.7 step 3, ADR-004 "Decided by Daniel,
//! 2026-11-15 (late)": each `fstp-edge` polls a signed route table from
//! `fstp-control` over mutual TLS. The erasure finishes route removal
//! once every edge reports a table version without the cell's routes.
//! Lane m3/erase-prod.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use fstp_control::erase::EdgeRoutes;
use fstp_control::routes::{EdgeId, RemoteEdges, RoutePublisher, serve_route_feed};
use fstp_cp_proto::CellId;
use fstp_edge::{CellEndpoint, HostName, LiveRoutes, RouteEntry, RouteFeed, TlsFeed};
use fstp_pgtest::certs::ClusterCa;
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{Listener as _, Runtime as _, Shutdown};

fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(2).unwrap())
}

fn ca() -> &'static ClusterCa {
    static CA: OnceLock<ClusterCa> = OnceLock::new();
    CA.get_or_init(|| ClusterCa::generate("fstp test control plane CA").unwrap())
}

const EDGE_A: EdgeId = EdgeId([0xa1; 16]);
const EDGE_B: EdgeId = EdgeId([0xb2; 16]);
const EDGE_C: EdgeId = EdgeId([0xc3; 16]);

fn cn(edge: EdgeId) -> String {
    let hex: String = edge.0.iter().map(|b| format!("{b:02x}")).collect();
    format!("edge_{hex}")
}

fn route(cell: u8, host: &str) -> RouteEntry {
    let ep = |port| CellEndpoint {
        cell: [cell; 16],
        address: SocketAddr::from(([10, 0, 4, cell], port)),
        tls_name: "tunnel.cell.internal".to_owned(),
    };
    RouteEntry {
        host: HostName::parse(host.as_bytes()).unwrap(),
        app: ep(8443),
        vault: ep(9443),
    }
}

/// Starts the route feed of `publisher` and returns its address.
fn feed(publisher: Arc<RoutePublisher>) -> SocketAddr {
    let server = ca().issue_server("control").unwrap();
    let tls =
        fstp_tls::ServerConfig::mutual(&server.cert_pem, &server.key_pem, ca().cert_pem()).unwrap();
    let listener = rt()
        .block_on(rt().bind_tcp(SocketAddr::from(([127, 0, 0, 1], 0))))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown: &'static Shutdown = Box::leak(Box::new(Shutdown::new()));
    let signal = shutdown.signal();
    drop(rt().spawn(serve_route_feed(
        rt().clone(),
        listener,
        tls,
        signal,
        publisher,
    )));
    addr
}

/// One remote edge: its live routes, and a thread that polls every 20 ms
/// until `stop` is set.
struct Edge {
    routes: LiveRoutes,
    stop: Arc<AtomicBool>,
}

fn edge(id: EdgeId, addr: SocketAddr, keys: Vec<Vec<u8>>) -> Edge {
    let me = ca().issue_role(&cn(id)).unwrap();
    let tls = fstp_tls::ClientConfig::mutual(ca().cert_pem(), &me.cert_pem, &me.key_pem).unwrap();
    let routes = LiveRoutes::default();
    let stop = Arc::new(AtomicBool::new(false));
    let feed = RouteFeed::new(
        TlsFeed::new(rt().clone(), addr, "localhost", tls),
        keys,
        routes.clone(),
    );
    let flag = Arc::clone(&stop);
    std::thread::spawn(move || {
        while !flag.load(Ordering::SeqCst) {
            let _ = rt().block_on(feed.poll_once());
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    Edge { routes, stop }
}

fn has(e: &Edge, host: &str) -> bool {
    e.routes
        .current()
        .route(&HostName::parse(host.as_bytes()).unwrap())
        .is_some()
}

fn wait_until(what: &str, f: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !f() {
        assert!(std::time::Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// R-SW-02, design section 3.7 step 3, ADR-004 (2026-11-15 late): two
/// remote edges poll the signed table over mutual TLS and serve both
/// cells. Removing one cell through `RemoteEdges` publishes a new
/// version and returns only once both edges report it. Both then serve
/// no host of the erased cell and every host of the other. An edge whose
/// certificate is not a configured edge gets no table.
#[test]
fn r_sw_02_route_removal_finishes_once_every_edge_reports_the_new_version() {
    let signer = fstp_crypto::composite::generate().unwrap();
    let keys = vec![signer.public_key().to_bytes().to_vec()];
    let publisher = Arc::new(RoutePublisher::new(signer, &[EDGE_A, EDGE_B]).unwrap());
    publisher.publish(route(1, "erased.example")).unwrap();
    let v = publisher.publish(route(2, "kept.example")).unwrap();
    let addr = feed(Arc::clone(&publisher));
    let a = edge(EDGE_A, addr, keys.clone());
    let b = edge(EDGE_B, addr, keys.clone());
    let stranger = edge(EDGE_C, addr, keys);
    wait_until("the edges never served the table", || {
        a.routes.version() >= v && b.routes.version() >= v
    });
    assert!(has(&a, "erased.example") && has(&b, "id.erased.example"));
    let remote = RemoteEdges::new(
        rt().clone(),
        Arc::clone(&publisher),
        Duration::from_secs(20),
    );
    let removed = rt().block_on(remote.remove_cell(CellId([1; 16]))).unwrap();
    assert_eq!(removed, 2);
    let without = publisher.version();
    assert!(publisher.reported(EDGE_A) >= without && publisher.reported(EDGE_B) >= without);
    for e in [&a, &b] {
        assert!(e.routes.version() >= without);
        assert!(!has(e, "erased.example") && !has(e, "id.erased.example"));
        assert!(has(e, "kept.example") && has(e, "id.kept.example"));
    }
    assert_eq!(
        stranger.routes.version(),
        0,
        "an unknown edge got the table"
    );
    assert_eq!(publisher.reported(EDGE_C), 0);
    // A second removal of the same cell changes nothing and returns at once.
    assert_eq!(rt().block_on(remote.remove_cell(CellId([1; 16]))), Ok(0));
    for e in [&a, &b, &stranger] {
        e.stop.store(true, Ordering::SeqCst);
    }
}

/// R-SW-02 teeth: while one edge does not poll, route removal does not
/// finish. It fails after its wait, so the erasure issues no
/// confirmation, though the polling edge already serves no host of the
/// cell.
#[test]
fn r_sw_02_route_removal_fails_while_an_edge_does_not_report() {
    let signer = fstp_crypto::composite::generate().unwrap();
    let keys = vec![signer.public_key().to_bytes().to_vec()];
    let publisher = Arc::new(RoutePublisher::new(signer, &[EDGE_A, EDGE_B]).unwrap());
    let v = publisher.publish(route(3, "gone.example")).unwrap();
    let addr = feed(Arc::clone(&publisher));
    let a = edge(EDGE_A, addr, keys);
    wait_until("edge A never served the table", || a.routes.version() >= v);
    let remote = RemoteEdges::new(
        rt().clone(),
        Arc::clone(&publisher),
        Duration::from_millis(500),
    );
    assert!(
        rt().block_on(remote.remove_cell(CellId([3; 16]))).is_err(),
        "route removal finished without edge B"
    );
    wait_until("edge A kept the erased cell", || !has(&a, "gone.example"));
    a.stop.store(true, Ordering::SeqCst);
}
