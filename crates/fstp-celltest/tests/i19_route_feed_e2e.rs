//! The pilot route feed end to end (lane L15 `prod/route-feed`, ADR-009
//! "Pilot route feed", decided by Daniel on 2026-11-21).
//!
//! The production `fstp-cell` binary runs from its configuration file
//! (`World::start_external`). In front of it run the `fstp-control
//! route-feed` and `fstp-edge` binaries, from the files an operator
//! writes (`fstp_celltest::external_edge::PilotFeed`). Routes change
//! through `fstp-control route add` and `fstp-control route remove` while
//! the edge runs, and the edge never restarts.
//!
//! The binaries must be built first: `cargo build -p fstp-cell --bin
//! fstp-cell -p fstp-control --bin fstp-control -p fstp-edge --bin
//! fstp-edge`. The CI part that runs this test builds them. Every value
//! is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use fstp_celltest::external_cell::ExternalSpec;
use fstp_celltest::external_edge::PilotFeed;
use fstp_celltest::world::{DbMode, VaultLayout, World, WorldSpec};
use fstp_celltest::world_host::{SimProcess, bin_path};
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{IoExt as _, Runtime as _};

/// How long a route change may take to reach the edge.
const CHANGE: Duration = Duration::from_secs(60);

type Tls = fstp_tls::TlsStream<<TokioRuntime as fstp_rt::Runtime>::Tcp>;

/// A TLS connection through the edge at `edge` with `sni`, verified
/// under the origin CA, as a browser opens it.
async fn through_edge(
    rt: &TokioRuntime,
    edge: SocketAddr,
    origin: &fstp_tls::ClientConfig,
    sni: &str,
) -> std::io::Result<Tls> {
    let tcp = rt.connect_tcp(edge).await?;
    fstp_tls::connect(origin, sni, tcp).await
}

/// `GET path` on the open connection `tls` with `host` as `Host`.
/// Returns the status and the body.
async fn get_on(tls: &mut Tls, host: &str, path: &str) -> std::io::Result<(u16, Vec<u8>)> {
    let head = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tls.write_all(head.as_bytes()).await?;
    tls.flush().await?;
    let mut answer = Vec::new();
    let _ = tls.read_to_end(&mut answer, 1 << 20).await;
    let method = fstp_http::Method::from_bytes(b"GET").unwrap();
    match fstp_http::parse_response(&answer, &method, &fstp_http::Limits::default(), true) {
        Ok(fstp_http::Parsed::Complete { message, .. }) => {
            Ok((message.status.as_u16(), message.body))
        }
        _ => Err(std::io::Error::from(std::io::ErrorKind::InvalidData)),
    }
}

const METADATA: &str = "/.well-known/oauth-protected-resource/mcp";

/// Whether a browser reaches the cell's protected resource metadata for
/// `host` through the edge now.
fn routed(
    rt: &TokioRuntime,
    edge: SocketAddr,
    origin: &fstp_tls::ClientConfig,
    host: &str,
) -> bool {
    rt.block_on(async {
        let Ok(mut tls) = through_edge(rt, edge, origin, host).await else {
            return false;
        };
        matches!(get_on(&mut tls, host, METADATA).await, Ok((200, _)))
    })
}

fn wait_for(what: &str, f: impl Fn() -> bool) {
    let begun = Instant::now();
    while !f() {
        assert!(begun.elapsed() < CHANGE, "{what}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// I-19, R-SW-02, TH-48 (ADR-009 "Pilot route feed"): in front of the
/// `fstp-cell` binary, a running `fstp-edge` starts with no route. A
/// route added with `fstp-control route add` reaches it without a
/// restart, and the tenant host and its vault origin then route to the
/// cell. A route the edge would refuse is refused by the command with
/// status 2 and changes nothing. `fstp-control route remove` closes new
/// connections for the host, while a connection opened before it still
/// gets its answer. A restarted `fstp-control` resumes its signed table
/// and version, so its next change still reaches the edge, which would
/// refuse an older version. Each route change applies at once and leaves
/// one audit record (Daniel, 2026-11-21). `route list` reads the served routes. An edge
/// restarted while `fstp-control` is down serves its signed cache. Both
/// processes drain to status 0.
#[test]
fn i19_r_sw_02_route_feed_changes_routes_of_a_running_edge() {
    let cell_bin = bin_path("fstp-cell").unwrap_or_else(|e| {
        panic!("{e}: run `cargo build -p fstp-cell --bin fstp-cell` before this test")
    });
    let tag = fstp_crypto::random_array::<6>().unwrap();
    let tag: String = tag.iter().map(|b| format!("{b:02x}")).collect();
    let dir: PathBuf = std::env::temp_dir().join(format!("fstp-l15-{tag}"));
    std::fs::create_dir_all(&dir).unwrap();
    let custody = SimProcess::spawn(0, &dir).unwrap_or_else(|e| panic!("{e}"));
    let key_file_custody = SimProcess::spawn(1, &dir).unwrap_or_else(|e| panic!("{e}"));
    let control_custody = SimProcess::spawn(2, &dir).unwrap_or_else(|e| panic!("{e}"));
    let spec = ExternalSpec {
        binary: cell_bin,
        dir: dir.clone(),
        key_file_custody: key_file_custody.socket().to_path_buf(),
        assets_dir: None,
        relay: None,
        shell: None,
    };
    let world = World::start_external(
        WorldSpec {
            cells: 1,
            mode: DbMode::Shared,
            vault_layout: VaultLayout::SeparateCluster,
            self_hosted: false,
            process_mode: false,
        },
        custody.socket().to_path_buf(),
        &spec,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let host = world.cell(0).unwrap().host().to_owned();
    let vault_host = format!("id.{host}");

    let mut feed = PilotFeed::start(&world, &dir, control_custody.socket(), 1).unwrap_or_else(|e| {
        panic!("{e}: run `cargo build -p fstp-control --bin fstp-control -p fstp-edge --bin fstp-edge` before this test")
    });
    let edge = feed.edge_addr();
    let pid = feed.edge_pid();
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let origin = fstp_tls::ClientConfig::new(&world.origin_ca_pem().unwrap()).unwrap();

    // The edge starts with no route.
    assert!(
        rt.block_on(through_edge(&rt, edge, &origin, &host))
            .is_err(),
        "the edge routed before any route was added"
    );

    // An operator adds the cell's route while the edge runs.
    let routes = feed.pinned_routes().unwrap();
    assert_eq!(routes.len(), 1);
    let route = &routes[0];
    assert_eq!(route.route.host.as_str(), host);
    let file = feed.route_file(route, "cell").unwrap();
    assert!(feed.add(&file).unwrap().success(), "route add failed");
    wait_for("the added route never reached the edge", || {
        routed(&rt, edge, &origin, &host)
    });
    let (status, body) = rt.block_on(async {
        let mut tls = through_edge(&rt, edge, &origin, &host).await.unwrap();
        get_on(&mut tls, &host, METADATA).await.unwrap()
    });
    assert_eq!(status, 200);
    let doc = fstp_json::parse(&body).unwrap();
    assert_eq!(
        doc.get("resource").and_then(|r| r.as_str()),
        Some(format!("https://{host}/mcp").as_str())
    );
    assert!(
        rt.block_on(through_edge(&rt, edge, &origin, &vault_host))
            .is_ok(),
        "the vault origin is not routed"
    );
    assert_eq!(feed.edge_pid(), pid, "the edge restarted");

    // A route the edge would refuse: both endpoints on one address.
    let mut clash = route.clone();
    clash.route.vault.address = clash.route.app.address;
    let clash_file = feed.route_file(&clash, "clash").unwrap();
    assert_eq!(feed.add(&clash_file).unwrap().code(), Some(2));
    assert!(
        routed(&rt, edge, &origin, &host),
        "a refused route changed the table"
    );

    // A connection opened before the removal.
    let mut held = rt
        .block_on(through_edge(&rt, edge, &origin, &host))
        .unwrap();
    assert!(feed.remove(&route.route.app.cell).unwrap().success());
    wait_for("the removed route still opened new connections", || {
        rt.block_on(through_edge(&rt, edge, &origin, &host))
            .is_err()
    });
    assert!(
        rt.block_on(through_edge(&rt, edge, &origin, &vault_host))
            .is_err()
    );
    let (status, _) = rt.block_on(get_on(&mut held, &host, METADATA)).unwrap();
    assert_eq!(status, 200, "the open connection did not finish");

    // A restarted control plane resumes its table and version.
    assert!(
        feed.stop_control(),
        "fstp-control did not drain to status 0"
    );
    feed.start_control().unwrap();
    assert!(
        rt.block_on(through_edge(&rt, edge, &origin, &host))
            .is_err(),
        "a restart of fstp-control brought a removed route back"
    );
    assert!(
        feed.add(&file).unwrap().success(),
        "route add after restart"
    );
    wait_for(
        "the route added after the restart never reached the edge",
        || routed(&rt, edge, &origin, &host),
    );
    assert_eq!(feed.edge_pid(), pid, "the edge restarted");

    // `route list` writes the served table to a file.
    let listed = dir.join("listed.json");
    assert!(feed.list(&listed).unwrap().success());
    let listed = fstp_json::parse(&std::fs::read(&listed).unwrap()).unwrap();
    let hosts: Vec<&str> = listed
        .get("routes")
        .and_then(|r| r.as_array())
        .unwrap()
        .iter()
        .filter_map(|r| r.get("host").and_then(|h| h.as_str()))
        .collect();
    assert_eq!(hosts, vec![host.as_str()]);

    // Each applied change left one audit record.
    let (records, _) =
        fstp_control::route_change::decode_audit_log(&std::fs::read(feed.audit_log()).unwrap())
            .unwrap();
    let ops: Vec<u8> = records.iter().map(|r| r.op).collect();
    assert_eq!(ops, vec![1, 2, 1], "one record per applied change");

    // The edge restarts while fstp-control is down: its signed cache
    // serves the last verified table.
    assert!(
        feed.stop_control(),
        "fstp-control did not drain to status 0"
    );
    assert!(feed.stop_edge(), "fstp-edge did not drain to status 0");
    feed.start_edge().unwrap();
    wait_for("the restarted edge did not serve its cache", || {
        routed(&rt, edge, &origin, &host)
    });

    assert!(feed.stop_edge(), "fstp-edge did not drain to status 0");
    drop(feed);
    drop(world);
    drop((custody, key_file_custody, control_custody));
    let _ = std::fs::remove_dir_all(&dir);
}
