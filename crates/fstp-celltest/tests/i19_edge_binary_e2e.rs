//! The pilot edge binary end to end (lane L9 `prod/edgerun`, ADR-009
//! "Pilot edge configuration", gap G12 of
//! `docs/handoff/production-mcp-design.md`).
//!
//! The production `fstp-cell` binary runs from its configuration file
//! (`World::start_external`, lane L4). In front of it, the `fstp-edge`
//! binary runs from its own configuration file and credentials
//! directory, as an operator writes them. Since lane L15 it takes its
//! routes from the signed route feed of the `fstp-control route-feed`
//! binary (ADR-009 "Pilot route feed"). A browser's HTTPS request with
//! the tenant SNI then passes through the edge to the cell's tunnel
//! listener, and the cell answers with its public origin.
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

/// How long the edge may take to route its first request.
const READY: Duration = Duration::from_secs(60);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A TLS connection through the edge at `edge` with `sni`, verified
/// under the origin CA, as a browser opens it.
async fn through_edge(
    rt: &TokioRuntime,
    edge: SocketAddr,
    origin: &fstp_tls::ClientConfig,
    sni: &str,
) -> std::io::Result<fstp_tls::TlsStream<<TokioRuntime as fstp_rt::Runtime>::Tcp>> {
    let tcp = rt.connect_tcp(edge).await?;
    fstp_tls::connect(origin, sni, tcp).await
}

/// `GET path` through the edge with `host` as SNI and `Host`. Returns the
/// status and the body.
fn get(
    rt: &TokioRuntime,
    edge: SocketAddr,
    origin: &fstp_tls::ClientConfig,
    host: &str,
    path: &str,
) -> std::io::Result<(u16, Vec<u8>)> {
    rt.block_on(async {
        let mut tls = through_edge(rt, edge, origin, host).await?;
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
    })
}

/// I-19, R-MC-01 (ADR-009 "Pilot edge configuration", rows "TLS role",
/// "Origin agreement", "Route file", "Credentials" and "Tunnel server
/// pin"; gap G12): the `fstp-edge` binary, started from its configuration
/// file in front of the `fstp-cell` binary, passes a browser's TLS for
/// the tenant host through to the cell. The protected resource metadata
/// it reaches names `https://<host>/mcp` with no port, the origin that
/// WebAuthn and claude.ai need, and the host equals the cell's own
/// configured `host`. The vault origin `id.<host>` reaches the cell's
/// vault. An unknown SNI gets no route. SIGTERM drains the edge to
/// status 0.
#[test]
fn i19_r_mc_01_edge_binary_routes_tenant_sni_to_the_cell_binary() {
    let cell_bin = bin_path("fstp-cell").unwrap_or_else(|e| {
        panic!("{e}: run `cargo build -p fstp-cell --bin fstp-cell` before this test")
    });
    let tag = fstp_crypto::random_array::<6>().unwrap();
    let dir: PathBuf = std::env::temp_dir().join(format!("fstp-l9-{}", hex(&tag)));
    std::fs::create_dir_all(&dir).unwrap();
    let custody = SimProcess::spawn(0, &dir).unwrap_or_else(|e| panic!("{e}"));
    let key_file_custody = SimProcess::spawn(1, &dir).unwrap_or_else(|e| panic!("{e}"));
    let spec = ExternalSpec {
        binary: cell_bin,
        dir: dir.clone(),
        key_file_custody: key_file_custody.socket().to_path_buf(),
        assets_dir: None,
        relay: None,
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
    let cell = world.cell(0).unwrap();
    let host = cell.host().to_owned();

    // The cell's own configuration names the host the edge routes.
    let cell_config = std::fs::read(cell.external().unwrap().config_path()).unwrap();
    let cell_config = fstp_json::parse(&cell_config).unwrap();
    assert_eq!(
        cell_config.get("host").and_then(|h| h.as_str()),
        Some(host.as_str())
    );

    // The operator's files and processes: the pilot route feed of lane
    // L15 in front of the cell, and the cell's route added through it.
    let control_custody = SimProcess::spawn(2, &dir).unwrap_or_else(|e| panic!("{e}"));
    let mut feed = PilotFeed::start(&world, &dir, control_custody.socket(), 1).unwrap_or_else(|e| {
        panic!("{e}: run `cargo build -p fstp-control --bin fstp-control -p fstp-edge --bin fstp-edge` before this test")
    });
    let routes = feed.pinned_routes().unwrap();
    assert_eq!(routes.len(), 1, "{routes:?}");
    assert_eq!(routes[0].route.host.as_str(), host);
    let file = feed.route_file(&routes[0], "cell").unwrap();
    assert!(feed.add(&file).unwrap().success(), "route add failed");
    let public = feed.edge_addr();
    let rt = TokioRuntime::new_multi_thread(2).unwrap();

    // A browser trusts the public origin CA and sends the tenant SNI.
    let origin = fstp_tls::ClientConfig::new(&world.origin_ca_pem().unwrap()).unwrap();
    let begun = Instant::now();
    let (status, body) = loop {
        match get(
            &rt,
            public,
            &origin,
            &host,
            "/.well-known/oauth-protected-resource/mcp",
        ) {
            Ok(answer) => break answer,
            Err(e) => {
                assert!(begun.elapsed() < READY, "the edge never routed: {e}");
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    };
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let doc = fstp_json::parse(&body).unwrap();
    assert_eq!(
        doc.get("resource").and_then(|r| r.as_str()),
        Some(format!("https://{host}/mcp").as_str()),
        "the cell's public origin has no port and names the routed host"
    );

    // The vault origin routes to the cell's vault, whose origin
    // certificate names `id.<host>`.
    let vault_host = format!("id.{host}");
    let vault = rt.block_on(through_edge(&rt, public, &origin, &vault_host));
    assert!(vault.is_ok(), "the vault origin: {:?}", vault.err());

    // An unknown SNI gets no route: the edge closes before any TLS answer.
    let other = rt.block_on(through_edge(&rt, public, &origin, "other.fstp.localhost"));
    assert!(other.is_err(), "an unknown host was routed");

    assert!(feed.stop_edge(), "the edge did not drain to status 0");
    assert!(
        feed.stop_control(),
        "fstp-control did not drain to status 0"
    );
    drop(feed);
    drop(world);
    drop((custody, key_file_custody, control_custody));
    let _ = std::fs::remove_dir_all(&dir);
}
