//! The pilot edge binary end to end (lane L9 `prod/edgerun`, ADR-009
//! "Pilot edge configuration", gap G12 of
//! `docs/handoff/production-mcp-design.md`).
//!
//! The production `fstp-cell` binary runs from its configuration file
//! (`World::start_external`, lane L4). In front of it, the `fstp-edge`
//! binary runs from its own configuration file, a static route file and
//! a credentials directory, as an operator writes them. A browser's
//! HTTPS request with the tenant SNI then passes through the edge to the
//! cell's tunnel listener, and the cell answers with its public origin.
//!
//! Both binaries must be built first: `cargo build -p fstp-cell --bin
//! fstp-cell -p fstp-edge --bin fstp-edge`. The CI part that runs this
//! test builds them. Every value is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use fstp_celltest::external_cell::ExternalSpec;
use fstp_celltest::world::{DbMode, VaultLayout, World, WorldSpec};
use fstp_celltest::world_host::{SimProcess, bin_path};
use fstp_edge::CellEndpoint;
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{IoExt as _, Runtime as _};

/// How long the edge may take to route its first request.
const READY: Duration = Duration::from_secs(60);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn free_port() -> SocketAddr {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    l.local_addr().unwrap()
}

fn write_private(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
}

/// The edge process. Dropping it sends SIGTERM and waits for the drain.
struct Edge {
    child: Option<Child>,
}

impl Edge {
    /// Sends SIGTERM and returns whether the edge exited with status 0.
    fn stop(&mut self) -> bool {
        let Some(mut child) = self.child.take() else {
            return true;
        };
        let sent = Command::new("kill")
            .arg("-TERM")
            .arg(child.id().to_string())
            .status()
            .is_ok_and(|s| s.success());
        let begun = Instant::now();
        while sent && begun.elapsed() < Duration::from_secs(60) {
            if let Ok(Some(status)) = child.try_wait() {
                return status.success();
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
        false
    }
}

impl Drop for Edge {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// The SHA-256 of the end-entity certificate the tunnel server of
/// `endpoint` presents, as an operator reads it off the certificate.
fn tunnel_pin(rt: &TokioRuntime, tls: &fstp_tls::ClientConfig, endpoint: &CellEndpoint) -> String {
    rt.block_on(async {
        let tcp = rt.connect_tcp(endpoint.address).await.unwrap();
        let stream = fstp_tls::connect(tls, &endpoint.tls_name, tcp)
            .await
            .unwrap();
        hex(&fstp_crypto::sha256(stream.peer_end_entity_der().unwrap()))
    })
}

fn endpoint_json(e: &CellEndpoint, pin: &str) -> String {
    format!(
        r#"{{"address":"{}","cert_sha256":"{pin}","server_name":"{}"}}"#,
        e.address, e.tls_name
    )
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
    let edge_bin = bin_path("fstp-edge").unwrap_or_else(|e| {
        panic!("{e}: run `cargo build -p fstp-edge --bin fstp-edge` before this test")
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

    // The operator's files: credentials, route file, configuration.
    let parts = world.edge_tunnel_parts().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(parts.routes.len(), 1, "{parts:?}");
    let route = &parts.routes[0];
    assert_eq!(route.host.as_str(), host);
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let tunnel = fstp_tls::ClientConfig::mutual(
        &parts.ca_pem,
        &parts.client_cert_pem,
        &parts.client_key_pem,
    )
    .unwrap();
    let app_pin = tunnel_pin(&rt, &tunnel, &route.app);
    let vault_pin = tunnel_pin(&rt, &tunnel, &route.vault);
    let edge_dir = dir.join("edge");
    let creds = edge_dir.join("credentials");
    std::fs::create_dir_all(&creds).unwrap();
    write_private(&creds.join("tunnel-ca.pem"), &parts.ca_pem);
    write_private(&creds.join("tunnel.pem"), &parts.client_cert_pem);
    write_private(&creds.join("tunnel.key"), &parts.client_key_pem);
    let routes_path = edge_dir.join("routes.json");
    write_private(
        &routes_path,
        format!(
            r#"{{"routes":[{{"app":{},"cell":"{}","host":"{host}","vault":{}}}]}}"#,
            endpoint_json(&route.app, &app_pin),
            hex(&route.app.cell),
            endpoint_json(&route.vault, &vault_pin),
        )
        .as_bytes(),
    );
    let public = free_port();
    let config_path = edge_dir.join("edge.json");
    write_private(
        &config_path,
        format!(
            r#"{{"credentials_dir":"{}","limits":{{"hello_seconds":10,"open_seconds":10}},"listen":{{"public":"{public}"}},"routes":"{}"}}"#,
            creds.display(),
            routes_path.display()
        )
        .as_bytes(),
    );

    let mut edge = Edge {
        child: Some(
            Command::new(&edge_bin)
                .env("FSTP_EDGE_CONFIG", &config_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        ),
    };

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
                if let Some(Ok(Some(status))) = edge.child.as_mut().map(Child::try_wait) {
                    panic!("fstp-edge exited before it routed: {status}");
                }
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

    assert!(edge.stop(), "the edge did not drain to status 0");
    drop(world);
    drop((custody, key_file_custody));
    let _ = std::fs::remove_dir_all(&dir);
}
