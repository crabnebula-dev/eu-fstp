//! The pilot edge of lane L9 `prod/edgerun` (ADR-009 "Pilot edge
//! configuration", gap G12, D1): its configuration and route file
//! decoders, its routing on a static table, its connection limits and its
//! tunnel server pin.
//!
//! The binary end to end, in front of the `fstp-cell` binary, is
//! `crates/fstp-celltest/tests/i19_edge_binary_e2e.rs`. Every value here
//! is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::{self, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fstp_edge::config::{ConfigError, Limits, PilotRoutes, decode_config, decode_routes};
use fstp_edge::run::{Gate, PinnedTunnelOpener, accept_loop, connection};
use fstp_edge::{
    CellEndpoint, CloseReason, Decision, EdgeError, HostName, RouteError, RouteKind,
    TUNNEL_HEADER_LEN, TunnelOpener, decide, decode_tunnel_header,
};
use fstp_rt::duplex::{DuplexStream, duplex};
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{IoExt as _, Listener as _, Runtime as _, Shutdown};

const CELL_A: &str = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";
const CELL_B: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A pin of 32 bytes `b`, as the route file spells it.
fn pin(b: u8) -> String {
    hex(&[b; 32])
}

/// One route of a route file.
fn route(cell: &str, host: &str, app: (&str, &str), vault: (&str, &str)) -> String {
    format!(
        r#"{{"app":{{"address":"{}","cert_sha256":"{}","server_name":"app.tunnel.test"}},"cell":"{cell}","host":"{host}","vault":{{"address":"{}","cert_sha256":"{}","server_name":"vault.tunnel.test"}}}}"#,
        app.0, app.1, vault.0, vault.1
    )
}

fn routes(list: &[String]) -> String {
    format!(r#"{{"routes":[{}]}}"#, list.join(","))
}

/// Tenants A and B, each with its application and vault endpoints.
fn two_tenants() -> String {
    routes(&[
        route(
            CELL_A,
            "a.pilot.test",
            ("10.0.0.1:7443", &pin(1)),
            ("10.0.0.1:7446", &pin(2)),
        ),
        route(
            CELL_B,
            "b.pilot.test",
            ("10.0.0.2:7443", &pin(3)),
            ("10.0.0.2:7446", &pin(4)),
        ),
    ])
}

const CONFIG: &str = r#"{"credentials_dir":"/etc/fstp/edge","feed":{"address":"10.0.0.2:7350","cert_sha256":"5555555555555555555555555555555555555555555555555555555555555555","server_name":"control.tunnel.test"},"listen":{"public":"0.0.0.0:443"}}"#;

/// A ClientHello record naming `host`, built by hand.
fn hello(host: &[u8]) -> Vec<u8> {
    let n = |len: usize| u16::try_from(len).unwrap().to_be_bytes();
    let mut sni = Vec::new();
    sni.extend_from_slice(&n(host.len() + 3));
    sni.push(0);
    sni.extend_from_slice(&n(host.len()));
    sni.extend_from_slice(host);
    let mut exts = vec![0, 0];
    exts.extend_from_slice(&n(sni.len()));
    exts.extend_from_slice(&sni);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[7; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
    body.extend_from_slice(&n(exts.len()));
    body.extend_from_slice(&exts);
    let mut hs = vec![1, 0];
    hs.extend_from_slice(&n(body.len()));
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 3, 1];
    rec.extend_from_slice(&n(hs.len()));
    rec.extend_from_slice(&hs);
    rec
}

/// ADR-009 "Pilot edge configuration" (lane L9): the configuration
/// decoder takes a minimal and a full file, and refuses every member it
/// does not know, a missing member, a relative path, an address in a
/// second spelling and a limit out of its range.
#[test]
fn adr009_l9_edge_config_refuses_bad_input() {
    let cfg = decode_config(CONFIG.as_bytes()).unwrap();
    assert_eq!(cfg.listen, SocketAddr::from(([0, 0, 0, 0], 443)));
    assert_eq!(cfg.limits, Limits::default());
    let full = r#"{"credentials_dir":"/e","limits":{"connections":10,"hello_seconds":5,"lifetime_seconds":600,"open_seconds":3,"per_client":2},"listen":{"public":"[::1]:8443"},"feed":{"address":"10.0.0.2:7350","cert_sha256":"5555555555555555555555555555555555555555555555555555555555555555","server_name":"control.tunnel.test"}}"#;
    let cfg = decode_config(full.as_bytes()).unwrap();
    assert_eq!(cfg.limits.connections, 10);
    assert_eq!(cfg.limits.per_client, 2);
    assert_eq!(cfg.limits.hello, Duration::from_secs(5));
    assert_eq!(cfg.limits.open, Duration::from_secs(3));
    assert_eq!(cfg.limits.lifetime, Duration::from_secs(600));
    let bad: [(&str, ConfigError); 16] = [
        ("", ConfigError::NotAnObject),
        ("[]", ConfigError::NotAnObject),
        (
            r#"{"credentials_dir":"/e","credentials_dir":"/e","listen":{"public":"0.0.0.0:443"},"feed":{"address":"10.0.0.2:7350","cert_sha256":"5555555555555555555555555555555555555555555555555555555555555555","server_name":"control.tunnel.test"}}"#,
            ConfigError::NotAnObject,
        ),
        (
            r#"{"credentials_dir":"/e","feed":{"address":"10.0.0.2:7350","cert_sha256":"5555555555555555555555555555555555555555555555555555555555555555","server_name":"control.tunnel.test"},"listen":{"public":"0.0.0.0:443"},"routes":"/r"}"#,
            ConfigError::UnknownMember("config"),
        ),
        (
            r#"{"listen":{"public":"0.0.0.0:443"},"feed":{"address":"10.0.0.2:7350","cert_sha256":"5555555555555555555555555555555555555555555555555555555555555555","server_name":"control.tunnel.test"}}"#,
            ConfigError::MissingMember("credentials_dir"),
        ),
        (
            r#"{"credentials_dir":"e","listen":{"public":"0.0.0.0:443"},"feed":{"address":"10.0.0.2:7350","cert_sha256":"5555555555555555555555555555555555555555555555555555555555555555","server_name":"control.tunnel.test"}}"#,
            ConfigError::Invalid("credentials_dir"),
        ),
        (
            r#"{"credentials_dir":"/e","listen":{"public":"0.0.0.0:443"}}"#,
            ConfigError::MissingMember("feed"),
        ),
        (
            r#"{"credentials_dir":"/e","feed":{"address":"10.0.0.2:7350","cert_sha256":"5555555555555555555555555555555555555555555555555555555555555555","server_name":"control.tunnel.test"}}"#,
            ConfigError::MissingMember("listen"),
        ),
        (
            r#"{"credentials_dir":"/e","listen":{"public":"0.0.0.0:443","health":"127.0.0.1:1"},"feed":{"address":"10.0.0.2:7350","cert_sha256":"5555555555555555555555555555555555555555555555555555555555555555","server_name":"control.tunnel.test"}}"#,
            ConfigError::UnknownMember("listen"),
        ),
        (
            r#"{"credentials_dir":"/e","listen":{"public":"localhost:443"},"feed":{"address":"10.0.0.2:7350","cert_sha256":"5555555555555555555555555555555555555555555555555555555555555555","server_name":"control.tunnel.test"}}"#,
            ConfigError::Invalid("listen.public"),
        ),
        (
            r#"{"credentials_dir":"/e","listen":{"public":"000.0.0.0:443"},"feed":{"address":"10.0.0.2:7350","cert_sha256":"5555555555555555555555555555555555555555555555555555555555555555","server_name":"control.tunnel.test"}}"#,
            ConfigError::Invalid("listen.public"),
        ),
        (
            r#"{"credentials_dir":"/e","limits":{"connections":0},"listen":{"public":"0.0.0.0:443"},"feed":{"address":"10.0.0.2:7350","cert_sha256":"5555555555555555555555555555555555555555555555555555555555555555","server_name":"control.tunnel.test"}}"#,
            ConfigError::Invalid("limits.connections"),
        ),
        (
            r#"{"credentials_dir":"/e","limits":{"connections":4,"per_client":5},"listen":{"public":"0.0.0.0:443"},"feed":{"address":"10.0.0.2:7350","cert_sha256":"5555555555555555555555555555555555555555555555555555555555555555","server_name":"control.tunnel.test"}}"#,
            ConfigError::Invalid("limits.per_client"),
        ),
        (
            r#"{"credentials_dir":"/e","limits":{"hello_seconds":61},"listen":{"public":"0.0.0.0:443"},"feed":{"address":"10.0.0.2:7350","cert_sha256":"5555555555555555555555555555555555555555555555555555555555555555","server_name":"control.tunnel.test"}}"#,
            ConfigError::Invalid("limits.hello_seconds"),
        ),
        (
            r#"{"credentials_dir":"/e","limits":{"lifetime_seconds":59},"listen":{"public":"0.0.0.0:443"},"feed":{"address":"10.0.0.2:7350","cert_sha256":"5555555555555555555555555555555555555555555555555555555555555555","server_name":"control.tunnel.test"}}"#,
            ConfigError::Invalid("limits.lifetime_seconds"),
        ),
        (
            r#"{"credentials_dir":"/e","limits":{"idle_seconds":5},"listen":{"public":"0.0.0.0:443"},"feed":{"address":"10.0.0.2:7350","cert_sha256":"5555555555555555555555555555555555555555555555555555555555555555","server_name":"control.tunnel.test"}}"#,
            ConfigError::UnknownMember("limits"),
        ),
    ];
    for (input, want) in bad {
        assert_eq!(decode_config(input.as_bytes()), Err(want), "{input}");
    }
    let long = format!(r#"{{"credentials_dir":"/{}"}}"#, "e".repeat(5000));
    assert_eq!(
        decode_config(long.as_bytes()),
        Err(ConfigError::Invalid("length"))
    );
}

/// ADR-009 "Pilot edge configuration", I-19 (lane L9): the route file
/// decoder takes two tenants, and refuses an unknown member, a cell id or
/// pin out of its grammar, a host in upper case, a host or cell or
/// address given twice, a cell whose two endpoints share an address, and
/// a pin that two endpoints share.
#[test]
fn adr009_l9_route_file_refuses_bad_input() {
    let ok = decode_routes(two_tenants().as_bytes()).unwrap();
    assert_eq!(ok.table.len(), 4);
    assert_eq!(ok.pins.len(), 4);
    let a = |app: (&str, &str), vault: (&str, &str)| route(CELL_A, "a.pilot.test", app, vault);
    let p = pin;
    let cases: Vec<(String, ConfigError)> = vec![
        (
            r#"{"routes":[]}"#.to_owned(),
            ConfigError::Invalid("routes"),
        ),
        (
            r#"{"routes":[],"version":1}"#.to_owned(),
            ConfigError::UnknownMember("route file"),
        ),
        (
            routes(&[route(
                &CELL_A.to_uppercase(),
                "a.pilot.test",
                ("10.0.0.1:1", &p(1)),
                ("10.0.0.1:2", &p(2)),
            )]),
            ConfigError::Invalid("route.cell"),
        ),
        (
            routes(&[route(
                CELL_A,
                "A.pilot.test",
                ("10.0.0.1:1", &p(1)),
                ("10.0.0.1:2", &p(2)),
            )]),
            ConfigError::Invalid("route.host"),
        ),
        (
            routes(&[a(("10.0.0.1:1", &p(1)[1..]), ("10.0.0.1:2", &p(2)))]),
            ConfigError::Invalid("route.app"),
        ),
        (
            routes(&[a(("10.0.0.1:1", &p(1)), ("10.0.0.1", &p(2)))]),
            ConfigError::Invalid("route.vault"),
        ),
        (
            routes(&[a(("10.0.0.1:1", &p(1)), ("10.0.0.1:1", &p(2)))]),
            ConfigError::Route(RouteError::SameAddress),
        ),
        (
            routes(&[a(("10.0.0.1:1", &p(1)), ("10.0.0.1:2", &p(1)))]),
            ConfigError::PinTaken,
        ),
        (
            routes(&[
                a(("10.0.0.1:1", &p(1)), ("10.0.0.1:2", &p(2))),
                route(
                    CELL_B,
                    "a.pilot.test",
                    ("10.0.0.2:1", &p(3)),
                    ("10.0.0.2:2", &p(4)),
                ),
            ]),
            ConfigError::Route(RouteError::HostTaken),
        ),
        (
            routes(&[
                a(("10.0.0.1:1", &p(1)), ("10.0.0.1:2", &p(2))),
                route(
                    CELL_A,
                    "c.pilot.test",
                    ("10.0.0.2:1", &p(3)),
                    ("10.0.0.2:2", &p(4)),
                ),
            ]),
            ConfigError::Route(RouteError::CellTaken),
        ),
        (
            routes(&[
                a(("10.0.0.1:1", &p(1)), ("10.0.0.1:2", &p(2))),
                route(
                    CELL_B,
                    "b.pilot.test",
                    ("10.0.0.1:1", &p(3)),
                    ("10.0.0.2:2", &p(4)),
                ),
            ]),
            ConfigError::Route(RouteError::AddressTaken),
        ),
        (
            routes(&[
                a(("10.0.0.1:1", &p(1)), ("10.0.0.1:2", &p(2))),
                route(
                    CELL_B,
                    "b.pilot.test",
                    ("10.0.0.2:1", &p(2)),
                    ("10.0.0.2:2", &p(4)),
                ),
            ]),
            ConfigError::PinTaken,
        ),
        (
            routes(&[a(("10.0.0.1:1", &p(1)), ("10.0.0.1:2", &p(2)))]).replace(
                r#""server_name":"app.tunnel.test""#,
                r#""server_name":"App""#,
            ),
            ConfigError::Invalid("route.app"),
        ),
        (
            routes(&[a(("10.0.0.1:1", &p(1)), ("10.0.0.1:2", &p(2)))])
                .replace(r#""cell""#, r#""tenant""#),
            ConfigError::UnknownMember("route"),
        ),
    ];
    for (input, want) in cases {
        assert_eq!(decode_routes(input.as_bytes()), Err(want), "{input}");
    }
    let many: Vec<String> = (0..65u32)
        .map(|i| {
            let cell = format!("{i:032x}");
            route(
                &cell,
                &format!("t{i}.pilot.test"),
                (&format!("10.1.{i}.1:1"), &hex(&[i as u8; 32])),
                (&format!("10.1.{i}.2:1"), &hex(&[i as u8 + 100; 32])),
            )
        })
        .collect();
    assert!(decode_routes(routes(&many).as_bytes()).is_err());
}

/// R-NF-02 (ADR-009 "Pilot edge configuration", "Decoders"): a refusal of
/// either decoder, and of a credential the edge reads, names its rule and
/// never quotes a byte of its input.
#[test]
fn r_nf_02_edge_config_refusals_never_quote_input() {
    const MARK: &str = "zqsecretzq";
    let configs = [
        format!(
            r#"{{"credentials_dir":"{MARK}","listen":{{"public":"0.0.0.0:443"}},"feed":{{"address":"10.0.0.2:7350","cert_sha256":"5555555555555555555555555555555555555555555555555555555555555555","server_name":"control.tunnel.test"}}}}"#
        ),
        format!(
            r#"{{"credentials_dir":"/e","listen":{{"public":"{MARK}"}},"feed":{{"address":"10.0.0.2:7350","cert_sha256":"5555555555555555555555555555555555555555555555555555555555555555","server_name":"control.tunnel.test"}}}}"#
        ),
        format!(r#"{{"{MARK}":1}}"#),
        format!(r#"{{"credentials_dir":"/e","limits":{{"{MARK}":1}}}}"#),
        format!("{MARK}{{"),
    ];
    for c in &configs {
        let e = decode_config(c.as_bytes()).unwrap_err();
        assert!(!format!("{e:?}").contains(MARK), "{e:?}");
    }
    let files = [
        routes(&[route(
            CELL_A,
            &format!("{MARK}.pilot.test").to_uppercase(),
            ("10.0.0.1:1", &pin(1)),
            ("10.0.0.1:2", &pin(2)),
        )]),
        routes(&[route(
            CELL_A,
            "a.pilot.test",
            ("10.0.0.1:1", MARK),
            ("10.0.0.1:2", &pin(2)),
        )]),
        routes(&[route(
            MARK,
            "a.pilot.test",
            ("10.0.0.1:1", &pin(1)),
            ("10.0.0.1:2", &pin(2)),
        )]),
        format!(r#"{{"routes":[{{"{MARK}":0}}]}}"#),
    ];
    for f in &files {
        let e = decode_routes(f.as_bytes()).unwrap_err();
        assert!(!format!("{e:?}").contains(MARK), "{e:?}");
    }
    // A credentials directory whose key file holds no key.
    let dir = std::env::temp_dir().join(format!("fstp-l9-creds-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["tunnel-ca.pem", "tunnel.pem", "tunnel.key"] {
        std::fs::write(dir.join(name), MARK).unwrap();
    }
    let e = fstp_edge::run::tunnel_client(&dir).err().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(matches!(e, EdgeError::Config(_)), "{e:?}");
    assert!(!format!("{e:?}").contains(MARK), "{e:?}");
}

/// I-19 (ADR-009 "Pilot edge configuration"): on a table from a route
/// file, a ClientHello for a host the file does not name gets no route,
/// and so does the vault origin of such a host. Through the connection
/// path, no tunnel opens for it.
#[test]
fn i19_pilot_unknown_sni_gets_no_route() {
    let PilotRoutes { table, .. } = decode_routes(two_tenants().as_bytes()).unwrap();
    for host in [
        "c.pilot.test",
        "id.c.pilot.test",
        "pilot.test",
        "x.a.pilot.test",
        "id.id.a.pilot.test",
    ] {
        assert_eq!(
            decide(&table, &hello(host.as_bytes())),
            Decision::Close(CloseReason::UnknownHost),
            "{host}"
        );
        let opener = Recording::default();
        let (mut client, edge_side) = duplex(64 * 1024);
        let rt = TokioRuntime::new_multi_thread(1).unwrap();
        let peer = SocketAddr::from(([192, 0, 2, 7], 40_000));
        let served = rt.block_on(async {
            client.write_all(&hello(host.as_bytes())).await.unwrap();
            connection(&rt, edge_side, peer, &table, &opener, &Limits::default()).await
        });
        assert!(
            matches!(served, Err(EdgeError::Closed(CloseReason::UnknownHost))),
            "{host}: {served:?}"
        );
        assert!(opener.opened.lock().unwrap().is_empty(), "{host}");
    }
}

/// Opens an in-memory tunnel for each endpoint and keeps the cell's end.
#[derive(Default)]
struct Recording {
    opened: Mutex<Vec<(CellEndpoint, DuplexStream)>>,
}

impl TunnelOpener for Recording {
    type Tunnel = DuplexStream;

    async fn open(&self, endpoint: &CellEndpoint) -> io::Result<DuplexStream> {
        let (edge, cell) = duplex(64 * 1024);
        self.opened.lock().unwrap().push((endpoint.clone(), cell));
        Ok(edge)
    }
}

fn cell_of(text: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// I-19 (ADR-009 "Pilot edge configuration"): two tenants behind one
/// pilot edge never cross. Through the real accept loop on loopback, a
/// ClientHello for each tenant's host and vault origin opens a tunnel to
/// that tenant's cell and that route's kind only, whose header names the
/// SNI. The pin of each endpoint belongs to its own cell, and no endpoint
/// of one tenant answers under the other tenant's cell id.
#[test]
fn i19_pilot_two_tenants_never_cross() {
    let PilotRoutes { table, pins } = decode_routes(two_tenants().as_bytes()).unwrap();
    let (a, b) = (cell_of(CELL_A), cell_of(CELL_B));
    let mut seen_pins = Vec::new();
    for (host, (endpoint, _)) in table.iter() {
        let own = pins.pin_of(endpoint).unwrap();
        assert!(!seen_pins.contains(&own), "{host:?}");
        seen_pins.push(own);
        let other = CellEndpoint {
            cell: if endpoint.cell == a { b } else { a },
            ..endpoint.clone()
        };
        assert_eq!(pins.pin_of(&other), None, "{host:?}");
    }
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let opener = Arc::new(Recording::default());
    let table = Arc::new(table);
    let shutdown = Shutdown::new();
    let listener = rt
        .block_on(rt.bind_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let (loop_rt, loop_opener, loop_table) = (rt.clone(), Arc::clone(&opener), Arc::clone(&table));
    let handle = move |client, peer| {
        let (rt, opener, table) = (
            loop_rt.clone(),
            Arc::clone(&loop_opener),
            Arc::clone(&loop_table),
        );
        async move {
            let _ = connection(&rt, client, peer, &table, &*opener, &Limits::default()).await;
        }
    };
    drop(rt.spawn(accept_loop(
        rt.clone(),
        listener,
        Gate::new(&Limits::default()),
        shutdown.signal(),
        handle,
    )));
    let cases = [
        ("a.pilot.test", a, RouteKind::Cell),
        ("id.a.pilot.test", a, RouteKind::VaultOrigin),
        ("b.pilot.test", b, RouteKind::Cell),
        ("id.b.pilot.test", b, RouteKind::VaultOrigin),
        ("A.Pilot.Test", a, RouteKind::Cell),
    ];
    let mut clients = Vec::new();
    for (i, (host, cell, kind)) in cases.iter().enumerate() {
        let mut client = std::net::TcpStream::connect(addr).unwrap();
        client.write_all(&hello(host.as_bytes())).unwrap();
        clients.push(client);
        let begun = Instant::now();
        while opener.opened.lock().unwrap().len() <= i {
            assert!(begun.elapsed() < Duration::from_secs(20), "{host}");
            std::thread::sleep(Duration::from_millis(10));
        }
        let (endpoint, mut tunnel) = opener.opened.lock().unwrap().pop().unwrap();
        opener
            .opened
            .lock()
            .unwrap()
            .push((endpoint.clone(), duplex(1).0));
        assert_eq!(endpoint.cell, *cell, "{host}");
        let routed = HostName::parse(host.as_bytes()).unwrap();
        assert_eq!(
            table.route(&routed).map(|(ep, k)| (ep.clone(), *k)),
            Some((endpoint.clone(), *kind)),
            "{host}"
        );
        let header = rt.block_on(async {
            let mut buf = [0u8; TUNNEL_HEADER_LEN];
            tunnel.read_exact(&mut buf).await.unwrap();
            decode_tunnel_header(&buf).unwrap()
        });
        assert_eq!(header.host, routed, "{host}");
    }
    drop(clients);
    let _ = rt.block_on(shutdown.shutdown(&rt, Duration::from_secs(5)));
}

/// ADR-009 "Pilot edge configuration", row "Limits": the gate admits at
/// most `connections` in all and `per_client` per client address, counts
/// an IPv4-mapped address as its IPv4 address, and frees a place when a
/// permit drops.
#[test]
fn adr009_l9_gate_holds_the_connection_limits() {
    let limits = Limits {
        connections: 3,
        per_client: 2,
        ..Limits::default()
    };
    let gate = Gate::new(&limits);
    let one = IpAddr::from([192, 0, 2, 1]);
    let mapped = IpAddr::from(Ipv4Addr::from([192, 0, 2, 1]).to_ipv6_mapped());
    let two = IpAddr::from([192, 0, 2, 2]);
    let p1 = gate.admit(one).unwrap();
    let p2 = gate.admit(mapped).unwrap();
    assert!(gate.admit(one).is_none(), "per client");
    let p3 = gate.admit(two).unwrap();
    assert!(gate.admit(IpAddr::from([192, 0, 2, 3])).is_none(), "in all");
    drop(p1);
    assert_eq!(gate.open(), 2);
    let p4 = gate.admit(one).unwrap();
    drop((p2, p3, p4));
    assert_eq!(gate.open(), 0);
}

/// I-19 (ADR-009 "Pilot edge configuration", row "Tunnel server pin"):
/// the pilot opener opens a tunnel only to a server whose end-entity
/// certificate matches the endpoint's pin. A server with a valid chain
/// and name but another certificate gets no byte, and an endpoint with
/// no pin is never dialled.
#[test]
fn i19_tunnel_pin_mismatch_opens_no_tunnel() {
    const CA: &[u8] = include_bytes!("../../fstp-tls/testdata/ca.pem");
    const SERVER: &[u8] = include_bytes!("../../fstp-tls/testdata/server.pem");
    const SERVER_KEY: &[u8] = include_bytes!("../../fstp-tls/testdata/server-key.pem");
    const CLIENT: &[u8] = include_bytes!("../../fstp-tls/testdata/client.pem");
    const CLIENT_KEY: &[u8] = include_bytes!("../../fstp-tls/testdata/client-key.pem");
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let server = Arc::new(fstp_tls::ServerConfig::mutual(SERVER, SERVER_KEY, CA).unwrap());
    let mut listener = rt
        .block_on(rt.bind_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    // Each accepted tunnel records how many bytes it received.
    let received = Arc::new(Mutex::new(Vec::<usize>::new()));
    let (srv_rt, srv_received) = (rt.clone(), Arc::clone(&received));
    drop(rt.spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (server, received) = (Arc::clone(&server), Arc::clone(&srv_received));
            drop(srv_rt.spawn(async move {
                let Ok(mut tls) = fstp_tls::accept(&server, tcp).await else {
                    received.lock().unwrap().push(0);
                    return;
                };
                let mut bytes = Vec::new();
                let _ = tls.read_to_end(&mut bytes, 1024).await;
                received.lock().unwrap().push(bytes.len());
            }));
        }
    }));
    let client = || fstp_tls::ClientConfig::mutual(CA, CLIENT, CLIENT_KEY).unwrap();
    let endpoint = CellEndpoint {
        cell: cell_of(CELL_A),
        address: addr,
        tls_name: "localhost".to_owned(),
    };
    // The operator reads the pin off the server's certificate.
    let leaf = rt.block_on(async {
        let tcp = rt.connect_tcp(addr).await.unwrap();
        let tls = fstp_tls::connect(&client(), "localhost", tcp)
            .await
            .unwrap();
        fstp_crypto::sha256(tls.peer_end_entity_der().unwrap())
    });
    let wait = |n: usize| {
        let begun = Instant::now();
        while received.lock().unwrap().len() < n {
            assert!(begun.elapsed() < Duration::from_secs(20));
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    wait(1);
    let file = |app_pin: &str| {
        routes(&[route(
            CELL_A,
            "a.pilot.test",
            (&addr.to_string(), app_pin),
            ("127.0.0.1:1", &pin(9)),
        )])
        .replace(
            r#""server_name":"app.tunnel.test""#,
            r#""server_name":"localhost""#,
        )
    };
    let open = |pins_file: &str, ep: &CellEndpoint| {
        let PilotRoutes { pins, .. } = decode_routes(pins_file.as_bytes()).unwrap();
        let opener = PinnedTunnelOpener::new(rt.clone(), client(), pins, Duration::from_secs(10));
        rt.block_on(async {
            let mut tunnel = opener.open(ep).await?;
            tunnel.write_all(b"header").await?;
            tunnel.shutdown().await?;
            io::Result::Ok(())
        })
    };
    // The right pin opens and carries bytes.
    open(&file(&hex(&leaf)), &endpoint).unwrap();
    wait(2);
    assert_eq!(received.lock().unwrap()[1], 6);
    // Another pin: the handshake completes, then the edge closes before
    // any byte leaves it.
    let e = open(&file(&pin(7)), &endpoint).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    wait(3);
    assert_eq!(received.lock().unwrap()[2], 0);
    // An endpoint the file does not pin is never dialled.
    let unpinned = CellEndpoint {
        tls_name: "other.tunnel.test".to_owned(),
        ..endpoint.clone()
    };
    let e = open(&file(&hex(&leaf)), &unpinned).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(received.lock().unwrap().len(), 3);
}

/// ADR-009 "Pilot route feed", rows "Edge configuration", "Poll
/// interval" and "How the edge pins the control plane" (lane L15): the
/// edge configuration names its feed source with the pin of the control
/// plane's certificate. A missing pin, a pin out of grammar, an unknown
/// feed member, a server name in upper case and a poll interval out of
/// range are refused. The member `routes` of lane L9 is gone. The feed
/// keys file holds one or two composite public keys as hex lines, and
/// anything else is refused without quoting it (R-NF-02).
#[test]
fn adr009_l15_edge_feed_config_and_keys_refuse_bad_input() {
    use fstp_edge::config::{DEFAULT_POLL, decode_feed_keys};
    let cfg = decode_config(CONFIG.as_bytes()).unwrap();
    assert_eq!(cfg.feed.address, SocketAddr::from(([10, 0, 0, 2], 7350)));
    assert_eq!(cfg.feed.server_name, "control.tunnel.test");
    assert_eq!(cfg.feed.cert_sha256, [0x55; 32]);
    assert_eq!(cfg.feed.poll, DEFAULT_POLL);
    let with_feed = |feed: &str| {
        format!(r#"{{"credentials_dir":"/e","feed":{feed},"listen":{{"public":"0.0.0.0:443"}}}}"#)
    };
    let pin = pin(0xab);
    let ok = with_feed(&format!(
        r#"{{"address":"[fd00::2]:7350","cert_sha256":"{pin}","poll_seconds":1,"server_name":"c.test"}}"#
    ));
    assert_eq!(
        decode_config(ok.as_bytes()).unwrap().feed.poll,
        Duration::from_secs(1)
    );
    let bad = [
        (
            r#"{"address":"10.0.0.2:7350","server_name":"c.test"}"#.to_owned(),
            ConfigError::MissingMember("feed.cert_sha256"),
        ),
        (
            format!(
                r#"{{"address":"10.0.0.2:7350","cert_sha256":"{}","server_name":"c.test"}}"#,
                pin.to_uppercase()
            ),
            ConfigError::Invalid("feed.cert_sha256"),
        ),
        (
            format!(
                r#"{{"address":"10.0.0.2:7350","cert_sha256":"{}","server_name":"c.test"}}"#,
                &pin[2..]
            ),
            ConfigError::Invalid("feed.cert_sha256"),
        ),
        (
            format!(
                r#"{{"address":"10.0.0.2:7350","cert_sha256":"{pin}","server_name":"c.test","spki_sha256":"{pin}"}}"#
            ),
            ConfigError::UnknownMember("feed"),
        ),
        (
            format!(
                r#"{{"address":"10.0.0.2:7350","cert_sha256":"{pin}","server_name":"C.test"}}"#
            ),
            ConfigError::Invalid("feed.server_name"),
        ),
        (
            format!(r#"{{"address":"control:7350","cert_sha256":"{pin}","server_name":"c.test"}}"#),
            ConfigError::Invalid("feed.address"),
        ),
        (
            format!(
                r#"{{"address":"10.0.0.2:7350","cert_sha256":"{pin}","poll_seconds":0,"server_name":"c.test"}}"#
            ),
            ConfigError::Invalid("feed.poll_seconds"),
        ),
        (
            format!(
                r#"{{"address":"10.0.0.2:7350","cert_sha256":"{pin}","poll_seconds":61,"server_name":"c.test"}}"#
            ),
            ConfigError::Invalid("feed.poll_seconds"),
        ),
        ("\"/r\"".to_owned(), ConfigError::Invalid("feed")),
    ];
    for (feed, want) in bad {
        let input = with_feed(&feed);
        assert_eq!(decode_config(input.as_bytes()), Err(want), "{input}");
    }

    let k1 = fstp_crypto::composite::generate()
        .unwrap()
        .public_key()
        .to_bytes();
    let k2 = fstp_crypto::composite::generate()
        .unwrap()
        .public_key()
        .to_bytes();
    let line = |k: &[u8]| format!("{}\n", hex(k));
    assert_eq!(
        decode_feed_keys(line(&k1).as_bytes()),
        Ok(vec![k1.to_vec()])
    );
    assert_eq!(
        decode_feed_keys(format!("{}{}", line(&k1), line(&k2)).as_bytes()),
        Ok(vec![k1.to_vec(), k2.to_vec()])
    );
    const MARK: &str = "zqsecretzq";
    for bad in [
        String::new(),
        "\n".to_owned(),
        hex(&k1),
        line(&k1).to_uppercase(),
        format!("{}{}", line(&k1), line(&k1)),
        format!("{}{}{}", line(&k1), line(&k2), line(&k1)),
        format!("{}\n", &hex(&k1)[2..]),
        format!("{}{MARK}\n", line(&k1)),
        format!("{}\n\n", hex(&k1)),
    ] {
        let e = decode_feed_keys(bad.as_bytes()).unwrap_err();
        assert_eq!(e, ConfigError::Invalid("route-feed.pub"));
        assert!(!format!("{e:?}").contains(MARK));
    }
}
