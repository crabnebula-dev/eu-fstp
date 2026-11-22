//! The pilot edge on the signed route feed (lane L15 `prod/route-feed`,
//! ADR-009 "Pilot route feed", decided by Daniel on 2026-11-21).
//!
//! The edge runs its real accept loop, its pinned tunnel opener on the
//! live routes, and its poll loop `fstp_edge::run::poll_routes`. The feed
//! answers from memory, so each test changes the signed table while the
//! edge runs. A real mutual TLS server stands in for the cell's tunnel
//! listener. The binaries end to end are
//! `crates/fstp-celltest/tests/i19_route_feed_e2e.rs`. Every value is
//! synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::{self, Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fstp_crypto::composite::{self, CompositeSigningKey};
use fstp_edge::config::Limits;
use fstp_edge::run::{Gate, PinnedTunnelOpener, accept_loop, connection, poll_routes};
use fstp_edge::{
    CellEndpoint, FeedTransport, HostName, LiveRoutes, PinnedRoute, ROUTE_TABLE_CONTEXT,
    RouteEntry, RouteFeed, TUNNEL_HEADER_LEN, decode_tunnel_header, encode_route_table_body,
    encode_signed_route_table,
};
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{IoExt as _, Listener as _, Runtime as _, Shutdown};

const CA: &[u8] = include_bytes!("../../fstp-tls/testdata/ca.pem");
const SERVER: &[u8] = include_bytes!("../../fstp-tls/testdata/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("../../fstp-tls/testdata/server-key.pem");
const CLIENT: &[u8] = include_bytes!("../../fstp-tls/testdata/client.pem");
const CLIENT_KEY: &[u8] = include_bytes!("../../fstp-tls/testdata/client-key.pem");

/// How long a test waits for the edge to see a change.
const WAIT: Duration = Duration::from_secs(20);

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

/// The feed from memory: each poll gets the signed table set last.
#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl FeedTransport for Shared {
    async fn fetch(&self, _poll: &[u8]) -> io::Result<Vec<u8>> {
        Ok(self.0.lock().unwrap().clone())
    }
}

/// The edge, its feed, and one tunnel server for cell 1.
struct Rig {
    rt: TokioRuntime,
    key: CompositeSigningKey,
    feed: Shared,
    live: LiveRoutes,
    edge: SocketAddr,
    /// The tunnel server.
    cell: SocketAddr,
    /// The pin of the tunnel server's certificate.
    pin: [u8; 32],
    /// Per accepted tunnel: the routed host, or "" for a tunnel that got
    /// no header.
    tunnels: Arc<Mutex<Vec<String>>>,
    shutdown: Shutdown,
}

impl Rig {
    fn start() -> Rig {
        let rt = TokioRuntime::new_multi_thread(2).unwrap();
        // The cell's tunnel listener: it reads the tunnel header, records
        // the host, and echoes every later byte.
        let server = Arc::new(fstp_tls::ServerConfig::mutual(SERVER, SERVER_KEY, CA).unwrap());
        let mut listener = rt
            .block_on(rt.bind_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))))
            .unwrap();
        let cell = listener.local_addr().unwrap();
        let tunnels = Arc::new(Mutex::new(Vec::new()));
        let (srv_rt, seen) = (rt.clone(), Arc::clone(&tunnels));
        drop(rt.spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (server, seen) = (Arc::clone(&server), Arc::clone(&seen));
                drop(srv_rt.spawn(async move {
                    let Ok(mut tls) = fstp_tls::accept(&server, tcp).await else {
                        return;
                    };
                    let mut header = [0u8; TUNNEL_HEADER_LEN];
                    if tls.read_exact(&mut header).await.is_err() {
                        seen.lock().unwrap().push(String::new());
                        return;
                    }
                    let host = decode_tunnel_header(&header).unwrap().host;
                    seen.lock().unwrap().push(host.as_str().to_owned());
                    let mut buf = [0u8; 1024];
                    loop {
                        match tls.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if tls.write_all(&buf[..n]).await.is_err()
                                    || tls.flush().await.is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                }));
            }
        }));
        let client = fstp_tls::ClientConfig::mutual(CA, CLIENT, CLIENT_KEY).unwrap();
        // The operator reads the pin off the tunnel server's certificate.
        let pin = rt.block_on(async {
            let tcp = rt.connect_tcp(cell).await.unwrap();
            let tls = fstp_tls::connect(&client, "localhost", tcp).await.unwrap();
            fstp_crypto::sha256(tls.peer_end_entity_der().unwrap())
        });
        // The probe opened no tunnel; forget its entry.
        let begun = Instant::now();
        while tunnels.lock().unwrap().is_empty() {
            assert!(begun.elapsed() < WAIT, "the probe never reached the server");
            std::thread::sleep(Duration::from_millis(10));
        }
        tunnels.lock().unwrap().clear();
        let key = composite::generate().unwrap();
        let feed = Shared::default();
        let live = LiveRoutes::default();
        let shutdown = Shutdown::new();
        drop(rt.spawn(poll_routes(
            rt.clone(),
            RouteFeed::new(
                feed.clone(),
                vec![key.public_key().to_bytes().to_vec()],
                live.clone(),
            ),
            Duration::from_millis(50),
            shutdown.signal(),
        )));
        let opener = Arc::new(PinnedTunnelOpener::new(
            rt.clone(),
            client,
            live.clone(),
            Duration::from_secs(10),
        ));
        let listener = rt
            .block_on(rt.bind_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))))
            .unwrap();
        let edge = listener.local_addr().unwrap();
        let (loop_rt, loop_live) = (rt.clone(), live.clone());
        let handle = move |client, peer| {
            let rt = loop_rt.clone();
            let table = loop_live.current();
            let opener = Arc::clone(&opener);
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
        Rig {
            rt,
            key,
            feed,
            live,
            edge,
            cell,
            pin,
            tunnels,
            shutdown,
        }
    }

    /// Cell 1's route on host `a.pilot.test`, its application pinned with
    /// `app_pin`. Its vault endpoint is never dialled here.
    fn route(&self, app_pin: [u8; 32]) -> PinnedRoute {
        let ep = |address: SocketAddr| CellEndpoint {
            cell: [1; 16],
            address,
            tls_name: "localhost".to_owned(),
        };
        PinnedRoute {
            route: RouteEntry {
                host: HostName::parse(b"a.pilot.test").unwrap(),
                app: ep(self.cell),
                vault: ep(SocketAddr::from((Ipv4Addr::LOCALHOST, 1))),
            },
            app_pin,
            vault_pin: [0x99; 32],
        }
    }

    /// Publishes `routes` as `version`, as `fstp-control` signs them, and
    /// waits until the running edge serves that version.
    fn publish(&self, version: u64, routes: &[PinnedRoute]) {
        let body = encode_route_table_body(version, routes).unwrap();
        let sig = self
            .key
            .sign_with_context(&body, ROUTE_TABLE_CONTEXT)
            .unwrap();
        *self.feed.0.lock().unwrap() = encode_signed_route_table(&body, &sig.to_bytes()).unwrap();
        let begun = Instant::now();
        while self.live.version() != version {
            assert!(begun.elapsed() < WAIT, "the edge never served {version}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A client connection that sent the hello for `a.pilot.test`.
    fn client(&self) -> TcpStream {
        let mut c = TcpStream::connect(self.edge).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(&hello(b"a.pilot.test")).unwrap();
        c
    }

    /// Waits until the tunnel server accepted `n` tunnels.
    fn tunnels(&self, n: usize) -> Vec<String> {
        let begun = Instant::now();
        while self.tunnels.lock().unwrap().len() < n {
            assert!(begun.elapsed() < WAIT, "tunnel {n} never opened");
            std::thread::sleep(Duration::from_millis(10));
        }
        self.tunnels.lock().unwrap().clone()
    }
}

/// Whether the edge closed `c` without forwarding anything back.
fn closed(c: &mut TcpStream) -> bool {
    let mut b = [0u8; 1];
    matches!(c.read(&mut b), Ok(0) | Err(_))
}

/// Sends `msg` on an open, routed connection and reads back its echo,
/// after the echo of the hello when `first`.
fn echoes(c: &mut TcpStream, msg: &[u8], first: bool) -> bool {
    let hello_len = if first {
        hello(b"a.pilot.test").len()
    } else {
        0
    };
    if c.write_all(msg).is_err() {
        return false;
    }
    let mut back = vec![0u8; hello_len + msg.len()];
    c.read_exact(&mut back).is_ok() && back[hello_len..] == *msg
}

/// I-19, R-SW-02 (ADR-009 "Pilot route feed", rows "Route changes",
/// "Start of the edge" and "Feed bytes"): a running edge starts with no
/// route. A route that the control plane publishes reaches it through the
/// signed feed, with no restart, and the next connection for the host
/// opens a tunnel whose header names it. A renewed pin also arrives
/// through the feed: under a pin that the server's certificate does not
/// match, no tunnel carries a byte, and under the right pin it opens
/// again.
#[test]
fn i19_r_sw_02_feed_route_reaches_a_running_edge() {
    let rig = Rig::start();
    rig.publish(1, &[]);
    let mut before = rig.client();
    assert!(closed(&mut before), "a host without a route was forwarded");
    rig.publish(2, &[rig.route(rig.pin)]);
    let mut after = rig.client();
    assert_eq!(rig.tunnels(1), vec!["a.pilot.test".to_owned()]);
    assert!(echoes(&mut after, b"ping", true));
    // A wrong pin in a newer table: the tunnel handshake completes, then
    // the edge closes it before the tunnel header.
    rig.publish(3, &[rig.route([0x42; 32])]);
    let mut wrong = rig.client();
    assert!(closed(&mut wrong), "a tunnel opened under a wrong pin");
    std::thread::sleep(Duration::from_millis(200));
    let headed = rig
        .tunnels
        .lock()
        .unwrap()
        .iter()
        .filter(|h| !h.is_empty())
        .count();
    assert_eq!(headed, 1, "a tunnel under a wrong pin got a header");
    rig.publish(4, &[rig.route(rig.pin)]);
    let mut renewed = rig.client();
    assert!(echoes(&mut renewed, b"pong", true));
    assert_eq!(rig.tunnels.lock().unwrap().last().unwrap(), "a.pilot.test");
    drop((before, after, wrong, renewed));
    let _ = rig
        .rt
        .block_on(rig.shutdown.shutdown(&rig.rt, Duration::from_secs(5)));
}

/// TH-48, I-19 (ADR-009 "Pilot route feed", row "Removed route"): once
/// the running edge applies a table without the route, a new connection
/// for the host closes before any tunnel opens. A connection whose tunnel
/// opened before the removal runs on and still carries bytes both ways.
#[test]
fn th48_removed_route_closes_new_connections_and_lets_open_ones_finish() {
    let rig = Rig::start();
    rig.publish(10, &[rig.route(rig.pin)]);
    let mut open = rig.client();
    assert_eq!(rig.tunnels(1), vec!["a.pilot.test".to_owned()]);
    assert!(echoes(&mut open, b"first", true));
    rig.publish(11, &[]);
    let mut late = rig.client();
    assert!(closed(&mut late), "a removed route was forwarded");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(rig.tunnels.lock().unwrap().len(), 1, "a tunnel opened");
    // The connection opened before the removal finishes its work.
    assert!(echoes(&mut open, b"second", false));
    drop((open, late));
    let _ = rig
        .rt
        .block_on(rig.shutdown.shutdown(&rig.rt, Duration::from_secs(5)));
}
