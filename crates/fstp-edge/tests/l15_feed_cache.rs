//! The edge's signed cache of its last verified table and its two control
//! certificate pins (lane L15 `prod/route-feed`, ADR-009 "Pilot route
//! feed", rows "Signed cache" and "How the edge pins the control plane",
//! decided by Daniel on 2026-11-21). Every value is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fstp_crypto::composite::{self, CompositeSigningKey};
use fstp_edge::{
    CellEndpoint, FeedError, FeedTransport, HostName, LiveRoutes, PinnedRoute, ROUTE_TABLE_CONTEXT,
    RouteEntry, RouteFeed, TlsFeed, encode_route_table_body, encode_signed_route_table,
};
use fstp_rt::future::block_on;
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{IoExt as _, Listener as _, Runtime as _};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    let tag: String = fstp_crypto::random_array::<4>()
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let dir = std::env::temp_dir().join(format!("fstp-l15-cache-{name}-{tag}"));
    std::fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

fn route(cell: u8, host: &str) -> PinnedRoute {
    let ep = |port| CellEndpoint {
        cell: [cell; 16],
        address: SocketAddr::from(([10, 0, 6, cell], port)),
        tls_name: "tunnel.cell.internal".to_owned(),
    };
    PinnedRoute {
        route: RouteEntry {
            host: HostName::parse(host.as_bytes()).unwrap(),
            app: ep(8443),
            vault: ep(9443),
        },
        app_pin: [cell; 32],
        vault_pin: [cell ^ 0x80; 32],
    }
}

fn signed(key: &CompositeSigningKey, version: u64, routes: &[PinnedRoute]) -> Vec<u8> {
    let body = encode_route_table_body(version, routes).unwrap();
    let sig = key.sign_with_context(&body, ROUTE_TABLE_CONTEXT).unwrap();
    encode_signed_route_table(&body, &sig.to_bytes()).unwrap()
}

/// The feed from memory, or an unreachable control plane when empty.
#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Option<Vec<u8>>>>);

impl FeedTransport for Shared {
    async fn fetch(&self, _poll: &[u8]) -> io::Result<Vec<u8>> {
        self.0
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| io::ErrorKind::ConnectionRefused.into())
    }
}

impl Shared {
    fn serve(&self, bytes: Option<Vec<u8>>) {
        *self.0.lock().unwrap() = bytes;
    }
}

/// A fresh edge over `transport` with its cache at `cache`.
fn edge(
    key: &CompositeSigningKey,
    transport: &Shared,
    cache: PathBuf,
) -> (RouteFeed<Shared>, LiveRoutes) {
    let live = LiveRoutes::default();
    let feed = RouteFeed::new(
        transport.clone(),
        vec![key.public_key().to_bytes().to_vec()],
        live.clone(),
    )
    .with_cache(cache);
    (feed, live)
}

fn has(live: &LiveRoutes, host: &str) -> bool {
    live.current()
        .route(&HostName::parse(host.as_bytes()).unwrap())
        .is_some()
}

/// TH-48, R-SW-02 (ADR-009 "Pilot route feed", row "Signed cache"): the
/// edge caches each newer table before it applies it. After a newer
/// table removed an erased cell's route, an edge restarted while the
/// control plane is unreachable serves the cache: the newer table,
/// without the erased cell, with its pins. The erased route never comes
/// back from the cache.
#[test]
fn th48_erased_route_never_returns_from_the_cache() {
    let dir = scratch("erased");
    let cache = dir.0.join("route-table.signed");
    let key = composite::generate().unwrap();
    let control = Shared::default();
    let (feed, live) = edge(&key, &control, cache.clone());
    assert_eq!(feed.load_cache(), Ok(None), "no cache yet");
    control.serve(Some(signed(
        &key,
        10,
        &[route(1, "erased.example"), route(2, "kept.example")],
    )));
    assert_eq!(block_on(feed.poll_once()), Ok(10));
    let without = signed(&key, 11, &[route(2, "kept.example")]);
    control.serve(Some(without.clone()));
    assert_eq!(block_on(feed.poll_once()), Ok(11));
    assert!(!has(&live, "erased.example"));
    assert_eq!(std::fs::read(&cache).unwrap(), without);
    drop((feed, live));
    // The edge restarts while the control plane is down.
    control.serve(None);
    let (feed, live) = edge(&key, &control, cache.clone());
    assert_eq!(feed.load_cache(), Ok(Some(11)));
    assert!(!has(&live, "erased.example") && !has(&live, "id.erased.example"));
    assert!(has(&live, "kept.example") && has(&live, "id.kept.example"));
    assert_eq!(
        live.pins().pin_of(&route(2, "kept.example").route.app),
        Some([2; 32])
    );
    assert_eq!(
        block_on(feed.poll_once()),
        Err(FeedError::Io(io::ErrorKind::ConnectionRefused))
    );
    assert_eq!(live.version(), 11);
    assert!(!has(&live, "erased.example"));
}

/// I-90 (ADR-009 "Pilot route feed", row "Signed cache"): the cache is
/// verified again at start under the feed keys. A cache with a changed
/// byte, one signed by another key, and bytes that are no table are
/// refused, and the edge starts with no route. The feed then fills it.
#[test]
fn i90_tampered_cache_is_ignored_at_start() {
    let dir = scratch("tampered");
    let cache = dir.0.join("route-table.signed");
    let key = composite::generate().unwrap();
    let good = signed(&key, 7, &[route(1, "a.example")]);
    let mut changed = good.clone();
    let at = changed.windows(9).position(|w| w == b"a.example").unwrap();
    changed[at] = b'b';
    let stranger = composite::generate().unwrap();
    for (bytes, want) in [
        (changed, FeedError::BadSignature),
        (
            signed(&stranger, 9, &[route(1, "a.example")]),
            FeedError::BadSignature,
        ),
        (
            b"not a table".to_vec(),
            FeedError::Malformed("the wrong magic"),
        ),
    ] {
        std::fs::write(&cache, &bytes).unwrap();
        let control = Shared::default();
        let (feed, live) = edge(&key, &control, cache.clone());
        assert_eq!(feed.load_cache(), Err(want));
        assert_eq!(live.version(), 0);
        assert!(live.current().is_empty());
        control.serve(Some(good.clone()));
        assert_eq!(block_on(feed.poll_once()), Ok(7));
        assert_eq!(std::fs::read(&cache).unwrap(), good);
    }
}

/// R-SW-02 (ADR-009 "Pilot route feed", rows "Signed cache" and
/// "Rollback"): a cache below the control plane's version serves until
/// the first poll, which replaces it in memory and on disk. A feed table
/// older than the cache is refused as a rollback, and the cache stays.
#[test]
fn r_sw_02_older_cache_is_replaced_at_the_first_poll() {
    let dir = scratch("older");
    let cache = dir.0.join("route-table.signed");
    let key = composite::generate().unwrap();
    let cached = signed(&key, 30, &[route(1, "a.example")]);
    std::fs::write(&cache, &cached).unwrap();
    let control = Shared::default();
    let (feed, live) = edge(&key, &control, cache.clone());
    assert_eq!(feed.load_cache(), Ok(Some(30)));
    assert!(has(&live, "a.example"));
    // A replay older than the cache.
    control.serve(Some(signed(&key, 29, &[route(2, "b.example")])));
    assert_eq!(block_on(feed.poll_once()), Err(FeedError::Rollback));
    assert_eq!(std::fs::read(&cache).unwrap(), cached);
    assert!(has(&live, "a.example") && !has(&live, "b.example"));
    // The control plane's newer table.
    let newer = signed(&key, 31, &[route(2, "b.example")]);
    control.serve(Some(newer.clone()));
    assert_eq!(block_on(feed.poll_once()), Ok(31));
    assert!(!has(&live, "a.example") && has(&live, "b.example"));
    assert_eq!(std::fs::read(&cache).unwrap(), newer);
}

/// TH-48 (ADR-009 "Pilot route feed", row "Signed cache"): a newer table
/// that cannot be cached is not applied. The edge keeps its table and
/// reports its old version, so an erasure never confirms on a table the
/// edge could lose at a restart.
#[test]
fn r_sw_02_cache_write_failure_keeps_the_table() {
    let dir = scratch("unwritable");
    let key = composite::generate().unwrap();
    let control = Shared::default();
    let ok_cache = dir.0.join("route-table.signed");
    let (feed, live) = edge(&key, &control, ok_cache);
    control.serve(Some(signed(&key, 3, &[route(1, "a.example")])));
    assert_eq!(block_on(feed.poll_once()), Ok(3));
    // The same live routes behind a feed whose cache directory is gone.
    let broken = RouteFeed::new(
        control.clone(),
        vec![key.public_key().to_bytes().to_vec()],
        live.clone(),
    )
    .with_cache(dir.0.join("missing").join("route-table.signed"));
    control.serve(Some(signed(&key, 4, &[])));
    assert!(matches!(
        block_on(broken.poll_once()),
        Err(FeedError::Cache(_))
    ));
    assert_eq!(live.version(), 3);
    assert!(has(&live, "a.example"));
    assert_eq!(FeedError::Cache(io::ErrorKind::NotFound).rule(), "TH-48");
}

const CA: &[u8] = include_bytes!("../../fstp-tls/testdata/ca.pem");
const SERVER: &[u8] = include_bytes!("../../fstp-tls/testdata/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("../../fstp-tls/testdata/server-key.pem");
const CLIENT: &[u8] = include_bytes!("../../fstp-tls/testdata/client.pem");
const CLIENT_KEY: &[u8] = include_bytes!("../../fstp-tls/testdata/client-key.pem");

/// ADR-009 "Pilot route feed", row "How the edge pins the control plane"
/// (Daniel, 2026-11-21): the edge takes one or two pins of the control
/// plane's certificate. With the pin of the served certificate first or
/// second, the poll gets its table, so a renewal is staged by adding the
/// next pin before the certificate changes. Without its pin the edge
/// writes no poll.
#[test]
fn adr009_l15_two_control_pins_stage_a_renewal() {
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let key = composite::generate().unwrap();
    let table = signed(&key, 5, &[route(1, "a.example")]);
    let server = Arc::new(fstp_tls::ServerConfig::mutual(SERVER, SERVER_KEY, CA).unwrap());
    let mut listener = rt
        .block_on(rt.bind_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let polls = Arc::new(Mutex::new(0usize));
    let (srv_rt, srv_polls, srv_table) = (rt.clone(), Arc::clone(&polls), table.clone());
    drop(rt.spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (server, polls, table) = (
                Arc::clone(&server),
                Arc::clone(&srv_polls),
                srv_table.clone(),
            );
            drop(srv_rt.spawn(async move {
                let Ok(mut tls) = fstp_tls::accept(&server, tcp).await else {
                    return;
                };
                let mut poll = Vec::new();
                if tls.read_to_end(&mut poll, 64).await.is_err() || poll.is_empty() {
                    return;
                }
                *polls.lock().unwrap() += 1;
                let _ = tls.write_all(&table).await;
                let _ = tls.flush().await;
                let _ = tls.shutdown().await;
            }));
        }
    }));
    let client = || fstp_tls::ClientConfig::mutual(CA, CLIENT, CLIENT_KEY).unwrap();
    let served_pin = rt.block_on(async {
        let tcp = rt.connect_tcp(addr).await.unwrap();
        let tls = fstp_tls::connect(&client(), "localhost", tcp)
            .await
            .unwrap();
        fstp_crypto::sha256(tls.peer_end_entity_der().unwrap())
    });
    let poll_with = |pins: Vec<[u8; 32]>| {
        let live = LiveRoutes::default();
        let feed = RouteFeed::new(
            TlsFeed::new(rt.clone(), addr, "localhost", client()).with_pins(pins),
            vec![key.public_key().to_bytes().to_vec()],
            live,
        );
        rt.block_on(feed.poll_once())
    };
    let next = [0x42; 32];
    assert_eq!(poll_with(vec![served_pin]), Ok(5));
    assert_eq!(
        poll_with(vec![next, served_pin]),
        Ok(5),
        "the old pin second"
    );
    assert_eq!(
        poll_with(vec![served_pin, next]),
        Ok(5),
        "the next pin second"
    );
    assert_eq!(*polls.lock().unwrap(), 3);
    assert_eq!(
        poll_with(vec![next]),
        Err(FeedError::Io(io::ErrorKind::PermissionDenied))
    );
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_eq!(
        *polls.lock().unwrap(),
        3,
        "a poll reached an unpinned server"
    );
}
