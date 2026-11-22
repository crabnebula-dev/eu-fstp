//! R-SW-02, design section 3.7 step 3, ADR-004 "Decided by Daniel,
//! 2026-11-15 (late)": each `fstp-edge` polls a signed, versioned route
//! table from `fstp-control`. Lane m3/erase-prod.
//!
//! The table has one spelling, its signature is composite (I-90), an
//! edge applies only a newer version, and a poll reports the version the
//! edge serves.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;

use fstp_crypto::composite::{self, CompositeSigningKey};
use fstp_edge::{
    CellEndpoint, FeedError, FeedTransport, HostName, LiveRoutes, PinnedRoute, ROUTE_TABLE_CONTEXT,
    RouteEntry, RouteError, RouteFeed, RouteTable, check_routes, decode_poll, decode_route,
    decode_signed_route_table, encode_poll, encode_route, encode_route_table_body,
    encode_signed_route_table, routes_of, verify_route_table,
};
use fstp_rt::future::block_on;

fn ep(cell: u8, addr: &str) -> CellEndpoint {
    CellEndpoint {
        cell: [cell; 16],
        address: addr.parse::<SocketAddr>().unwrap(),
        tls_name: "tunnel.cell.internal".to_owned(),
    }
}

fn route(cell: u8, host: &str) -> RouteEntry {
    RouteEntry {
        host: HostName::parse(host.as_bytes()).unwrap(),
        app: ep(cell, &format!("10.0.0.{cell}:8443")),
        vault: ep(cell, &format!("[fd00::{cell}]:9443")),
    }
}

/// `r` with a pin per endpoint that no other endpoint of these tests
/// carries: the cell byte, then 1 for the application or 2 for the vault.
fn pinned(r: RouteEntry) -> PinnedRoute {
    let cell = r.app.cell[0];
    let mut app_pin = [cell; 32];
    app_pin[1] = 1;
    let mut vault_pin = [cell; 32];
    vault_pin[1] = 2;
    PinnedRoute {
        route: r,
        app_pin,
        vault_pin,
    }
}

fn pinned_all(routes: &[RouteEntry]) -> Vec<PinnedRoute> {
    routes.iter().cloned().map(pinned).collect()
}

fn signed(key: &CompositeSigningKey, version: u64, routes: &[RouteEntry]) -> Vec<u8> {
    signed_pinned(key, version, &pinned_all(routes))
}

fn signed_pinned(key: &CompositeSigningKey, version: u64, routes: &[PinnedRoute]) -> Vec<u8> {
    let body = encode_route_table_body(version, routes).unwrap();
    let sig = key.sign_with_context(&body, ROUTE_TABLE_CONTEXT).unwrap();
    encode_signed_route_table(&body, &sig.to_bytes()).unwrap()
}

fn pk(key: &CompositeSigningKey) -> Vec<u8> {
    key.public_key().to_bytes().to_vec()
}

/// R-SW-02, TH-26: a signed table decodes to its routes in host order,
/// whatever order they were given in, and verifies under the signing key
/// only. Each cut, a trailing byte, a route out of order, an upper-case
/// host, a changed body and another key are refused.
#[test]
fn r_sw_02_route_table_has_one_spelling_and_a_composite_signature() {
    let key = composite::generate().unwrap();
    let other = composite::generate().unwrap();
    let routes = [route(2, "b.example"), route(1, "a.example")];
    let bytes = signed(&key, 7, &routes);
    let decoded = decode_signed_route_table(&bytes).unwrap();
    assert_eq!(decoded.version, 7);
    assert_eq!(
        decoded.routes,
        pinned_all(&[route(1, "a.example"), route(2, "b.example")])
    );
    let v = verify_route_table(&[pk(&other), pk(&key)], &bytes).unwrap();
    assert_eq!(v.version, 7);
    assert_eq!(v.table.len(), 4);
    assert_eq!(v.pins.len(), 4);
    assert_eq!(v.routes, decoded.routes);
    let unpinned: Vec<RouteEntry> = decoded.routes.iter().map(|r| r.route.clone()).collect();
    assert_eq!(routes_of(&v.table), unpinned);
    for r in &decoded.routes {
        assert_eq!(v.pins.pin_of(&r.route.app), Some(r.app_pin));
        assert_eq!(v.pins.pin_of(&r.route.vault), Some(r.vault_pin));
    }
    assert_eq!(
        verify_route_table(&[pk(&other)], &bytes).map(|_| ()),
        Err(FeedError::BadSignature)
    );
    let mut changed = bytes.clone();
    changed[11] ^= 1;
    assert!(verify_route_table(&[pk(&key)], &changed).is_err());
    for cut in 0..bytes.len() {
        assert!(
            decode_signed_route_table(&bytes[..cut]).is_err(),
            "cut {cut}"
        );
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(decode_signed_route_table(&longer).is_err());
    // Hand-built bodies: routes out of host order, and an upper-case host.
    let a = encode_route_table_body(1, &pinned_all(&[route(1, "a.example")])).unwrap();
    let b = encode_route_table_body(1, &pinned_all(&[route(2, "b.example")])).unwrap();
    let mut swapped = a[..12].to_vec();
    swapped.extend_from_slice(&[0, 2]);
    swapped.extend_from_slice(&b[14..]);
    swapped.extend_from_slice(&a[14..]);
    swapped.extend_from_slice(&[0, 0]);
    assert!(decode_signed_route_table(&swapped).is_err());
    let mut ordered = a[..12].to_vec();
    ordered.extend_from_slice(&[0, 2]);
    ordered.extend_from_slice(&a[14..]);
    ordered.extend_from_slice(&b[14..]);
    ordered.extend_from_slice(&[0, 0]);
    assert!(
        decode_signed_route_table(&ordered).is_ok(),
        "the control case does not decode"
    );
    let mut upper = a.clone();
    let at = upper.iter().position(|c| *c == b'a').unwrap();
    upper[at] = b'A';
    upper.extend_from_slice(&[0, 0]);
    assert!(decode_signed_route_table(&upper).is_err());
    assert!(
        encode_route_table_body(
            1,
            &pinned_all(&[route(1, "a.example"), route(2, "a.example")])
        )
        .is_err()
    );
}

/// R-SW-02, TH-48, I-19: a signed table whose routes break a rule of the
/// route table, two cells on one tunnel address, is refused whole.
#[test]
fn r_sw_02_route_table_refuses_routes_that_share_an_address() {
    let key = composite::generate().unwrap();
    let mut b = route(2, "b.example");
    b.app.address = route(1, "a.example").app.address;
    let bytes = signed(&key, 3, &[route(1, "a.example"), b]);
    assert_eq!(
        verify_route_table(&[pk(&key)], &bytes).map(|_| ()),
        Err(FeedError::Route(RouteError::AddressTaken))
    );
}

/// R-SW-02, ADR-004 (2026-11-15 late): live routes take a table of the
/// feed only when its version is newer than the one served, so a
/// replayed older table never brings back a removed route.
#[test]
fn r_sw_02_live_routes_apply_only_a_newer_version() {
    let routes = LiveRoutes::default();
    assert_eq!(routes.version(), 0);
    let mut with = RouteTable::new();
    let r = route(1, "a.example");
    with.add_cell(r.host.clone(), r.app.clone(), r.vault.clone())
        .unwrap();
    assert!(routes.apply(4, with.clone()));
    assert!(routes.apply(5, RouteTable::new()));
    assert!(!routes.apply(4, with.clone()), "an older table was applied");
    assert!(!routes.apply(5, with));
    assert_eq!(routes.version(), 5);
    assert!(routes.current().is_empty());
}

/// An in-memory feed: each poll is recorded and answered with the
/// table that is current then.
struct Memory {
    table: RefCell<Vec<u8>>,
    polls: RefCell<Vec<u64>>,
}

impl FeedTransport for Memory {
    async fn fetch(&self, poll: &[u8]) -> io::Result<Vec<u8>> {
        self.polls.borrow_mut().push(decode_poll(poll).unwrap());
        Ok(self.table.borrow().clone())
    }
}

/// R-SW-02, design section 3.7 step 3: an edge polls, reports the version
/// it serves, and applies the signed table. After the control plane
/// publishes a version without a cell, the next poll removes the cell's
/// hosts, and the poll after it reports that version. A table signed by
/// another key changes nothing.
#[test]
fn r_sw_02_edge_feed_polls_reports_and_applies() {
    let key = composite::generate().unwrap();
    let memory = Memory {
        table: RefCell::new(signed(
            &key,
            2,
            &[route(1, "a.example"), route(2, "b.example")],
        )),
        polls: RefCell::new(Vec::new()),
    };
    let live = LiveRoutes::default();
    let feed = RouteFeed::new(memory, vec![pk(&key)], live.clone());
    assert_eq!(block_on(feed.poll_once()), Ok(2));
    assert_eq!(live.current().len(), 4);
    let gone = HostName::parse(b"a.example").unwrap();
    assert!(live.current().route(&gone).is_some());
    let transport = feed_transport(&feed);
    *transport.table.borrow_mut() = signed(&key, 3, &[route(2, "b.example")]);
    assert_eq!(block_on(feed.poll_once()), Ok(3));
    assert!(live.current().route(&gone).is_none());
    assert!(
        live.current()
            .route(&HostName::parse(b"id.b.example").unwrap())
            .is_some()
    );
    let stranger = composite::generate().unwrap();
    *transport.table.borrow_mut() = signed(&stranger, 9, &[route(1, "a.example")]);
    assert_eq!(block_on(feed.poll_once()), Err(FeedError::BadSignature));
    assert_eq!(live.version(), 3);
    assert_eq!(*transport.polls.borrow(), vec![0, 2, 3]);
    assert_eq!(decode_poll(&encode_poll(3)), Ok(3));
    assert!(decode_poll(&[0; 12]).is_err());
}

fn feed_transport(feed: &RouteFeed<Memory>) -> &Memory {
    feed.transport()
}

// ---- lane L15 `prod/route-feed` (ADR-009 "Pilot route feed") ----

/// A feed into fresh live routes over an in-memory transport that
/// answers `table`.
fn memory_feed(key: &CompositeSigningKey, table: Vec<u8>) -> (RouteFeed<Memory>, LiveRoutes) {
    let live = LiveRoutes::default();
    let feed = RouteFeed::new(
        Memory {
            table: RefCell::new(table),
            polls: RefCell::new(Vec::new()),
        },
        vec![pk(key)],
        live.clone(),
    );
    (feed, live)
}

fn host(h: &str) -> HostName {
    HostName::parse(h.as_bytes()).unwrap()
}

/// I-19, B5 (ADR-009 "Pilot route feed", row "Feed bytes"): version 2 of
/// the table carries a pin after each endpoint, and the edge serves a
/// verified table with exactly those pins. One route decodes on its own
/// in one spelling, as the operator request of `fstp-control` carries it.
#[test]
fn i19_feed_carries_the_pin_of_each_tunnel_endpoint() {
    let key = composite::generate().unwrap();
    let r = pinned(route(1, "a.example"));
    let (feed, live) = memory_feed(&key, signed_pinned(&key, 11, std::slice::from_ref(&r)));
    assert_eq!(block_on(feed.poll_once()), Ok(11));
    let pins = live.pins();
    assert_eq!(pins.pin_of(&r.route.app), Some(r.app_pin));
    assert_eq!(pins.pin_of(&r.route.vault), Some(r.vault_pin));
    let mut one = Vec::new();
    encode_route(&mut one, &r).unwrap();
    assert_eq!(decode_route(&one), Ok(r.clone()));
    for cut in 0..one.len() {
        assert!(decode_route(&one[..cut]).is_err(), "cut {cut}");
    }
    let mut longer = one.clone();
    longer.push(0);
    assert!(decode_route(&longer).is_err());
    // A table of the version 1 bytes, without pins, is no longer read.
    let mut v1 = signed_pinned(&key, 12, &[r]);
    v1[3] = b'1';
    assert!(decode_signed_route_table(&v1).is_err());
}

/// R-SW-02, TH-48 (ADR-009 "Pilot route feed", row "Rollback"): a table
/// that verifies but is older than the one the edge serves is refused as
/// a rollback, and the edge keeps its table and its version. A table of
/// the same version changes nothing and is no error.
#[test]
fn r_sw_02_feed_rollback_is_refused_and_keeps_the_table() {
    let key = composite::generate().unwrap();
    let (feed, live) = memory_feed(
        &key,
        signed(&key, 20, &[route(1, "a.example"), route(2, "b.example")]),
    );
    assert_eq!(block_on(feed.poll_once()), Ok(20));
    // The control plane removes cell 1 in version 21.
    *feed.transport().table.borrow_mut() = signed(&key, 21, &[route(2, "b.example")]);
    assert_eq!(block_on(feed.poll_once()), Ok(21));
    assert!(live.current().route(&host("a.example")).is_none());
    // A replay of version 20, validly signed, would bring cell 1 back.
    *feed.transport().table.borrow_mut() =
        signed(&key, 20, &[route(1, "a.example"), route(2, "b.example")]);
    assert_eq!(block_on(feed.poll_once()), Err(FeedError::Rollback));
    assert_eq!(live.version(), 21);
    assert!(live.current().route(&host("a.example")).is_none());
    assert!(live.current().route(&host("b.example")).is_some());
    // The same version again is the steady state.
    *feed.transport().table.borrow_mut() = signed(&key, 21, &[route(2, "b.example")]);
    assert_eq!(block_on(feed.poll_once()), Ok(21));
    assert_eq!(FeedError::Rollback.rule(), "R-SW-02");
}

/// I-90 (ADR-009 "Pilot route feed", row "Unreachable or refused feed"):
/// a table with a changed byte, a table signed by another key, a table
/// whose signature carries only one valid half, and a failed exchange are
/// each refused. The edge keeps serving its last verified table and
/// version, and never applies an unsigned table.
#[test]
fn i90_tampered_or_foreign_feed_keeps_the_last_good_table() {
    let key = composite::generate().unwrap();
    let good = signed(&key, 5, &[route(1, "a.example")]);
    let (feed, live) = memory_feed(&key, good.clone());
    assert_eq!(block_on(feed.poll_once()), Ok(5));
    let keeps = |feed: &RouteFeed<Memory>, bytes: Vec<u8>| {
        *feed.transport().table.borrow_mut() = bytes;
        let refused = block_on(feed.poll_once());
        assert!(refused.is_err(), "a refused table was applied");
        assert_eq!(live.version(), 5);
        assert!(live.current().route(&host("a.example")).is_some());
        assert!(live.current().route(&host("b.example")).is_none());
        refused.err().unwrap()
    };
    let newer = signed(&key, 6, &[route(1, "a.example"), route(2, "b.example")]);
    // A changed host byte in the signed body.
    let mut tampered = newer.clone();
    let at = tampered.windows(9).position(|w| w == b"b.example").unwrap();
    tampered[at] = b'c';
    assert_eq!(keeps(&feed, tampered), FeedError::BadSignature);
    // Another key.
    let stranger = composite::generate().unwrap();
    assert_eq!(
        keeps(&feed, signed(&stranger, 6, &[route(2, "b.example")])),
        FeedError::BadSignature
    );
    // One half spliced from another key's signature over the same body.
    let body = encode_route_table_body(6, &pinned_all(&[route(2, "b.example")])).unwrap();
    let mine = key
        .sign_with_context(&body, ROUTE_TABLE_CONTEXT)
        .unwrap()
        .to_bytes();
    let theirs = stranger
        .sign_with_context(&body, ROUTE_TABLE_CONTEXT)
        .unwrap()
        .to_bytes();
    let split = composite::SIGNATURE_LEN - 64;
    let mut spliced = mine.to_vec();
    spliced[split..].copy_from_slice(&theirs[split..]);
    assert_eq!(
        keeps(&feed, encode_signed_route_table(&body, &spliced).unwrap()),
        FeedError::BadSignature
    );
    // No signature at all.
    assert!(matches!(
        keeps(&feed, encode_signed_route_table(&body, &[]).unwrap()),
        FeedError::BadSignature
    ));
    // Not a table.
    assert!(matches!(
        keeps(&feed, b"routes".to_vec()),
        FeedError::Malformed(_)
    ));
    assert_eq!(FeedError::BadSignature.rule(), "I-90");
    // The good newer table still applies afterwards.
    *feed.transport().table.borrow_mut() = newer;
    assert_eq!(block_on(feed.poll_once()), Ok(6));
}

/// I-19, TH-48 (ADR-009 "Pilot route feed", row "Checks before
/// signing"): the contents of a validly signed feed obey every rule of
/// `RouteTable::add_cell` and the pin rule. A host of two cells, a cell
/// with two hosts, a shared tunnel address, a cell whose endpoints share
/// an address, and a pin of two endpoints are each refused whole, and the
/// edge keeps its table. `check_routes` gives the same answers, so
/// `fstp-control` can refuse before it signs.
#[test]
fn i19_feed_contents_follow_the_route_table_rules() {
    let key = composite::generate().unwrap();
    let (feed, live) = memory_feed(&key, signed(&key, 1, &[route(1, "a.example")]));
    assert_eq!(block_on(feed.poll_once()), Ok(1));
    let a = pinned(route(1, "a.example"));
    let b = pinned(route(2, "b.example"));
    let mut cases: Vec<(Vec<PinnedRoute>, FeedError)> = Vec::new();
    // Cell 2 also on the vault origin host of cell 1.
    let mut b_on_a = b.clone();
    b_on_a.route.host = host("id.a.example");
    cases.push((
        vec![a.clone(), b_on_a],
        FeedError::Route(RouteError::HostTaken),
    ));
    // Cell 1 under a second host, on other addresses and pins.
    let mut a2 = pinned(route(1, "a2.example"));
    a2.route.app.address = "10.0.0.9:8443".parse().unwrap();
    a2.route.vault.address = "[fd00::9]:9443".parse().unwrap();
    a2.app_pin = [0x91; 32];
    a2.vault_pin = [0x92; 32];
    cases.push((vec![a.clone(), a2], FeedError::Route(RouteError::CellTaken)));
    // Cell 2 on cell 1's application address.
    let mut shared = b.clone();
    shared.route.app.address = a.route.app.address;
    cases.push((
        vec![a.clone(), shared],
        FeedError::Route(RouteError::AddressTaken),
    ));
    // A cell whose two endpoints share one address.
    let mut same = b.clone();
    same.route.vault.address = same.route.app.address;
    cases.push((vec![same], FeedError::Route(RouteError::SameAddress)));
    // Cell 2 with cell 1's application pin.
    let mut pin_twice = b.clone();
    pin_twice.vault_pin = a.app_pin;
    cases.push((vec![a.clone(), pin_twice], FeedError::PinTaken));
    // One cell whose two endpoints carry one pin.
    let mut own_twice = b.clone();
    own_twice.vault_pin = own_twice.app_pin;
    cases.push((vec![own_twice], FeedError::PinTaken));
    for (i, (routes, want)) in cases.into_iter().enumerate() {
        assert_eq!(
            check_routes(&routes).map(|_| ()),
            Err(want),
            "case {i}: check_routes"
        );
        *feed.transport().table.borrow_mut() = signed_pinned(&key, 2 + i as u64, &routes);
        assert_eq!(block_on(feed.poll_once()), Err(want), "case {i}: the feed");
        assert_eq!(live.version(), 1, "case {i}");
        assert!(live.current().route(&host("a.example")).is_some());
    }
    assert!(check_routes(&[a, b]).is_ok());
}
