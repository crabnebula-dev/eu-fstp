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
    CellEndpoint, FeedError, FeedTransport, HostName, LiveRoutes, ROUTE_TABLE_CONTEXT, RouteEntry,
    RouteError, RouteFeed, RouteTable, decode_poll, decode_signed_route_table, encode_poll,
    encode_route_table_body, encode_signed_route_table, routes_of, verify_route_table,
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

fn signed(key: &CompositeSigningKey, version: u64, routes: &[RouteEntry]) -> Vec<u8> {
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
        vec![route(1, "a.example"), route(2, "b.example")]
    );
    let (version, table) = verify_route_table(&[pk(&other), pk(&key)], &bytes).unwrap();
    assert_eq!(version, 7);
    assert_eq!(table.len(), 4);
    assert_eq!(routes_of(&table), decoded.routes);
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
    let a = encode_route_table_body(1, &[route(1, "a.example")]).unwrap();
    let b = encode_route_table_body(1, &[route(2, "b.example")]).unwrap();
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
    assert!(encode_route_table_body(1, &[route(1, "a.example"), route(2, "a.example")]).is_err());
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
