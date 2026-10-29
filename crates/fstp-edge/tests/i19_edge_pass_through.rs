//! I-19 and boundary rule B5 at the edge: the edge reads the SNI and
//! passes every byte through unchanged (M3 design sections 1.2, 1.5, 2.4
//! rule 5, 9.4 and 14.4, ADR-009 "Edge and tunnel").
//!
//! `i19_edge_forwards_bytes_after_client_hello_unchanged` is the exit test
//! that design sections 14.4 and 20 and ADR-009 name. It drives the public
//! `serve` that the edge runs for each client connection, over in-memory
//! streams. The other tests hold the parser's part of the same property:
//!
//! - The parser's verdict on a ClientHello does not depend on any byte
//!   after it, so the edge never needs to read, change or drop them.
//! - The parser takes a shared slice, so it cannot change the bytes it
//!   reads. Its verdict on a hello is the same before and after any tail.
//! - A host that is not in the route table has no route, so it closes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/capture.rs"]
mod capture;
#[path = "support/common.rs"]
mod common;
#[path = "support/hello.rs"]
mod hello;

use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;

use fstp_edge::{
    CellEndpoint, HostName, MAX_HOST_LEN, RouteKind, RouteTable, SniOutcome, Spliced,
    TUNNEL_HEADER_LEN, TunnelOpener, decode_tunnel_header, parse_client_hello_sni, serve,
};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};
use fstp_rt::IoExt;
use fstp_rt::duplex::{DuplexStream, duplex};
use fstp_rt::future::{block_on, join, yield_now};

use common::{gen_hello_naming, gen_host, host_of, host_via_parser};
use hello::lowercase;

/// I-19, B5 (design section 2.4 rule 5, ADR-009): the verdict on a valid
/// hello equals the verdict on that hello followed by any bytes: random
/// bytes, a second hello naming another host, or an application data
/// record. The bytes after the hello never steer the edge.
#[test]
fn i19_sni_verdict_ignores_bytes_after_client_hello() {
    check("i19_sni_verdict_ignores_bytes_after_client_hello", |g| {
        let host = gen_host(g);
        let first = gen_hello_naming(g, &host).record();
        let tail = match g.u8_in(0..=2) {
            0 => g.bytes(0..=2048),
            1 => {
                let other = gen_host(g);
                gen_hello_naming(g, &other).record()
            }
            _ => {
                let mut r = vec![0x17, 0x03, 0x03];
                let body = g.bytes(1..=512);
                hello::put_len16(&mut r, &body);
                r
            }
        };
        let alone = parse_client_hello_sni(&first);
        let mut joined = first.clone();
        joined.extend_from_slice(&tail);
        let followed = parse_client_hello_sni(&joined);
        let named = host_of(&alone).map(|h| h.as_str().to_owned());
        prop_assert_eq!(named, Some(lowercase(&host)), "alone {:?}", alone);
        prop_assert_eq!(followed, alone);
        Ok(())
    });
}

/// I-19, B5 (design section 15, `client_hello_sni`): on a real `fstp-tls`
/// client's byte stream, which holds the ClientHello and then the rest of
/// the client's handshake, the verdict equals the verdict on the
/// ClientHello alone, and names the host the `fstp-tls` server reported.
#[test]
fn i19_sni_verdict_on_a_real_stream_equals_verdict_on_its_hello() {
    let cap = capture::handshake("localhost");
    assert!(
        cap.client_bytes.len() > cap.first_record().len(),
        "the client sent more than its hello"
    );
    let alone = parse_client_hello_sni(cap.first_record());
    let whole = parse_client_hello_sni(&cap.client_bytes);
    let named = host_of(&alone).map(|h| h.as_str().to_owned());
    assert_eq!(named, cap.server_sni, "alone {alone:?}");
    assert_eq!(whole, alone);
}

/// I-19 (design sections 1.5 and 9.4): the route table holds verified
/// hosts only, so a host that no one registered has no route and the edge
/// closes the connection. This test covers the empty table. The routed
/// case is `i19_edge_forwards_bytes_after_client_hello_unchanged`.
#[test]
fn i19_unregistered_host_has_no_route() {
    check("i19_unregistered_host_has_no_route", |g| {
        let host = host_via_parser(g)?;
        let table = RouteTable::default();
        prop_assert!(table.route(&host).is_none(), "{:?} routed", host);
        Ok(())
    });
}

/// I-19, B5 (design section 9.4): the verdict needs no more than the
/// ClientHello. Once the hello's last byte has arrived the parser decides,
/// and before it the parser waits. A routing edge therefore forwards the
/// first byte after the hello untouched.
#[test]
fn i19_sni_decides_exactly_at_the_end_of_the_hello() {
    check("i19_sni_decides_exactly_at_the_end_of_the_hello", |g| {
        let host = gen_host(g);
        let mut bytes = gen_hello_naming(g, &host).record();
        let end = bytes.len();
        bytes.extend_from_slice(&g.bytes(1..=64));
        let before = parse_client_hello_sni(&bytes[..end - 1]);
        let at = parse_client_hello_sni(&bytes[..end]);
        prop_assert_eq!(before, Ok(SniOutcome::NeedMore));
        let named = host_of(&at).map(|h| h.as_str().to_owned());
        prop_assert_eq!(named, Some(lowercase(&host)), "at the end {:?}", at);
        Ok(())
    });
}

/// Hands out one prepared tunnel end and records the endpoint it opened.
struct OneTunnel {
    tunnel: Mutex<Option<DuplexStream>>,
    opened: Mutex<Vec<CellEndpoint>>,
}

impl TunnelOpener for OneTunnel {
    type Tunnel = DuplexStream;

    async fn open(&self, endpoint: &CellEndpoint) -> io::Result<DuplexStream> {
        self.opened.lock().unwrap().push(endpoint.clone());
        self.tunnel
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))
    }
}

/// An endpoint of cell `cell` on `port`.
fn endpoint(cell: u8, port: u16) -> CellEndpoint {
    CellEndpoint {
        cell: [cell; fstp_edge::CELL_ID_LEN],
        address: SocketAddr::from(([10, 0, 0, cell], port)),
        tls_name: "tunnel.cell.internal".to_owned(),
    }
}

/// The handshake message of `record` cut into handshake records of random
/// sizes, as a client may send a ClientHello.
fn fragment(g: &mut Gen, record: &[u8]) -> Vec<u8> {
    let version = [record[1], record[2]];
    let mut rest = &record[5..];
    let mut out = Vec::new();
    while !rest.is_empty() {
        let n = g.usize_in(1..=rest.len());
        let (part, tail) = rest.split_at(n);
        out.extend_from_slice(&hello::record(version, part));
        rest = tail;
    }
    out
}

/// I-19, B5 (design sections 2.4 rule 5, 9.4 and 14.4, ADR-009 "Edge and
/// tunnel"): through the public `serve`, the routed cell process receives
/// the tunnel header and then every client byte unchanged, the ClientHello
/// included. The client receives every cell byte. The header names the
/// routed host and the client's address and port. The hello may span
/// several records and arrive in segments of any size. It names the cell
/// host or its vault origin, in any case.
#[test]
fn i19_edge_forwards_bytes_after_client_hello_unchanged() {
    check(
        "i19_edge_forwards_bytes_after_client_hello_unchanged",
        |g| {
            let host = gen_host(g);
            g.assume(host.len() <= MAX_HOST_LEN - 3);
            let cell_host = HostName::parse(&host).map_err(|e| format!("{e:?}"))?;
            let (app, vault) = (endpoint(7, 8443), endpoint(7, 9443));
            let mut table = RouteTable::new();
            table
                .add_cell(cell_host, app.clone(), vault.clone())
                .map_err(|e| format!("{e:?}"))?;
            let other = HostName::parse(b"other-cell.invalid").map_err(|e| format!("{e:?}"))?;
            let added = table.add_cell(other, endpoint(8, 8443), endpoint(8, 9443));
            g.assume(added.is_ok());

            let to_vault = g.bool();
            let named = if to_vault {
                [b"iD.".as_slice(), &host].concat()
            } else {
                host.clone()
            };
            let record = gen_hello_naming(g, &named).record();
            let mut sent = if g.bool() {
                fragment(g, &record)
            } else {
                record
            };
            sent.extend_from_slice(&g.bytes(0..=4096));
            let reply = g.bytes(0..=4096);
            let segment = g.usize_in(1..=2048);
            let peer = if g.bool() {
                SocketAddr::from((g.u32().to_be_bytes(), g.u16()))
            } else {
                let mut a = [0u8; 16];
                a.iter_mut().for_each(|b| *b = g.u8());
                a[0] = 0x20;
                SocketAddr::from((a, g.u16()))
            };

            let (mut client, edge_side) = duplex(g.usize_in(1..=8192));
            let (tunnel_edge, mut cell) = duplex(g.usize_in(1..=8192));
            let opener = OneTunnel {
                tunnel: Mutex::new(Some(tunnel_edge)),
                opened: Mutex::new(Vec::new()),
            };
            let client_side = async {
                for part in sent.chunks(segment) {
                    client.write_all(part).await?;
                    yield_now().await;
                }
                client.shutdown().await?;
                let mut got = Vec::new();
                client.read_to_end(&mut got, 1 << 20).await?;
                io::Result::Ok(got)
            };
            let cell_side = async {
                let mut got = Vec::new();
                cell.read_to_end(&mut got, 1 << 20).await?;
                cell.write_all(&reply).await?;
                cell.shutdown().await?;
                io::Result::Ok(got)
            };
            let (served, (to_client, to_cell)) = block_on(join(
                serve(edge_side, peer, &table, &opener),
                join(client_side, cell_side),
            ));
            let to_client = to_client.map_err(|e| format!("client: {e}"))?;
            let to_cell = to_cell.map_err(|e| format!("cell: {e}"))?;

            let (expect_endpoint, expect_kind) = if to_vault {
                (vault, RouteKind::VaultOrigin)
            } else {
                (app, RouteKind::Cell)
            };
            prop_assert_eq!(opener.opened.lock().unwrap().clone(), vec![expect_endpoint]);
            prop_assert!(to_cell.len() >= TUNNEL_HEADER_LEN, "short tunnel");
            let (header, rest) = to_cell.split_at(TUNNEL_HEADER_LEN);
            let header = decode_tunnel_header(header).map_err(|e| format!("header: {e:?}"))?;
            prop_assert_eq!(header.host.as_str(), lowercase(&named));
            prop_assert_eq!((header.client_ip(), header.port), (peer.ip(), peer.port()));
            prop_assert!(rest == &sent[..], "the cell received changed bytes");
            prop_assert!(to_client == reply, "the client received changed bytes");
            let served = served.map_err(|e| format!("serve: {e:?}"))?;
            prop_assert_eq!(
                served,
                Spliced {
                    kind: expect_kind,
                    to_cell: u64::try_from(sent.len()).unwrap(),
                    to_client: u64::try_from(reply.len()).unwrap(),
                }
            );
            Ok(())
        },
    );
}
