//! Tests of `fstp_edge::parse_client_hello_sni` (M3 design sections 9.4
//! and 15, ADR-009 "Edge and tunnel", TH-26, H-05, I-19 and boundary rule
//! B5).
//!
//! - The differential: on hellos that a real `fstp-tls` client sends, the
//!   parser names the host that an `fstp-tls` server reports.
//! - Synthetic hellos from the independent writer in `support/hello.rs`:
//!   valid hellos name their host in lowercase, and every proper prefix
//!   needs more bytes.
//! - Refusals: malformed, truncated, oversized and multi-SNI hellos, and
//!   invalid host names. Hellos the edge cannot route close.
//! - ECH: a hello with `encrypted_client_hello` routes on its outer SNI
//!   (ADR-009, Daniel 2026-10-29 and 2026-11-13).
//!
//! The parser reads only. Bytes after the ClientHello are covered in
//! `i19_edge_pass_through.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/capture.rs"]
mod capture;
#[path = "support/common.rs"]
mod common;
#[path = "support/hello.rs"]
mod hello;

use std::net::SocketAddr;

use fstp_edge::{
    CELL_ID_LEN, CellEndpoint, CloseReason, Decision, HostName, RouteKind, RouteTable, SniOutcome,
    decide, parse_client_hello_sni,
};
use fstp_prop::{check, prop_assert, prop_assert_eq};

use common::{closes, gen_hello_naming, gen_hello_with, gen_host, host_of, refused};
use hello::{
    EXT_ECH, EXT_SERVER_NAME, HANDSHAKE_SERVER_HELLO, Hello, MAX_RECORD_BODY, MAX_SNI_BUF,
    NAME_TYPE_HOST, handshake_message, lowercase, put_len16, put_u24, record, server_name,
};

// ---------------------------------------------------------------------
// The differential against a real fstp-tls server (design section 15).
// ---------------------------------------------------------------------

/// I-19, B5, TH-26 (design section 15, `client_hello_sni`): on a hello
/// that an `fstp-tls` client sends to a DNS name, the parser names the
/// host the `fstp-tls` server reports. Each spelling runs three
/// handshakes, so random values and key shares differ.
#[test]
fn i19_th26_sni_differential_matches_fstp_tls_server() {
    for name in capture::DNS_NAMES {
        for _ in 0..3 {
            let cap = capture::handshake(name);
            let reported = cap
                .server_sni
                .as_deref()
                .unwrap_or_else(|| panic!("the fstp-tls server saw no SNI for {name}"));
            let verdict = parse_client_hello_sni(cap.first_record());
            let host = host_of(&verdict)
                .unwrap_or_else(|| panic!("{name}: the parser did not name a host: {verdict:?}"));
            assert_eq!(host.as_str(), reported, "{name}");
        }
    }
}

/// I-19, B5, TH-26 (design section 15): a client that connects to an
/// address sends no SNI, the `fstp-tls` server reports none, and the
/// parser reports `NoSni`.
#[test]
fn i19_th26_sni_differential_address_names_carry_no_sni() {
    for name in capture::IP_NAMES {
        let cap = capture::handshake(name);
        assert_eq!(cap.server_sni, None, "{name}");
        let verdict = parse_client_hello_sni(cap.first_record());
        assert_eq!(verdict, Ok(SniOutcome::NoSni), "{name}");
    }
}

/// TH-26 (design section 9.4): every proper prefix of a real `fstp-tls`
/// ClientHello record needs more bytes. The edge waits rather than
/// guesses.
#[test]
fn th26_sni_every_prefix_of_a_real_hello_needs_more() {
    let cap = capture::handshake("localhost");
    let first = cap.first_record();
    for cut in 0..first.len() {
        let verdict = parse_client_hello_sni(&first[..cut]);
        assert_eq!(verdict, Ok(SniOutcome::NeedMore), "prefix of {cut} bytes");
    }
}

// ---------------------------------------------------------------------
// Valid synthetic hellos.
// ---------------------------------------------------------------------

/// TH-26, B5 (design section 9.4): a valid hello naming a valid host in
/// any case yields that host in lowercase (`HostName` holds lowercase
/// ASCII).
#[test]
fn th26_sni_valid_hellos_name_their_lowercase_host() {
    check("th26_sni_valid_hellos_name_their_lowercase_host", |g| {
        let host = gen_host(g);
        let hello = gen_hello_naming(g, &host);
        g.note("host", &String::from_utf8_lossy(&host));
        let verdict = parse_client_hello_sni(&hello.record());
        let got = host_of(&verdict).map(|h| h.as_str().to_owned());
        prop_assert_eq!(got, Some(lowercase(&host)), "verdict {:?}", verdict);
        Ok(())
    });
}

/// TH-26 (design section 9.4): every proper prefix of a valid synthetic
/// hello needs more bytes, whatever its host and extension order.
#[test]
fn th26_sni_every_proper_prefix_needs_more() {
    check("th26_sni_every_proper_prefix_needs_more", |g| {
        let host = gen_host(g);
        let bytes = gen_hello_naming(g, &host).record();
        for cut in 0..bytes.len() {
            let verdict = parse_client_hello_sni(&bytes[..cut]);
            prop_assert_eq!(verdict, Ok(SniOutcome::NeedMore), "prefix of {} bytes", cut);
        }
        Ok(())
    });
}

/// TH-26 (design section 9.4): a valid hello without a `server_name`
/// extension yields `NoSni`, which closes the connection.
#[test]
fn th26_sni_hello_without_server_name_has_no_sni() {
    check("th26_sni_hello_without_server_name_has_no_sni", |g| {
        let hello = gen_hello_with(g, None);
        let verdict = parse_client_hello_sni(&hello.record());
        prop_assert_eq!(verdict, Ok(SniOutcome::NoSni));
        Ok(())
    });
}

/// TH-26 (design section 9.4): bytes that do not start a TLS handshake
/// record are `NotTls`, such as a plain HTTP request or an SSLv2 hello.
#[test]
fn th26_sni_non_handshake_first_byte_is_not_tls() {
    check("th26_sni_non_handshake_first_byte_is_not_tls", |g| {
        let mut bytes = g.bytes(1..=64);
        if bytes[0] == hello::CONTENT_HANDSHAKE {
            bytes[0] = *g.pick(&[b'G', 0x80, 0x17, 0x15, 0x00]);
        }
        let verdict = parse_client_hello_sni(&bytes);
        prop_assert_eq!(verdict, Ok(SniOutcome::NotTls), "input {:?}", bytes);
        Ok(())
    });
}

/// TH-26 (design section 9.4): nothing read yet means more bytes are
/// needed.
#[test]
fn th26_sni_empty_buffer_needs_more() {
    assert_eq!(parse_client_hello_sni(&[]), Ok(SniOutcome::NeedMore));
}

// ---------------------------------------------------------------------
// Refusals.
// ---------------------------------------------------------------------

/// Rebuilds a hello record around a changed body, with consistent record
/// and handshake lengths.
fn record_of_body(body: &[u8]) -> Vec<u8> {
    record(
        [0x03, 0x01],
        &handshake_message(hello::HANDSHAKE_CLIENT_HELLO, body),
    )
}

/// TH-26, H-05 (design section 9.4, ADR-009): structurally malformed
/// hellos are refused with a typed error, never routed and never waited
/// on. Every length here is consistent at the record and handshake layer,
/// so only the inner structure is wrong.
#[test]
fn th26_sni_malformed_hellos_are_refused() {
    let base = Hello::tls13(Some(b"cell.example"));
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();

    let mut h = base.clone();
    h.session_id = vec![0; 33];
    cases.push(("session id longer than 32 bytes", h.record()));

    let mut body = base.fixed_part();
    // Cipher suites of odd length: the two-byte length sits after
    // version (2), random (32) and the session id (1 + 32).
    let at = 2 + 32 + 1 + 32;
    body[at + 1] = 5;
    body.remove(at + 2 + 5);
    body.extend_from_slice(&base.extensions_block());
    cases.push(("cipher suites of odd length", record_of_body(&body)));

    let mut h = base.clone();
    h.cipher_suites.clear();
    cases.push(("no cipher suites", h.record()));

    let mut h = base.clone();
    h.compression.clear();
    cases.push(("no compression methods", h.record()));

    let mut body = base.fixed_part();
    let mut block = base.extensions_block();
    let claimed = u16::from_be_bytes([block[0], block[1]]) + 7;
    block[..2].copy_from_slice(&claimed.to_be_bytes());
    body.extend_from_slice(&block);
    cases.push((
        "extensions block longer than the body",
        record_of_body(&body),
    ));

    let mut body = base.body();
    body.extend_from_slice(&[0, 0, 0]);
    cases.push(("bytes after the extensions block", record_of_body(&body)));

    let mut h = base.clone();
    h.extensions.push((0x0a0a, Vec::new()));
    let mut body = h.fixed_part();
    let mut block = h.extensions_block();
    // The last extension (empty GREASE) claims a body of 9 bytes.
    let n = block.len();
    block[n - 2..].copy_from_slice(&9u16.to_be_bytes());
    body.extend_from_slice(&block);
    cases.push(("extension body past the block", record_of_body(&body)));

    let mut sni = server_name(&[(NAME_TYPE_HOST, b"cell.example")]);
    sni[1] += 3;
    let mut h = base.clone();
    h.extensions[0] = (EXT_SERVER_NAME, sni);
    cases.push(("server name list longer than its extension", h.record()));

    let mut sni = server_name(&[(NAME_TYPE_HOST, b"cell.example")]);
    sni.push(0);
    let mut h = base.clone();
    h.extensions[0] = (EXT_SERVER_NAME, sni);
    cases.push(("bytes after the server name list", h.record()));

    let mut sni = server_name(&[(NAME_TYPE_HOST, b"cell.example")]);
    sni[4] += 2;
    let mut h = base.clone();
    h.extensions[0] = (EXT_SERVER_NAME, sni);
    cases.push(("host name longer than the list", h.record()));

    let mut h = base.clone();
    h.extensions[0] = (EXT_SERVER_NAME, vec![0, 0]);
    cases.push(("empty server name list", h.record()));

    let mut h = base.clone();
    h.extensions[0] = (EXT_SERVER_NAME, Vec::new());
    cases.push(("empty server_name extension body", h.record()));

    for (what, bytes) in &cases {
        let verdict = parse_client_hello_sni(bytes);
        assert!(refused(&verdict), "{what}: {verdict:?}");
    }
}

/// TH-26, H-05 (design section 9.4): a hello whose record and handshake
/// lengths are complete but whose body stops early is refused. Each cut
/// keeps the outer lengths consistent, so the inner lengths run past the
/// end. The one cut that leaves exactly the fixed part is a hello without
/// extensions, which closes as well.
#[test]
fn th26_sni_truncated_inner_lengths_are_refused() {
    check("th26_sni_truncated_inner_lengths_are_refused", |g| {
        let host = gen_host(g);
        let h = gen_hello_naming(g, &host);
        let body = h.body();
        let fixed = h.fixed_part().len();
        let cut = g.usize_in(0..=body.len() - 1);
        let verdict = parse_client_hello_sni(&record_of_body(&body[..cut]));
        if cut == fixed {
            prop_assert!(
                closes(&verdict),
                "cut {} at the fixed part: {:?}",
                cut,
                verdict
            );
        } else {
            prop_assert!(
                refused(&verdict),
                "cut {} of {}: {:?}",
                cut,
                body.len(),
                verdict
            );
        }
        Ok(())
    });
}

/// TH-26, H-05 (design section 9.4, ADR-009: at most 16 KiB): a record
/// longer than TLS allows, or a ClientHello that claims more than 16 KiB,
/// is refused at once, before its bytes arrive.
#[test]
fn th26_sni_oversized_hellos_are_refused() {
    let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
    for len in [MAX_RECORD_BODY + 1, 0x8000, 0xffff] {
        let n = u16::try_from(len).unwrap();
        let mut bytes = vec![hello::CONTENT_HANDSHAKE, 0x03, 0x01];
        bytes.extend_from_slice(&n.to_be_bytes());
        bytes.push(hello::HANDSHAKE_CLIENT_HELLO);
        put_u24(&mut bytes, len - 4);
        cases.push((format!("record body of {len} bytes"), bytes));
    }
    for len in [MAX_SNI_BUF, 0x01_0000, 0xff_ffff] {
        let mut bytes = vec![hello::CONTENT_HANDSHAKE, 0x03, 0x01, 0x40, 0x00];
        bytes.push(hello::HANDSHAKE_CLIENT_HELLO);
        put_u24(&mut bytes, len);
        cases.push((format!("ClientHello of {len} bytes"), bytes));
    }
    for (what, bytes) in &cases {
        let verdict = parse_client_hello_sni(bytes);
        assert!(refused(&verdict), "{what}: {verdict:?}");
    }
}

/// TH-26, H-05 (design section 9.4: at most 16 KiB): once more than
/// 16 KiB are buffered, the parser never asks for more. The edge's read
/// buffer is bounded.
#[test]
fn th26_sni_never_needs_more_beyond_16_kib() {
    check("th26_sni_never_needs_more_beyond_16_kib", |g| {
        let mut bytes = vec![hello::CONTENT_HANDSHAKE, 0x03, *g.pick(&[0x01, 0x03])];
        bytes.extend_from_slice(&g.u16().to_be_bytes());
        bytes.push(hello::HANDSHAKE_CLIENT_HELLO);
        put_u24(&mut bytes, g.usize_in(0..=0xff_ffff));
        let fill = g.u8();
        let len = g.usize_in(MAX_SNI_BUF + 1..=4 * MAX_SNI_BUF);
        bytes.resize(len, fill);
        let verdict = parse_client_hello_sni(&bytes);
        prop_assert!(
            verdict.is_ok() || refused(&verdict),
            "stub verdict {:?}",
            verdict
        );
        prop_assert!(
            verdict != Ok(SniOutcome::NeedMore),
            "asked for more after {} bytes",
            len
        );
        Ok(())
    });
}

/// TH-26, H-05 (design section 9.4, RFC 6066 section 3): a server name
/// list with two host names, equal or not, is refused. The edge never
/// picks one of several names.
#[test]
fn th26_sni_multi_sni_list_is_refused() {
    check("th26_sni_multi_sni_list_is_refused", |g| {
        let a = gen_host(g);
        let b = if g.bool() { a.clone() } else { gen_host(g) };
        let mut names = vec![
            (NAME_TYPE_HOST, a.as_slice()),
            (NAME_TYPE_HOST, b.as_slice()),
        ];
        g.shuffle(&mut names);
        let hello = gen_hello_with(g, Some(server_name(&names)));
        let verdict = parse_client_hello_sni(&hello.record());
        prop_assert!(refused(&verdict), "verdict {:?}", verdict);
        Ok(())
    });
}

/// TH-26, H-05 (design section 9.4, RFC 8446 section 4.2): two
/// `server_name` extensions in one hello are refused.
#[test]
fn th26_sni_two_server_name_extensions_are_refused() {
    check("th26_sni_two_server_name_extensions_are_refused", |g| {
        let a = gen_host(g);
        let b = if g.bool() { a.clone() } else { gen_host(g) };
        let mut hello = gen_hello_naming(g, &a);
        let at = g.usize_in(0..=hello.extensions.len());
        hello
            .extensions
            .insert(at, (EXT_SERVER_NAME, server_name(&[(NAME_TYPE_HOST, &b)])));
        let verdict = parse_client_hello_sni(&hello.record());
        prop_assert!(refused(&verdict), "verdict {:?}", verdict);
        Ok(())
    });
}

/// TH-26, H-05 (design section 9.4, RFC 6066 section 3, RFC 1123): host
/// names that are not LDH DNS names are refused, so no such name reaches
/// the route table.
#[test]
fn th26_sni_invalid_host_names_are_refused() {
    let long_label = vec![b'a'; 64];
    let mut long_name = Vec::new();
    for _ in 0..4 {
        long_name.extend_from_slice(&[b'b'; 63]);
        long_name.push(b'.');
    }
    long_name.truncate(254);
    let names: Vec<(&str, Vec<u8>)> = vec![
        ("empty name", Vec::new()),
        ("NUL byte", b"cell\0.example".to_vec()),
        ("non-ASCII byte", b"c\xc3\xa9ll.example".to_vec()),
        ("space", b"cell .example".to_vec()),
        ("slash", b"cell/x.example".to_vec()),
        ("empty label", b"cell..example".to_vec()),
        ("leading dot", b".cell.example".to_vec()),
        ("trailing dot", b"cell.example.".to_vec()),
        ("label of 64 bytes", long_label),
        ("name of 254 bytes", long_name),
        ("label starting with a hyphen", b"-cell.example".to_vec()),
        ("label ending with a hyphen", b"cell-.example".to_vec()),
        ("IPv4 literal", b"127.0.0.1".to_vec()),
        ("IPv6 literal", b"::1".to_vec()),
    ];
    for (what, name) in &names {
        let hello = Hello::tls13(Some(name));
        let verdict = parse_client_hello_sni(&hello.record());
        assert!(refused(&verdict), "{what}: {verdict:?}");
    }
}

/// The cell id of the one cell in [`ech_table`].
const ECH_CELL: [u8; CELL_ID_LEN] = [7; CELL_ID_LEN];

/// A route table with one cell, `cell.example`, and its vault origin
/// `id.cell.example`.
fn ech_table() -> RouteTable {
    let endpoint = |port: u16| CellEndpoint {
        cell: ECH_CELL,
        address: SocketAddr::from(([10, 0, 2, 7], port)),
        tls_name: "tunnel.cell.internal".to_owned(),
    };
    let mut table = RouteTable::new();
    table
        .add_cell(
            HostName::parse(b"cell.example").unwrap(),
            endpoint(8443),
            endpoint(9443),
        )
        .unwrap();
    table
}

/// Inserts an `encrypted_client_hello` extension with a random body at a
/// random position, as a GREASE or a real ECH client would send it.
fn add_ech(g: &mut fstp_prop::Gen, hello: &mut Hello) {
    let at = g.usize_in(0..=hello.extensions.len());
    let ech = g.bytes(0..=200);
    hello.extensions.insert(at, (EXT_ECH, ech));
}

/// B5, TH-26, I-19 (design section 9.4, ADR-009 "Edge and tunnel"):
/// a hello with an `encrypted_client_hello` extension routes on its outer
/// SNI, like any other hello. Daniel decided this on 2026-10-29 (ADR-009,
/// design section 21) and again on 2026-11-13 (M3 exit audit section 7,
/// item 8). Chromium-family browsers send that extension as GREASE. This
/// test replaces `b5_th26_sni_encrypted_client_hello_closes`.
#[test]
fn b5_th26_sni_encrypted_client_hello_routes_on_outer_sni() {
    let table = ech_table();
    check(
        "b5_th26_sni_encrypted_client_hello_routes_on_outer_sni",
        |g| {
            let (name, kind): (&[u8], RouteKind) = if g.bool() {
                (b"cell.example", RouteKind::Cell)
            } else {
                (b"id.cell.example", RouteKind::VaultOrigin)
            };
            let mut outer = name.to_vec();
            for b in &mut outer {
                if g.bool() {
                    *b = b.to_ascii_uppercase();
                }
            }
            let mut hello = gen_hello_naming(g, &outer);
            add_ech(g, &mut hello);
            match decide(&table, &hello.record()) {
                Decision::Forward {
                    host,
                    endpoint,
                    kind: routed,
                } => {
                    prop_assert_eq!(host.as_str().as_bytes(), name);
                    prop_assert_eq!(endpoint.cell, ECH_CELL);
                    prop_assert_eq!(routed, kind);
                }
                other => prop_assert!(false, "an ECH hello did not route: {:?}", other),
            }
            Ok(())
        },
    );
}

/// B5, TH-26, I-19 (design section 9.4, ADR-009): a hello with an
/// `encrypted_client_hello` extension whose outer SNI names no route
/// still closes as an unknown host, and one without an outer SNI closes
/// as having none (Daniel, 2026-10-29 and 2026-11-13). The extension
/// never opens a route of its own.
#[test]
fn b5_th26_sni_encrypted_client_hello_without_a_route_closes() {
    let table = ech_table();
    check(
        "b5_th26_sni_encrypted_client_hello_without_a_route_closes",
        |g| {
            let outer = gen_host(g);
            let lower = lowercase(&outer);
            if lower == "cell.example" || lower == "id.cell.example" {
                return Ok(());
            }
            let mut hello = gen_hello_naming(g, &outer);
            add_ech(g, &mut hello);
            let decision = decide(&table, &hello.record());
            prop_assert_eq!(decision, Decision::Close(CloseReason::UnknownHost));

            let mut bare = gen_hello_with(g, None);
            add_ech(g, &mut bare);
            let decision = decide(&table, &bare.record());
            prop_assert_eq!(decision, Decision::Close(CloseReason::NoSni));
            Ok(())
        },
    );
}

/// TH-26 (design section 9.4, RFC 6066 section 3): a server name of a
/// type other than `host_name` names no host, so the connection closes.
#[test]
fn th26_sni_unknown_name_type_closes() {
    for ty in [1u8, 2, 0xff] {
        let mut hello = Hello::tls13(None);
        hello
            .extensions
            .insert(0, (EXT_SERVER_NAME, server_name(&[(ty, b"cell.example")])));
        let verdict = parse_client_hello_sni(&hello.record());
        assert!(closes(&verdict), "name type {ty}: {verdict:?}");
    }
}

/// TH-26 (design section 9.4): a handshake record whose first message is
/// not a ClientHello names no host, so the connection closes.
#[test]
fn th26_sni_other_handshake_message_closes() {
    let body = Hello::tls13(Some(b"cell.example")).body();
    let bytes = record(
        [0x03, 0x03],
        &handshake_message(HANDSHAKE_SERVER_HELLO, &body),
    );
    let verdict = parse_client_hello_sni(&bytes);
    assert!(closes(&verdict), "{verdict:?}");
}

/// TH-26 (design section 9.4): a well-formed record whose length field
/// disagrees with its ClientHello is refused. The record ends before the
/// hello, which is longer than the record says.
#[test]
fn th26_sni_handshake_longer_than_its_record_is_refused() {
    let hs = Hello::tls13(Some(b"cell.example")).handshake();
    let mut bytes = vec![hello::CONTENT_HANDSHAKE, 0x03, 0x01];
    put_len16(&mut bytes, &hs[..hs.len() - 1]);
    // A second record follows that is not a handshake record, so no
    // reading of the record layer can complete the hello.
    bytes.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]);
    let verdict = parse_client_hello_sni(&bytes);
    assert!(refused(&verdict), "{verdict:?}");
}
