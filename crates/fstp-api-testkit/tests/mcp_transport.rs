//! The Streamable HTTP rules of `fstp-mcp` (M4 design section 3.8,
//! ADR-013 "Transport", H-23), driven through `McpServer::serve`.
//!
//! Revision readings: ADR-013 pins MCP 2026-07-28 with 2025-06-18 as the
//! floor. Design section 3.8 and the lane scope build the 2025-06-18
//! methods: `initialize`, `notifications/initialized`, `ping`, protocol
//! sessions and `DELETE`. Those tests send `MCP-Protocol-Version:
//! 2025-06-18` and name the floor. The rules both revisions share are
//! tested without a revision: one message per POST, `GET` gets 405, a
//! present foreign `Origin` gets 403, an unsupported protocol version
//! gets 400. The 2026-07-28 shape (`server/discover`, per-request
//! `_meta`, `Mcp-Method` and `Mcp-Name`, `resultType`, no sessions) is
//! outside the lane scope, and is an open point for Daniel.
//!
//! The 2025-06-18 facts used here, checked against its published text on
//! 2026-11-06 and paraphrased: a server that offers no stream answers
//! `GET` with 405; a present invalid `Origin` gets 403; a posted
//! notification that is accepted gets 202 with no body; a request
//! answers `application/json` or an event stream; a session id is
//! visible ASCII; a server that requires a session answers 400 to a
//! request without one; a terminated session gets 404; an invalid or
//! unsupported `MCP-Protocol-Version` gets 400; `initialize` answers the
//! requested version when supported, else another supported version.
//!
//! The fake token port issues binary tokens that no HTTP field can carry,
//! so the `/mcp` rules that need a valid bearer run through
//! `McpServer::call_tool` in the other files. Here `/mcp` is driven with
//! no token or a well-formed unknown one.
//!
//! Status: red until `fstp_mcp::McpServer` exists, except the
//! self-tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod mcp_support;

use std::collections::BTreeSet;

use fstp_http::Method;
use fstp_json::Value;
use fstp_mcp::{OriginRefusal, OriginSeen, Surface, check_origin, server_name};
use fstp_prop::{check, prop_assert, prop_assert_eq};
use mcp_support::{
    DOMAIN, FLOOR, McpCell, ORIGIN, RESOURCE_METADATA, body_json, error_code, header, http,
    initialize, open_session, result_of, serve,
};

/// A well-formed bearer token that no grant holds.
const UNKNOWN_BEARER: &str = "Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// A `tools/list` request.
const TOOLS_LIST: &[u8] = br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;

/// H-23, ADR-013: `GET` on either endpoint answers 405, so no
/// server-initiated stream exists. Both revisions agree.
#[test]
fn adr013_get_answers_405() {
    let c = McpCell::new();
    let s = c.server();
    for surface in [Surface::Mcp, Surface::Public] {
        let r = serve(
            &s,
            surface,
            http(
                surface,
                Method::GET,
                &[("accept", "text/event-stream")],
                b"",
            ),
        );
        assert_eq!(r.status.as_u16(), 405, "{surface:?}");
        assert!(r.headers.get("mcp-session-id").is_none());
    }
}

/// H-23, ADR-013: a POST of one request answers 200 with
/// `Content-Type: application/json` and one JSON-RPC response that echoes
/// the id. No response sets a cookie.
#[test]
fn adr013_post_answers_application_json() {
    let c = McpCell::new();
    let s = c.server();
    let r = serve(
        &s,
        Surface::Public,
        http(Surface::Public, Method::POST, &[], &initialize(41)),
    );
    assert_eq!(r.status.as_u16(), 200);
    assert_eq!(
        header(&r, "content-type").map(|v| v.split(';').next().unwrap_or("").trim().to_owned()),
        Some("application/json".to_owned())
    );
    let v = body_json(&r).unwrap();
    let o = v.as_object().unwrap();
    assert_eq!(o.get("jsonrpc").and_then(Value::as_str), Some("2.0"));
    assert_eq!(o.get("id").and_then(Value::as_i64), Some(41));
    assert!(r.headers.get("set-cookie").is_none());
}

/// H-23, design section 3.8: a JSON-RPC batch is refused with 400, on
/// either endpoint, and nothing in it runs.
#[test]
fn adr013_batch_post_is_refused() {
    let c = McpCell::new();
    let s = c.server();
    let head = c.ports.engine.appended().len();
    let batch = format!(
        "[{},{}]",
        String::from_utf8(initialize(1)).unwrap(),
        r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#
    );
    for surface in [Surface::Public, Surface::Mcp] {
        let r = serve(
            &s,
            surface,
            http(surface, Method::POST, &[], batch.as_bytes()),
        );
        let status = r.status.as_u16();
        assert!(
            status == 400 || (surface == Surface::Mcp && status == 401),
            "{surface:?}: {status}"
        );
        assert!(r.headers.get("mcp-session-id").is_none());
    }
    assert_eq!(c.ports.engine.appended().len(), head);
}

/// H-23, ADR-013 "Origin": a present `Origin` that is not a tenant origin
/// gets 403 on `/mcp/public`, and on `/mcp` before any token check.
#[test]
fn adr013_foreign_origin_gets_403() {
    let c = McpCell::new();
    let s = c.server();
    for o in ["https://evil.example", "http://tenant.fstp.test", "null"] {
        let r = serve(
            &s,
            Surface::Public,
            http(
                Surface::Public,
                Method::POST,
                &[("origin", o)],
                &initialize(1),
            ),
        );
        assert_eq!(r.status.as_u16(), 403, "{o} on /mcp/public");
        for auth in [None, Some(UNKNOWN_BEARER)] {
            let mut h = vec![("origin", o)];
            if let Some(a) = auth {
                h.push(("authorization", a));
            }
            let r = serve(
                &s,
                Surface::Mcp,
                http(Surface::Mcp, Method::POST, &h, &initialize(1)),
            );
            assert_eq!(r.status.as_u16(), 403, "{o} on /mcp with {auth:?}");
        }
    }
}

/// H-23, ADR-013 "Origin": a missing `Origin` is accepted. On
/// `/mcp/public` the request is served. On `/mcp` it reaches the token
/// check, so it gets the 401 of a missing or unknown token, never 403.
/// The tenant's own origin is accepted the same way.
#[test]
fn adr013_absent_or_tenant_origin_is_accepted() {
    let c = McpCell::new();
    let s = c.server();
    for h in [vec![], vec![("origin", ORIGIN)]] {
        let r = serve(
            &s,
            Surface::Public,
            http(Surface::Public, Method::POST, &h, &initialize(1)),
        );
        assert_eq!(r.status.as_u16(), 200, "{h:?} on /mcp/public");
        let mut with = h.clone();
        with.push(("authorization", UNKNOWN_BEARER));
        for hs in [h.clone(), with] {
            let r = serve(
                &s,
                Surface::Mcp,
                http(Surface::Mcp, Method::POST, &hs, &initialize(1)),
            );
            assert_eq!(r.status.as_u16(), 401, "{hs:?} on /mcp");
        }
    }
}

/// H-23, ADR-013 "Origin": a duplicated or unparsable `Origin` is
/// refused with 400 or 403, never served.
#[test]
fn adr013_duplicated_or_unparsable_origin_is_refused() {
    let c = McpCell::new();
    let s = c.server();
    let cases: [Vec<(&str, &str)>; 5] = [
        vec![("origin", ORIGIN), ("origin", ORIGIN)],
        vec![("origin", ORIGIN), ("origin", "https://evil.example")],
        vec![("origin", "https://tenant.fstp.test/path")],
        vec![("origin", "tenant.fstp.test")],
        vec![("origin", "https://tenant.fstp.test:99999")],
    ];
    for h in cases {
        let r = serve(
            &s,
            Surface::Public,
            http(Surface::Public, Method::POST, &h, &initialize(1)),
        );
        let st = r.status.as_u16();
        assert!(st == 400 || st == 403, "{h:?}: {st}");
    }
}

/// H-23: the pure `Origin` rule, as a property. No field is `Absent`,
/// one field equal to a tenant origin is `Tenant`, a well-formed other
/// origin is `Foreign`, two or more fields are `Duplicated`, and a value
/// that is no serialised origin is `Unparsable`.
#[test]
fn adr013_check_origin_rule() {
    let tenant = vec![ORIGIN.to_owned()];
    check("adr013_check_origin_rule", |g| {
        let host: String = (0..g.usize_in(1..=10))
            .map(|_| char::from(b'a' + g.u8_in(0..=25)))
            .collect();
        let other = format!("https://{host}.example");
        let garbage = format!("{host} https://");
        let k = g.u8_in(0..=4);
        let values: Vec<&[u8]> = match k {
            0 => vec![],
            1 => vec![ORIGIN.as_bytes()],
            2 => vec![other.as_bytes()],
            3 => vec![ORIGIN.as_bytes(), other.as_bytes()],
            _ => vec![garbage.as_bytes()],
        };
        let want = match k {
            0 => Ok(OriginSeen::Absent),
            1 => Ok(OriginSeen::Tenant),
            2 => Err(OriginRefusal::Foreign),
            3 => Err(OriginRefusal::Duplicated),
            _ => Err(OriginRefusal::Unparsable),
        };
        prop_assert_eq!(check_origin(&values, &tenant), want);
        Ok(())
    });
}

/// I-86, ADR-013 "Metadata", RFC 9728 section 5.1: a POST to `/mcp`
/// without `Authorization` gets 401 with one `WWW-Authenticate` field: a
/// `Bearer` challenge naming the protected resource metadata URL, with no
/// `error` parameter. The body holds no account and no token.
#[test]
fn adr013_missing_token_gets_401_with_resource_metadata() {
    let c = McpCell::new();
    let s = c.server();
    for body in [initialize(1), TOOLS_LIST.to_vec()] {
        let r = serve(
            &s,
            Surface::Mcp,
            http(Surface::Mcp, Method::POST, &[], &body),
        );
        assert_eq!(r.status.as_u16(), 401);
        assert_eq!(r.headers.count("www-authenticate"), 1);
        let v = header(&r, "www-authenticate").unwrap();
        assert!(v.starts_with("Bearer "), "{v}");
        assert!(
            v.contains(&format!("resource_metadata=\"{RESOURCE_METADATA}\"")),
            "{v}"
        );
        assert!(!v.contains("error="), "{v}");
    }
}

/// TH-63, Q43, design section 3.8 (floor revision 2025-06-18): `initialize`
/// answers the requested floor version, the tools capability only, and a
/// `serverInfo` whose name is the first label of the verified domain,
/// with no `title`. No `instructions` member is sent.
#[test]
fn adr013_initialize_floor_white_labels_the_server() {
    let c = McpCell::new();
    let s = c.server();
    let r = serve(
        &s,
        Surface::Public,
        http(Surface::Public, Method::POST, &[], &initialize(1)),
    );
    let res = result_of(&r).unwrap_or_else(|| panic!("{}", String::from_utf8_lossy(&r.body)));
    assert_eq!(
        res.get("protocolVersion").and_then(Value::as_str),
        Some(FLOOR)
    );
    assert!(res.get("instructions").is_none());
    let info = res.get("serverInfo").and_then(Value::as_object).unwrap();
    assert_eq!(info.get("name").and_then(Value::as_str), Some("tenant"));
    assert_eq!(server_name(DOMAIN), "tenant");
    assert!(info.get("title").is_none());
    let caps = res.get("capabilities").and_then(Value::as_object).unwrap();
    let keys: BTreeSet<&str> = caps.keys().collect();
    assert_eq!(keys, ["tools"].into_iter().collect());
}

/// Design section 3.8 (floor revision 2025-06-18): an `initialize` for a
/// version the server does not support answers with a version it does
/// support, at least the floor, never the requested one.
#[test]
fn adr013_initialize_unknown_version_answers_a_supported_one() {
    let c = McpCell::new();
    let s = c.server();
    let body = String::from_utf8(initialize(1))
        .unwrap()
        .replace(FLOOR, "1999-01-01");
    let r = serve(
        &s,
        Surface::Public,
        http(Surface::Public, Method::POST, &[], body.as_bytes()),
    );
    let res = result_of(&r).unwrap_or_else(|| panic!("{}", String::from_utf8_lossy(&r.body)));
    let v = res.get("protocolVersion").and_then(Value::as_str).unwrap();
    assert_ne!(v, "1999-01-01");
    assert!(v >= FLOOR, "{v}");
}

/// The visible ASCII session id as its 16 bytes: 32 hexadecimal digits or
/// 22 characters of unpadded base64url.
fn session_bytes(id: &str) -> Option<Vec<u8>> {
    if !id.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return None;
    }
    if id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return (0..16)
            .map(|i| u8::from_str_radix(&id[2 * i..2 * i + 2], 16).ok())
            .collect();
    }
    if id.len() == 22 {
        return fstp_oauth::decode_base64url(id.as_bytes())
            .ok()
            .map(|b| b.as_bytes().to_vec())
            .filter(|b| b.len() == 16);
    }
    None
}

/// Design section 3.8, ADR-013 `Mcp-Session-Id` (floor revision): each
/// `initialize` mints a new session id of 128 bits as visible ASCII. Over
/// 64 sessions every id is distinct, and the bits are balanced within
/// about six standard deviations, as random bits are.
#[test]
fn adr013_session_id_is_128_random_bits() {
    let c = McpCell::new();
    let s = c.server();
    let mut seen = BTreeSet::new();
    let mut ones = 0u32;
    for i in 0..64u32 {
        let r = serve(
            &s,
            Surface::Public,
            http(Surface::Public, Method::POST, &[], &initialize(i)),
        );
        assert_eq!(r.status.as_u16(), 200);
        let id = header(&r, "mcp-session-id").expect("an Mcp-Session-Id header");
        let b = session_bytes(&id).unwrap_or_else(|| panic!("{id:?} is not 128 bits"));
        ones += b.iter().map(|x| x.count_ones()).sum::<u32>();
        assert!(seen.insert(b), "a repeated session id");
    }
    assert!((3800..=4392).contains(&ones), "{ones} of 8192 bits set");
}

/// Self-test of [`session_bytes`]. Green now.
#[test]
fn adr013_session_bytes_self_test() {
    assert_eq!(
        session_bytes("00112233445566778899aabbccddeeff").map(|b| b.len()),
        Some(16)
    );
    assert_eq!(
        session_bytes("AAAAAAAAAAAAAAAAAAAAAA").map(|b| b.len()),
        Some(16)
    );
    assert_eq!(session_bytes("short"), None);
    assert_eq!(session_bytes("00112233445566778899aabbccddee f"), None);
}

/// Design section 3.8 (floor revision): after initialisation a request
/// carries `MCP-Protocol-Version`. The negotiated version is served, an
/// unsupported one gets 400, and so does a request without the field
/// (the design's reading: the header is required after initialisation).
#[test]
fn adr013_protocol_version_header_after_initialisation() {
    let c = McpCell::new();
    let s = c.server();
    let id =
        open_session(&s, Surface::Public, &[]).unwrap_or_else(|r| panic!("{}", r.status.as_u16()));
    let ok = serve(
        &s,
        Surface::Public,
        http(
            Surface::Public,
            Method::POST,
            &[("mcp-session-id", &id), ("mcp-protocol-version", FLOOR)],
            TOOLS_LIST,
        ),
    );
    assert_eq!(ok.status.as_u16(), 200);
    assert!(result_of(&ok).is_some());
    for h in [
        vec![
            ("mcp-session-id", id.as_str()),
            ("mcp-protocol-version", "1999-01-01"),
        ],
        vec![
            ("mcp-session-id", id.as_str()),
            ("mcp-protocol-version", "2025-06-18x"),
        ],
        vec![("mcp-session-id", id.as_str())],
    ] {
        let r = serve(
            &s,
            Surface::Public,
            http(Surface::Public, Method::POST, &h, TOOLS_LIST),
        );
        assert_eq!(r.status.as_u16(), 400, "{h:?}");
    }
}

/// Design section 3.8 (floor revision): a request other than
/// `initialize` without a session id gets 400, and one with an id the
/// server never minted gets 404.
#[test]
fn adr013_request_outside_a_session_is_refused() {
    let c = McpCell::new();
    let s = c.server();
    let r = serve(
        &s,
        Surface::Public,
        http(
            Surface::Public,
            Method::POST,
            &[("mcp-protocol-version", FLOOR)],
            TOOLS_LIST,
        ),
    );
    assert_eq!(r.status.as_u16(), 400);
    let r = serve(
        &s,
        Surface::Public,
        http(
            Surface::Public,
            Method::POST,
            &[
                ("mcp-session-id", "00000000000000000000000000000000"),
                ("mcp-protocol-version", FLOOR),
            ],
            TOOLS_LIST,
        ),
    );
    assert_eq!(r.status.as_u16(), 404);
}

/// Design section 3.8 (floor revision): `notifications/initialized` gets
/// 202 with no body, `ping` answers an empty result, and an unknown
/// method answers the JSON-RPC error -32601 (no resources, prompts,
/// sampling or elicitation in M4).
#[test]
fn adr013_lifecycle_methods() {
    let c = McpCell::new();
    let s = c.server();
    let id =
        open_session(&s, Surface::Public, &[]).unwrap_or_else(|r| panic!("{}", r.status.as_u16()));
    let h = [
        ("mcp-session-id", id.as_str()),
        ("mcp-protocol-version", FLOOR),
    ];
    let r = serve(
        &s,
        Surface::Public,
        http(
            Surface::Public,
            Method::POST,
            &h,
            br#"{"jsonrpc":"2.0","id":5,"method":"ping"}"#,
        ),
    );
    assert_eq!(r.status.as_u16(), 200);
    assert_eq!(result_of(&r).map(|o| o.len()), Some(0));
    for m in [
        "resources/list",
        "prompts/list",
        "sampling/createMessage",
        "logging/setLevel",
    ] {
        let body = format!(r#"{{"jsonrpc":"2.0","id":6,"method":"{m}"}}"#);
        let r = serve(
            &s,
            Surface::Public,
            http(Surface::Public, Method::POST, &h, body.as_bytes()),
        );
        assert_eq!(error_code(&r), Some(-32601), "{m}");
    }
    let n = serve(
        &s,
        Surface::Public,
        http(
            Surface::Public,
            Method::POST,
            &h,
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        ),
    );
    assert_eq!(n.status.as_u16(), 202);
    assert!(n.body.is_empty());
}

/// Design section 3.8 (floor revision): `DELETE` with a session id ends
/// that session. A later request naming it gets 404, and another session
/// stays open.
#[test]
fn adr013_delete_ends_the_session() {
    let c = McpCell::new();
    let s = c.server();
    let a =
        open_session(&s, Surface::Public, &[]).unwrap_or_else(|r| panic!("{}", r.status.as_u16()));
    let b =
        open_session(&s, Surface::Public, &[]).unwrap_or_else(|r| panic!("{}", r.status.as_u16()));
    let d = serve(
        &s,
        Surface::Public,
        http(
            Surface::Public,
            Method::DELETE,
            &[("mcp-session-id", &a), ("mcp-protocol-version", FLOOR)],
            b"",
        ),
    );
    assert!(d.status.is_success(), "{}", d.status.as_u16());
    for (id, want) in [(&a, 404), (&b, 200)] {
        let r = serve(
            &s,
            Surface::Public,
            http(
                Surface::Public,
                Method::POST,
                &[("mcp-session-id", id), ("mcp-protocol-version", FLOOR)],
                TOOLS_LIST,
            ),
        );
        assert_eq!(r.status.as_u16(), want);
    }
}

/// TH-63, Q43: `serverInfo.name` is the first label of the verified
/// domain when it matches `^[a-z0-9][a-z0-9-]{0,30}$`, and whatever the
/// domain holds, the name matches that pattern, so no free text reaches
/// an agent.
#[test]
fn th63_server_name_is_the_first_label() {
    fn matches(s: &str) -> bool {
        let b = s.as_bytes();
        !b.is_empty()
            && b.len() <= 31
            && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
    }
    check("th63_server_name_is_the_first_label", |g| {
        let label = if g.bool() {
            let n = g.usize_in(1..=31);
            let mut s: String = (0..n)
                .map(|_| *g.pick(&['a', 'q', 'z', '0', '7', '-']))
                .collect();
            if s.starts_with('-') {
                s.replace_range(0..1, "x");
            }
            s
        } else {
            g.string(0..=40)
        };
        let domain = format!("{label}.example.org");
        let got = server_name(&domain);
        prop_assert!(matches(&got), "{domain:?} gave {got:?}");
        if matches(&label) {
            prop_assert_eq!(got, label);
        }
        Ok(())
    });
}
