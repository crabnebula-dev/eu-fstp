//! The modern requests of MCP revision 2026-07-28 next to the legacy
//! handshake of the floor revision (ADR-013 "MCP revision", record of
//! lane mcp-demo), driven through `McpServer::serve`.
//!
//! ADR-013 pins revision 2026-07-28 with 2025-06-18 as the floor. The
//! server answers both eras on one endpoint, as the pinned revision
//! permits a server to do. The 2026-07-28 facts used here were checked
//! against its published text on 2026-11-20 and are paraphrased:
//!
//! - a modern request carries its protocol version in `_meta` under
//!   `io.modelcontextprotocol/protocolVersion`, and the
//!   `MCP-Protocol-Version` header must equal it;
//! - every request carries `Mcp-Method`, and `tools/call` carries
//!   `Mcp-Name`, each equal to its body value; a missing or different
//!   value gets 400 with JSON-RPC error -32020;
//! - a version the server does not serve gets 400 with -32022, whose
//!   data lists the supported versions and the requested one;
//! - a method the server does not offer gets 404 with -32601;
//! - `server/discover` answers the supported versions, the capabilities
//!   and the server name under `_meta`;
//! - every result names `resultType`, and no session id is minted or
//!   needed;
//! - a request with no modern `_meta` keeps the legacy rules, so a
//!   dual-era client that is refused falls back to `initialize`.
//!
//! The `server/discover` probe below is the one Claude Code 2.1.328 sent
//! to the e2e cell on 2026-11-20, with its headers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod mcp_support;

use fstp_http::Method;
use fstp_json::Value;
use fstp_mcp::Surface;
use mcp_support::{
    McpCell, RESOURCE_METADATA, body_json, error_code, header, http, result_of, serve,
};

/// The pinned revision.
const MODERN: &str = "2026-07-28";

/// The probe Claude Code 2.1.328 sends first, as captured.
const CLAUDE_CODE_PROBE: &str = r#"{"jsonrpc":"2.0","id":"server-discover-probe-1","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"claude-code","title":"Claude Code","version":"2.1.328","description":"Anthropic's agentic coding tool","websiteUrl":"https://claude.com/claude-code"},"io.modelcontextprotocol/clientCapabilities":{"roots":{"listChanged":true},"elicitation":{"form":{},"url":{}}}}}}"#;

/// A modern request body of `method` with `params` members besides
/// `_meta`, at protocol version `version`.
fn modern(id: u32, method: &str, version: &str, params: &str) -> Vec<u8> {
    let sep = if params.is_empty() { "" } else { "," };
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{{{params}{sep}"_meta":{{"io.modelcontextprotocol/protocolVersion":"{version}","io.modelcontextprotocol/clientInfo":{{"name":"synthetic-client","version":"0.0.1"}},"io.modelcontextprotocol/clientCapabilities":{{}}}}}}}}"#
    )
    .into_bytes()
}

/// The JSON-RPC `error.data` object of a response.
fn error_data(resp: &fstp_http::Response) -> Option<fstp_json::Object> {
    let v = body_json(resp)?;
    v.as_object()?
        .get("error")?
        .as_object()?
        .get("data")?
        .as_object()
        .cloned()
}

/// The strings of array member `k` of `o`.
fn strings(o: &fstp_json::Object, k: &str) -> Vec<String> {
    o.get(k)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// ADR-013 record of lane mcp-demo: the captured `server/discover` probe
/// of Claude Code gets the discovery result on `/mcp/public`, with no
/// session minted: the supported versions name the pinned revision, the
/// capabilities offer tools, and the white-labelled name sits under
/// `_meta`. No `instructions` member is sent (ADR-013, TH-63).
#[test]
fn adr013_modern_claude_code_probe_gets_the_discovery_result() {
    let c = McpCell::new();
    let s = c.server();
    let r = serve(
        &s,
        Surface::Public,
        http(
            Surface::Public,
            Method::POST,
            &[
                ("mcp-method", "server/discover"),
                ("mcp-protocol-version", MODERN),
            ],
            CLAUDE_CODE_PROBE.as_bytes(),
        ),
    );
    assert_eq!(
        r.status.as_u16(),
        200,
        "{}",
        String::from_utf8_lossy(&r.body)
    );
    assert!(r.headers.get("mcp-session-id").is_none());
    let res = result_of(&r).unwrap();
    assert_eq!(
        res.get("resultType").and_then(Value::as_str),
        Some("complete")
    );
    assert_eq!(strings(&res, "supportedVersions"), [MODERN]);
    assert!(
        res.get("capabilities")
            .and_then(Value::as_object)
            .and_then(|c| c.get("tools"))
            .is_some_and(|t| t.as_object().is_some())
    );
    let name = res
        .get("_meta")
        .and_then(Value::as_object)
        .and_then(|m| m.get("io.modelcontextprotocol/serverInfo"))
        .and_then(Value::as_object)
        .and_then(|i| i.get("name"))
        .and_then(Value::as_str);
    assert_eq!(name, Some("tenant"));
    assert!(res.get("instructions").is_none());
    let id = body_json(&r).and_then(|v| v.as_object()?.get("id")?.as_str().map(str::to_owned));
    assert_eq!(id.as_deref(), Some("server-discover-probe-1"));
}

/// ADR-013, RFC 9728: on `/mcp` the probe without a token gets the 401
/// challenge naming the resource metadata, before any era rule, so a
/// client discovers the authorisation server first.
#[test]
fn adr013_modern_probe_without_token_gets_the_challenge() {
    let c = McpCell::new();
    let s = c.server();
    let r = serve(
        &s,
        Surface::Mcp,
        http(
            Surface::Mcp,
            Method::POST,
            &[
                ("mcp-method", "server/discover"),
                ("mcp-protocol-version", MODERN),
            ],
            CLAUDE_CODE_PROBE.as_bytes(),
        ),
    );
    assert_eq!(r.status.as_u16(), 401);
    let v = header(&r, "www-authenticate").unwrap_or_default();
    assert!(
        v.contains(&format!("resource_metadata=\"{RESOURCE_METADATA}\"")),
        "{v}"
    );
}

/// ADR-013 record of lane mcp-demo: a modern `tools/list` needs no
/// session and names `resultType`. A session id sent with it is ignored
/// and none is minted.
#[test]
fn adr013_modern_tools_list_is_stateless() {
    let c = McpCell::new();
    let s = c.server();
    let r = serve(
        &s,
        Surface::Public,
        http(
            Surface::Public,
            Method::POST,
            &[
                ("mcp-method", "tools/list"),
                ("mcp-protocol-version", MODERN),
                ("mcp-session-id", "00112233445566778899aabbccddeeff"),
            ],
            &modern(2, "tools/list", MODERN, ""),
        ),
    );
    assert_eq!(
        r.status.as_u16(),
        200,
        "{}",
        String::from_utf8_lossy(&r.body)
    );
    assert!(r.headers.get("mcp-session-id").is_none());
    let res = result_of(&r).unwrap();
    assert_eq!(
        res.get("resultType").and_then(Value::as_str),
        Some("complete")
    );
    let tools = res.get("tools").and_then(Value::as_array).unwrap();
    assert!(!tools.is_empty());
}

/// ADR-013 record of lane mcp-demo, I-87: a modern `tools/call` of a
/// public tool with a matching `Mcp-Name` is dispatched and names
/// `resultType`. Without `Mcp-Name`, or with another name, it gets 400
/// with -32020 and reaches no operation.
#[test]
fn adr013_modern_tools_call_needs_a_matching_mcp_name() {
    let c = McpCell::new();
    let s = c.server();
    let body = modern(
        3,
        "tools/call",
        MODERN,
        r#""name":"fstp_public_list_open_calls","arguments":{"slug":"1"}"#,
    );
    let send = |extra: &[(&str, &str)]| {
        let mut h = vec![
            ("mcp-method", "tools/call"),
            ("mcp-protocol-version", MODERN),
        ];
        h.extend_from_slice(extra);
        serve(
            &s,
            Surface::Public,
            http(Surface::Public, Method::POST, &h, &body),
        )
    };
    let ok = send(&[("mcp-name", "fstp_public_list_open_calls")]);
    assert_eq!(
        ok.status.as_u16(),
        200,
        "{}",
        String::from_utf8_lossy(&ok.body)
    );
    let res = result_of(&ok).unwrap();
    assert_eq!(
        res.get("resultType").and_then(Value::as_str),
        Some("complete")
    );
    assert!(res.get("structuredContent").is_some(), "{res:?}");
    for extra in [
        &[][..],
        &[("mcp-name", "fstp_public_get_call")][..],
        &[(
            "mcp-name",
            "=?base64?ZnN0cF9wdWJsaWNfbGlzdF9vcGVuX2NhbGxz?=",
        )][..],
    ] {
        let r = send(extra);
        assert_eq!(r.status.as_u16(), 400, "{extra:?}");
        assert_eq!(error_code(&r), Some(-32020), "{extra:?}");
    }
}

/// ADR-013 record of lane mcp-demo: `Mcp-Method` must be present and
/// equal the body's method, and `MCP-Protocol-Version` must be present
/// and equal the version in `_meta`. Each failure gets 400 with -32020.
#[test]
fn adr013_modern_header_mismatch_is_refused() {
    let c = McpCell::new();
    let s = c.server();
    let body = modern(4, "tools/list", MODERN, "");
    for h in [
        vec![("mcp-protocol-version", MODERN)],
        vec![
            ("mcp-method", "server/discover"),
            ("mcp-protocol-version", MODERN),
        ],
        vec![("mcp-method", "tools/list")],
        vec![
            ("mcp-method", "tools/list"),
            ("mcp-protocol-version", "2025-06-18"),
        ],
    ] {
        let r = serve(
            &s,
            Surface::Public,
            http(Surface::Public, Method::POST, &h, &body),
        );
        assert_eq!(r.status.as_u16(), 400, "{h:?}");
        assert_eq!(error_code(&r), Some(-32020), "{h:?}");
    }
}

/// ADR-013 record of lane mcp-demo: a modern request for a version the
/// server does not serve gets 400 with -32022, naming the supported
/// versions and the requested one, so a client retries with one of them.
#[test]
fn adr013_modern_unsupported_version_names_the_supported_ones() {
    let c = McpCell::new();
    let s = c.server();
    let r = serve(
        &s,
        Surface::Public,
        http(
            Surface::Public,
            Method::POST,
            &[
                ("mcp-method", "tools/list"),
                ("mcp-protocol-version", "2099-01-01"),
            ],
            &modern(5, "tools/list", "2099-01-01", ""),
        ),
    );
    assert_eq!(r.status.as_u16(), 400);
    assert_eq!(error_code(&r), Some(-32022));
    let data = error_data(&r).unwrap();
    assert_eq!(strings(&data, "supported"), [MODERN]);
    assert_eq!(
        data.get("requested").and_then(Value::as_str),
        Some("2099-01-01")
    );
}

/// ADR-013 record of lane mcp-demo: a modern request for a method the
/// server does not offer, such as the legacy `ping`, gets 404 with
/// -32601.
#[test]
fn adr013_modern_unknown_method_gets_404() {
    let c = McpCell::new();
    let s = c.server();
    for method in ["ping", "resources/list"] {
        let r = serve(
            &s,
            Surface::Public,
            http(
                Surface::Public,
                Method::POST,
                &[("mcp-method", method), ("mcp-protocol-version", MODERN)],
                &modern(6, method, MODERN, ""),
            ),
        );
        assert_eq!(r.status.as_u16(), 404, "{method}");
        assert_eq!(error_code(&r), Some(-32601), "{method}");
    }
}

/// ADR-013 record of lane mcp-demo: a request with no modern `_meta` keeps
/// the legacy rules. A legacy `tools/list` outside a session still gets
/// 400 with a legacy error, which a dual-era client reads as a legacy
/// server and answers with `initialize`.
#[test]
fn adr013_legacy_request_keeps_the_legacy_rules() {
    let c = McpCell::new();
    let s = c.server();
    let r = serve(
        &s,
        Surface::Public,
        http(
            Surface::Public,
            Method::POST,
            &[],
            br#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#,
        ),
    );
    assert_eq!(r.status.as_u16(), 400);
    assert_eq!(error_code(&r), Some(-32600));
}
