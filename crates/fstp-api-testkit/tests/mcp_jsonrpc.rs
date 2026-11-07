//! TH-26 and H-05: the JSON-RPC 2.0 decoder of `fstp-mcp` (M4 design
//! sections 3.8 and 9). The fuzz target `jsonrpc_decode` of
//! `crates/fstp-mcp/fuzz` checks the same rules on arbitrary bytes.
//!
//! - One message per body. A batch, a JSON array at the top, is refused
//!   with `McpError::Batch`, empty or not (MCP 2025-06-18 and 2026-07-28
//!   both take one message per POST).
//! - A request has `"jsonrpc":"2.0"`, an integer or string `id`, a string
//!   `method` and an optional object `params`. A notification has no `id`.
//! - Refused (interim readings of the test author, pending Daniel): a
//!   missing or other `jsonrpc` value, a null, boolean, fractional,
//!   exponent or object `id`, a missing or non-string `method`, non-object
//!   `params`, a `result` or `error` member (no server request exists, so
//!   no client response is expected), any other member, a duplicate
//!   member, bytes that are not one JSON value, and trailing bytes.
//!
//! Status: red until `fstp_mcp::decode_jsonrpc` exists.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_json::Value;
use fstp_mcp::{JsonRpcId, JsonRpcMessage, McpError, decode_jsonrpc};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

/// A method name a client could send.
fn method(g: &mut Gen) -> String {
    let fixed = [
        "initialize",
        "notifications/initialized",
        "ping",
        "tools/list",
        "tools/call",
        "resources/list",
    ];
    if g.bool() {
        (*g.pick(&fixed)).to_owned()
    } else {
        g.ascii_string(1..=24)
    }
}

/// The JSON text of a string.
fn quoted(s: &str) -> String {
    Value::String(s.to_owned()).to_compact()
}

/// TH-26: a request and a notification decode to exactly their id,
/// method and params, as a property over generated messages.
#[test]
fn th26_jsonrpc_decode_reads_requests_and_notifications() {
    check(
        "th26_jsonrpc_decode_reads_requests_and_notifications",
        |g| {
            let m = method(g);
            let id = if g.bool() {
                Some(JsonRpcId::Number(g.i64_in(-1_000_000..=1_000_000)))
            } else if g.bool() {
                Some(JsonRpcId::String(g.ascii_string(0..=12)))
            } else {
                None
            };
            let params = if g.bool() {
                Some(format!(r#"{{"name":{},"n":7}}"#, quoted(&g.string(0..=10))))
            } else {
                None
            };
            let mut text = String::from(r#"{"jsonrpc":"2.0""#);
            match &id {
                Some(JsonRpcId::Number(n)) => text.push_str(&format!(r#","id":{n}"#)),
                Some(JsonRpcId::String(s)) => text.push_str(&format!(r#","id":{}"#, quoted(s))),
                None => {}
            }
            text.push_str(&format!(r#","method":{}"#, quoted(&m)));
            if let Some(p) = &params {
                text.push_str(&format!(r#","params":{p}"#));
            }
            text.push('}');
            g.note("text", &text);
            let got = decode_jsonrpc(text.as_bytes()).map_err(|e| e.to_string())?;
            let want_params = params.as_deref().map(|p| {
                fstp_json::parse(p.as_bytes())
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .clone()
            });
            let want = match id {
                Some(id) => JsonRpcMessage::Request {
                    id,
                    method: m,
                    params: want_params,
                },
                None => JsonRpcMessage::Notification {
                    method: m,
                    params: want_params,
                },
            };
            prop_assert_eq!(got, want);
            Ok(())
        },
    );
}

/// TH-26, design section 3.8: a JSON-RPC batch is refused with
/// `McpError::Batch`, whatever it holds, the empty array included.
#[test]
fn th26_jsonrpc_decode_refuses_batches() {
    check("th26_jsonrpc_decode_refuses_batches", |g| {
        let n = g.usize_in(0..=4);
        let items: Vec<String> = (0..n)
            .map(|i| format!(r#"{{"jsonrpc":"2.0","id":{i},"method":"ping"}}"#))
            .collect();
        let pad = if g.bool() { " \n" } else { "" };
        let text = format!("{pad}[{}]{pad}", items.join(","));
        g.note("text", &text);
        prop_assert_eq!(decode_jsonrpc(text.as_bytes()), Err(McpError::Batch));
        Ok(())
    });
}

/// TH-26: malformed messages are refused with a typed error, never with
/// the stub's refusal, and a valid ping decodes (so the refusals are not
/// a decoder that refuses everything).
#[test]
fn th26_jsonrpc_decode_refuses_malformed_input() {
    let ok = decode_jsonrpc(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#);
    assert_eq!(
        ok,
        Ok(JsonRpcMessage::Request {
            id: JsonRpcId::Number(1),
            method: "ping".to_owned(),
            params: None,
        })
    );
    let bad: [&[u8]; 22] = [
        b"",
        b"   ",
        b"{",
        b"null",
        b"\"ping\"",
        br#"{"id":1,"method":"ping"}"#,
        br#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#,
        br#"{"jsonrpc":2.0,"id":1,"method":"ping"}"#,
        br#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
        br#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#,
        br#"{"jsonrpc":"2.0","id":1e3,"method":"ping"}"#,
        br#"{"jsonrpc":"2.0","id":true,"method":"ping"}"#,
        br#"{"jsonrpc":"2.0","id":{},"method":"ping"}"#,
        br#"{"jsonrpc":"2.0","id":1}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":7}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"ping","params":[1]}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"ping","params":"x"}"#,
        br#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        br#"{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"x"}}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"ping","extra":1}"#,
        br#"{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"ping"} {}"#,
    ];
    for b in bad {
        let r = decode_jsonrpc(b);
        assert!(
            matches!(
                r,
                Err(McpError::NotJson | McpError::Invalid(_) | McpError::TooLong)
            ),
            "{:?} gave {r:?}",
            String::from_utf8_lossy(b)
        );
    }
}

/// TH-26: a refusal never echoes the input, so a hostile body cannot
/// reach an agent or a log through the error text (R-NF-02).
#[test]
fn th26_jsonrpc_refusal_never_echoes_input() {
    check("th26_jsonrpc_refusal_never_echoes_input", |g| {
        let marker = format!("ECHO{}Z", g.u32_in(1000..=9999));
        let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"ping","{marker}":"{marker}"}}"#);
        let r = decode_jsonrpc(body.as_bytes());
        prop_assert!(
            matches!(r, Err(McpError::Invalid(_))),
            "an unknown member gave {r:?}"
        );
        let shown = format!(
            "{:?} {}",
            r,
            r.clone().err().map(|e| e.to_string()).unwrap_or_default()
        );
        prop_assert!(!shown.contains(&marker), "{shown}");
        Ok(())
    });
}
