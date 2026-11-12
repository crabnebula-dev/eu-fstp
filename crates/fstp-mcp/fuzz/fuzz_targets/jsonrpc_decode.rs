//! Fuzz target `jsonrpc_decode` of `fstp-mcp` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: the JSON-RPC 2.0 envelope. No input panics. A decoded
//! message comes only from one JSON object, so a batch never decodes
//! (design section 3.8). A top-level array that is valid JSON is refused
//! as a batch. A refusal formats, and its text never holds the input
//! (R-NF-02). `tests/mcp_jsonrpc.rs` of `fstp-api-testkit` pins the same
//! rules on chosen inputs.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// The input with JSON whitespace removed at the front.
fn trimmed(data: &[u8]) -> &[u8] {
    let n = data
        .iter()
        .take_while(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        .count();
    data.get(n..).unwrap_or(&[])
}

/// Whether the refusal `e` echoes the input text `s` (R-NF-02). `Batch`,
/// `NotJson` and `TooLong` carry nothing, so each has one fixed text. An
/// input inside that text is a coincidence, not an echo: CI run
/// 42359742731 found `s not one JSON value` inside the `NotJson` text.
fn echoes(e: &fstp_mcp::McpError, s: &str) -> bool {
    use fstp_mcp::McpError as E;
    !matches!(e, E::Batch | E::NotJson | E::TooLong) && e.to_string().contains(s)
}

fuzz_target!(|data: &[u8]| {
    let r = fstp_mcp::decode_jsonrpc(data);
    let shown = format!("{r:?}");
    assert!(!shown.is_empty());
    let first = trimmed(data).first().copied();
    match &r {
        Ok(_) => assert_eq!(first, Some(b'{'), "a message from a non-object"),
        Err(e) => {
            let text = e.to_string();
            if data.len() >= 8
                && !matches!(e, fstp_mcp::McpError::NotImplemented(_))
                && let Ok(s) = std::str::from_utf8(data)
            {
                assert!(!echoes(e, s), "the refusal echoes the input: {text}");
            }
        }
    }
    let is_array = first == Some(b'[') && fstp_json::parse(data).is_ok();
    if is_array && !matches!(r, Err(fstp_mcp::McpError::NotImplemented(_))) {
        assert_eq!(r, Err(fstp_mcp::McpError::Batch));
    }
});
