//! Fuzz target `mcp_message_decode` of `fstp-mcp` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: method params. No input panics. A decoded message comes
//! only from bytes that `decode_jsonrpc` accepts, and a refusal formats
//! without echoing the input (R-NF-02).

#![no_main]

use libfuzzer_sys::fuzz_target;

/// Whether the refusal `e` echoes the input text `s` (R-NF-02). `Batch`,
/// `NotJson` and `TooLong` carry nothing, so each has one fixed text. An
/// input inside that text is a coincidence, not an echo: CI run
/// 42359742731 found `ot one JSON value` inside the `NotJson` text.
fn echoes(e: &fstp_mcp::McpError, s: &str) -> bool {
    use fstp_mcp::McpError as E;
    !matches!(e, E::Batch | E::NotJson | E::TooLong) && e.to_string().contains(s)
}

fuzz_target!(|data: &[u8]| {
    let r = fstp_mcp::decode_message(data);
    let shown = format!("{r:?}");
    assert!(!shown.is_empty());
    match &r {
        Ok(_) => assert!(fstp_mcp::decode_jsonrpc(data).is_ok()),
        Err(e) => {
            let text = e.to_string();
            if data.len() >= 8
                && let Ok(s) = std::str::from_utf8(data)
            {
                assert!(!echoes(e, s), "the refusal echoes the input: {text}");
            }
        }
    }
});
