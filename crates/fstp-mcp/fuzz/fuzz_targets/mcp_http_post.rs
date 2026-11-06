//! Fuzz target `mcp_http_post` of `fstp-mcp` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: raw HTTP into the decoder, then the MCP transport over
//! a server with no dispatch. No input panics. No answer sets a cookie,
//! and a `GET` that parses answers 405 (H-23).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let r = fstp_mcp::handle_http_post(data);
    let shown = format!("{r:?}");
    assert!(!shown.is_empty());
    if let Ok(reply) = &r {
        let resp = reply.response();
        assert!(resp.headers.get("set-cookie").is_none());
        if data.starts_with(b"GET ") {
            assert_eq!(resp.status.as_u16(), 405);
        }
    }
});
