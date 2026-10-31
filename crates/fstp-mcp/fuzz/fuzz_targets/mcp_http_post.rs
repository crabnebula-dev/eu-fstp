//! Fuzz target `mcp_http_post` of `fstp-mcp` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: raw HTTP into the decoder, then the MCP handler over a stub dispatch, through fstp_rt::scripted.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W3c lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_mcp::handle_http_post(data));
    assert!(!shown.is_empty());
});
