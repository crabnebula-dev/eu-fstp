//! Fuzz target `tool_args_decode` of `fstp-mcp` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: every tool's input.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W3c lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_mcp::decode_tool_args(data));
    assert!(!shown.is_empty());
});
