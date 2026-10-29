//! Fuzz target `web_op_request` of `fstp-web` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: route, headers and body into the adapter over a stub dispatch.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W4e lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_web::handle_op_request(data));
    assert!(!shown.is_empty());
});
