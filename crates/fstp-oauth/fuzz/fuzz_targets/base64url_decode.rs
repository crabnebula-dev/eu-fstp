//! Fuzz target `base64url_decode` of `fstp-oauth` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: base64url text.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W1e lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_oauth::decode_base64url(data));
    assert!(!shown.is_empty());
});
