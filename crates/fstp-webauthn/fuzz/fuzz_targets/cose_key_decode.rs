//! Fuzz target `cose_key_decode` of `fstp-webauthn` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; depth and size limits; non-shortest forms and duplicate keys refused.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2a lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_webauthn::parse_cose_key(data));
    assert!(!shown.is_empty());
});
