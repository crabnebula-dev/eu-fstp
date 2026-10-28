//! Fuzz target `client_hello_sni` of `fstp-edge` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; on valid hellos the SNI equals what an fstp-tls server reports.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2i lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_edge::parse_client_hello_sni(data));
    assert!(!shown.is_empty());
});
