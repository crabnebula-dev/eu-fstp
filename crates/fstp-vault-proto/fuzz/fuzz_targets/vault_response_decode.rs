//! Fuzz target `vault_response_decode` of `fstp-vault-proto` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; round trip; exact amount strings; one-bit answers carry no account set.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2d lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_vault_proto::decode_response(data));
    assert!(!shown.is_empty());
});
