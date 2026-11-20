//! Fuzz target `chain_state_decode` of `fstp-keys` (ADR-004, decided by
//! Daniel on 2026-11-20: the chain state row of the keystore tables).
//!
//! Design checks: no panic, and an accepted state re-encodes byte for
//! byte, so a stored chain state has one spelling only.

#![no_main]

use fstp_keys::erasure::codec::{decode, encode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(state) = decode(data) {
        let again = encode(&state);
        assert_eq!(again.as_deref().ok(), Some(data), "not one spelling");
        // A restart of an accepted state never panics.
        let _ = state.restart();
    }
});
