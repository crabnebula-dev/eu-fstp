//! Fuzz target `key_op_decode` of `fstp-keys` (ADR-004 "Reconciliation").
//!
//! Design checks: no panic, and an accepted body re-encodes byte for
//! byte, so a `KeyOp` record has one spelling only.

#![no_main]

use fstp_keys::keyop::{decode, encode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(op) = decode(data) {
        let again = encode(&op);
        assert_eq!(again.as_deref().ok(), Some(data), "not one spelling");
    }
});
