//! Fuzz target `identity_tuple_decode` of `fstp-vault` (TH-26, ADR-033
//! record of lane L31).
//!
//! The name mask reads the identity tuple the keystore opened. For every
//! input `parse_identity_tuple` never panics, and a tuple it accepts is
//! written back by `identity_tuple` into bytes it accepts again.

#![no_main]

use fstp_vault::codec::{identity_tuple, parse_identity_tuple};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(a) = parse_identity_tuple(data) {
        assert!(parse_identity_tuple(&identity_tuple(&a)).is_some());
    }
});
