//! Fuzz target `declaration_keys_decode` of `fstp-witness` (TH-26, ADR-012
//! record of lane m10/saas-declare): the restore declaration key file a
//! SaaS witness pins.
//!
//! Checks:
//!
//! - no panic, and decoding is deterministic.
//! - an accepted file holds one or two keys of the composite length, and
//!   encodes back to the same bytes, so each file has one spelling.

#![no_main]

use fstp_witness::config::{
    MAX_DECLARATION_KEYS, decode_declaration_keys, encode_declaration_keys,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode_declaration_keys(data);
    assert_eq!(first, decode_declaration_keys(data), "not deterministic");
    let Ok(keys) = first else {
        return;
    };
    assert!(!keys.is_empty() && keys.len() <= MAX_DECLARATION_KEYS);
    assert!(keys.iter().all(|k| k.len() == fstp_audit::PUBLIC_KEY_LEN));
    assert_eq!(encode_declaration_keys(&keys), data, "not one spelling");
});
