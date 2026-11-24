//! Fuzz target `guarded_copy_header_decode` (ADR-028 record of lane
//! `m10/guard-key`, part 3): the clear header of a guarded key copy, which
//! `fstp-admin restore-keys` reads from a copy in the operator's directory.
//!
//! Design checks: no panic; an accepted header has a known entry and a
//! generation of at least 1, and encodes to the first 36 input bytes.

#![no_main]

use fstp_admin::custodian::{COPY_HEADER_LEN, decode_copy_header};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(h) = decode_copy_header(data) {
        assert!(data.len() >= COPY_HEADER_LEN);
        assert!((1..=5).contains(&h.entry) && h.generation >= 1);
        assert_eq!(data.get(..COPY_HEADER_LEN), Some(h.encode().as_slice()));
    }
});
