//! Fuzz target `witness_copy_status_decode` of `fstp-obs` (ADR-012
//! record of lane m10/witness-copy): the witness copy status file that
//! `fstp-admin status` reads.
//!
//! Design checks: no panic, deterministic, and one spelling only: an
//! accepted file encodes back to the same bytes.

#![no_main]

use fstp_obs::witness_copy::{decode, encode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode(data);
    assert_eq!(first, decode(data), "not deterministic");
    if let Ok(s) = first {
        assert_eq!(encode(&s).as_bytes(), data, "not one spelling");
    }
});
