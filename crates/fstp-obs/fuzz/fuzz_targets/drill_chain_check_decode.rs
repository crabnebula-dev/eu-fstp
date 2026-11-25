//! Fuzz target `drill_chain_check_decode` of `fstp-obs` (ADR-012 record
//! of lane m10/drill-chain): the line that `fstp-cell check-chain` and
//! `fstp-vault check-chain` print and the restore drill reads.
//!
//! Design checks: no panic, deterministic, and one spelling only: an
//! accepted line encodes back to the same bytes.

#![no_main]

use fstp_obs::drill_status::{decode_chain_check, encode_chain_check};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode_chain_check(data);
    assert_eq!(first, decode_chain_check(data), "not deterministic");
    if let Ok(c) = first {
        assert_eq!(encode_chain_check(&c).as_bytes(), data, "not one spelling");
    }
});
