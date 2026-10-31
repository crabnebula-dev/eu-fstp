//! Fuzz target `chain_row_decode` of `fstp-audit` (TH-26, H-05, M3 design
//! section 15).
//!
//! Checks, for the one layout of `fstp_audit::chain::encode_chain_row`:
//!
//! - no panic, and decoding is deterministic.
//! - an accepted input decodes to a row numbered from 1 (ADR-010).
//! - an accepted input re-encodes byte for byte (round trip, one
//!   spelling).
//! - neither the input without its last byte nor the input with one more
//!   byte decodes to the same row.

#![no_main]

use fstp_audit::chain::{decode_chain_row, encode_chain_row};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode_chain_row(data);
    assert_eq!(first, decode_chain_row(data), "decode is not deterministic");
    if let Ok(row) = &first {
        assert!(row.n >= 1, "row number 0 accepted");
        assert_eq!(
            encode_chain_row(row).as_deref().ok(),
            Some(data),
            "an accepted row does not re-encode to its input"
        );
        if let Some((_, head)) = data.split_last() {
            assert_ne!(
                decode_chain_row(head).as_ref().ok(),
                Some(row),
                "truncation accepted"
            );
        }
        let mut longer = data.to_vec();
        longer.push(0);
        assert_ne!(
            decode_chain_row(&longer).as_ref().ok(),
            Some(row),
            "trailing byte accepted"
        );
    }
});
