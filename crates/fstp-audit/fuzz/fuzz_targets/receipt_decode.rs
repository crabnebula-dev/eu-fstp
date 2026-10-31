//! Fuzz target `receipt_decode` of `fstp-audit` (TH-26, H-05, M3 design
//! section 15).
//!
//! Checks, for the one layout of `fstp_audit::anchor::encode_receipt`:
//!
//! - no panic, and decoding is deterministic.
//! - an accepted receipt names a row and a witness sequence from 1, and
//!   carries a signature of the composite length of draft 19 (R-CR-03).
//! - an accepted input re-encodes byte for byte.
//! - neither the input without its last byte nor the input with one more
//!   byte decodes to the same receipt.

#![no_main]

use fstp_audit::anchor::{decode_receipt, encode_receipt};
use libfuzzer_sys::fuzz_target;

/// The composite signature length of draft 19: ML-DSA-65 then Ed25519.
const SIG_LEN: usize = 3309 + 64;

fuzz_target!(|data: &[u8]| {
    let first = decode_receipt(data);
    assert_eq!(first, decode_receipt(data), "decode is not deterministic");
    if let Ok(r) = &first {
        assert!(r.fields.n >= 1, "receipt of row 0 accepted");
        assert!(r.fields.witness_seq >= 1, "witness sequence 0 accepted");
        assert_eq!(r.signature.len(), SIG_LEN, "non-composite signature length");
        assert_eq!(
            encode_receipt(r).as_deref().ok(),
            Some(data),
            "an accepted receipt does not re-encode to its input"
        );
        if let Some((_, head)) = data.split_last() {
            assert_ne!(
                decode_receipt(head).as_ref().ok(),
                Some(r),
                "truncation accepted"
            );
        }
        let mut longer = data.to_vec();
        longer.push(0);
        assert_ne!(
            decode_receipt(&longer).as_ref().ok(),
            Some(r),
            "trailing byte accepted"
        );
    }
});
