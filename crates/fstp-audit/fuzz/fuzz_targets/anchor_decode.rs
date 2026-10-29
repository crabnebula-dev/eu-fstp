//! Fuzz target `anchor_decode` of `fstp-audit` (TH-26, H-05, M3 design
//! section 15).
//!
//! Checks, for the one layout of `fstp_audit::anchor::encode_anchor`:
//!
//! - no panic, and decoding is deterministic.
//! - an accepted anchor names a row from 1 and carries a signature of the
//!   composite length of draft 19 (R-CR-03).
//! - an accepted input re-encodes byte for byte.
//! - neither the input without its last byte nor the input with one more
//!   byte decodes to the same anchor.

#![no_main]

use fstp_audit::anchor::{decode_anchor, encode_anchor};
use libfuzzer_sys::fuzz_target;

/// The composite signature length of draft 19: ML-DSA-65 then Ed25519.
const SIG_LEN: usize = 3309 + 64;

fuzz_target!(|data: &[u8]| {
    let first = decode_anchor(data);
    assert_eq!(first, decode_anchor(data), "decode is not deterministic");
    if let Ok(a) = &first {
        assert!(a.n >= 1, "anchor of row 0 accepted");
        assert_eq!(a.signature.len(), SIG_LEN, "non-composite signature length");
        assert_eq!(
            encode_anchor(a).as_deref().ok(),
            Some(data),
            "an accepted anchor does not re-encode to its input"
        );
        if let Some((_, head)) = data.split_last() {
            assert_ne!(
                decode_anchor(head).as_ref().ok(),
                Some(a),
                "truncation accepted"
            );
        }
        let mut longer = data.to_vec();
        longer.push(0);
        assert_ne!(
            decode_anchor(&longer).as_ref().ok(),
            Some(a),
            "trailing byte accepted"
        );
    }
});
