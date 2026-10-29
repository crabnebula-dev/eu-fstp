//! Fuzz target `cell_record_decode` of `fstp-cell-core` (TH-26, H-05, M3
//! design section 15).
//!
//! Design checks: decoding never panics; the two decoders agree, so
//! `record_from_canonical_at` at schema 1 accepts exactly what
//! `decode_cell_record` accepts, with the same record; every accepted
//! input re-encodes byte for byte (ADR-007, I-23, one spelling).
//!
//! [`reencode`] is `impl fstp_ledger::Canonical for CellRecord`.

#![no_main]

use fstp_cell_core::{CellRecord, decode_cell_record, record_from_canonical_at};
use libfuzzer_sys::fuzz_target;

/// The stored bytes of `r`.
fn reencode(r: &CellRecord) -> Option<Vec<u8>> {
    Some(fstp_ledger::Canonical::canonical(r))
}

fuzz_target!(|data: &[u8]| {
    let plain = decode_cell_record(data);
    let at_v1 = record_from_canonical_at(data, 1);
    assert!(!format!("{plain:?}").is_empty());
    match (&plain, &at_v1) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a, b, "the decoders disagree");
            if let Some(bytes) = reencode(a) {
                assert_eq!(
                    bytes.as_slice(),
                    data,
                    "accepted bytes re-encode differently"
                );
            }
        }
        (Err(_), Err(_)) => {}
        _ => panic!("one decoder accepted what the other refused"),
    }
    // Schema 0 is no version, so it is refused whatever the body.
    assert!(record_from_canonical_at(data, 0).is_err());
});
