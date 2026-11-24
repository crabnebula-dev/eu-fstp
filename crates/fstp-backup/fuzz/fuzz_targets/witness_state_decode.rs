//! Fuzz target `witness_state_decode` of `fstp-backup` (TH-26, H-05,
//! ADR-012 record of lane m10/witness-copy): the state file of the
//! witness store's archiver.
//!
//! Design checks: no panic, deterministic, and one spelling only: an
//! accepted file encodes back to the same bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = fstp_backup::witness::decode_state(data);
    assert_eq!(
        first,
        fstp_backup::witness::decode_state(data),
        "not deterministic"
    );
    if let Ok(s) = first {
        assert_eq!(
            fstp_backup::witness::encode_state(&s).as_bytes(),
            data,
            "not one spelling"
        );
    }
});
