//! Fuzz target `auth_record_decode` of `fstp-auth` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; round trip.
//!
//! Every input gets an answer without a panic, and decoding is a function
//! of the input. Each accepted input re-encodes through
//! `encode_auth_record` to exactly the input bytes, so every record has
//! one spelling.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = fstp_auth::codec::decode_auth_record(data);
    let shown = format!("{first:?}");
    assert!(!shown.is_empty());
    if let Ok(record) = first {
        let again = fstp_auth::codec::decode_auth_record(data);
        assert_eq!(
            again.as_ref(),
            Ok(&record),
            "decoding the same input twice differs"
        );
        let bytes = fstp_auth::codec::encode_auth_record(&record);
        assert_eq!(bytes.as_deref(), Ok(data), "the record does not re-encode");
    }
});
