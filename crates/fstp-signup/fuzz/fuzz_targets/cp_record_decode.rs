//! Fuzz target `cp_record_decode` of `fstp-signup` (TH-26, H-05, ADR-007,
//! M4 design section 9).
//!
//! Design checks: control plane records round trip. The decoder accepts
//! only canonical text, so every accepted input must be exactly the
//! encoding of the record it decodes to. Refusals are record errors.

#![no_main]

use fstp_signup::{SignupError, SignupState, decode_cp_record, encode_cp_record};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match decode_cp_record(data) {
        Err(SignupError::Record(_)) => {}
        Err(other) => panic!("not a record refusal: {other:?}"),
        Ok(record) => {
            let again = encode_cp_record(&record);
            assert_eq!(
                again.as_deref(),
                Ok(data),
                "an accepted record has another spelling"
            );
            // Folding a decoded record never panics.
            let _ = SignupState::new().apply(&record);
        }
    }
});
