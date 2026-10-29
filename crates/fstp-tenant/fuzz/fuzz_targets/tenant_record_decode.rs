//! Fuzz target `tenant_record_decode` of `fstp-tenant` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: round trip. No input panics. A refusal is a typed
//! decoding error. An accepted input is canonical text, so encoding the
//! decoded record gives the same bytes again (ADR-007).

#![no_main]

use fstp_tenant::TenantError;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match fstp_tenant::decode_record(data) {
        Ok(rec) => {
            let again = fstp_tenant::encode_record(&rec);
            assert_eq!(again.as_deref(), Ok(data), "round trip changed the bytes");
        }
        Err(e) => {
            assert!(
                matches!(e, TenantError::Decode(_)),
                "untyped refusal: {e:?}"
            );
            assert!(!e.to_string().is_empty());
        }
    }
});
