//! Fuzz target `copy_register_decode` of `fstp-custody` (TH-26, H-05,
//! ADR-004 record of lane L16, Q-L16-3).
//!
//! Design checks: no panic; one spelling only: an accepted register
//! encodes back to the input. Every refusal has a short display.

#![no_main]

use fstp_custody::copies::{decode_register, encode_record};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match decode_register(data) {
        Ok(records) => {
            let mut again = Vec::new();
            for r in &records {
                again.extend(encode_record(r).unwrap());
            }
            assert_eq!(again, data);
        }
        Err(e) => {
            let shown = e.to_string();
            assert!(!shown.is_empty() && shown.len() <= 512);
        }
    }
});
