//! Fuzz target `synthetic_answer` (M7 design section 7, TH-26).
//!
//! The synthetic model reads request bodies in both protocols. It never
//! panics, and every answer it gives passes the strict decoder of the
//! same protocol.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(answer) = fstp_infer::SyntheticModel.answer(data) {
        assert!(fstp_infer::decode_response(&answer).is_ok());
    }
    if let Ok(answer) = fstp_infer::SyntheticModel.answer_anthropic(data) {
        assert!(fstp_infer::decode_anthropic_response(&answer).is_ok());
    }
});
