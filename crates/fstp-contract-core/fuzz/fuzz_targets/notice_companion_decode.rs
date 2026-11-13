//! Fuzz target `notice_companion_decode` of `fstp-contract-core` (TH-26,
//! R-CR-04, R-NF-02, M9 design D6).
//!
//! The input is read as the stored form of a notice companion signature.
//! A form that decodes must encode back to exactly the input bytes, since
//! only the canonical spelling is a stored form. Nothing panics.

#![no_main]

use fstp_contract_core::notice::{decode_notice_companion, encode_notice_companion};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(rec) = decode_notice_companion(data) else {
        return;
    };
    let back = encode_notice_companion(&rec).expect("a decoded record encodes");
    assert_eq!(back, data);
    assert_eq!(decode_notice_companion(&back).expect("re-decodes"), rec);
});
