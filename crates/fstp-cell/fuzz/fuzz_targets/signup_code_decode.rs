//! Fuzz target `signup_code_decode` of `fstp-cell` (ADR-008 "Registration
//! code", TH-26, H-05, I-18).
//!
//! `fstp_cell::routes::signup_code::decode_signup_code` reads the body of
//! `POST /auth/signup/code`:
//!
//! - No input panics, and every refusal formats.
//! - Decoding is a function of the input.
//! - An accepted body holds exactly 6 ASCII digits and an address with
//!   an `@`, and stays refused once a `minor` member is added (I-18).
//!
//! The seeds under `fuzz/seeds/signup_code_decode` are accepted bodies.

#![no_main]

use fstp_cell::routes::signup_code::decode_signup_code;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode_signup_code(data);
    assert_eq!(first, decode_signup_code(data));
    match &first {
        Err(e) => assert!(!e.to_string().is_empty()),
        Ok((email, code)) => {
            assert!(code.iter().all(u8::is_ascii_digit));
            assert!(email.contains('@'));
            if let Some(body) = data.strip_suffix(b"}") {
                let mut trail = body.to_vec();
                trail.extend_from_slice(b",\"minor\":true}");
                assert!(decode_signup_code(&trail).is_err(), "I-18");
            }
        }
    }
});
