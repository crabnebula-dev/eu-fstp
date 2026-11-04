//! Fuzz target `signup_form_decode` of `fstp-signup` (TH-26, H-05, TH-46,
//! M4 design section 9).
//!
//! Design checks: duplicate fields, unknown fields, bad percent-encoding
//! and over-long values are refused. The target checks that the decoder
//! never panics, that it refuses only with a form error, that a body over
//! the limit is refused, and that every accepted form encodes to a body
//! that decodes back to the same form.

#![no_main]

use fstp_signup::{
    MAX_FIELD_BYTES, MAX_FORM_BYTES, SignupError, SignupForm, decode_signup_form,
    encode_signup_form,
};
use libfuzzer_sys::fuzz_target;

fn texts(form: &SignupForm) -> Vec<&str> {
    match form {
        SignupForm::Signup(f) => vec![
            f.legal_name.as_str(),
            f.billing_address.as_str(),
            f.contracting_signatory.as_str(),
        ],
        SignupForm::Agreements(f) => vec![f.accepted_by.as_str()],
    }
}

fuzz_target!(|data: &[u8]| {
    match decode_signup_form(data) {
        Err(SignupError::Form(_)) => {}
        Err(other) => panic!("not a form refusal: {other:?}"),
        Ok(form) => {
            assert!(
                data.len() <= MAX_FORM_BYTES,
                "a body over the limit decoded"
            );
            for t in texts(&form) {
                assert!(!t.is_empty() && t.len() <= MAX_FIELD_BYTES);
                assert!(t.chars().all(|c| c == '\r' || c == '\n' || !c.is_control()));
            }
            let again = encode_signup_form(&form);
            assert_eq!(decode_signup_form(&again), Ok(form), "round trip failed");
        }
    }
});
