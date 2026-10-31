//! Fuzz target `keyd_request_decode` of `fstp-keyd` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; limits enforced.
//!
//! A refusal must have a short display, so no error can carry a copy of
//! a request. An accepted request must re-encode, through the client's
//! own encoder in `fstp_custody::keyd`, to exactly the input: the
//! decoder accepts one spelling only.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// The longest error display the target accepts.
const DISPLAY_LIMIT: usize = 512;

fuzz_target!(|data: &[u8]| {
    match fstp_keyd::decode_request(data) {
        Ok(r) => {
            assert!(!format!("{r:?}").is_empty());
            let again = fstp_custody::keyd::encode_request(&r);
            assert_eq!(again.as_deref().ok(), Some(data), "not one spelling");
        }
        Err(e) => {
            let shown = e.to_string();
            assert!(!shown.is_empty(), "an empty error display");
            assert!(
                shown.len() <= DISPLAY_LIMIT,
                "an error display of {} bytes",
                shown.len()
            );
        }
    }
});
