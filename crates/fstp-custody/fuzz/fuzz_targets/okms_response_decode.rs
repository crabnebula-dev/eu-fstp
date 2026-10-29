//! Fuzz target `okms_response_decode` of `fstp-custody` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; bounded allocation; unknown members refused;
//! key bytes never in error displays.
//!
//! libFuzzer's `-rss_limit_mb` bounds allocation. The target checks that
//! a refusal has a short display, so no error can carry a copy of the
//! input. Which input bytes are key bytes depends on the OKMS schema,
//! which is a record at first use (ADR-004 part 2, Q11). The crate test
//! `adr004_okms_decoder_error_never_shows_key_bytes` plants a canary
//! instead. An echo check over the input is not made here, because
//! libFuzzer learns comparison operands and would feed the static error
//! text back as input. "Unknown members refused" is the crate test
//! `adr004_okms_decoder_refuses_unknown_members`.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// The longest error display the target accepts.
const DISPLAY_LIMIT: usize = 512;

fuzz_target!(|data: &[u8]| {
    match fstp_custody::okms::decode_response(data) {
        Ok(r) => assert!(!format!("{r:?}").is_empty()),
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
