//! Fuzz target `keyd_frame_decode` of `fstp-custody` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; bounded allocation; unknown members refused;
//! key bytes never in error displays.
//!
//! libFuzzer's `-rss_limit_mb` bounds allocation. A refusal must have a
//! short display, so no error can carry a copy of a frame body. An
//! accepted frame must have a body shorter than its input and re-encode
//! to exactly the input. The same input also feeds the response decoder
//! of the client, under the same display rule. The canary checks are
//! the crate tests in `tests/keyd_frame.rs`.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// The longest error display the target accepts.
const DISPLAY_LIMIT: usize = 512;

fn check_display(e: &fstp_custody::CustodyError) {
    let shown = e.to_string();
    assert!(!shown.is_empty(), "an empty error display");
    assert!(
        shown.len() <= DISPLAY_LIMIT,
        "an error display of {} bytes",
        shown.len()
    );
}

fuzz_target!(|data: &[u8]| {
    match fstp_custody::keyd::decode_frame(data) {
        Ok(f) => {
            assert!(f.body.len() < data.len(), "a body as long as its frame");
            assert!(!format!("{f:?}").is_empty());
            let again = fstp_custody::keyd::encode_frame(&f);
            assert_eq!(again.as_deref().ok(), Some(data), "not one spelling");
        }
        Err(e) => check_display(&e),
    }
    match fstp_custody::keyd::decode_response(data) {
        Ok(r) => assert!(!format!("{r:?}").is_empty()),
        Err(e) => check_display(&e),
    }
});
