//! Fuzz target `app_keystore_image_decode` of `fstp-cell` (H-05, ADR-012
//! record of lane L27): the App keystore snapshot image `"FAK1"`.
//!
//! Design checks: no panic, and one spelling only: an accepted image
//! encodes back to the same bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((cell, rows)) = fstp_cell::tasks::erasure::rows_image::decode(data) {
        assert_eq!(
            fstp_cell::tasks::erasure::rows_image::encode(cell, &rows).unwrap(),
            data
        );
    }
});
