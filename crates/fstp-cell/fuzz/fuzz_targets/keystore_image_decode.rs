//! Fuzz target `keystore_image_decode` of `fstp-cell` (ADR-012 "Keystore
//! snapshots", I-81, lane F-ERASE).
//!
//! Design checks: no panic, and one spelling only: an image that decodes
//! encodes back to the same bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;

use fstp_cell::tasks::erasure::snapshot::{decode_image, encode_image};

fuzz_target!(|data: &[u8]| {
    match decode_image(data) {
        Ok(image) => assert_eq!(encode_image(&image).ok().as_deref(), Some(data)),
        Err(e) => assert!(!e.to_string().is_empty()),
    }
});
