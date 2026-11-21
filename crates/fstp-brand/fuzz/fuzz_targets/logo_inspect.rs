//! Fuzz target `logo_inspect` of `fstp-brand` (ADR-030 section 3, I-68).
//!
//! Checks: the logo check is total over any bytes. An accepted file is a
//! PNG or WebP within the size and dimension bounds, and its rewrite
//! passes the check again unchanged. The PDF reader is total too.

#![no_main]

use fstp_brand::image::{MAX_DIMENSION, MAX_LOGO_BYTES, MIN_DIMENSION, inspect, pdf_image};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pdf_image(data);
    let Ok(logo) = inspect(data) else {
        return;
    };
    assert!(logo.bytes.len() <= MAX_LOGO_BYTES);
    assert!((MIN_DIMENSION..=MAX_DIMENSION).contains(&logo.width));
    assert!((MIN_DIMENSION..=MAX_DIMENSION).contains(&logo.height));
    assert!(logo.bytes.starts_with(b"\x89PNG") || logo.bytes.starts_with(b"RIFF"));
    let again = inspect(&logo.bytes).map(|l| l.bytes);
    assert_eq!(again.as_ref().ok(), Some(&logo.bytes));
    let _ = pdf_image(&logo.bytes);
});
