//! Fuzz target `import_text_decode` of `fstp-import` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: arbitrary bytes per media type; output is valid UTF-8 within limits; spans stay in bounds (T-FUZZ-IMPORT, T-FUZZ-UPLOAD).
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2b lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// The media type the first byte selects.
fn media(data: &[u8]) -> fstp_import::ImportMedia {
    match data.first() {
        Some(b) if b % 2 == 1 => fstp_import::ImportMedia::TextMarkdown,
        _ => fstp_import::ImportMedia::TextPlain,
    }
}

fuzz_target!(|data: &[u8]| {
    let shown = format!(
        "{:?}",
        fstp_import::ImportLimits::standard().and_then(|l| fstp_import::normalise(
            data,
            media(data),
            l
        ))
    );
    assert!(!shown.is_empty());
});
