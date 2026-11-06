//! Fuzz target `guide_pdf` of `fstp-guide` (R-GA-02, TH-26, M5 design
//! section 3.3).
//!
//! Over arbitrary bytes taken as a stored canonical Guide:
//!
//! - reading and rendering never panic;
//! - rendering one input twice gives the same bytes (I-53);
//! - an accepted input gives a PDF.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = fstp_guide::guide_pdf(data);
    let again = fstp_guide::guide_pdf(data);
    assert_eq!(first, again, "the Guide PDF is not deterministic");
    if let Ok(pdf) = first {
        assert!(pdf.starts_with(b"%PDF-"), "an accepted Guide gave no PDF");
    }
});
