//! Fuzz target `truetype_decode` of `fstp-pdf` (TH-26, M5 design section
//! 3.4, ADR-017).
//!
//! The input is read twice: as a whole font, and as a list of
//! `(offset, byte)` edits to the pinned font, which reaches the deep
//! tables. Parsing must return a typed result without panicking, and an
//! accepted font must answer every lookup within its glyph count.

#![no_main]

use fstp_pdf::TrueType;
use fstp_pdf::font::EMBEDDED_FONT;
use libfuzzer_sys::fuzz_target;

fn probe(font: &TrueType) {
    for c in ['\0', ' ', 'A', 'z', '€', 'ł', '\u{ffff}', '\u{10ffff}'] {
        if let Some(g) = font.glyph(c) {
            assert!(g > 0 && g < font.num_glyphs);
            let _ = font.advance(g);
        }
    }
    let _ = font.to_pdf_units(i32::from(font.ascent));
}

fuzz_target!(|data: &[u8]| {
    if let Ok(font) = TrueType::parse(data) {
        probe(&font);
    }
    let mut edited = EMBEDDED_FONT.to_vec();
    for edit in data.chunks_exact(4) {
        let at = usize::from(u16::from_be_bytes([edit[0], edit[1]])) * usize::from(edit[2] % 4 + 1);
        if let Some(b) = edited.get_mut(at) {
            *b = edit[3];
        }
    }
    if let Ok(font) = TrueType::parse(&edited) {
        probe(&font);
    }
});
