//! Fuzz target for the in-house PNG decoder (ADR-031, TH-26, I-68).
//!
//! Checks, for any input under the logo limits:
//! - decoding never panics;
//! - a decoded image has the size its sides give, within the limits;
//! - its canonical re-encoding decodes to the same pixels and encodes to
//!   the same bytes again;
//! - the PDF helpers and the contrast estimate never panic on it.

#![no_main]

use fstp_creator::Rgb;
use fstp_png::{Limits, contrast, decode, encode, flatten, pdf_alpha, pdf_rgb};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(img) = decode(data, &Limits::LOGO) else {
        return;
    };
    let (w, h) = (img.width(), img.height());
    assert!((16..=2048).contains(&w) && (16..=2048).contains(&h));
    assert_eq!(img.rgba().len(), w as usize * h as usize * 4);
    let out = encode(&img);
    let loose = Limits {
        max_file_bytes: usize::MAX,
        ..Limits::LOGO
    };
    let again = decode(&out, &loose).expect("the canonical PNG decodes");
    assert_eq!(again, img, "re-encoding changed the pixels");
    assert_eq!(encode(&again), out, "the canonical PNG is not stable");
    let white = Rgb::hex(0xFF_FF_FF);
    assert_eq!(flatten(&img, white).len(), w as usize * h as usize * 3);
    let _ = pdf_rgb(&img, white);
    let _ = pdf_alpha(&img);
    let _ = contrast(&img, Rgb::hex(0x12_12_12));
});
