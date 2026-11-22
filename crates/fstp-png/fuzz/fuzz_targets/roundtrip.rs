//! Round-trip fuzz target of the in-house codec (ADR-031, TH-26, I-68).
//!
//! Checks, for any input:
//! - every block choice of deflate inflates back to the input;
//! - an image built from the input bytes encodes to a PNG that decodes
//!   to the same pixels, and re-encodes to the same bytes.

#![no_main]

use fstp_png::{
    Blocks, Image, Limits, decode, deflate_with, encode, inflate, zlib_compress, zlib_decompress,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for b in [Blocks::Stored, Blocks::Fixed, Blocks::Dynamic, Blocks::Best] {
        let raw = deflate_with(data, b);
        assert_eq!(
            inflate(&raw, data.len()).ok().as_deref(),
            Some(data),
            "{b:?}"
        );
    }
    let z = zlib_compress(data);
    assert_eq!(zlib_decompress(&z, data.len()).ok().as_deref(), Some(data));

    let Some((&w, rest)) = data.split_first() else {
        return;
    };
    let w = u32::from(w % 64) + 1;
    let pixels = rest.len() / 4;
    let h = pixels as u32 / w;
    if h == 0 {
        return;
    }
    let n = (w * h) as usize * 4;
    let Some(img) = Image::new(w, h, rest[..n].to_vec()) else {
        return;
    };
    let png = encode(&img);
    let loose = Limits {
        max_file_bytes: usize::MAX,
        min_side: 1,
        max_side: 2048,
    };
    let back = decode(&png, &loose).expect("the canonical PNG decodes");
    assert_eq!(back, img);
    assert_eq!(encode(&back), png);
});
