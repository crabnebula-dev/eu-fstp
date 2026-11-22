//! Fuzz target for the in-house inflate (ADR-031, TH-26).
//!
//! Checks, for any input:
//! - neither raw inflate nor the zlib wrapper panics;
//! - no output passes its cap, which the first input byte chooses;
//! - a raw stream that inflates also inflates inside a zlib wrapper with
//!   its Adler-32, to the same bytes.

#![no_main]

use fstp_png::{adler32, inflate, zlib_decompress};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&choice, rest)) = data.split_first() else {
        return;
    };
    let cap = usize::from(choice) * 1024;
    if let Ok(out) = zlib_decompress(rest, cap) {
        assert!(out.len() <= cap, "zlib output passed the cap");
    }
    if let Ok(out) = inflate(rest, cap) {
        assert!(out.len() <= cap, "raw output passed the cap");
        let mut z = vec![0x78, 0xDA];
        z.extend_from_slice(rest);
        z.extend_from_slice(&adler32(&out).to_be_bytes());
        assert_eq!(
            zlib_decompress(&z, cap).ok(),
            Some(out),
            "zlib differs from raw"
        );
    }
});
