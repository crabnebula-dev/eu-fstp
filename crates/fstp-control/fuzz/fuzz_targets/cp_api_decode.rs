//! Fuzz target `cp_api_decode` of `fstp-control` (TH-26, H-05, M3 design
//! section 15).
//!
//! Design checks: no panic; identifiers outside the grammar refused.
//!
//! On every input the decoder returns without a panic, its result formats,
//! and a second decode gives the same result. A request carries random
//! ids and closed enums only, never free text. So an accepted frame is the
//! one encoding of its request: `encode_cp_api(&req)` gives the input back,
//! and no byte is left free to carry anything else.

#![no_main]

use fstp_control::api::{decode_cp_api, encode_cp_api};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode_cp_api(data);
    let shown = format!("{first:?}");
    assert!(!shown.is_empty());
    assert_eq!(decode_cp_api(data), first);
    if let Ok(req) = first {
        assert_eq!(encode_cp_api(&req), data, "{req:?} does not round-trip");
    }
});
