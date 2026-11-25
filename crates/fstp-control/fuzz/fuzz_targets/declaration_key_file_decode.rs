//! Fuzz target `declaration_key_file_decode` of `fstp-control` (TH-26,
//! I-80, ADR-012 record of lane m10/saas-declare): the sealed restore
//! declaration key file.
//!
//! Design checks: no panic; deterministic; one spelling. An accepted file
//! re-encodes to its input byte for byte, and is never a route feed key
//! file, since the magic differs.

#![no_main]

use fstp_control::declare::{decode_declaration_key_file, encode_declaration_key_file};
use fstp_control::route_feed::decode_feed_key_file;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode_declaration_key_file(data);
    assert_eq!(
        first,
        decode_declaration_key_file(data),
        "not deterministic"
    );
    let Ok(f) = first else {
        return;
    };
    assert_eq!(
        encode_declaration_key_file(&f).unwrap(),
        data,
        "not one spelling"
    );
    assert!(decode_feed_key_file(data).is_err(), "a feed key file too");
});
