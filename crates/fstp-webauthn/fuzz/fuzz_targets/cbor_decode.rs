//! Fuzz target `cbor_decode` of `fstp-webauthn` (TH-26, H-05, M3 design
//! section 15, ADR-008).
//!
//! Design checks: no panic; depth and size limits; non-shortest forms and
//! duplicate keys refused. For every input:
//!
//! - `decode` never panics and is deterministic.
//! - An accepted input is at most 64 KiB, the item has depth at most 4,
//!   no map repeats a key, and the shortest definite encoding of the item
//!   is the input byte for byte. So no non-shortest head, indefinite
//!   length, tag, float or trailing byte is ever accepted.
//!
//! Against the W0 stub every input is refused, so only the first check
//! has teeth until lane W2a lands the decoder.

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let got = fstp_webauthn::cbor::decode(data);
    assert_eq!(
        got,
        fstp_webauthn::cbor::decode(data),
        "decode is not deterministic"
    );
    if let Ok(item) = got {
        common::assert_canonical(data, &item);
    }
});
