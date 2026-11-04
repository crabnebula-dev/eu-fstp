//! Fuzz target `witness_wire_decode` of `fstp-witness` (TH-26, H-05,
//! I-24, lane int5).
//!
//! Checks, for the framed requests and replies of `fstp_witness::wire`:
//!
//! - no panic, and decoding is deterministic, for a request and a reply;
//! - an accepted request or reply re-encodes byte for byte, so each value
//!   has one spelling;
//! - the input without its last byte never decodes to the same value.

#![no_main]

use fstp_witness::wire::{decode_reply, decode_request, encode_reply, encode_request};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let req = decode_request(data);
    assert_eq!(
        req,
        decode_request(data),
        "request decode is not deterministic"
    );
    if let Ok(r) = &req {
        let again = encode_request(r).expect("an accepted request encodes");
        assert_eq!(again.as_slice(), data, "request round trip");
        if let Some(short) = data.get(..data.len().saturating_sub(1)) {
            assert_ne!(
                decode_request(short).as_ref().ok(),
                Some(r),
                "a cut request decodes"
            );
        }
    }
    let rep = decode_reply(data);
    assert_eq!(rep, decode_reply(data), "reply decode is not deterministic");
    if let Ok(r) = &rep {
        let again = encode_reply(r).expect("an accepted reply encodes");
        assert_eq!(again.as_slice(), data, "reply round trip");
        if let Some(short) = data.get(..data.len().saturating_sub(1)) {
            assert_ne!(
                decode_reply(short).as_ref().ok(),
                Some(r),
                "a cut reply decodes"
            );
        }
    }
});
