//! Fuzz target `origin_write_decode` of `fstp-vault` (TH-26, H-05, I-17,
//! M3 design sections 6.5 and 15, ADR-009 "Vault origin").
//!
//! Design checks: no panic; signature checked before any field is used.
//! For every input:
//!
//! - `decode_origin_write` never panics and is deterministic.
//! - An accepted write re-encodes as `{"body":<body>,"ticket":"<hex>"}`
//!   to the input byte for byte, with a non-empty ticket. The decoder only
//!   frames: the ticket claims and the body wait for the signature check,
//!   which the origin handler runs on the returned ticket bytes.
//!
//! Against the W0 stub every input is refused, so only the first check
//! has teeth until lane W2d lands the decoder.

#![no_main]

use std::fmt::Write as _;

use libfuzzer_sys::fuzz_target;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fuzz_target!(|data: &[u8]| {
    let got = fstp_vault::decode_origin_write(data);
    assert_eq!(
        got,
        fstp_vault::decode_origin_write(data),
        "decode is not deterministic"
    );
    if let Ok(w) = got {
        assert!(!w.ticket.is_empty(), "an empty ticket was accepted");
        let again = format!(
            "{{\"body\":{},\"ticket\":\"{}\"}}",
            String::from_utf8_lossy(&w.body),
            hex(&w.ticket)
        );
        assert_eq!(
            again.as_bytes(),
            data,
            "an accepted write has another spelling"
        );
    }
});
