//! Fuzz target `release_body_decode` of `fstp-vault` (TH-26, H-05, I-17,
//! M3 design sections 6.5 and 15, ADR-009 "Vault origin" and "Delivery").
//!
//! `release_hex` frames the body of `POST /r`: the bare ticket hex, or
//! the release loader's form body `ticket=<hex>`. For every input:
//!
//! - it never panics and is deterministic;
//! - an accepted body gives non-empty hex of at most `MAX_RELEASE_LEN`
//!   bytes, which is the input itself or the input after the one field
//!   name. The framing invents no byte and drops no other one.
//!
//! The hex then goes through the ticket decoder, whose signature check
//! runs before any field is used.

#![no_main]

use fstp_vault::origin::{MAX_RELEASE_LEN, RELEASE_FIELD, release_hex};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let got = release_hex(data);
    assert_eq!(got, release_hex(data), "framing is not deterministic");
    if let Ok(hex) = got {
        assert!(!hex.is_empty(), "empty hex was accepted");
        assert!(
            hex.len() <= MAX_RELEASE_LEN,
            "hex over the limit was accepted"
        );
        let whole = hex == data;
        let field = data.strip_prefix(RELEASE_FIELD.as_bytes()) == Some(hex);
        assert!(whole || field, "the framing changed the body");
    }
});
