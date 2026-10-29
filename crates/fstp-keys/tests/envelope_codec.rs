//! The sealed key and sealed blob decoders of `fstp_keys::envelope`
//! (design section 3.2, ADR-004 part 1, R-CR-01, TH-26).
//!
//! ADR-004 part 1: "The decoder accepts exactly 1210 bytes, the magic,
//! version 1, and known codes. Any other input is refused. It re-encodes
//! byte for byte." These tests build FSK1 bytes by hand from that text,
//! so they need no sealing call and run against the decoders of the W0
//! stub. They are red until lane W2f writes the decoders, because the
//! stub refuses every input with `NotImplemented`, which no test here
//! counts as a refusal.
//!
//! The blob layout is not fixed in any ADR yet (the `SEALED_BLOB_SEAM` of
//! the W1d reference). The blob test here assumes only that a blob holds
//! a 12-byte nonce and a 16-byte tag.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code indexes fixed layouts"
)]

mod common;

use common::{E_AT, HEADER_LEN, SEALED_KEY_LEN, classify, expect_refused, gen_fsk1};
use fstp_keys::envelope::{decode_sealed_blob, decode_sealed_key, encode_sealed_key};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

/// ADR-004 part 1, R-CR-01: every well-formed FSK1 key decodes, reports
/// version 1, and re-encodes byte for byte.
#[test]
fn adr004_sealed_key_decoder_accepts_the_fsk1_layout_and_re_encodes() {
    fstp_prop::check(
        "adr004_sealed_key_decoder_accepts_the_fsk1_layout_and_re_encodes",
        |g: &mut Gen| {
            let bytes = gen_fsk1(g);
            let key = decode_sealed_key(&bytes).map_err(classify)?;
            prop_assert_eq!(key.header().version, 1, "header version");
            let again = encode_sealed_key(&key).map_err(classify)?;
            prop_assert_eq!(again, bytes, "re-encoding differs");
            Ok(())
        },
    );
}

/// ADR-004 part 1: a sealed key is exactly 1210 bytes. A well-formed key
/// cut short or grown by any number of bytes is refused.
#[test]
fn adr004_sealed_key_decoder_refuses_every_other_length() {
    fstp_prop::check(
        "adr004_sealed_key_decoder_refuses_every_other_length",
        |g: &mut Gen| {
            let mut bytes = gen_fsk1(g);
            if g.bool() {
                let keep = g.usize_in(0..=SEALED_KEY_LEN - 1);
                bytes.truncate(keep);
            } else {
                bytes.extend(g.bytes(1..=64));
            }
            g.note("length", &bytes.len());
            expect_refused(
                decode_sealed_key(&bytes).map_err(classify),
                "a sealed key of the wrong length",
            )
        },
    );
}

/// The header fields ADR-004 part 1 fixes, with their offsets and the
/// values the decoder allows.
#[derive(Clone, Copy, Debug)]
enum HeaderField {
    /// Bytes 0 to 3: `"FSK1"`.
    Magic,
    /// Byte 4: version 1.
    Version,
    /// Bytes 5 and 6: `kem` 1.
    Kem,
    /// Bytes 7 and 8: `aead` 1.
    Aead,
    /// Byte 9: chain codes 1 to 5.
    Chain,
}

const FIELDS: [HeaderField; 5] = [
    HeaderField::Magic,
    HeaderField::Version,
    HeaderField::Kem,
    HeaderField::Aead,
    HeaderField::Chain,
];

/// Writes a value the decoder must refuse into `field` of `bytes`.
fn spoil(g: &mut Gen, bytes: &mut [u8], field: HeaderField) {
    match field {
        HeaderField::Magic => {
            let at = g.usize_in(0..=3);
            bytes[at] ^= g.u8_in(1..=255);
        }
        HeaderField::Version => bytes[4] = 1 ^ g.u8_in(1..=255),
        HeaderField::Kem => {
            let v = 1 ^ g.u16_in(1..=u16::MAX);
            bytes[5..7].copy_from_slice(&v.to_be_bytes());
        }
        HeaderField::Aead => {
            let v = 1 ^ g.u16_in(1..=u16::MAX);
            bytes[7..9].copy_from_slice(&v.to_be_bytes());
        }
        HeaderField::Chain => {
            bytes[9] = if g.bool() { 0 } else { g.u8_in(6..=255) };
        }
    }
}

/// ADR-004 part 1: a key with a wrong magic, a version other than 1, a
/// `kem` or `aead` code other than 1, or an unknown chain code is refused.
#[test]
fn adr004_sealed_key_decoder_refuses_a_wrong_magic_version_or_code() {
    fstp_prop::check(
        "adr004_sealed_key_decoder_refuses_a_wrong_magic_version_or_code",
        |g: &mut Gen| {
            let mut bytes = gen_fsk1(g);
            let field = *g.pick(&FIELDS);
            spoil(g, &mut bytes, field);
            g.note("field", &field);
            g.note("header", &bytes[..HEADER_LEN].to_vec());
            expect_refused(
                decode_sealed_key(&bytes).map_err(classify),
                "a sealed key with a spoilt header",
            )
        },
    );
}

/// ADR-004 part 1, one spelling: two keys that differ in any byte decode
/// to two keys that differ, since each re-encodes to its own bytes. A
/// decoder that drops a field fails here.
#[test]
fn adr004_sealed_key_decoder_keeps_every_byte() {
    fstp_prop::check(
        "adr004_sealed_key_decoder_keeps_every_byte",
        |g: &mut Gen| {
            let bytes = gen_fsk1(g);
            let mut other = bytes.clone();
            let at = g.usize_in(E_AT..=SEALED_KEY_LEN - 1);
            other[at] ^= g.u8_in(1..=255);
            let a = decode_sealed_key(&bytes).map_err(classify)?;
            let b = decode_sealed_key(&other).map_err(classify)?;
            g.note("changed byte", &at);
            prop_assert!(a != b, "two different keys decoded equal");
            prop_assert_eq!(encode_sealed_key(&b).map_err(classify)?, other);
            Ok(())
        },
    );
}

/// The shortest sealed blob: a 12-byte nonce and a 16-byte tag over an
/// empty body. Any header only adds to it.
const BLOB_FLOOR: usize = 12 + 16;

/// Design section 3.2: a blob holds its nonce and its tag, so input
/// shorter than both never decodes.
#[test]
fn adr004_sealed_blob_decoder_refuses_input_shorter_than_nonce_and_tag() {
    fstp_prop::check(
        "adr004_sealed_blob_decoder_refuses_input_shorter_than_nonce_and_tag",
        |g: &mut Gen| {
            let bytes = g.bytes(0..=BLOB_FLOOR - 1);
            expect_refused(
                decode_sealed_blob(&bytes).map_err(classify),
                "a blob shorter than its nonce and tag",
            )
        },
    );
}
