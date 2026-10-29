//! Tests of `fstp_release::licence::decode_licence_file` (Q41, I-38,
//! design sections 10.2 and 15).
//!
//! The holder registers on a CrabNebula web page and imports the signed
//! token file, so the cell never sends registration data. The file is
//! the W1g armour: a BEGIN line, the token in standard padded base64 on
//! one line, and an END line, each ending in one line feed. It has one
//! spelling. The decoder returns the token bytes; `verify_token` checks
//! the signature next.
//!
//! The tests are red until lane W2j lands the decoder.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/oracle.rs"]
mod oracle;
#[path = "support/seams.rs"]
mod seams;

use fstp_prop::{Gen, check, prop_assert_eq};
use fstp_release::licence::decode_licence_file;

use oracle::{FILE_BEGIN, FILE_END, TOKEN_LEN, base64, gen_token, key, licence_file, sign_token};
use seams::stub_msg;

/// `decode_licence_file`: the token, `None` for a typed refusal.
fn decode(file: &[u8]) -> Result<Option<Vec<u8>>, String> {
    match decode_licence_file(file) {
        Ok(t) => Ok(Some(t)),
        Err(e) => stub_msg(&e).map_or(Ok(None), Err),
    }
}

fn signed_token(g: &mut Gen) -> Vec<u8> {
    sign_token(&gen_token(g), &key(0x11))
}

/// I-38, Q41: the file of a signed token decodes to exactly that token.
#[test]
fn i38_licence_file_round_trips_the_token() {
    check("i38_licence_file_round_trips_the_token", |g| {
        let token = signed_token(g);
        prop_assert_eq!(decode(&licence_file(&token))?, Some(token));
        Ok(())
    });
}

/// I-38, Q41, design section 15: the file has one spelling, so every
/// other spelling of the same token is refused. The cases are CRLF line
/// ends, a missing or extra line feed, and a changed armour byte. They
/// also cover a wrapped or indented base64 line, missing padding, set
/// unused bits, a byte order mark and the URL-safe alphabet.
#[test]
fn i38_licence_file_refuses_every_other_spelling() {
    check("i38_licence_file_refuses_every_other_spelling", |g| {
        let token = signed_token(g);
        let b64 = base64(&token);
        let good = licence_file(&token);
        let text = String::from_utf8(good.clone()).unwrap();
        let (file, what) = match g.u8_in(0..=9) {
            0 => (text.replace('\n', "\r\n").into_bytes(), "CRLF"),
            1 => (good[..good.len() - 1].to_vec(), "no final line feed"),
            2 => ([good.as_slice(), b"\n"].concat(), "extra line feed"),
            3 => {
                let mut f = good.clone();
                let i = g.usize_in(0..=FILE_BEGIN.len() - 2);
                f[i] ^= g.u8_in(1..=255);
                (f, "armour byte changed")
            }
            4 => {
                let (a, b) = b64.split_at(64);
                (
                    format!("{FILE_BEGIN}{a}\n{b}\n{FILE_END}").into_bytes(),
                    "wrapped at 64",
                )
            }
            5 => (
                format!("{FILE_BEGIN} {b64}\n{FILE_END}").into_bytes(),
                "indented",
            ),
            6 => (
                format!("{FILE_BEGIN}{}\n{FILE_END}", b64.trim_end_matches('=')).into_bytes(),
                "unpadded",
            ),
            7 => {
                // TOKEN_LEN is 113 bytes, so the last quad holds two bytes
                // and its third character has two unused bits.
                let mut chars: Vec<u8> = b64.clone().into_bytes();
                let at = chars.len() - 2;
                const B64: &[u8] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                let pos = B64.iter().position(|c| *c == chars[at]).unwrap();
                chars[at] = B64[(pos & !0b11) | g.usize_in(1..=3)];
                (
                    format!(
                        "{FILE_BEGIN}{}\n{FILE_END}",
                        String::from_utf8(chars).unwrap()
                    )
                    .into_bytes(),
                    "unused bits set",
                )
            }
            8 => (
                [b"\xef\xbb\xbf".as_slice(), good.as_slice()].concat(),
                "byte order mark",
            ),
            _ => (
                format!(
                    "{FILE_BEGIN}{}\n{FILE_END}",
                    b64.replace('+', "-").replace('/', "_")
                )
                .into_bytes(),
                "url-safe alphabet",
            ),
        };
        if file == good {
            return Ok(());
        }
        prop_assert_eq!(decode(&file)?, None, "{what}");
        Ok(())
    });
}

/// I-38, Q41: a well-formed armour around anything but a token of
/// exactly the token length is refused.
#[test]
fn i38_licence_file_refuses_a_token_of_another_length() {
    check("i38_licence_file_refuses_a_token_of_another_length", |g| {
        let mut token = signed_token(g);
        if g.bool() {
            token.truncate(g.usize_in(0..=TOKEN_LEN - 1));
        } else {
            token.extend_from_slice(&g.bytes(1..=96));
        }
        prop_assert_eq!(
            decode(&licence_file(&token))?,
            None,
            "{} bytes",
            token.len()
        );
        Ok(())
    });
}

/// I-38, TH-26 (design section 15, `licence_file_import_decode`): a
/// 4 MiB file is refused with a typed error, without a panic.
#[test]
fn i38_licence_file_refuses_an_oversized_file() {
    let file = format!("{FILE_BEGIN}{}\n{FILE_END}", "A".repeat(4 * 1024 * 1024));
    let got = decode(file.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got, None, "I-38: a 4 MiB licence file was accepted");
}

/// I-38, Q41, design section 10.2: import is decode then verify. A file
/// of a token signed by the pinned key yields that token's fields, and
/// no other key verifies it.
#[test]
fn i38_licence_file_import_then_verify_yields_the_token() {
    let pinned = key(0x11);
    let other = key(0x99);
    check(
        "i38_licence_file_import_then_verify_yields_the_token",
        |g| {
            let t = gen_token(g);
            let token = decode(&licence_file(&sign_token(&t, &pinned)))?
                .ok_or("a well-formed licence file was refused")?;
            prop_assert_eq!(seams::verify(&token, pinned.public_key())?.ok(), Some(t));
            prop_assert_eq!(seams::verify(&token, other.public_key())?.ok(), None);
            Ok(())
        },
    );
}
