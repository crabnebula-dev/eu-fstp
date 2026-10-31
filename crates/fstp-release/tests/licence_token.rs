//! Tests of `fstp_release::licence::verify_token` (I-39, design sections
//! 10.2 and 15, ADR-004 "Licence token key").
//!
//! A token is `"FSTPLT01" || licence || kind || issued_at ||
//! refresh_after || not_after || Ed25519 signature` (W1g proposal). The
//! signature is checked before any field is used. So a refusal of a badly
//! signed token never depends on its fields.
//!
//! The tests are red until lane W2j lands `verify_token` and the two
//! licence kinds ([`seams::KIND_SEAM`]).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/oracle.rs"]
mod oracle;
#[path = "support/seams.rs"]
mod seams;

use fstp_prop::{check, prop_assert, prop_assert_eq};

use oracle::{TOKEN_CONTEXT, TOKEN_LEN, gen_token, key, sign_body, sign_token, token_body_raw};
use seams::verify;

/// I-39, design section 10.2: a token signed by the given key verifies,
/// and production reads back exactly the fields that were signed.
#[test]
fn i39_verify_token_reads_back_a_token_signed_by_the_key() {
    let k = key(0x11);
    check(
        "i39_verify_token_reads_back_a_token_signed_by_the_key",
        |g| {
            let t = gen_token(g);
            let got = verify(&sign_token(&t, &k), k.public_key())?;
            prop_assert_eq!(got.ok(), Some(t));
            Ok(())
        },
    );
}

/// I-39, TH-32, design section 10.2: a token signed by any other key is
/// refused with a typed error, so a forged token never changes the
/// licence state.
#[test]
fn i39_verify_token_refuses_a_token_signed_by_another_key() {
    let pinned = key(0x11);
    check(
        "i39_verify_token_refuses_a_token_signed_by_another_key",
        |g| {
            let other = key(g.u8_in(0x12..=0xff));
            let t = gen_token(g);
            let got = verify(&sign_token(&t, &other), pinned.public_key())?;
            prop_assert!(got.is_err(), "accepted {t:?} signed by another key");
            Ok(())
        },
    );
}

/// I-39, design section 15 ("signature checked before use"): flipping
/// any one bit of a signed token, in its body or its signature, is
/// refused.
#[test]
fn i39_verify_token_refuses_any_flipped_bit() {
    let k = key(0x11);
    check("i39_verify_token_refuses_any_flipped_bit", |g| {
        let mut bytes = sign_token(&gen_token(g), &k);
        let i = g.usize_in(0..=TOKEN_LEN - 1);
        bytes[i] ^= 1u8 << g.u8_in(0..=7);
        let got = verify(&bytes, k.public_key())?;
        prop_assert!(got.is_err(), "accepted a token with byte {i} changed");
        Ok(())
    });
}

/// I-39, design section 15: a token of any other length is refused, so
/// no prefix, suffix or padding of a signed token verifies.
#[test]
fn i39_verify_token_refuses_every_other_length() {
    let k = key(0x11);
    check("i39_verify_token_refuses_every_other_length", |g| {
        let mut bytes = sign_token(&gen_token(g), &k);
        if g.bool() {
            bytes.truncate(g.usize_in(0..=TOKEN_LEN - 1));
        } else {
            bytes.extend_from_slice(&g.bytes(1..=64));
        }
        let got = verify(&bytes, k.public_key())?;
        prop_assert!(got.is_err(), "accepted {} bytes", bytes.len());
        Ok(())
    });
}

/// I-39, design section 10.2: a validly signed token with an unknown kind
/// byte is refused. Only codes 1 (commercial) and 2 (noncommercial) of
/// the W1g proposal exist.
#[test]
fn i39_verify_token_refuses_a_signed_unknown_kind() {
    let k = key(0x11);
    check("i39_verify_token_refuses_a_signed_unknown_kind", |g| {
        let t = gen_token(g);
        let code = if g.bool() { 0 } else { g.u8_in(3..=255) };
        let bytes = sign_body(&k, TOKEN_CONTEXT, token_body_raw(&t, code));
        let got = verify(&bytes, k.public_key())?;
        prop_assert!(got.is_err(), "accepted kind byte {code}");
        Ok(())
    });
}

/// I-39, design section 10.2: a validly signed token whose instants are
/// not `issued_at <= refresh_after <= not_after` is refused.
#[test]
fn i39_verify_token_refuses_signed_unordered_instants() {
    let k = key(0x11);
    check("i39_verify_token_refuses_signed_unordered_instants", |g| {
        let mut t = gen_token(g);
        let gap = g.i64_in(1..=oracle::DAY_S);
        if g.bool() {
            t.issued_at = t.refresh_after + gap;
        } else {
            t.refresh_after = t.not_after + gap;
        }
        let got = verify(&sign_token(&t, &k), k.public_key())?;
        prop_assert!(got.is_err(), "accepted {t:?}");
        Ok(())
    });
}

/// I-39, design section 10.2: a validly signed body with another magic
/// is refused, so a signed transition or metadata body is never read as
/// a token. The context string alone does not stand in for the magic.
#[test]
fn i39_verify_token_refuses_a_signed_body_with_another_magic() {
    let k = key(0x11);
    check(
        "i39_verify_token_refuses_a_signed_body_with_another_magic",
        |g| {
            let t = gen_token(g);
            let mut body = token_body_raw(&t, t.kind.code());
            let i = g.usize_in(0..=7);
            body[i] ^= g.u8_in(1..=255);
            let got = verify(&sign_body(&k, TOKEN_CONTEXT, body), k.public_key())?;
            prop_assert!(got.is_err(), "accepted magic byte {i} changed");
            Ok(())
        },
    );
}

/// I-39, design section 15 ("signature checked before use"): the refusal
/// of a token that no key signed never depends on its fields. Two such
/// tokens of the right length and magic, one with a valid body and one
/// with an unknown kind or unordered instants, get the same error.
#[test]
fn i39_verify_token_refusal_of_a_bad_signature_reads_no_field() {
    let pinned = key(0x11);
    let other = key(0x99);
    check(
        "i39_verify_token_refusal_of_a_bad_signature_reads_no_field",
        |g| {
            let t = gen_token(g);
            let good = sign_token(&t, &other);
            let mut bad_fields = t;
            bad_fields.issued_at = t.not_after + 1;
            let code = if g.bool() { 0 } else { t.kind.code() };
            let bad = sign_body(&other, TOKEN_CONTEXT, token_body_raw(&bad_fields, code));
            let a = verify(&good, pinned.public_key())?;
            let b = verify(&bad, pinned.public_key())?;
            prop_assert!(a.is_err() && b.is_err(), "{a:?} / {b:?}");
            prop_assert_eq!(a.err(), b.err());
            Ok(())
        },
    );
}
