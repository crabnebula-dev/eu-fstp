//! `fstp_auth::codec::decode_token`: one-time tokens of constant length
//! (ADR-008 "Sessions" and "Constants", design sections 4.2 and 15,
//! TH-26).
//!
//! ADR-008 fixes a token at 32 random bytes, and `Token` holds exactly
//! that. Design section 15 asks the decoder to accept constant-length
//! tokens only.
//!
//! Reading, reported by lane W2b's test author: the codec decodes the
//! token's byte form. Any text armour of a URL or cookie belongs to the
//! route layer. So the decoder accepts exactly 32 bytes and keeps them
//! unchanged.
//!
//! Gap: the stub has no `encode_token`, so the round trip of design
//! section 15 is checked here as "the decoded token holds the input
//! bytes". Once an encoder lands, it should re-encode byte for byte.
//!
//! Lane W2b test author. Red until lane W2b lands `decode_token`, because
//! the W0 stub refuses every input with `NotImplemented`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::{assert_refused, real, refused};
use fstp_auth::codec::{Token, decode_token};
use fstp_prop::{Gen, check, prop_assert_eq};

/// ADR-008: a token is 32 bytes.
const TOKEN_LEN: usize = 32;

/// ADR-008: a 32-byte input decodes to the token of those bytes.
#[test]
fn adr008_token_of_32_bytes_decodes_to_itself() {
    let bytes: [u8; TOKEN_LEN] = core::array::from_fn(|i| i as u8);
    assert_eq!(decode_token(&bytes), Ok(Token(bytes)));
}

/// ADR-008: the all-zero and all-ones tokens decode too. A token is random
/// bytes, so no value is reserved.
#[test]
fn adr008_token_edge_values_decode() {
    for b in [0x00, 0xff] {
        let bytes = [b; TOKEN_LEN];
        assert_eq!(decode_token(&bytes), Ok(Token(bytes)), "all {b:#04x}");
    }
}

/// ADR-008, design section 15: one byte short or one byte long is refused.
#[test]
fn adr008_token_off_by_one_lengths_refused() {
    for len in [0, 1, TOKEN_LEN - 1, TOKEN_LEN + 1, 2 * TOKEN_LEN] {
        assert_refused(&format!("{len} bytes"), &decode_token(&vec![0x41; len]));
    }
}

/// ADR-008, design section 15: only constant-length tokens decode, and
/// each decoded token holds exactly its input bytes.
#[test]
fn adr008_token_decode_accepts_only_its_constant_length() {
    check(
        "adr008_token_decode_accepts_only_its_constant_length",
        |g: &mut Gen| {
            let len = if g.bool() {
                TOKEN_LEN
            } else {
                g.usize_in(0..=96)
            };
            let bytes = g.bytes(len..=len);
            let got = decode_token(&bytes);
            real("decode_token", &got)?;
            if bytes.len() == TOKEN_LEN {
                prop_assert_eq!(got.map(|t| t.0.to_vec()), Ok(bytes));
                Ok(())
            } else {
                refused(&format!("{} bytes", bytes.len()), &got)
            }
        },
    );
}
