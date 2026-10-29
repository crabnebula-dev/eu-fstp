//! `fstp_auth::codec::decode_session_cookie`: the `__Host-fstp` cookie
//! value (B11, ADR-008 "Sessions", design sections 1.2, 8.2 and 15,
//! TH-26).
//!
//! ADR-008: the cookie value is the cell id followed by the token. A cell
//! id is 16 bytes (`fstp_cp_proto::CellId`), and a token is 32 random
//! bytes. So a cookie value is 48 bytes, and design section 15 asks for
//! constant lengths only.
//!
//! Reading, reported by lane W2b's test author: the codec decodes the
//! cookie's byte form, and any text armour belongs to the route layer.
//! The W0 `SessionCookie` names its fields `session` (16 bytes) and `tag`
//! (32 bytes). These tests read them by position as the cell id and the
//! token. Each decoded field must hold its input bytes unchanged.
//!
//! Gaps:
//! - B11 says another cell refuses the cookie before any lookup. The
//!   decoder takes no expected cell id, so no crate test can check that
//!   refusal. Proposed: `decode_session_cookie(bytes, cell)` refusing a
//!   foreign cell id, or a `SessionCookie::cell_matches` check. The W1f and
//!   W3a isolation tests check B11 over HTTP.
//! - The stub has no encoder, so the round trip is checked as "the fields
//!   hold the input bytes".
//!
//! Lane W2b test author. Red until lane W2b lands `decode_session_cookie`,
//! because the W0 stub refuses every input with `NotImplemented`.

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
use fstp_auth::codec::{SessionCookie, decode_session_cookie};
use fstp_prop::{Gen, check, prop_assert_eq};

/// The cell id length.
const CELL_LEN: usize = 16;
/// ADR-008: the token length.
const TOKEN_LEN: usize = 32;
/// ADR-008: a cookie value is the cell id followed by the token.
const COOKIE_LEN: usize = CELL_LEN + TOKEN_LEN;

/// The cookie of `bytes` split by position.
fn split(bytes: &[u8]) -> SessionCookie {
    SessionCookie {
        session: bytes[..CELL_LEN].try_into().unwrap(),
        tag: bytes[CELL_LEN..].try_into().unwrap(),
    }
}

/// B11, ADR-008: a 48-byte value decodes into its cell id and token,
/// each holding its input bytes.
#[test]
fn b11_cookie_of_cell_id_and_token_decodes_to_its_parts() {
    let bytes: Vec<u8> = (0..COOKIE_LEN).map(|i| i as u8).collect();
    assert_eq!(decode_session_cookie(&bytes), Ok(split(&bytes)));
}

/// B11, design section 15: a value one byte short or long, or holding the
/// cell id or the token alone, is refused.
#[test]
fn b11_cookie_off_lengths_refused() {
    for len in [
        0,
        CELL_LEN,
        TOKEN_LEN,
        COOKIE_LEN - 1,
        COOKIE_LEN + 1,
        2 * COOKIE_LEN,
    ] {
        assert_refused(
            &format!("{len} bytes"),
            &decode_session_cookie(&vec![0x42; len]),
        );
    }
}

/// B11, design section 15: only the constant length decodes, and each
/// decoded cookie holds exactly its input bytes.
#[test]
fn b11_cookie_decode_accepts_only_its_constant_length() {
    check(
        "b11_cookie_decode_accepts_only_its_constant_length",
        |g: &mut Gen| {
            let len = if g.bool() {
                COOKIE_LEN
            } else {
                g.usize_in(0..=128)
            };
            let bytes = g.bytes(len..=len);
            let got = decode_session_cookie(&bytes);
            real("decode_session_cookie", &got)?;
            if bytes.len() == COOKIE_LEN {
                prop_assert_eq!(got, Ok(split(&bytes)));
                Ok(())
            } else {
                refused(&format!("{} bytes", bytes.len()), &got)
            }
        },
    );
}
