//! The keyd frame decoder of the `KeydCustody` client (ADR-004 part 2
//! "File custody", design sections 3.3 and 15, TH-26).
//!
//! ADR-004 part 2 says only that "The key table and frame decoders are
//! fuzzed". So these tests assume one thing: frames have one spelling,
//! which an encoder writes. Lane W2f wrote the layout in
//! `fstp_custody::keyd` and added `encode_frame`, which [`encode_frame`]
//! calls. Its record in ADR-004 is with the lead.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

mod common;

use common::{Fail, classify, expect_refused, leaks};
use fstp_custody::keyd::{KeydFrame, decode_frame};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};
use zeroize::Zeroizing;

/// Encodes `frame` in its one spelling, through
/// `fstp_custody::keyd::encode_frame`.
fn encode_frame(frame: &KeydFrame) -> Result<Vec<u8>, Fail> {
    fstp_custody::keyd::encode_frame(frame).map_err(classify)
}

/// A generated frame with a body of up to 256 bytes.
fn gen_frame(g: &mut Gen) -> KeydFrame {
    KeydFrame {
        kind: g.u8(),
        body: Zeroizing::new(g.bytes(0..=256)),
    }
}

/// The encoding of `frame`. A frame the encoder refuses discards the
/// case, as in the round trip test.
fn encoded(g: &mut Gen, frame: &KeydFrame) -> Result<Vec<u8>, String> {
    match encode_frame(frame) {
        Ok(bytes) => Ok(bytes),
        Err(Fail::Refused { .. }) => g.reject(),
        Err(seam) => Err(seam.into()),
    }
}

/// Design section 15: empty input is no frame.
#[test]
fn adr004_keyd_frame_decoder_refuses_empty_input() {
    if let Err(e) = expect_refused(decode_frame(&[]).map_err(classify), "empty input") {
        panic!("{e}");
    }
}

/// ADR-004 part 2: a frame the encoder writes decodes to itself. Some
/// generated frames may be outside the protocol, such as an unknown
/// kind. The encoder may refuse those, and such a case is discarded. A
/// run where the encoder refuses nearly every frame fails with too many
/// discards, so the property cannot pass empty.
#[test]
fn adr004_keyd_frame_round_trips_through_its_one_spelling() {
    fstp_prop::check(
        "adr004_keyd_frame_round_trips_through_its_one_spelling",
        |g: &mut Gen| {
            let frame = gen_frame(g);
            let bytes = match encode_frame(&frame) {
                Ok(bytes) => bytes,
                Err(Fail::Refused { .. }) => g.reject(),
                Err(seam) => return Err(seam.into()),
            };
            prop_assert_eq!(decode_frame(&bytes).map_err(classify)?, frame);
            Ok(())
        },
    );
}

/// Design section 15: the decoder accepts one spelling. On any input it
/// either refuses, or returns a frame whose encoding is that input.
#[test]
fn adr004_keyd_frame_decoder_accepts_only_its_one_spelling() {
    fstp_prop::check(
        "adr004_keyd_frame_decoder_accepts_only_its_one_spelling",
        |g: &mut Gen| {
            let bytes = g.bytes(0..=300);
            match decode_frame(&bytes).map_err(classify) {
                Err(Fail::Refused { .. }) => Ok(()),
                Err(Fail::Seam(s)) => Err(s),
                Ok(frame) => {
                    prop_assert_eq!(encode_frame(&frame)?, bytes, "a second spelling decoded");
                    Ok(())
                }
            }
        },
    );
}

/// Design section 15: a frame followed by any further byte, or cut short
/// by any number of bytes, is refused.
#[test]
fn adr004_keyd_frame_decoder_refuses_trailing_and_missing_bytes() {
    fstp_prop::check(
        "adr004_keyd_frame_decoder_refuses_trailing_and_missing_bytes",
        |g: &mut Gen| {
            let frame = gen_frame(g);
            let mut bytes = encoded(g, &frame)?;
            if g.bool() {
                bytes.extend(g.bytes(1..=8));
            } else {
                let keep = g.usize_in(0..=bytes.len() - 1);
                bytes.truncate(keep);
            }
            expect_refused(decode_frame(&bytes).map_err(classify), "a spoilt frame")?;
            Ok(())
        },
    );
}

/// Design section 15: "key bytes never in error displays". A frame whose
/// body is a 32-byte canary, cut short so it is refused, gives an error
/// that shows the canary in no spelling.
#[test]
fn adr004_keyd_frame_error_never_shows_body_bytes() {
    fstp_prop::check(
        "adr004_keyd_frame_error_never_shows_body_bytes",
        |g: &mut Gen| {
            let canary = g.bytes(32..=32);
            let frame = KeydFrame {
                kind: g.u8(),
                body: Zeroizing::new(canary.clone()),
            };
            let mut bytes = encoded(g, &frame)?;
            bytes.pop();
            let (debug, display) =
                expect_refused(decode_frame(&bytes).map_err(classify), "a cut frame")?;
            prop_assert!(
                !leaks(&display, &canary),
                "Display shows the body: {display}"
            );
            prop_assert!(!leaks(&debug, &canary), "Debug shows the body: {debug}");
            Ok(())
        },
    );
}
