//! The OVHcloud KMS response decoder and client constructor (ADR-004
//! part 2 "Backends", design sections 3.3 and 15, R-NF-09, TH-26).
//!
//! The OKMS API version is a record at first use (ADR-004 part 2, Q11),
//! so no test here assumes a member name of a real response. They check
//! what design section 15 fixes for `okms_response_decode`: "No panic;
//! bounded allocation; unknown members refused; key bytes never in error
//! displays". Every member name used here is one no schema has.
//!
//! State: red. The W0 decoder and `OkmsCustody::new` refuse every input
//! with `NotImplemented`, which no test here counts as a refusal.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

mod common;

use common::{classify, expect_refused, leaks, spellings};
use fstp_custody::OkmsCustody;
use fstp_custody::okms::decode_response;
use fstp_prop::{Gen, prop_assert};

/// A member name no OKMS schema has, built from generated letters.
fn unknown_member(g: &mut Gen) -> String {
    let tail: String = g
        .vec(1..=12, |g| char::from(b'a' + g.u8_in(0..=25)))
        .into_iter()
        .collect();
    format!("fstp_not_an_okms_member_{tail}")
}

/// Design section 15: input that is not JSON is refused. Every input here
/// starts with a byte no JSON text starts with.
#[test]
fn adr004_okms_decoder_refuses_bytes_that_are_not_json() {
    fstp_prop::check(
        "adr004_okms_decoder_refuses_bytes_that_are_not_json",
        |g: &mut Gen| {
            let lead = *g.pick(&[0x00u8, 0x01, b'<', b'x', 0xff, 0xfe, b')']);
            let mut bytes = vec![lead];
            bytes.extend(g.bytes(0..=64));
            expect_refused(decode_response(&bytes).map_err(classify), "non-JSON input")?;
            Ok(())
        },
    );
}

/// Design section 15: "unknown members refused". An object whose members
/// are all unknown names is refused, whatever their values.
#[test]
fn adr004_okms_decoder_refuses_unknown_members() {
    fstp_prop::check(
        "adr004_okms_decoder_refuses_unknown_members",
        |g: &mut Gen| {
            let members: Vec<String> = g.vec(1..=4, |g| {
                let value = match g.usize_in(0..=3) {
                    0 => "1".to_owned(),
                    1 => "true".to_owned(),
                    2 => "null".to_owned(),
                    _ => "\"value\"".to_owned(),
                };
                format!("\"{}\":{value}", unknown_member(g))
            });
            let text = format!("{{{}}}", members.join(","));
            g.note("response", &text);
            expect_refused(
                decode_response(text.as_bytes()).map_err(classify),
                "an object of unknown members",
            )?;
            Ok(())
        },
    );
}

/// Design section 15: "bounded allocation". A response nested 100 000
/// levels deep is refused, and the decoder does not overflow its stack.
#[test]
fn adr004_okms_decoder_refuses_deep_nesting() {
    let depth = 100_000;
    let mut text = "[".repeat(depth);
    text.push_str(&"]".repeat(depth));
    let r = decode_response(text.as_bytes()).map_err(classify);
    if let Err(e) = expect_refused(r, "a response nested 100 000 deep") {
        panic!("{e}");
    }
}

/// Design section 15: "key bytes never in error displays". A refused
/// response carries a 32-byte canary as a member value, in hex and in
/// both base64 alphabets. Neither the `Display` nor the `Debug` form of
/// the error shows the canary in any of those spellings.
#[test]
fn adr004_okms_decoder_error_never_shows_key_bytes() {
    fstp_prop::check(
        "adr004_okms_decoder_error_never_shows_key_bytes",
        |g: &mut Gen| {
            let canary = g.bytes(32..=32);
            let spelled = spellings(&canary);
            let value = g.pick(&spelled).clone();
            let text = format!("{{\"{}\":\"{value}\"}}", unknown_member(g));
            let (debug, display) = expect_refused(
                decode_response(text.as_bytes()).map_err(classify),
                "a response with an unknown member",
            )?;
            prop_assert!(
                !leaks(&display, &canary),
                "Display shows the key: {display}"
            );
            prop_assert!(!leaks(&debug, &canary), "Debug shows the key: {debug}");
            Ok(())
        },
    );
}

/// R-NF-09, ADR-004 part 2 (Q11): the OKMS link is TLS with an access
/// certificate. A client for a plain `http` endpoint, or for an endpoint
/// with no scheme, is refused at construction.
#[test]
fn r_nf_09_okms_client_refuses_an_endpoint_without_tls() {
    let mut wrong = Vec::new();
    for endpoint in [
        "http://eu-west-par.okms.example",
        "eu-west-par.okms.example",
        "ftp://eu-west-par.okms.example",
        "",
    ] {
        let r = OkmsCustody::new(endpoint).map_err(classify);
        if let Err(e) = expect_refused(r, endpoint) {
            wrong.push(e);
        }
    }
    assert!(wrong.is_empty(), "{wrong:?}");
}
