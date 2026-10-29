//! Client data, `fstp_webauthn::parse_client_data` (WebAuthn Level 2
//! section 5.8.1, ADR-008, design section 8.1, TH-26).
//!
//! The parser reads the JSON through `fstp-json` and reports the type,
//! the challenge bytes (decoded from unpadded base64url) and the origin.
//! Browsers may add members, so unknown members are not refused. The
//! checks of type, challenge and origin against the expectation belong to
//! the verifiers (`registration_verify.rs`, `assertion_verify.rs`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::authn::{CHALLENGE, HOST, client_data, origin_of};
use common::{assert_refused, b64};
use fstp_prop::{check, prop_assert_eq};
use fstp_webauthn::{ClientData, parse_client_data};

fn want(kind: &str, challenge: &[u8], origin: &str) -> ClientData {
    ClientData {
        kind: kind.to_owned(),
        challenge: challenge.to_vec(),
        origin: origin.to_owned(),
    }
}

/// R-LG-01: assertion client data decodes to its type, challenge bytes
/// and origin.
#[test]
fn r_lg_01_client_data_of_a_get_decodes() {
    let origin = origin_of(HOST);
    let bytes = client_data("webauthn.get", &CHALLENGE, &origin, false);
    assert_eq!(
        parse_client_data(&bytes),
        Ok(want("webauthn.get", &CHALLENGE, &origin))
    );
}

/// R-LG-01: registration client data decodes to its type, challenge
/// bytes and origin.
#[test]
fn r_lg_01_client_data_of_a_create_decodes() {
    let origin = origin_of(HOST);
    let bytes = client_data("webauthn.create", &CHALLENGE, &origin, false);
    assert_eq!(
        parse_client_data(&bytes),
        Ok(want("webauthn.create", &CHALLENGE, &origin))
    );
}

/// R-LG-01: members in another order, the member Chrome adds at random,
/// an older `tokenBinding` member and JSON whitespace do not change the
/// result.
#[test]
fn r_lg_01_client_data_tolerates_unknown_members_and_order() {
    let c = b64::url(&CHALLENGE);
    let o = origin_of(HOST);
    let cases = [
        format!(r#"{{"origin":"{o}","challenge":"{c}","type":"webauthn.get"}}"#),
        format!(
            r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}}"#
        ),
        format!(
            r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","tokenBinding":{{"status":"not-supported"}}}}"#
        ),
        format!("{{ \"type\" : \"webauthn.get\",\n \"challenge\":\"{c}\", \"origin\":\"{o}\" }}"),
    ];
    for json in cases {
        assert_eq!(
            parse_client_data(json.as_bytes()),
            Ok(want("webauthn.get", &CHALLENGE, &o)),
            "{json}"
        );
    }
}

/// R-LG-01: JSON string escapes are decoded before any comparison, so
/// `\/` in an origin is `/`.
#[test]
fn r_lg_01_client_data_json_escapes_are_decoded() {
    let c = b64::url(&CHALLENGE);
    let json =
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"https:\/\/{HOST}"}}"#);
    assert_eq!(
        parse_client_data(json.as_bytes()),
        Ok(want("webauthn.get", &CHALLENGE, &origin_of(HOST)))
    );
}

/// ADR-008: the challenge has one spelling, unpadded base64url. Padding,
/// the standard alphabet, other characters and non-zero trailing bits are
/// refused.
#[test]
fn adr008_client_data_challenge_must_be_unpadded_base64url() {
    // 0xfb bytes give the characters that differ between the alphabets.
    let bytes = [0xfb_u8; 32];
    let o = origin_of(HOST);
    let url = b64::url(&bytes);
    assert!(url.contains('-') && url.contains('_'));
    // 32 bytes leave 2 unused low bits in the last of 43 characters. For
    // 0xfb bytes it is 's' (44). 't' (45) sets an unused bit.
    assert!(url.ends_with('s'));
    let trailing_bits = format!("{}t", &url[..42]);
    let bad = [
        b64::url_padded(&bytes),
        b64::standard(&bytes),
        b64::standard(&bytes).trim_end_matches('=').to_owned(),
        format!("{}*", &url[..42]),
        format!("{url} "),
        trailing_bits,
    ];
    for challenge in bad {
        let json = format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{o}"}}"#);
        assert_refused(&json, &parse_client_data(json.as_bytes()));
    }
}

/// ADR-008: a missing type, challenge or origin is refused.
#[test]
fn adr008_client_data_missing_member_refused() {
    let c = b64::url(&CHALLENGE);
    let o = origin_of(HOST);
    let cases = [
        format!(r#"{{"challenge":"{c}","origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.get","origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}"}}"#),
        "{}".to_owned(),
    ];
    for json in cases {
        assert_refused(&json, &parse_client_data(json.as_bytes()));
    }
}

/// ADR-008: a type, challenge or origin that is not a string is refused.
#[test]
fn adr008_client_data_member_of_wrong_type_refused() {
    let c = b64::url(&CHALLENGE);
    let o = origin_of(HOST);
    let cases = [
        format!(r#"{{"type":["webauthn.get"],"challenge":"{c}","origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":7,"origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":null}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":{{"v":"{c}"}},"origin":"{o}"}}"#),
    ];
    for json in cases {
        assert_refused(&json, &parse_client_data(json.as_bytes()));
    }
}

/// ADR-008, TH-26: a repeated member is refused, so no two readers can
/// see different challenges or origins in the same bytes.
#[test]
fn adr008_client_data_duplicate_member_refused() {
    let c = b64::url(&CHALLENGE);
    let other = b64::url(&[0x51; 32]);
    let o = origin_of(HOST);
    let cases = [
        format!(
            r#"{{"type":"webauthn.get","challenge":"{other}","challenge":"{c}","origin":"{o}"}}"#
        ),
        format!(
            r#"{{"type":"webauthn.get","challenge":"{c}","origin":"https://evil.example","origin":"{o}"}}"#
        ),
        format!(
            r#"{{"type":"webauthn.create","type":"webauthn.get","challenge":"{c}","origin":"{o}"}}"#
        ),
    ];
    for json in cases {
        assert_refused(&json, &parse_client_data(json.as_bytes()));
    }
}

/// TH-26: bytes that are not one UTF-8 JSON object are refused.
#[test]
fn th_26_client_data_not_one_json_object_refused() {
    let good = client_data("webauthn.get", &CHALLENGE, &origin_of(HOST), false);
    let mut trailing = good.clone();
    trailing.extend_from_slice(b"{}");
    let mut bad_utf8 = good.clone();
    bad_utf8.insert(2, 0xff);
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"[]".to_vec(),
        b"\"webauthn.get\"".to_vec(),
        good[..good.len() - 1].to_vec(),
        trailing,
        bad_utf8,
    ];
    for input in cases {
        assert_refused(&String::from_utf8_lossy(&input), &parse_client_data(&input));
    }
}

/// R-LG-01: any challenge bytes and any ASCII host origin come back
/// unchanged.
#[test]
fn r_lg_01_client_data_round_trips_generated_values() {
    check("r_lg_01_client_data_round_trips_generated_values", |g| {
        let challenge = g.bytes(1..=64);
        let host: String = (0..g.usize_in(1..=20))
            .map(|_| char::from(*g.pick(b"abcdefghijklmnopqrstuvwxyz0123456789-.")))
            .collect();
        let origin = format!("https://{host}");
        let kind = *g.pick(&["webauthn.get", "webauthn.create"]);
        let bytes = client_data(kind, &challenge, &origin, g.bool());
        g.note("input", &String::from_utf8_lossy(&bytes));
        prop_assert_eq!(
            parse_client_data(&bytes),
            Ok(want(kind, &challenge, &origin))
        );
        Ok(())
    });
}
