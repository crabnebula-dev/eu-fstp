//! Attestation objects, `fstp_webauthn::parse_attestation_object`
//! (WebAuthn Level 2 section 6.5, ADR-008 "Attestation", design section
//! 8.1, TH-26).
//!
//! ADR-008 admits the format `none` only, and no attestation statement is
//! parsed or trusted. So `attStmt` must be the empty map. The object is a
//! strict CBOR map of exactly `fmt`, `attStmt` and `authData`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::authn::{Attested, HOST, Key, attestation_object, auth_data, flags, none_attestation};
use common::{assert_refused, cbor, refused};
use fstp_prop::{check, prop_assert, prop_assert_eq};
use fstp_webauthn::cbor::{Item, decode};
use fstp_webauthn::{AttestationObject, parse_attestation_object, parse_authenticator_data};

/// Registration authenticator data for an Ed25519 credential.
fn reg_auth_data() -> Vec<u8> {
    let cose = Key::ed25519(11).cose();
    let a = Attested {
        aaguid: [0; 16],
        id: &[0xc1; 16],
        cose: &cose,
    };
    auth_data(HOST, flags::UP | flags::UV | flags::AT, 0, Some(&a))
}

/// R-LG-01, ADR-008: a `none` attestation object decodes, and its
/// authenticator data is what `parse_authenticator_data` reports.
#[test]
fn adr008_none_attestation_object_decodes() {
    let ad = reg_auth_data();
    let want = AttestationObject {
        auth_data: parse_authenticator_data(&ad).expect("authenticator data"),
    };
    assert_eq!(parse_attestation_object(&none_attestation(&ad)), Ok(want));
}

/// ADR-008 "Attestation": every format other than `none` is refused,
/// including other spellings of `none`.
#[test]
fn adr008_attestation_format_other_than_none_refused() {
    let ad = reg_auth_data();
    let stmt = cbor::map(&[]);
    for fmt in [
        "packed",
        "fido-u2f",
        "tpm",
        "android-key",
        "android-safetynet",
        "apple",
        "None",
        "none ",
        "",
    ] {
        assert_refused(
            fmt,
            &parse_attestation_object(&attestation_object(fmt, &stmt, &ad)),
        );
    }
}

/// ADR-008 "No attestation statement is parsed or trusted": a `none`
/// object whose `attStmt` is not the empty map is refused.
#[test]
fn adr008_none_attestation_with_a_statement_refused() {
    let ad = reg_auth_data();
    let stmts = [
        cbor::map(&[(cbor::text("alg"), cbor::int(-7))]),
        cbor::map(&[(cbor::text("sig"), cbor::bytes(&[1, 2, 3]))]),
        cbor::array(&[]),
        cbor::bytes(&[]),
    ];
    for stmt in stmts {
        assert_refused(
            &format!("attStmt {stmt:02x?}"),
            &parse_attestation_object(&attestation_object("none", &stmt, &ad)),
        );
    }
}

/// ADR-008: a missing member, or a member other than `fmt`, `attStmt` and
/// `authData`, is refused.
#[test]
fn adr008_attestation_object_members_are_exact() {
    let ad = cbor::bytes(&reg_auth_data());
    let fmt = (cbor::text("fmt"), cbor::text("none"));
    let stmt = (cbor::text("attStmt"), cbor::map(&[]));
    let data = (cbor::text("authData"), ad);
    let cases = [
        cbor::map(&[stmt.clone(), data.clone()]),
        cbor::map(&[fmt.clone(), data.clone()]),
        cbor::map(&[fmt.clone(), stmt.clone()]),
        cbor::map(&[
            (cbor::text("ep"), cbor::int(1)),
            fmt.clone(),
            stmt.clone(),
            data.clone(),
        ]),
        cbor::map(&[
            fmt.clone(),
            stmt.clone(),
            data.clone(),
            (cbor::text("largeBlobKey"), cbor::bytes(&[0; 32])),
        ]),
        cbor::map(&[
            (cbor::int(1), cbor::text("none")),
            (cbor::int(2), cbor::map(&[])),
            (cbor::int(3), cbor::bytes(&reg_auth_data())),
        ]),
    ];
    for input in cases {
        assert_refused(&format!("{input:02x?}"), &parse_attestation_object(&input));
    }
}

/// ADR-008: members of the wrong CBOR type are refused: `authData` as
/// text, `fmt` as bytes, and an array in place of the map.
#[test]
fn adr008_attestation_object_member_of_wrong_type_refused() {
    let ad = reg_auth_data();
    let text_auth = cbor::map(&[
        (cbor::text("fmt"), cbor::text("none")),
        (cbor::text("attStmt"), cbor::map(&[])),
        (cbor::text("authData"), cbor::text("x")),
    ]);
    let bytes_fmt = cbor::map(&[
        (cbor::text("fmt"), cbor::bytes(b"none")),
        (cbor::text("attStmt"), cbor::map(&[])),
        (cbor::text("authData"), cbor::bytes(&ad)),
    ]);
    let array = cbor::array(&[cbor::text("none"), cbor::map(&[]), cbor::bytes(&ad)]);
    for (what, input) in [
        ("text authData", text_auth),
        ("bytes fmt", bytes_fmt),
        ("array", array),
    ] {
        assert_refused(what, &parse_attestation_object(&input));
    }
}

/// ADR-008: the authenticator data inside must itself be valid. A short
/// one and one with a trailing byte are refused.
#[test]
fn adr008_attestation_object_auth_data_must_parse() {
    let ad = reg_auth_data();
    assert_refused(
        "36 bytes",
        &parse_attestation_object(&none_attestation(&ad[..36])),
    );
    let mut long = ad.clone();
    long.push(0x00);
    assert_refused(
        "a trailing byte",
        &parse_attestation_object(&none_attestation(&long)),
    );
}

/// ADR-008: the strict CBOR rules hold for the object. A duplicate `fmt`,
/// a non-shortest head, an indefinite map and a trailing byte are refused.
#[test]
fn adr008_attestation_object_cbor_rules_apply() {
    let ad = reg_auth_data();
    let good = none_attestation(&ad);
    let duplicate = cbor::map(&[
        (cbor::text("fmt"), cbor::text("packed")),
        (cbor::text("fmt"), cbor::text("none")),
        (cbor::text("attStmt"), cbor::map(&[])),
        (cbor::text("authData"), cbor::bytes(&ad)),
    ]);
    let mut wide = good.clone();
    assert_eq!(wide[0], 0xa3);
    wide.splice(0..1, [0xb8, 0x03]);
    let mut indefinite = good.clone();
    indefinite[0] = 0xbf;
    indefinite.push(0xff);
    let mut trailing = good.clone();
    trailing.push(0x00);
    for (what, input) in [
        ("duplicate fmt", duplicate),
        ("non-shortest map head", wide),
        ("indefinite map", indefinite),
        ("trailing byte", trailing),
    ] {
        assert_refused(what, &parse_attestation_object(&input));
    }
}

/// TH-26: one changed byte of a valid object is either refused for a
/// real reason, or decodes to the authenticator data that the object's
/// own `authData` member holds.
#[test]
fn th_26_attestation_object_mutation_is_refused_or_consistent() {
    let base = none_attestation(&reg_auth_data());
    check(
        "th_26_attestation_object_mutation_is_refused_or_consistent",
        |g| {
            let mut input = base.clone();
            let at = g.usize_in(0..=input.len() - 1);
            input[at] ^= g.u8_in(1..=255);
            g.note("input", &input);
            match parse_attestation_object(&input) {
                Ok(obj) => {
                    let Ok(Item::Map(pairs)) = decode(&input) else {
                        return Err("accepted bytes that are not one strict CBOR map".to_owned());
                    };
                    let ad = pairs.iter().find_map(|(k, v)| match (k, v) {
                        (Item::Text(k), Item::Bytes(b)) if k == "authData" => Some(b.clone()),
                        _ => None,
                    });
                    prop_assert!(ad.is_some(), "accepted an object without authData bytes");
                    let ad = ad.unwrap_or_default();
                    prop_assert_eq!(parse_authenticator_data(&ad), Ok(obj.auth_data));
                    Ok(())
                }
                other => refused("mutated attestation object", &other),
            }
        },
    );
}
