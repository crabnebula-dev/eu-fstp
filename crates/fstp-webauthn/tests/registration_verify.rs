//! Registration verification, `fstp_webauthn::verify_registration`
//! (WebAuthn Level 2 section 7.1, ADR-008, design sections 8.1 and 8.3).
//!
//! `RegistrationExpect` fixes the RP id (the exact cell host, I-20), the
//! origin, the challenge and user presence. The attestation format is
//! `none` and the key must be of an admitted algorithm.
//!
//! Each fault test changes one knob of `common::authn::Reg`, the
//! registration twin of the `fstp-celltest` SoftAuthenticator faults. It
//! first checks that the unchanged ceremony verifies, so a refusal cannot
//! come from a broken fixture.
//!
//! `RegistrationExpect` also fixes user verification, and `NewCredential`
//! reports whether UV was given. ADR-008 says applicant passkeys request
//! UV and the cell records whether it was given, and an account with
//! holdings needs UV.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::authn::{
    CHALLENGE, CRED_ID, HOST, Key, OTHER_CELL, PREVIOUS_CHALLENGE, Reg, auth_data, flags,
    none_attestation, origin_of, reg_expect, reg_expect_uv, rs256_cose,
};
use common::{assert_refused, cbor, hex, refused, rsa};
use fstp_prop::{check, prop_assert, prop_assert_eq};
use fstp_webauthn::{
    CoseKey, NewCredential, RegistrationResponse, WebAuthnError, parse_attestation_object,
    parse_client_data, verify_registration,
};

/// The unchanged ceremony of `key` verifies to its credential.
#[track_caller]
fn control(key: &Key) {
    assert_eq!(
        verify_registration(&Reg::valid(key).response(), &reg_expect()),
        Ok(NewCredential {
            id: CRED_ID.to_vec(),
            key: key.expected(),
            sign_count: 0,
            user_verified: true,
        }),
        "control: the unchanged registration must verify"
    );
}

/// Checks the control, then refuses `reg`.
#[track_caller]
fn refuses(what: &str, key: &Key, reg: &Reg) {
    control(key);
    assert_refused(what, &verify_registration(&reg.response(), &reg_expect()));
}

/// R-LG-01, ADR-008: an ES256 passkey registers, with its id, key and
/// counter.
#[test]
fn r_lg_01_es256_registration_verifies() {
    control(&Key::es256());
}

/// R-LG-01, ADR-008: an Ed25519 passkey registers, with its id, key and
/// counter.
#[test]
fn r_lg_01_ed25519_registration_verifies() {
    control(&Key::ed25519(21));
}

/// R-LG-01, ADR-008: an RS256 passkey with a 2048-bit modulus registers.
#[test]
fn r_lg_01_rs256_registration_verifies() {
    let mut reg = Reg::valid(&Key::ed25519(22));
    reg.cose = rs256_cose(&hex(rsa::N), &rsa::E);
    assert_eq!(
        verify_registration(&reg.response(), &reg_expect()),
        Ok(NewCredential {
            id: CRED_ID.to_vec(),
            key: CoseKey::Rs256 {
                n: hex(rsa::N),
                e: rsa::E.to_vec(),
            },
            sign_count: 0,
            user_verified: true,
        })
    );
}

/// ADR-008 "Expectations" and "User verification", I-77: when the
/// ceremony requires UV, a registration with UV clear is refused as
/// `UserVerification`, and one with UV set verifies as verified.
#[test]
fn adr008_registration_without_uv_refused_when_required() {
    let key = Key::ed25519(30);
    let mut reg = Reg::valid(&key);
    assert_eq!(
        verify_registration(&reg.response(), &reg_expect_uv(true)).map(|c| c.user_verified),
        Ok(true),
        "control: a registration with UV meets the requirement"
    );
    reg.flags = flags::UP | flags::AT;
    assert_eq!(
        verify_registration(&reg.response(), &reg_expect_uv(true)),
        Err(WebAuthnError::UserVerification)
    );
}

/// ADR-008 "User verification": when UV is only requested, a
/// registration with UV clear verifies and is reported as not verified,
/// so the cell can record it.
#[test]
fn adr008_registration_without_uv_reported_as_not_verified() {
    let key = Key::ed25519(31);
    let mut reg = Reg::valid(&key);
    reg.flags = flags::UP | flags::AT;
    assert_eq!(
        verify_registration(&reg.response(), &reg_expect()),
        Ok(NewCredential {
            id: CRED_ID.to_vec(),
            key: key.expected(),
            sign_count: 0,
            user_verified: false,
        })
    );
}

/// ADR-008 "Sign counts": a registration reports the counter the
/// authenticator sent, which later assertions are compared against.
#[test]
fn adr008_registration_reports_its_counter() {
    let key = Key::ed25519(23);
    let mut reg = Reg::valid(&key);
    reg.counter = 7;
    assert_eq!(
        verify_registration(&reg.response(), &reg_expect()).map(|c| c.sign_count),
        Ok(7)
    );
}

/// I-20, B11, SoftAuthenticator `WrongOrigin`: client data from any
/// origin but `https://<cell host>` is refused. That covers another cell,
/// the vault origin (ADR-008), plain HTTP, an explicit port, a path and
/// other spellings.
#[test]
fn i20_registration_from_another_origin_refused() {
    let key = Key::es256();
    for origin in [
        format!("https://wrong.{HOST}"),
        origin_of(OTHER_CELL),
        format!("https://id.{HOST}"),
        format!("http://{HOST}"),
        format!("https://{HOST}:443"),
        format!("https://{HOST}/"),
        format!("https://{}", HOST.to_uppercase()),
        "https://cells.fstp.example".to_owned(),
        "null".to_owned(),
    ] {
        let mut reg = Reg::valid(&key);
        reg.origin = origin.clone();
        refuses(&origin, &key, &reg);
    }
}

/// I-20, SoftAuthenticator `WrongRpIdHash`: authenticator data for
/// another RP id is refused, including another cell and the parent
/// domain of the cell host.
#[test]
fn i20_registration_with_another_rp_id_hash_refused() {
    let key = Key::ed25519(24);
    for host in [
        format!("wrong.{HOST}"),
        OTHER_CELL.to_owned(),
        "cells.fstp.example".to_owned(),
        "fstp.example".to_owned(),
    ] {
        let mut reg = Reg::valid(&key);
        reg.rp_hash_host = host.clone();
        refuses(&host, &key, &reg);
    }
}

/// ADR-008 "Challenges", SoftAuthenticator `ReplayedChallenge`: client
/// data carrying an earlier challenge, or any other, is refused.
#[test]
fn adr008_registration_with_another_challenge_refused() {
    let key = Key::es256();
    let mut flipped = CHALLENGE;
    flipped[31] ^= 0x01;
    for challenge in [PREVIOUS_CHALLENGE, flipped, [0; 32]] {
        let mut reg = Reg::valid(&key);
        reg.challenge = challenge;
        refuses(&format!("challenge {challenge:02x?}"), &key, &reg);
    }
}

/// ADR-008: a registration needs client data of type `webauthn.create`.
#[test]
fn adr008_registration_with_another_type_refused() {
    let key = Key::ed25519(25);
    for kind in [
        "webauthn.get",
        "webauthn.create ",
        "WebAuthn.create",
        "payment.get",
        "",
    ] {
        let mut reg = Reg::valid(&key);
        reg.kind = kind.to_owned();
        refuses(kind, &key, &reg);
    }
}

/// ADR-008 "user presence": a registration without the UP flag is
/// refused, with or without UV.
#[test]
fn adr008_registration_without_user_presence_refused() {
    let key = Key::es256();
    for bits in [flags::UV | flags::AT, flags::AT] {
        let mut reg = Reg::valid(&key);
        reg.flags = bits;
        refuses(&format!("flags {bits:#04x}"), &key, &reg);
    }
}

/// ADR-008: a registration needs attested credential data. AT clear with
/// the data present, and AT clear with no data, are refused.
#[test]
fn adr008_registration_without_attested_credential_refused() {
    let key = Key::ed25519(26);
    let mut reg = Reg::valid(&key);
    reg.flags = flags::UP | flags::UV;
    refuses("AT clear, data present", &key, &reg);
    let bare = auth_data(HOST, flags::UP | flags::UV, 0, None);
    let resp = RegistrationResponse {
        client_data_json: Reg::valid(&key).client_data(),
        attestation_object: none_attestation(&bare),
    };
    assert_refused(
        "no credential data",
        &verify_registration(&resp, &reg_expect()),
    );
}

/// ADR-008 "Attestation": a `packed` registration is refused, even with a
/// well-formed statement.
#[test]
fn adr008_registration_with_attestation_other_than_none_refused() {
    let key = Key::es256();
    let mut reg = Reg::valid(&key);
    reg.fmt = "packed".to_owned();
    reg.att_stmt = cbor::map(&[
        (cbor::text("alg"), cbor::int(-7)),
        (cbor::text("sig"), cbor::bytes(&[0x30, 0x00])),
    ]);
    refuses("packed", &key, &reg);
    let mut stmt = Reg::valid(&key);
    stmt.att_stmt = cbor::map(&[(cbor::text("alg"), cbor::int(-7))]);
    refuses("none with a statement", &key, &stmt);
}

/// ADR-008 "Algorithms" (the wrong-algorithm fault): a credential key of
/// an algorithm outside ES256, EdDSA and RS256 of 2048 bits is refused.
#[test]
fn adr008_registration_with_key_outside_the_allowlist_refused() {
    let key = Key::es256();
    let (x, y) = key.point();
    let es384 = cbor::map(&[
        (cbor::int(1), cbor::int(2)),
        (cbor::int(3), cbor::int(-35)),
        (cbor::int(-1), cbor::int(2)),
        (cbor::int(-2), cbor::bytes(&x)),
        (cbor::int(-3), cbor::bytes(&y)),
    ]);
    let ec2_eddsa = cbor::map(&[
        (cbor::int(1), cbor::int(2)),
        (cbor::int(3), cbor::int(-8)),
        (cbor::int(-1), cbor::int(1)),
        (cbor::int(-2), cbor::bytes(&x)),
        (cbor::int(-3), cbor::bytes(&y)),
    ]);
    let rsa1024 = rs256_cose(&hex(rsa::N)[..128], &rsa::E);
    for (what, cose) in [
        ("ES384", es384),
        ("EC2 with EdDSA", ec2_eddsa),
        ("RS256 of 1024 bits", rsa1024),
    ] {
        let mut reg = Reg::valid(&key);
        reg.cose = cose;
        refuses(what, &key, &reg);
    }
}

/// ADR-008, strict reading (lane report): client data with `crossOrigin`
/// true is refused, since the cell pages never embed a ceremony in
/// another origin's frame.
#[test]
fn adr008_registration_cross_origin_refused() {
    let key = Key::ed25519(27);
    let mut reg = Reg::valid(&key);
    reg.cross_origin = true;
    refuses("crossOrigin true", &key, &reg);
}

/// ADR-008: a credential id over 1023 bytes is refused.
#[test]
fn adr008_registration_with_overlong_credential_id_refused() {
    let key = Key::es256();
    let mut reg = Reg::valid(&key);
    reg.credential_id = vec![0xc1; 1024];
    refuses("1024-byte id", &key, &reg);
}

/// R-LG-01, ADR-008: the registration returns the attested credential id
/// and key, and substitutes no other.
#[test]
fn r_lg_01_registration_returns_the_attested_key_and_id() {
    let key = Key::ed25519(28);
    let mut reg = Reg::valid(&key);
    reg.credential_id = vec![0x5a; 64];
    let got = verify_registration(&reg.response(), &reg_expect()).expect("verifies");
    assert_eq!(got.id, vec![0x5a; 64]);
    assert_eq!(got.key, key.expected());
}

/// TH-26: one changed byte of the client data or the attestation object
/// never yields a credential for another type, challenge, origin or RP
/// id, or without user presence.
#[test]
fn th_26_registration_mutation_never_widens_acceptance() {
    let key = Key::ed25519(29);
    let base = Reg::valid(&key).response();
    check("th_26_registration_mutation_never_widens_acceptance", |g| {
        let mut resp = base.clone();
        let target = if g.bool() {
            &mut resp.client_data_json
        } else {
            &mut resp.attestation_object
        };
        let at = g.usize_in(0..=target.len() - 1);
        target[at] ^= g.u8_in(1..=255);
        g.note("response", &resp);
        match verify_registration(&resp, &reg_expect()) {
            Ok(_) => {
                let cd = parse_client_data(&resp.client_data_json);
                let ao = parse_attestation_object(&resp.attestation_object);
                prop_assert!(cd.is_ok() && ao.is_ok(), "accepted unparsable parts");
                let (cd, ao) = (cd.unwrap(), ao.unwrap());
                prop_assert_eq!(cd.kind, "webauthn.create");
                prop_assert_eq!(cd.challenge, CHALLENGE.to_vec());
                prop_assert_eq!(cd.origin, origin_of(HOST));
                prop_assert_eq!(
                    ao.auth_data.rp_id_hash,
                    fstp_crypto::sha256(HOST.as_bytes())
                );
                prop_assert!(ao.auth_data.flags & flags::UP != 0, "accepted without UP");
                Ok(())
            }
            other => refused("mutated registration", &other),
        }
    });
}
