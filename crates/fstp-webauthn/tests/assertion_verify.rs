//! Assertion verification, `fstp_webauthn::verify_assertion` (WebAuthn
//! Level 2 section 7.2, ADR-008, design sections 8.1 and 8.4).
//!
//! `AssertionExpect` fixes the RP id (the exact cell host, I-20), the
//! origin, the challenge, user presence and whether user verification is
//! required. UV is required for every login of an account with holdings
//! (I-77, `authentication.md` "Strong methods") and for every step-up
//! (I-78). The signature is checked through `fstp_crypto::sig` over the
//! authenticator data and the SHA-256 of the client data. The sign count
//! rule is WebAuthn Level 2 section 7.2 step 21: when either count is
//! non-zero, the new count must be greater than the stored one.
//!
//! Each fault test changes one knob of `common::authn::Asn`, the twin of
//! a SoftAuthenticator fault, and first checks that the unchanged
//! ceremony verifies.
//!
//! Gap (lane report): `WebAuthnError` has only `NotImplemented`. A
//! counter regression must be told apart from other refusals, so that
//! `fstp-auth` can record `CredentialSuspect` (ADR-008 "Sign counts").
//! These tests can only check that it is refused.

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
    Asn, CHALLENGE, CRED_ID, HOST, Key, OTHER_CELL, PREVIOUS_CHALLENGE, asn_expect, flags,
    origin_of, stored,
};
use common::{assert_refused, hex, refused, rsa};
use fstp_prop::{check, prop_assert_eq};
use fstp_webauthn::{AssertionOk, CoseKey, StoredCredential, verify_assertion};

/// The stored count of the fault tests. The valid twin asserts one more.
const STORED: u32 = 5;

/// The unchanged ceremony of `key` verifies with UV required.
#[track_caller]
fn control(key: &Key) {
    let asn = Asn::valid(STORED + 1);
    assert_eq!(
        verify_assertion(&asn.signed_by(key), &stored(key, STORED), &asn_expect(true)),
        Ok(AssertionOk {
            sign_count: STORED + 1,
            user_verified: true,
        }),
        "control: the unchanged assertion must verify"
    );
}

/// Checks the control, then refuses `asn` signed by `key`, with UV
/// required as `uv` says.
#[track_caller]
fn refuses(what: &str, key: &Key, asn: &Asn, uv: bool) {
    control(key);
    assert_refused(
        what,
        &verify_assertion(&asn.signed_by(key), &stored(key, STORED), &asn_expect(uv)),
    );
}

/// The stored RS256 credential of the fixed vector.
fn rs256_stored(sign_count: u32) -> StoredCredential {
    StoredCredential {
        id: CRED_ID.to_vec(),
        key: CoseKey::Rs256 {
            n: hex(rsa::N),
            e: rsa::E.to_vec(),
        },
        sign_count,
    }
}

/// The RS256 vector's assertion, checked against its fixed bytes.
fn rs256_assertion() -> Asn {
    let asn = Asn::valid(1);
    assert_eq!(
        asn.auth_data(),
        hex(rsa::AUTH_DATA),
        "vector authenticator data"
    );
    assert_eq!(
        asn.client_data(),
        rsa::CLIENT_DATA.as_bytes(),
        "vector client data"
    );
    asn
}

/// R-LG-01, I-77, I-78: an ES256 passkey assertion with UV verifies and
/// reports its counter and UV.
#[test]
fn r_lg_01_es256_assertion_verifies() {
    control(&Key::es256());
}

/// R-LG-01, I-77, I-78: an Ed25519 passkey assertion with UV verifies and
/// reports its counter and UV.
#[test]
fn r_lg_01_ed25519_assertion_verifies() {
    control(&Key::ed25519(31));
}

/// R-LG-01, ADR-008: an RS256 assertion with a 2048-bit key verifies
/// (fixed synthetic vector, `common::rsa`).
#[test]
fn r_lg_01_rs256_assertion_verifies() {
    let asn = rs256_assertion();
    assert_eq!(
        verify_assertion(
            &asn.with_signature(hex(rsa::SIGNATURE)),
            &rs256_stored(0),
            &asn_expect(true)
        ),
        Ok(AssertionOk {
            sign_count: 1,
            user_verified: true,
        })
    );
}

/// ADR-008: the RS256 vector with one signature bit changed is refused.
#[test]
fn adr008_rs256_bad_signature_refused() {
    let asn = rs256_assertion();
    let mut sig = hex(rsa::SIGNATURE);
    sig[100] ^= 0x01;
    assert_refused(
        "RS256 bit flip",
        &verify_assertion(
            &asn.with_signature(sig),
            &rs256_stored(0),
            &asn_expect(true),
        ),
    );
}

/// I-77, I-78, TH-55, SoftAuthenticator `NoUserVerification`: with UV
/// required, an assertion without the UV flag is refused. Logins of
/// accounts with holdings and every step-up require it.
#[test]
fn i77_i78_assertion_without_uv_refused_when_uv_required() {
    let key = Key::es256();
    let mut asn = Asn::valid(STORED + 1);
    asn.flags = flags::UP;
    refuses("UV clear", &key, &asn, true);
}

/// ADR-008 "User verification": an applicant login that does not require
/// UV verifies without it and reports that UV was not given. With the UV
/// flag it reports that UV was given.
#[test]
fn r_lg_01_assertion_reports_whether_uv_was_given() {
    let key = Key::ed25519(32);
    let mut without = Asn::valid(STORED + 1);
    without.flags = flags::UP;
    assert_eq!(
        verify_assertion(
            &without.signed_by(&key),
            &stored(&key, STORED),
            &asn_expect(false)
        ),
        Ok(AssertionOk {
            sign_count: STORED + 1,
            user_verified: false,
        })
    );
    let with = Asn::valid(STORED + 1);
    assert_eq!(
        verify_assertion(
            &with.signed_by(&key),
            &stored(&key, STORED),
            &asn_expect(false)
        ),
        Ok(AssertionOk {
            sign_count: STORED + 1,
            user_verified: true,
        })
    );
}

/// ADR-008 "user presence": an assertion without UP is refused, whether
/// UV is required or not, and even with UV set.
#[test]
fn adr008_assertion_without_user_presence_refused() {
    let key = Key::ed25519(33);
    for (bits, uv) in [(flags::UV, true), (flags::UV, false), (0, false)] {
        let mut asn = Asn::valid(STORED + 1);
        asn.flags = bits;
        refuses(
            &format!("flags {bits:#04x}, uv required {uv}"),
            &key,
            &asn,
            uv,
        );
    }
}

/// I-20, B11, SoftAuthenticator `WrongOrigin`: client data from any
/// origin but `https://<cell host>` is refused, including another cell
/// and the vault origin.
#[test]
fn i20_assertion_from_another_origin_refused() {
    let key = Key::es256();
    for origin in [
        format!("https://wrong.{HOST}"),
        origin_of(OTHER_CELL),
        format!("https://id.{HOST}"),
        format!("http://{HOST}"),
        format!("https://{HOST}:443"),
        format!("https://{HOST}/"),
        "https://cells.fstp.example".to_owned(),
    ] {
        let mut asn = Asn::valid(STORED + 1);
        asn.origin = origin.clone();
        refuses(&origin, &key, &asn, true);
    }
}

/// I-20, SoftAuthenticator `WrongRpIdHash`: authenticator data for
/// another RP id is refused, including another cell and the parent
/// domain. The signature is valid, so only the hash check can refuse.
#[test]
fn i20_assertion_with_another_rp_id_hash_refused() {
    let key = Key::ed25519(34);
    for host in [
        format!("wrong.{HOST}"),
        OTHER_CELL.to_owned(),
        "cells.fstp.example".to_owned(),
    ] {
        let mut asn = Asn::valid(STORED + 1);
        asn.rp_hash_host = host.clone();
        refuses(&host, &key, &asn, true);
    }
}

/// ADR-008 "Challenges", SoftAuthenticator `ReplayedChallenge`: client
/// data carrying the previous challenge is refused. Single use across
/// requests is held by `fstp-auth` and `auth_log`.
#[test]
fn adr008_assertion_with_replayed_challenge_refused() {
    let key = Key::es256();
    let mut asn = Asn::valid(STORED + 1);
    asn.challenge = PREVIOUS_CHALLENGE;
    refuses("replayed challenge", &key, &asn, true);
}

/// I-78: a step-up challenge is bound to one action digest, so an
/// assertion over a challenge that differs in one bit is refused.
#[test]
fn i78_assertion_over_another_challenge_refused() {
    let key = Key::ed25519(35);
    let mut flipped = CHALLENGE;
    flipped[0] ^= 0x80;
    let mut asn = Asn::valid(STORED + 1);
    asn.challenge = flipped;
    refuses("one-bit challenge change", &key, &asn, true);
}

/// ADR-008: an assertion needs client data of type `webauthn.get`.
#[test]
fn adr008_assertion_with_another_type_refused() {
    let key = Key::ed25519(36);
    for kind in ["webauthn.create", "webauthn.get ", "payment.get"] {
        let mut asn = Asn::valid(STORED + 1);
        asn.kind = kind.to_owned();
        refuses(kind, &key, &asn, true);
    }
}

/// ADR-008 "Sign counts", SoftAuthenticator `CounterRegression`: with a
/// stored count above zero, a count below it, equal to it, or zero is
/// refused.
#[test]
fn adr008_sign_count_regression_refused() {
    let key = Key::es256();
    for counter in [STORED - 1, STORED, 0] {
        let mut asn = Asn::valid(STORED + 1);
        asn.counter = counter;
        refuses(
            &format!("counter {counter} after {STORED}"),
            &key,
            &asn,
            true,
        );
    }
}

/// ADR-008 "Sign counts": an authenticator without a counter reports 0
/// every time, and 0 after a stored 0 verifies.
#[test]
fn adr008_sign_count_zero_after_zero_accepted() {
    let key = Key::ed25519(37);
    let asn = Asn::valid(0);
    assert_eq!(
        verify_assertion(&asn.signed_by(&key), &stored(&key, 0), &asn_expect(true)),
        Ok(AssertionOk {
            sign_count: 0,
            user_verified: true,
        })
    );
}

/// ADR-008 "Sign counts": over every pair of stored and asserted counts,
/// the assertion verifies exactly when both are zero or the new count is
/// greater, and then reports the new count.
#[test]
fn adr008_sign_count_rule_matches_webauthn_step_21() {
    let key = Key::ed25519(38);
    check("adr008_sign_count_rule_matches_webauthn_step_21", |g| {
        let old = g.u32();
        let new = if g.bool() {
            g.u32()
        } else {
            old.saturating_add(g.u32_in(0..=2)).saturating_sub(1)
        };
        g.note("stored, asserted", &(old, new));
        let got = verify_assertion(
            &Asn::valid(new).signed_by(&key),
            &stored(&key, old),
            &asn_expect(true),
        );
        if (old == 0 && new == 0) || new > old {
            prop_assert_eq!(
                got,
                Ok(AssertionOk {
                    sign_count: new,
                    user_verified: true,
                })
            );
            Ok(())
        } else {
            refused(&format!("count {new} after {old}"), &got)
        }
    });
}

/// ADR-008: a bad signature is refused: one flipped bit, empty,
/// truncated, by another key of the same algorithm, or over the
/// authenticator data alone.
#[test]
fn adr008_assertion_bad_signature_refused() {
    for key in [Key::es256(), Key::ed25519(39)] {
        control(&key);
        let asn = Asn::valid(STORED + 1);
        let good = key.sign(&asn.message());
        let mut flipped = good.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x01;
        let other = match key {
            Key::Es256(_) => Key::es256(),
            Key::Ed25519(_) => Key::ed25519(40),
        };
        let cases = [
            ("flipped bit", flipped),
            ("empty", Vec::new()),
            ("truncated", good[..good.len() - 1].to_vec()),
            ("another key", other.sign(&asn.message())),
            ("authenticator data only", key.sign(&asn.auth_data())),
        ];
        for (what, sig) in cases {
            assert_refused(
                what,
                &verify_assertion(
                    &asn.with_signature(sig),
                    &stored(&key, STORED),
                    &asn_expect(true),
                ),
            );
        }
    }
}

/// ADR-008 (the wrong-algorithm fault): a signature of another algorithm
/// than the stored credential's is refused, in each direction.
#[test]
fn adr008_assertion_with_wrong_algorithm_refused() {
    let es = Key::es256();
    let ed = Key::ed25519(41);
    control(&es);
    control(&ed);
    let asn = Asn::valid(STORED + 1);
    assert_refused(
        "Ed25519 signature for an ES256 credential",
        &verify_assertion(&asn.signed_by(&ed), &stored(&es, STORED), &asn_expect(true)),
    );
    assert_refused(
        "ES256 signature for an Ed25519 credential",
        &verify_assertion(&asn.signed_by(&es), &stored(&ed, STORED), &asn_expect(true)),
    );
    assert_refused(
        "Ed25519 signature for an RS256 credential",
        &verify_assertion(
            &asn.signed_by(&ed),
            &rs256_stored(STORED),
            &asn_expect(true),
        ),
    );
}

/// ADR-008: an assertion that names another credential id than the
/// stored credential is refused.
#[test]
fn adr008_assertion_for_another_credential_refused() {
    let key = Key::es256();
    let mut asn = Asn::valid(STORED + 1);
    asn.credential_id = vec![0xc2; 32];
    refuses("another credential id", &key, &asn, true);
}

/// ADR-008, strict reading (lane report): client data with `crossOrigin`
/// true is refused.
#[test]
fn adr008_assertion_cross_origin_refused() {
    let key = Key::ed25519(42);
    let mut asn = Asn::valid(STORED + 1);
    asn.cross_origin = true;
    refuses("crossOrigin true", &key, &asn, true);
}

/// TH-26: authenticator data that does not parse is refused even when
/// the signature covers it.
#[test]
fn th_26_assertion_with_unparsable_auth_data_refused() {
    let key = Key::ed25519(43);
    control(&key);
    let asn = Asn::valid(STORED + 1);
    let cd = asn.client_data();
    for ad in [
        asn.auth_data()[..36].to_vec(),
        [asn.auth_data(), vec![0x00]].concat(),
    ] {
        let mut m = ad.clone();
        m.extend_from_slice(&fstp_crypto::sha256(&cd));
        let resp = fstp_webauthn::AssertionResponse {
            credential_id: CRED_ID.to_vec(),
            client_data_json: cd.clone(),
            authenticator_data: ad.clone(),
            signature: key.sign(&m),
        };
        assert_refused(
            &format!("{} bytes", ad.len()),
            &verify_assertion(&resp, &stored(&key, STORED), &asn_expect(true)),
        );
    }
}

/// Design section 15, TH-26: one changed byte of the authenticator data,
/// the client data or the signature never verifies (Ed25519).
#[test]
fn th_26_assertion_mutation_of_a_signed_byte_never_verifies_ed25519() {
    let key = Key::ed25519(44);
    let base = Asn::valid(STORED + 1).signed_by(&key);
    let cred = stored(&key, STORED);
    check(
        "th_26_assertion_mutation_of_a_signed_byte_never_verifies_ed25519",
        |g| {
            let mut resp = base.clone();
            let target = match g.u8_in(0..=2) {
                0 => &mut resp.authenticator_data,
                1 => &mut resp.client_data_json,
                _ => &mut resp.signature,
            };
            let at = g.usize_in(0..=target.len() - 1);
            target[at] ^= g.u8_in(1..=255);
            g.note("response", &resp);
            refused(
                "mutated assertion",
                &verify_assertion(&resp, &cred, &asn_expect(true)),
            )
        },
    );
}

/// Design section 15, TH-26: one changed byte of the authenticator data,
/// the client data or the signature never verifies (ES256).
#[test]
fn th_26_assertion_mutation_of_a_signed_byte_never_verifies_es256() {
    let key = Key::es256();
    let base = Asn::valid(STORED + 1).signed_by(&key);
    let cred = stored(&key, STORED);
    check(
        "th_26_assertion_mutation_of_a_signed_byte_never_verifies_es256",
        |g| {
            let mut resp = base.clone();
            let target = match g.u8_in(0..=2) {
                0 => &mut resp.authenticator_data,
                1 => &mut resp.client_data_json,
                _ => &mut resp.signature,
            };
            let at = g.usize_in(0..=target.len() - 1);
            target[at] ^= g.u8_in(1..=255);
            g.note("response", &resp);
            refused(
                "mutated assertion",
                &verify_assertion(&resp, &cred, &asn_expect(true)),
            )
        },
    );
}
