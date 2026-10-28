//! Proof of possession over an SPKI digest (design sections 1.3 and 9.1,
//! ADR-005 "Role certificates", ADR-009 "Certificate authorities").
//!
//! A component sends its public key with a signature over a fresh
//! challenge, and no certificate request is parsed. `RoleCredential` and
//! `CertRenewal` carry the SPKI as a SHA-256 digest. The signed bytes are
//! the reference layout of `common::pop`. A forged or mismatched proof
//! must be refused by real code, never by the W0 stub.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::keys::{ED25519_ZERO_SPKI, EcKey};
use common::pop::{Ctx, PURPOSE_CERT_RENEWAL, pop_message};
use fstp_pki::PkiError;
use fstp_pki::pop::{ProofOfPossession, message, verify};
use fstp_prop::{Config, check_with, prop_assert};

const CHALLENGE: [u8; 32] = [0x5a; 32];

/// The cell the requests are for.
const CELL_ID: [u8; 16] = [0x01; 16];

const ROLE: &str = "c_0123456789abcdef0123456789abcdef_app";

/// The context of a `RoleCredential` for [`ROLE`] (design section 9.1).
fn ctx() -> Ctx {
    Ctx::role(CELL_ID, ROLE)
}

/// Verifies `p` for the context [`ctx`] against the issuer's challenge
/// [`CHALLENGE`].
fn check(p: &ProofOfPossession) -> Result<(), PkiError> {
    verify(p, &ctx().to_pki(), &CHALLENGE)
}

fn proof(key: &EcKey, challenge: [u8; 32]) -> ProofOfPossession {
    let spki_der = key.spki_der();
    let signature = key.sign(&pop_message(&spki_der, &ctx(), &challenge));
    ProofOfPossession {
        spki_der,
        signature,
    }
}

fn refused(r: &Result<(), PkiError>) -> bool {
    common::profile::real_pki_refusal(r)
}

/// ADR-005: a proof signed by the SPKI's own key over the reference
/// message for that SPKI and challenge is accepted.
#[test]
fn adr005_pop_valid_proof_is_accepted() {
    let key = EcKey::generate();
    let r = check(&proof(&key, CHALLENGE));
    assert!(r.is_ok(), "{r:?}");
}

/// ADR-005: a signature over another challenge is refused, so an old proof
/// cannot answer a fresh challenge.
#[test]
fn adr005_pop_signature_over_another_challenge_is_refused() {
    let key = EcKey::generate();
    let p = proof(&key, [0x01; 32]);
    let r = check(&p);
    assert!(refused(&r), "{r:?}");
}

/// ADR-005: a signature by another key over the message for this SPKI is
/// refused. Only the holder of the private key can prove possession.
#[test]
fn adr005_pop_signature_by_another_key_is_refused() {
    let key = EcKey::generate();
    let other = EcKey::generate();
    let spki_der = key.spki_der();
    let p = ProofOfPossession {
        signature: other.sign(&pop_message(&spki_der, &ctx(), &CHALLENGE)),
        spki_der,
    };
    let r = check(&p);
    assert!(refused(&r), "{r:?}");
}

/// Design section 9.1: a valid proof for one SPKI, moved onto another
/// SPKI, is refused. The SPKI digest is part of the signed message.
#[test]
fn adr005_pop_proof_moved_to_another_spki_is_refused() {
    let key = EcKey::generate();
    let other = EcKey::generate();
    let mut p = proof(&key, CHALLENGE);
    p.spki_der = other.spki_der();
    let r = check(&p);
    assert!(refused(&r), "{r:?}");
}

/// Design section 9.1: a signature by the right key over the digest and
/// the challenge, without the domain prefix, is refused. A signature made
/// for another purpose never passes as a proof of possession.
#[test]
fn adr005_pop_signature_without_the_domain_prefix_is_refused() {
    let key = EcKey::generate();
    let spki_der = key.spki_der();
    let mut msg = fstp_crypto::sha256(&spki_der).to_vec();
    msg.extend_from_slice(&CHALLENGE);
    let p = ProofOfPossession {
        signature: key.sign(&msg),
        spki_der,
    };
    let r = check(&p);
    assert!(refused(&r), "{r:?}");
}

/// Design section 9.1: a signature by the right key over the bare
/// challenge is refused, since it binds no SPKI digest.
#[test]
fn adr005_pop_signature_over_the_bare_challenge_is_refused() {
    let key = EcKey::generate();
    let p = ProofOfPossession {
        signature: key.sign(&CHALLENGE),
        spki_der: key.spki_der(),
    };
    let r = check(&p);
    assert!(refused(&r), "{r:?}");
}

/// ADR-005: flipping any one bit of a valid signature gives a refusal.
#[test]
fn adr005_pop_any_flipped_signature_bit_is_refused() {
    let key = EcKey::generate();
    let good = proof(&key, CHALLENGE);
    check_with(
        "adr005_pop_any_flipped_signature_bit_is_refused",
        Config::default().with_cases(256),
        |g| {
            let bit = g.usize_in(0..=good.signature.len() * 8 - 1);
            g.note("bit", &bit);
            let mut p = good.clone();
            p.signature[bit / 8] ^= 1 << (bit % 8);
            let r = check(&p);
            prop_assert!(refused(&r), "a flipped bit was not refused: {r:?}");
            Ok(())
        },
    );
}

/// ADR-005: flipping any one bit of the challenge gives a refusal.
#[test]
fn adr005_pop_any_flipped_challenge_bit_is_refused() {
    let key = EcKey::generate();
    let good = proof(&key, CHALLENGE);
    check_with(
        "adr005_pop_any_flipped_challenge_bit_is_refused",
        Config::default().with_cases(256),
        |g| {
            let bit = g.usize_in(0..=255);
            g.note("bit", &bit);
            let mut issued = CHALLENGE;
            issued[bit / 8] ^= 1 << (bit % 8);
            let r = verify(&good, &ctx().to_pki(), &issued);
            prop_assert!(refused(&r), "a flipped bit was not refused: {r:?}");
            Ok(())
        },
    );
}

/// ADR-005: empty and truncated signatures are refused.
#[test]
fn adr005_pop_empty_or_truncated_signature_is_refused() {
    let key = EcKey::generate();
    let good = proof(&key, CHALLENGE);
    for len in [0, 1, good.signature.len() - 1] {
        let mut p = good.clone();
        p.signature.truncate(len);
        let r = check(&p);
        assert!(refused(&r), "length {len}: {r:?}");
    }
}

/// ADR-005: a valid signature followed by one more byte is refused.
#[test]
fn adr005_pop_signature_with_trailing_bytes_is_refused() {
    let key = EcKey::generate();
    let mut p = proof(&key, CHALLENGE);
    p.signature.push(0);
    let r = check(&p);
    assert!(refused(&r), "{r:?}");
}

/// Design section 1.3: every component key is EC secp256r1, so a proof
/// over an SPKI of another algorithm is refused.
#[test]
fn adr005_pop_over_a_non_p256_spki_is_refused() {
    let key = EcKey::generate();
    let spki_der = ED25519_ZERO_SPKI.to_vec();
    let p = ProofOfPossession {
        signature: key.sign(&pop_message(&spki_der, &ctx(), &CHALLENGE)),
        spki_der,
    };
    let r = check(&p);
    assert!(refused(&r), "{r:?}");
}

/// ADR-005: an SPKI with one more byte after it is refused, even with a
/// signature over the message for those exact bytes.
#[test]
fn adr005_pop_over_an_spki_with_trailing_bytes_is_refused() {
    let key = EcKey::generate();
    let mut spki_der = key.spki_der();
    spki_der.push(0);
    let p = ProofOfPossession {
        signature: key.sign(&pop_message(&spki_der, &ctx(), &CHALLENGE)),
        spki_der,
    };
    let r = check(&p);
    assert!(refused(&r), "{r:?}");
}

/// Design section 9.1: `fstp_pki::pop::message` writes the reference
/// layout of `common::pop` for every context and challenge, so the
/// signed bytes bind the purpose, the scope, the name, the SPKI digest
/// and the challenge.
#[test]
fn adr005_pop_message_equals_the_reference_layout() {
    let spki_der = EcKey::generate().spki_der();
    check_with(
        "adr005_pop_message_equals_the_reference_layout",
        Config::default().with_cases(256),
        |g| {
            let purpose = if g.bool() { 1 } else { PURPOSE_CERT_RENEWAL };
            let scope: Vec<u8> = g.bytes(16..=16);
            let mut scope_id = [0u8; 16];
            scope_id.copy_from_slice(&scope);
            let name = g.ascii_string(1..=64);
            let challenge_bytes = g.bytes(32..=32);
            let mut challenge = [0u8; 32];
            challenge.copy_from_slice(&challenge_bytes);
            let c = Ctx {
                purpose,
                scope_id,
                name,
            };
            g.note("context", &c);
            let got = message(&spki_der, &c.to_pki(), &challenge)
                .map_err(|e| format!("fstp-pki refused: {e:?}"))?;
            prop_assert!(got == pop_message(&spki_der, &c, &challenge));
            Ok(())
        },
    );
}

/// Design section 9.1, ADR-005: a proof made for one role is refused for
/// another role of the same cell, even with the same key and challenge.
#[test]
fn adr005_pop_proof_for_another_role_is_refused() {
    let key = EcKey::generate();
    let p = proof(&key, CHALLENGE);
    let other = Ctx::role(CELL_ID, "c_0123456789abcdef0123456789abcdef_keys");
    let r = verify(&p, &other.to_pki(), &CHALLENGE);
    assert!(refused(&r), "{r:?}");
}

/// Design section 9.1, ADR-009 B7: a proof made for a role of one cell is
/// refused for the same role name under another cell or cluster id.
#[test]
fn adr005_pop_proof_for_another_scope_is_refused() {
    let key = EcKey::generate();
    let p = proof(&key, CHALLENGE);
    let other = Ctx::role([0x02; 16], ROLE);
    let r = verify(&p, &other.to_pki(), &CHALLENGE);
    assert!(refused(&r), "{r:?}");
}

/// Design section 9.1: a `RoleCredential` proof is refused as a
/// `CertRenewal` proof for the same name.
#[test]
fn adr005_pop_proof_for_another_purpose_is_refused() {
    let key = EcKey::generate();
    let p = proof(&key, CHALLENGE);
    let mut other = ctx();
    other.purpose = PURPOSE_CERT_RENEWAL;
    let r = verify(&p, &other.to_pki(), &CHALLENGE);
    assert!(refused(&r), "{r:?}");
}
