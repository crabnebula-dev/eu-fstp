//! T-CR-COMPOSITE for TH-67, I-75 and I-90: production composite signing
//! round trips, the application context, the private key encoding and
//! refusals (M3 design sections 3.9 and 7.4, ADR-010 "Composite
//! encoding", draft-ietf-lamps-pq-composite-sigs version 19).
//!
//! Every production signature is also checked against the reference in
//! `common::composite_ref`, which builds `M'` and the concatenations from
//! the ADR-010 table alone. So a production composite that agrees only
//! with itself still fails.
//!
//! The API under test, as this file expects it. The W0 stub has
//! `generate`, `CompositeSigningKey::sign`, `verify` and the two decoders.
//! It lacks the items marked "new", so this file does not compile until
//! the production lane adds them:
//!
//! ```text
//! fstp_crypto::composite::PUBLIC_KEY_LEN: usize    // 1984, draft 19 Appendix A
//! fstp_crypto::composite::SIGNATURE_LEN: usize     // 3373, draft 19 Appendix A
//! fstp_crypto::composite::PRIVATE_KEY_LEN: usize   // new: 64, mldsaSeed || Ed25519 seed (section 4.2)
//! fstp_crypto::composite::generate() -> Result<CompositeSigningKey, CryptoError>
//! // new: DeserializePrivateKey (section 4.2), then the section 3.1 key
//! // regeneration. Only PRIVATE_KEY_LEN bytes are accepted.
//! fstp_crypto::composite::CompositeSigningKey::from_bytes(&[u8]) -> Result<CompositeSigningKey, CryptoError>
//! // new: SerializePrivateKey (section 4.2), wiped on drop.
//! fstp_crypto::composite::CompositeSigningKey::to_bytes(&self)
//!     -> Result<zeroize::Zeroizing<[u8; 64]>, CryptoError>
//! // new: SerializePublicKey (section 4.1).
//! fstp_crypto::composite::CompositeSigningKey::public_key(&self) -> CompositePublicKey
//! // Composite-ML-DSA.Sign(sk, M, ctx) with the empty context (section 3.2).
//! fstp_crypto::composite::CompositeSigningKey::sign(&self, message: &[u8])
//!     -> Result<CompositeSignature, CryptoError>
//! // new: the same with an application context of at most 255 bytes.
//! fstp_crypto::composite::CompositeSigningKey::sign_with_context(&self, message: &[u8], ctx: &[u8])
//!     -> Result<CompositeSignature, CryptoError>
//! fstp_crypto::composite::CompositePublicKey::to_bytes(&self) -> [u8; 1984]
//! fstp_crypto::composite::CompositeSignature::to_bytes(&self) -> [u8; 3373]
//! // Composite-ML-DSA.Verify(pk, M, s, ctx) with the empty context (section 3.3).
//! fstp_crypto::composite::verify(public_key: &[u8], message: &[u8], signature: &[u8])
//!     -> Result<(), CryptoError>
//! // new: the same with an application context of at most 255 bytes.
//! fstp_crypto::composite::verify_with_context(public_key: &[u8], message: &[u8], ctx: &[u8], signature: &[u8])
//!     -> Result<(), CryptoError>
//! ```
//!
//! The ML-DSA-65 half signs hedged, with `rnd` from aws-lc-rs. The
//! Ed25519 half is deterministic (RFC 8032).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::composite_ref::{
    self as reference, ED25519_SIG_LEN, MLDSA_PK_LEN, MLDSA_SIG_LEN, PK_LEN, SIG_LEN, SK_LEN,
    verify_halves,
};
use common::impls;
use fstp_crypto::composite::{self, CompositeSigningKey};
use fstp_prop::{Config, check_with, prop_assert, prop_assert_eq};

/// One fresh composite key, generated once per test.
fn key() -> CompositeSigningKey {
    composite::generate().expect("composite key generation")
}

/// T-CR-COMPOSITE: a production signature over a random message and
/// context verifies with the same context, and `sign` with `verify` is
/// the empty-context case of both.
#[test]
fn t_cr_composite_sign_verify_round_trip() {
    let key = key();
    let pk = key.public_key().to_bytes();
    check_with(
        "t_cr_composite_sign_verify_round_trip",
        Config::default().with_cases(32),
        |g| {
            let m = g.bytes(0..=256);
            let ctx = g.bytes(0..=255);
            let s = key.sign_with_context(&m, &ctx).unwrap().to_bytes();
            prop_assert_eq!(composite::verify_with_context(&pk, &m, &ctx, &s), Ok(()));
            let plain = key.sign(&m).unwrap().to_bytes();
            prop_assert_eq!(composite::verify(&pk, &m, &plain), Ok(()));
            prop_assert_eq!(composite::verify_with_context(&pk, &m, b"", &plain), Ok(()));
            Ok(())
        },
    );
}

/// TH-67, I-75: every production signature is a draft 19 composite. The
/// reference splits the key and the signature as sections 4.1 and 4.3
/// say, and both halves verify over the reference `M'`, the ML-DSA-65
/// half with the label as its ML-DSA context.
#[test]
fn th_67_composite_production_signatures_verify_under_the_reference() {
    let key = key();
    let pk = key.public_key().to_bytes();
    check_with(
        "th_67_composite_production_signatures_verify_under_the_reference",
        Config::default().with_cases(32),
        |g| {
            let m = g.bytes(0..=256);
            let ctx = g.bytes(0..=255);
            let s = key.sign_with_context(&m, &ctx).unwrap().to_bytes();
            prop_assert_eq!(verify_halves(&pk, &m, &ctx, &s), (true, true));
            Ok(())
        },
    );
}

/// TH-67: the production verifier accepts both draft 19 Appendix E
/// signatures, `s` with the empty context and `sWithContext` with the
/// published context.
#[test]
fn th_67_composite_verify_accepts_both_draft19_vectors() {
    let v = reference::vector();
    assert_eq!(
        composite::verify_with_context(&v.pk, &v.m, b"", &v.s),
        Ok(())
    );
    assert_eq!(
        composite::verify_with_context(&v.pk, &v.m, &v.ctx, &v.s_with_context),
        Ok(())
    );
    assert!(composite::verify_with_context(&v.pk, &v.m, &v.ctx, &v.s).is_err());
    assert!(composite::verify_with_context(&v.pk, &v.m, b"", &v.s_with_context).is_err());
}

/// TH-67, draft 19 Appendix E test 3: the Appendix E private key loads,
/// gives the published public key, and signs new signatures that the
/// published public key verifies, with and without the context.
#[test]
fn th_67_composite_draft19_private_key_signs_for_its_public_key() {
    let v = reference::vector();
    let key = CompositeSigningKey::from_bytes(&v.sk).unwrap();
    assert_eq!(key.public_key().to_bytes().to_vec(), v.pk);
    let s = key.sign(&v.m).unwrap().to_bytes();
    assert_eq!(composite::verify(&v.pk, &v.m, &s), Ok(()));
    let sc = key.sign_with_context(&v.m, &v.ctx).unwrap().to_bytes();
    assert_eq!(
        composite::verify_with_context(&v.pk, &v.m, &v.ctx, &sc),
        Ok(())
    );
    assert_eq!(verify_halves(&v.pk, &v.m, &v.ctx, &sc), (true, true));
}

/// T-CR-COMPOSITE, draft 19 section 4.2: the private key encoding is the
/// 32-byte ML-DSA-65 seed then the 32-byte Ed25519 seed. It round-trips,
/// and a reloaded key has the same public key.
#[test]
fn t_cr_composite_private_key_round_trips() {
    let v = reference::vector();
    assert_eq!(composite::PRIVATE_KEY_LEN, SK_LEN);
    let loaded = CompositeSigningKey::from_bytes(&v.sk).unwrap();
    assert_eq!(loaded.to_bytes().unwrap()[..].to_vec(), v.sk);
    let fresh = key();
    let bytes = fresh.to_bytes().unwrap();
    let again = CompositeSigningKey::from_bytes(&bytes[..]).unwrap();
    assert_eq!(again.public_key(), fresh.public_key());
    assert_eq!(
        reference::RefKey::from_private_key(&bytes[..]).public_key(),
        fresh.public_key().to_bytes().to_vec()
    );
}

/// TH-67: a private key of any other length is refused.
#[test]
fn th_67_composite_signing_key_refuses_wrong_lengths() {
    let v = reference::vector();
    for len in [0, 32, SK_LEN - 1, SK_LEN + 1, 32 + 4032, 4032] {
        let mut sk = v.sk.clone();
        sk.resize(len, 0);
        assert_eq!(
            CompositeSigningKey::from_bytes(&sk).err(),
            Some(fstp_crypto::CryptoError::InvalidLength),
            "private key of {len} bytes"
        );
    }
}

/// TH-67, draft 19 sections 3.2 and 3.3 step 1: a context of 255 bytes
/// signs and verifies, and one of 256 bytes is refused by both.
#[test]
fn th_67_composite_refuses_contexts_over_255_bytes() {
    let key = key();
    let pk = key.public_key().to_bytes();
    let ctx = vec![0x3c; 255];
    let s = key.sign_with_context(b"anchor", &ctx).unwrap().to_bytes();
    assert_eq!(
        composite::verify_with_context(&pk, b"anchor", &ctx, &s),
        Ok(())
    );
    let long = vec![0x3c; 256];
    assert!(key.sign_with_context(b"anchor", &long).is_err());
    assert!(composite::verify_with_context(&pk, b"anchor", &long, &s).is_err());
}

/// TH-67, draft 19 section 3.3: the verifier keeps the two refusals of
/// the draft apart. Step 1, a context over 255 bytes, is "return error"
/// (`InvalidLength`) and comes first, whatever the key and signature.
/// Step 2, a key or signature of the wrong length, is "Invalid
/// signature" (`InvalidSignature`).
#[test]
fn th_67_composite_verify_separates_step_1_error_from_step_2_invalid_signature() {
    use fstp_crypto::CryptoError::{InvalidLength, InvalidSignature};
    let key = key();
    let pk = key.public_key().to_bytes();
    let s = key.sign(b"anchor").unwrap().to_bytes();
    let long = vec![0x3c; 256];
    let short_pk = &pk[..PK_LEN - 1];
    let short_s = &s[..SIG_LEN - 1];
    /// What the case is, the key, the context, the signature and the outcome.
    type Case<'a> = (
        &'a str,
        &'a [u8],
        &'a [u8],
        &'a [u8],
        fstp_crypto::CryptoError,
    );
    let cases: [Case<'_>; 6] = [
        ("long ctx", &pk, &long, &s, InvalidLength),
        ("long ctx, short key", short_pk, &long, &s, InvalidLength),
        ("long ctx, short sig", &pk, &long, short_s, InvalidLength),
        ("short key", short_pk, b"", &s, InvalidSignature),
        ("short sig", &pk, b"", short_s, InvalidSignature),
        ("empty key and sig", b"", b"", b"", InvalidSignature),
    ];
    for (what, cpk, ctx, cs, want) in cases {
        assert_eq!(
            composite::verify_with_context(cpk, b"anchor", ctx, cs),
            Err(want),
            "{what}"
        );
    }
}

/// TH-67: a signature made under one context does not verify under any
/// other, and one made under one key does not verify under another.
#[test]
fn th_67_composite_verify_rejects_another_context_or_key() {
    let (key, other) = (key(), key());
    let pk = key.public_key().to_bytes();
    let other_pk = other.public_key().to_bytes();
    check_with(
        "th_67_composite_verify_rejects_another_context_or_key",
        Config::default().with_cases(32),
        |g| {
            let m = g.bytes(0..=64);
            let ctx = g.bytes(0..=32);
            let mut ctx2 = ctx.clone();
            if g.bool() || ctx2.is_empty() {
                ctx2.push(g.u8());
            } else {
                ctx2[0] ^= 1;
            }
            let s = key.sign_with_context(&m, &ctx).unwrap().to_bytes();
            prop_assert_eq!(composite::verify_with_context(&pk, &m, &ctx, &s), Ok(()));
            prop_assert!(composite::verify_with_context(&pk, &m, &ctx2, &s).is_err());
            prop_assert!(composite::verify_with_context(&other_pk, &m, &ctx, &s).is_err());
            Ok(())
        },
    );
}

/// I-90: a production signature verifies only with both halves. Each
/// half replaced by zeros, or by the same half of a production signature
/// over another message, is refused.
#[test]
fn i90_composite_verify_rejects_either_half_alone_of_production_signatures() {
    let key = key();
    let pk = key.public_key().to_bytes();
    check_with(
        "i90_composite_verify_rejects_either_half_alone_of_production_signatures",
        Config::default().with_cases(16),
        |g| {
            let m = g.bytes(0..=64);
            let mut other = m.clone();
            other.push(g.u8());
            let s = key.sign(&m).unwrap().to_bytes();
            let t = key.sign(&other).unwrap().to_bytes();
            prop_assert_eq!(composite::verify(&pk, &m, &s), Ok(()));
            let (s_mldsa, s_ed) = s.split_at(MLDSA_SIG_LEN);
            let (t_mldsa, t_ed) = t.split_at(MLDSA_SIG_LEN);
            let forged: [(&str, Vec<u8>); 4] = [
                (
                    "zero Ed25519 half",
                    [s_mldsa, &[0u8; ED25519_SIG_LEN][..]].concat(),
                ),
                (
                    "zero ML-DSA-65 half",
                    [&[0u8; MLDSA_SIG_LEN][..], s_ed].concat(),
                ),
                ("Ed25519 half of another message", [s_mldsa, t_ed].concat()),
                (
                    "ML-DSA-65 half of another message",
                    [t_mldsa, s_ed].concat(),
                ),
            ];
            for (what, f) in forged {
                prop_assert!(composite::verify(&pk, &m, &f).is_err(), "{what} accepted");
            }
            Ok(())
        },
    );
}

/// I-75, I-90, draft 19 section 3.1: `generate` gives a key with both
/// halves. Its public key has an ML-DSA-65 half that verifies the ML-DSA
/// half of its signatures, so no Ed25519-only key stands in for a
/// composite one. This replaces the W0 refusal test of the stub.
#[test]
fn i90_composite_generate_gives_a_key_with_both_halves() {
    let key = key();
    let pk = key.public_key().to_bytes();
    assert_eq!((pk.len(), composite::SIGNATURE_LEN), (PK_LEN, SIG_LEN));
    assert_ne!(pk[..MLDSA_PK_LEN], [0u8; MLDSA_PK_LEN][..]);
    let s = key.sign(b"anchor").unwrap().to_bytes();
    assert_eq!(verify_halves(&pk, b"anchor", b"", &s), (true, true));
    assert!(composite::verify(&pk[MLDSA_PK_LEN..], b"anchor", &s[MLDSA_SIG_LEN..]).is_err());
}

/// TH-67, draft 19 section 3.1: key generation is fresh for both halves.
/// Two keys share neither their ML-DSA-65 nor their Ed25519 public key.
#[test]
fn th_67_composite_generate_gives_fresh_halves() {
    let a = key().public_key().to_bytes();
    let b = key().public_key().to_bytes();
    assert_ne!(a[..MLDSA_PK_LEN], b[..MLDSA_PK_LEN]);
    assert_ne!(a[MLDSA_PK_LEN..], b[MLDSA_PK_LEN..]);
}

/// T-CR-MLDSA, TH-68: the ML-DSA-65 half signs hedged, with fresh `rnd`
/// from aws-lc-rs for every signature. Two signatures over the same
/// message differ in their ML-DSA-65 half and agree in their
/// deterministic Ed25519 half.
#[test]
fn t_cr_mldsa_composite_signing_is_hedged() {
    let key = key();
    let a = key.sign(b"anchor").unwrap().to_bytes();
    let b = key.sign(b"anchor").unwrap().to_bytes();
    assert_ne!(a[..MLDSA_SIG_LEN], b[..MLDSA_SIG_LEN]);
    assert_eq!(a[MLDSA_SIG_LEN..], b[MLDSA_SIG_LEN..]);
}

/// ADR-001 A1, design section 2.2: the composite private key bytes come
/// back `Zeroizing`, so they are wiped on drop. The function is pinned to
/// its return type, and a plain array breaks the build.
#[test]
fn adr001_a1_composite_private_key_bytes_are_zeroizing() {
    type Bytes = Result<zeroize::Zeroizing<[u8; 64]>, fstp_crypto::CryptoError>;
    let _to_bytes: fn(&CompositeSigningKey) -> Bytes = CompositeSigningKey::to_bytes;
    assert!(impls!(zeroize::Zeroizing<[u8; 64]>: ::zeroize::ZeroizeOnDrop));
    assert!(!impls!(CompositeSigningKey: ::core::fmt::Debug));
}
