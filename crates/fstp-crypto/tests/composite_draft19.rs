//! T-CR-COMPOSITE for TH-67, and I-90: `fstp_crypto::composite` against
//! draft-ietf-lamps-pq-composite-sigs version 19, id-MLDSA65-Ed25519-SHA512
//! (M3 design section 7.4, ADR-001 "Post-quantum signatures", ADR-010
//! "Composite encoding").
//!
//! Two kinds of test live here:
//!
//! - `t_cr_composite_*` check the transcription itself. The reference
//!   composite in `common::composite_ref` reproduces the draft's Appendix
//!   D message representatives, rebuilds the Appendix E public key from its
//!   private key, and verifies both halves of both Appendix E signatures.
//!   They need no production code and pass today.
//! - `th_67_*` and `i90_*` run the production verifier. It must accept the
//!   Appendix E signature, reject every single-bit flip of the message and
//!   of each signature half, and reject either half alone. Each one first
//!   requires that the unchanged vector verifies, so none passes on a
//!   verifier that refuses everything. They are red until `composite`
//!   calls moduletto.
//!
//! The vector is `tests/data/composite_mldsa65_ed25519_draft19.json`, the
//! Appendix E base64 values copied verbatim from the draft text.
//!
//! The API under test, as this file expects it. All of it exists in the
//! W0 stub, which refuses:
//!
//! ```text
//! fstp_crypto::composite::PUBLIC_KEY_LEN: usize   // 1984, draft 19 Appendix A
//! fstp_crypto::composite::SIGNATURE_LEN: usize    // 3373, draft 19 Appendix A
//! fstp_crypto::composite::CompositePublicKey::from_bytes(&[u8]) -> Result<CompositePublicKey, CryptoError>
//! fstp_crypto::composite::CompositePublicKey::to_bytes(&self) -> [u8; 1984]
//! fstp_crypto::composite::CompositeSignature::from_bytes(&[u8]) -> Result<CompositeSignature, CryptoError>
//! fstp_crypto::composite::CompositeSignature::to_bytes(&self) -> [u8; 3373]
//! // Composite-ML-DSA.Verify(pk, M, s, ctx) with the empty application
//! // context, the draft's default (section 3.3).
//! fstp_crypto::composite::verify(public_key: &[u8], message: &[u8], signature: &[u8])
//!     -> Result<(), CryptoError>
//! ```
//!
//! The calls with a non-empty application context and the production
//! signing round trips are in `composite_api.rs`.

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
    self as reference, ED25519_PK_LEN, ED25519_SIG_LEN, LABEL, MLDSA_PK_LEN, MLDSA_SIG_LEN, PK_LEN,
    PREFIX, PREFIX_HEX, RefKey, SIG_LEN, SK_LEN, accepted_flips, bit_flips, m_prime, verify_halves,
};
use common::hex;
use fstp_crypto::composite::{self, CompositePublicKey, CompositeSignature};
use fstp_prop::{Config, check_with, prop_assert};

/// Whether the production verifier accepts, with the empty context.
fn accepts(pk: &[u8], m: &[u8], s: &[u8]) -> bool {
    composite::verify(pk, m, s).is_ok()
}

/// The precondition of every rejection test here: the production
/// verifier accepts the unchanged Appendix E signature. Without it, a
/// verifier that refuses everything would pass the rejection tests.
fn require_vector_accepted(v: &reference::Vector) {
    assert_eq!(
        composite::verify(&v.pk, &v.m, &v.s),
        Ok(()),
        "precondition: the draft 19 Appendix E signature verifies"
    );
}

/// Draft 19 section 2.2: the prefix is the ASCII string
/// "CompositeAlgorithmSignatures2025", whose hex the draft gives. Section 6
/// gives the label and the OID. The reference uses these values.
#[test]
fn t_cr_composite_draft19_prefix_label_and_oid_as_transcribed() {
    assert_eq!(PREFIX.to_vec(), hex(PREFIX_HEX));
    assert_eq!(LABEL, b"COMPSIG-MLDSA65-Ed25519-SHA512");
    assert_eq!(reference::OID, "1.3.6.1.5.5.7.6.48");
    assert_eq!(reference::vector_field("tcId"), "id-MLDSA65-Ed25519-SHA512");
}

/// Draft 19 Appendix D: the reference message representative reproduces
/// both worked examples, without and with a context. They use the label
/// of id-MLDSA65-ECDSA-P256-SHA512, whose pre-hash is SHA-512 as well.
#[test]
fn t_cr_composite_reference_m_prime_matches_draft19_appendix_d() {
    let label = b"COMPSIG-MLDSA65-ECDSA-P256-SHA512";
    let m = hex("00010203040506070809");
    assert_eq!(
        m_prime(label, b"", &m),
        reference::appendix_d_hex(false),
        "Appendix D, empty ctx"
    );
    assert_eq!(
        m_prime(label, &hex("0813061205162623"), &m),
        reference::appendix_d_hex(true),
        "Appendix D, 8-byte ctx"
    );
}

/// Draft 19 Appendix E and Appendix A Table 4: the vector decodes to the
/// published message and context, and to a 1984-byte public key, a 64-byte
/// private key and two 3373-byte signatures. The production lengths agree.
#[test]
fn t_cr_composite_draft19_vector_sizes() {
    let v = reference::vector();
    assert_eq!(v.m, b"The quick brown fox jumps over the lazy dog.");
    assert_eq!(
        v.ctx,
        b"The lethargic, colorless dog sat beneath the energetic, stationary fox."
    );
    assert_eq!(
        (v.pk.len(), v.sk.len(), v.s.len(), v.s_with_context.len()),
        (PK_LEN, SK_LEN, SIG_LEN, SIG_LEN)
    );
    assert_eq!(PK_LEN, MLDSA_PK_LEN + ED25519_PK_LEN);
    assert_eq!(SIG_LEN, MLDSA_SIG_LEN + ED25519_SIG_LEN);
    assert_eq!(
        (composite::PUBLIC_KEY_LEN, composite::SIGNATURE_LEN),
        (PK_LEN, SIG_LEN)
    );
}

/// The vector file decodes to the bytes whose SHA-256 the ADR-010
/// "Composite encoding" table records, so the file and the ADR name one
/// vector.
#[test]
fn t_cr_composite_draft19_vector_matches_the_adr010_digests() {
    let v = reference::vector();
    let digest = |b: &[u8]| -> String {
        fstp_crypto::sha256(b)
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect()
    };
    let rows = [
        (
            "pk",
            &v.pk,
            "10775911b6c3c2dbf3c98485be51c5cc2c1b9ca5d2047a7faedab1d6cd573c27",
        ),
        (
            "sk",
            &v.sk,
            "e6361cda094fd0b587b192a3eb414545d181f78b53a1578e3de61b6d0de8e3d0",
        ),
        (
            "s",
            &v.s,
            "e00b69d9885679613d138c6d9c0e2762d5d8b210f8cf5fe5d73402a4de460c3d",
        ),
        (
            "sWithContext",
            &v.s_with_context,
            "392f002608faab90bac3d0f0aa5f5bdf57df244464225a4af3b59b5b68f51187",
        ),
    ];
    for (name, bytes, want) in rows {
        assert_eq!(digest(bytes), want, "{name}");
    }
}

/// Draft 19 sections 3.1 and 4.2: the Appendix E private key is
/// `mldsaSeed || tradSK`, and the keys it regenerates serialise to the
/// published public key `mldsaPK || tradPK` (section 4.1).
#[test]
fn t_cr_composite_draft19_vector_private_key_gives_its_public_key() {
    let v = reference::vector();
    let key = RefKey::from_private_key(&v.sk);
    assert_eq!(key.public_key(), v.pk);
}

/// Draft 19 section 3.3: both halves of both Appendix E signatures verify
/// under the reference, the ML-DSA-65 half with the label as its ML-DSA
/// context. The same half does not verify with an empty ML-DSA context,
/// so the reference really applies the label.
#[test]
fn t_cr_composite_draft19_vector_halves_verify_under_the_reference() {
    let v = reference::vector();
    assert_eq!(verify_halves(&v.pk, &v.m, b"", &v.s), (true, true), "s");
    assert_eq!(
        verify_halves(&v.pk, &v.m, &v.ctx, &v.s_with_context),
        (true, true),
        "sWithContext"
    );
    assert_eq!(
        verify_halves(&v.pk, &v.m, &v.ctx, &v.s),
        (false, false),
        "s under the non-empty ctx"
    );
    let mp = m_prime(LABEL, b"", &v.m);
    assert!(!moduletto::dsa::ml_dsa_65::verify(
        &v.pk[..MLDSA_PK_LEN],
        &mp,
        b"",
        &v.s[..MLDSA_SIG_LEN]
    ));
}

/// TH-67, I-90: the production verifier accepts the draft 19 Appendix E
/// signature `s` over `m` with the empty context.
#[test]
fn th_67_composite_verify_accepts_the_draft19_vector() {
    let v = reference::vector();
    assert_eq!(composite::verify(&v.pk, &v.m, &v.s), Ok(()));
}

/// TH-67: the decoders accept the Appendix E public key and signature,
/// and each re-encodes byte for byte (draft 19 sections 4.1 and 4.3).
#[test]
fn th_67_composite_decoders_accept_the_draft19_vector() {
    let v = reference::vector();
    let pk = CompositePublicKey::from_bytes(&v.pk).expect("public key decodes");
    assert_eq!(pk.to_bytes().to_vec(), v.pk);
    let s = CompositeSignature::from_bytes(&v.s).expect("signature decodes");
    assert_eq!(s.to_bytes().to_vec(), v.s);
}

/// TH-67: no single-bit flip of the Appendix E message verifies.
#[test]
fn th_67_composite_verify_rejects_every_bit_flip_in_the_message() {
    let v = reference::vector();
    require_vector_accepted(&v);
    let flips = bit_flips(0..v.m.len());
    let bad = accepted_flips(&v.m, &flips, &|m| accepts(&v.pk, m, &v.s));
    assert!(bad.is_empty(), "accepted message flips: {bad:?}");
}

/// TH-67, I-90: no single-bit flip of the Ed25519 half of the Appendix E
/// signature verifies, though its ML-DSA-65 half is still valid.
#[test]
fn th_67_composite_verify_rejects_every_bit_flip_in_the_ed25519_half() {
    let v = reference::vector();
    require_vector_accepted(&v);
    let flips = bit_flips(MLDSA_SIG_LEN..SIG_LEN);
    let bad = accepted_flips(&v.s, &flips, &|s| accepts(&v.pk, &v.m, s));
    assert!(bad.is_empty(), "accepted Ed25519 half flips: {bad:?}");
}

/// TH-67, TH-68, I-90: no single-bit flip of the ML-DSA-65 half of the
/// Appendix E signature verifies, though its Ed25519 half is still valid.
/// All 26 472 flips run, spread over every core.
#[test]
fn th_67_composite_verify_rejects_every_bit_flip_in_the_mldsa_half() {
    let v = reference::vector();
    require_vector_accepted(&v);
    let flips = bit_flips(0..MLDSA_SIG_LEN);
    let bad = accepted_flips(&v.s, &flips, &|s| accepts(&v.pk, &v.m, s));
    assert!(bad.is_empty(), "accepted ML-DSA-65 half flips: {bad:?}");
}

/// TH-67, I-90: no single-bit flip of the Ed25519 public key half
/// verifies.
#[test]
fn th_67_composite_verify_rejects_every_bit_flip_in_the_ed25519_public_key() {
    let v = reference::vector();
    require_vector_accepted(&v);
    let flips = bit_flips(MLDSA_PK_LEN..PK_LEN);
    let bad = accepted_flips(&v.pk, &flips, &|pk| accepts(pk, &v.m, &v.s));
    assert!(bad.is_empty(), "accepted Ed25519 key flips: {bad:?}");
}

/// TH-67, TH-68, I-90: flips of the ML-DSA-65 public key half do not
/// verify. Every bit of `rho` (the first 32 bytes) flips, and one bit of
/// every byte of `t1`, the bit position rotating with the byte index.
#[test]
fn th_67_composite_verify_rejects_bit_flips_in_the_mldsa_public_key() {
    let v = reference::vector();
    require_vector_accepted(&v);
    let mut flips = bit_flips(0..32);
    flips.extend((32..MLDSA_PK_LEN).map(|i| (i, 1u8 << (i % 8))));
    let bad = accepted_flips(&v.pk, &flips, &|pk| accepts(pk, &v.m, &v.s));
    assert!(bad.is_empty(), "accepted ML-DSA-65 key flips: {bad:?}");
}

/// TH-67: keys and signatures of any other length are refused, by the
/// decoders and by the verifier. That includes the bare ML-DSA-65 and
/// Ed25519 values, so a single-half value never passes as a composite
/// (I-90).
#[test]
fn th_67_composite_refuses_wrong_lengths() {
    let v = reference::vector();
    require_vector_accepted(&v);
    for len in [0, ED25519_PK_LEN, MLDSA_PK_LEN, PK_LEN - 1, PK_LEN + 1] {
        let mut pk = v.pk.clone();
        pk.resize(len, 0);
        assert!(!accepts(&pk, &v.m, &v.s), "public key of {len} bytes");
        assert_eq!(
            CompositePublicKey::from_bytes(&pk).err(),
            Some(fstp_crypto::CryptoError::InvalidLength),
            "public key of {len} bytes"
        );
    }
    assert!(!accepts(&v.pk[MLDSA_PK_LEN..], &v.m, &v.s[MLDSA_SIG_LEN..]));
    assert!(!accepts(&v.pk[..MLDSA_PK_LEN], &v.m, &v.s[..MLDSA_SIG_LEN]));
    for len in [0, ED25519_SIG_LEN, MLDSA_SIG_LEN, SIG_LEN - 1, SIG_LEN + 1] {
        let mut s = v.s.clone();
        s.resize(len, 0);
        assert!(!accepts(&v.pk, &v.m, &s), "signature of {len} bytes");
        assert_eq!(
            CompositeSignature::from_bytes(&s).err(),
            Some(fstp_crypto::CryptoError::InvalidLength),
            "signature of {len} bytes"
        );
    }
}

/// TH-67: the Appendix E signature does not verify under another key,
/// nor under a key that mixes one half of the vector key with a half of
/// another key.
#[test]
fn th_67_composite_verify_rejects_a_wrong_key() {
    let v = reference::vector();
    require_vector_accepted(&v);
    let mut other_sk = v.sk.clone();
    other_sk[0] ^= 1;
    other_sk[SK_LEN - 1] ^= 1;
    let other = RefKey::from_private_key(&other_sk).public_key();
    assert_ne!(other[..MLDSA_PK_LEN], v.pk[..MLDSA_PK_LEN]);
    assert_ne!(other[MLDSA_PK_LEN..], v.pk[MLDSA_PK_LEN..]);
    assert!(!accepts(&other, &v.m, &v.s), "another key");
    let mut mixed = v.pk[..MLDSA_PK_LEN].to_vec();
    mixed.extend_from_slice(&other[MLDSA_PK_LEN..]);
    assert!(!accepts(&mixed, &v.m, &v.s), "another Ed25519 half");
    let mut mixed = other[..MLDSA_PK_LEN].to_vec();
    mixed.extend_from_slice(&v.pk[MLDSA_PK_LEN..]);
    assert!(!accepts(&mixed, &v.m, &v.s), "another ML-DSA-65 half");
    let mut swapped = v.pk[MLDSA_PK_LEN..].to_vec();
    swapped.extend_from_slice(&v.pk[..MLDSA_PK_LEN]);
    assert!(!accepts(&swapped, &v.m, &v.s), "halves in the other order");
}

/// TH-67: the Appendix E signature made with a context does not verify
/// with the empty context. Context binding is part of `M'` (draft 19
/// section 2.2).
#[test]
fn th_67_composite_verify_rejects_the_context_vector_without_its_context() {
    let v = reference::vector();
    require_vector_accepted(&v);
    assert!(!accepts(&v.pk, &v.m, &v.s_with_context));
}

/// I-90: a composite signature verifies only when both halves verify.
/// The reference signs random messages under the Appendix E key, and the
/// production verifier accepts each whole signature. It refuses the
/// signature once either half is replaced. The replacements are zeros,
/// random bytes, the same half of a valid signature over another message,
/// and a half over the raw message instead of `M'`. An ML-DSA-65 half made
/// without the label as its ML-DSA context is refused too, and so is the
/// signature with its halves swapped.
#[test]
fn i90_composite_verify_rejects_either_half_alone() {
    let v = reference::vector();
    let key = RefKey::from_private_key(&v.sk);
    let pk = key.public_key();
    check_with(
        "i90_composite_verify_rejects_either_half_alone",
        Config::default().with_cases(8),
        |g| {
            let m = g.bytes(0..=64);
            let mut other = g.bytes(0..=64);
            other.push(0x5a);
            let rnd: [u8; 32] = g.bytes(32..=32).try_into().unwrap();
            let whole = key.sign(&m, b"", &rnd);
            prop_assert!(accepts(&pk, &m, &whole), "the whole signature verifies");
            let (mldsa, ed) = whole.split_at(MLDSA_SIG_LEN);
            let over_other = key.sign(&other, b"", &rnd);
            let (other_mldsa, other_ed) = over_other.split_at(MLDSA_SIG_LEN);
            let mp = m_prime(LABEL, b"", &m);
            let ed_halves: [(&str, Vec<u8>); 4] = [
                ("zero Ed25519 half", vec![0; ED25519_SIG_LEN]),
                ("random Ed25519 half", g.bytes(64..=64)),
                ("Ed25519 half over another message", other_ed.to_vec()),
                ("Ed25519 half over the raw message", key.ed25519_half(&m)),
            ];
            for (what, half) in ed_halves {
                let s = [mldsa, &half[..]].concat();
                prop_assert!(!accepts(&pk, &m, &s), "{what} accepted");
            }
            let mldsa_halves: [(&str, Vec<u8>); 5] = [
                ("zero ML-DSA-65 half", vec![0; MLDSA_SIG_LEN]),
                ("random ML-DSA-65 half", g.bytes(3309..=3309)),
                ("ML-DSA-65 half over another message", other_mldsa.to_vec()),
                (
                    "ML-DSA-65 half over the raw message",
                    key.mldsa_half(&m, LABEL, &rnd),
                ),
                (
                    "ML-DSA-65 half with an empty ML-DSA context",
                    key.mldsa_half(&mp, b"", &rnd),
                ),
            ];
            for (what, half) in mldsa_halves {
                let s = [&half[..], ed].concat();
                prop_assert!(!accepts(&pk, &m, &s), "{what} accepted");
            }
            let swapped = [ed, mldsa].concat();
            prop_assert!(!accepts(&pk, &m, &swapped), "swapped halves accepted");
            Ok(())
        },
    );
}

/// TH-67: a signature whose halves sign an `M'` with another label, with
/// no prefix, or with the message unhashed is refused, although each half
/// verifies over the `M'` it was made for. This is the label binding of
/// draft 19 section 2.2.
#[test]
fn th_67_composite_verify_rejects_another_message_representative() {
    let v = reference::vector();
    require_vector_accepted(&v);
    let key = RefKey::from_private_key(&v.sk);
    let pk = key.public_key();
    let rnd = [7u8; 32];
    let hashed = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA512, &v.m);
    let wrong: [(&str, Vec<u8>); 4] = [
        (
            "the ML-DSA-44 label",
            m_prime(b"COMPSIG-MLDSA44-Ed25519-SHA512", b"", &v.m),
        ),
        (
            "no prefix",
            m_prime(LABEL, b"", &v.m)[PREFIX.len()..].to_vec(),
        ),
        (
            "the message unhashed",
            [
                &m_prime(LABEL, b"", b"")[..PREFIX.len() + LABEL.len() + 1],
                &v.m,
            ]
            .concat(),
        ),
        (
            "no length byte",
            [&PREFIX[..], LABEL, hashed.as_ref()].concat(),
        ),
    ];
    for (what, mp) in wrong {
        let s = [key.mldsa_half(&mp, LABEL, &rnd), key.ed25519_half(&mp)].concat();
        assert!(!accepts(&pk, &v.m, &s), "{what} accepted");
    }
}
