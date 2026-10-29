//! I-75, I-90, TH-67: the composite refuses an ML-DSA-65 half with a
//! degenerate `t1` (ADR-010 "Composite encoding", the platform rule
//! beyond draft 19 and FIPS 204).
//!
//! FIPS 204 has no public key check beyond length, and moduletto has
//! none. An ML-DSA-65 public key `rho || t1` whose `t1` coefficients are
//! all 0 or 1023 has `t1 * 2^13` equal to 0 or -1 modulo q at each
//! coefficient. It is the key of the public secret `s1 = s2 = 0`, with
//! each `t0` coefficient 0 or 1. Anyone can sign for it, so a composite
//! key with that half would rest on Ed25519 alone.
//!
//! The rule refuses every `t1` whose coefficients all lie in 0 to 255 or
//! 768 to 1023, that is, within 2^21 of 0 modulo q after the shift by 13
//! bits. Each coefficient's top two bits are then equal. An honest `t1`
//! is close to uniform, so it falls in that band with probability about
//! 2^-1536. The keys here are packed independently of the production
//! check, coefficient by coefficient, as FIPS 204 `pkEncode` packs them
//! (Algorithms 16 and 22).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values and packs fixed small offsets"
)]

mod common;

use common::composite_ref::{LABEL, MLDSA_PK_LEN, m_prime};
use fstp_crypto::CryptoError;
use fstp_crypto::composite::{self, CompositePublicKey};
use fstp_crypto::sig::Ed25519SigningKey;
use moduletto::dsa::ml_dsa_65;

/// Coefficients of `t1`: six polynomials of 256 (FIPS 204 Table 1, k = 6).
const T1_COEFFS: usize = 6 * 256;

/// FIPS 204 skEncode offsets for ML-DSA-65 (Algorithm 24): `rho`, `K` and
/// `tr` take 128 bytes, then `s1` and `s2` take 4 bits per coefficient.
const S1_AT: usize = 128;
const T0_AT: usize = S1_AT + (5 + 6) * 128;

/// Bytes of one packed `t0` polynomial, 13 bits per coefficient.
const T0_POLY_BYTES: usize = 416;

/// Sets bit `bit` of a little-endian bit stream.
fn set_bit(out: &mut [u8], bit: usize) {
    out[bit / 8] |= 1 << (bit % 8);
}

/// `rho || t1`, with `t1` packed 10 bits per coefficient, least
/// significant bit first (FIPS 204 Algorithms 16 and 22).
fn mldsa_pk(rho: [u8; 32], t1: &[u16]) -> Vec<u8> {
    assert_eq!(t1.len(), T1_COEFFS);
    let mut packed = vec![0u8; MLDSA_PK_LEN - 32];
    for (i, &c) in t1.iter().enumerate() {
        assert!(c < 1024);
        for k in 0..10 {
            if c >> k & 1 == 1 {
                set_bit(&mut packed, 10 * i + k);
            }
        }
    }
    [&rho[..], &packed[..]].concat()
}

/// A composite key: the ML-DSA-65 half `mldsa` and a genuine Ed25519
/// half, which is never of small order.
fn composite_pk(mldsa: &[u8]) -> Vec<u8> {
    let ed = Ed25519SigningKey::generate().unwrap();
    [mldsa, &ed.public_key()[..]].concat()
}

/// A deterministic spread of values in the band, from a small
/// linear congruential sequence.
fn band_values(seed: u32) -> Vec<u16> {
    let mut x = seed;
    (0..T1_COEFFS)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            let v = ((x >> 16) & 0xff) as u16;
            if x >> 31 == 1 { 1023 - v } else { v }
        })
        .collect()
}

/// I-75, I-90: every degenerate `t1` pattern is refused with
/// `InvalidKey`. That covers all 0, all 1023, the band edges 255 and 768,
/// a mix of 0 and 1023, a lone small value among zeros, and values spread
/// over the whole band.
#[test]
fn i90_composite_public_key_refuses_degenerate_mldsa_t1() {
    let mut patterns: Vec<(String, Vec<u16>)> = vec![
        ("all 0".into(), vec![0; T1_COEFFS]),
        ("all 1023".into(), vec![1023; T1_COEFFS]),
        ("all 255".into(), vec![255; T1_COEFFS]),
        ("all 768".into(), vec![768; T1_COEFFS]),
        (
            "0 and 1023".into(),
            (0..T1_COEFFS)
                .map(|i| if i % 3 == 0 { 1023 } else { 0 })
                .collect(),
        ),
    ];
    for at in [0, 1, 2, 3, 777, T1_COEFFS - 1] {
        let mut t1 = vec![0; T1_COEFFS];
        t1[at] = 1;
        patterns.push((format!("one 1 at {at}"), t1));
    }
    for seed in 1..=4 {
        patterns.push((format!("band seed {seed}"), band_values(seed)));
    }
    for (what, t1) in patterns {
        for rho in [[0u8; 32], [0x42; 32], [0xff; 32]] {
            let pk = composite_pk(&mldsa_pk(rho, &t1));
            assert_eq!(
                CompositePublicKey::from_bytes(&pk).err(),
                Some(CryptoError::InvalidKey),
                "degenerate t1 ({what}) decoded"
            );
        }
    }
}

/// I-90: the refusal is exact. One coefficient just outside the band, in
/// each of the four places of a packed group of five bytes, makes a key
/// the decoder accepts and re-encodes. So the rule refuses only `t1`
/// values with every coefficient in the band.
#[test]
fn i90_composite_public_key_refuses_only_degenerate_mldsa_t1() {
    for base in [0u16, 1023] {
        for value in [256u16, 511, 512, 767] {
            for at in [0, 1, 2, 3, 1000, 1001, 1002, T1_COEFFS - 1] {
                let mut t1 = vec![base; T1_COEFFS];
                t1[at] = value;
                let pk = composite_pk(&mldsa_pk([0x42; 32], &t1));
                let decoded = CompositePublicKey::from_bytes(&pk)
                    .unwrap_or_else(|e| panic!("t1 of {base} with {value} at {at} refused: {e:?}"));
                assert_eq!(decoded.to_bytes()[..], pk[..]);
            }
        }
    }
}

/// The expanded ML-DSA-65 private key with `s1 = s2 = 0` and the given
/// `t0` coefficients, under the matrix seed `rho`. `tr` stays zero, which
/// signing from an external `mu` does not read.
fn public_secret_key(rho: [u8; 32], t0: &[u32]) -> Vec<u8> {
    let mut sk = vec![0u8; ml_dsa_65::SK_BYTES];
    sk[..32].copy_from_slice(&rho);
    sk[32..64].copy_from_slice(&[0x17; 32]);
    // s1 and s2: each coefficient packed as eta - 0 = 4, four bits.
    for b in &mut sk[S1_AT..T0_AT] {
        *b = 0x44;
    }
    // t0: each coefficient packed as 2^12 - t0, thirteen bits.
    for (i, &t) in t0.iter().enumerate() {
        let packed = 4096 - t;
        let poly = i / 256;
        for k in 0..13 {
            if packed >> k & 1 == 1 {
                set_bit(&mut sk[T0_AT + poly * T0_POLY_BYTES..], 13 * (i % 256) + k);
            }
        }
    }
    sk
}

/// I-75, I-90, draft 19 section 3.3 step 2: under a `t1` that mixes 0
/// and 1023, an ML-DSA-65 half signed with the public secret verifies in
/// moduletto, and the composite still refuses with "Invalid signature".
#[test]
fn i90_composite_verify_refuses_mixed_public_secret_mldsa_half() {
    let rho = [0x42u8; 32];
    let t1: Vec<u16> = (0..T1_COEFFS)
        .map(|i| if (i * 7) % 5 < 2 { 1023 } else { 0 })
        .collect();
    let t0: Vec<u32> = t1.iter().map(|&c| u32::from(c == 1023)).collect();
    let mldsa = mldsa_pk(rho, &t1);
    let sk = public_secret_key(rho, &t0);
    let ed = Ed25519SigningKey::generate().unwrap();
    let pk = [&mldsa[..], &ed.public_key()[..]].concat();
    for msg in [&b"anchor"[..], &b"any other message"[..]] {
        let mp = m_prime(LABEL, b"", msg);
        let mu = ml_dsa_65::external_mu(&mldsa, &mp, LABEL).unwrap();
        let mldsa_sig = ml_dsa_65::sign_mu(&sk, &mu, &[0u8; 32]).unwrap();
        assert!(
            ml_dsa_65::verify(&mldsa, &mp, LABEL, &mldsa_sig),
            "precondition: the public-secret ML-DSA-65 signature verifies"
        );
        let sig = [&mldsa_sig[..], &ed.sign(&mp).unwrap()[..]].concat();
        assert_eq!(
            composite::verify(&pk, msg, &sig),
            Err(CryptoError::InvalidSignature),
            "a composite with a public-secret ML-DSA-65 half verified"
        );
    }
}

/// I-90: honest keys are not refused. Fresh composite keys decode and
/// re-encode, so the band never catches a generated `t1` in practice.
#[test]
fn i90_composite_public_key_accepts_generated_keys() {
    for _ in 0..32 {
        let pk = composite::generate().unwrap().public_key().to_bytes();
        let decoded = CompositePublicKey::from_bytes(&pk).unwrap();
        assert_eq!(decoded.to_bytes(), pk);
    }
}
