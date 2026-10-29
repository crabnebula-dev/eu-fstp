//! Review reproducer (I-75, I-90, ADR-010 "Composite encoding", the
//! small-order platform rule beyond draft 19).
//!
//! The small-order fix refuses a composite key whose Ed25519 half anyone
//! can forge for. It does not refuse the mirror case. An ML-DSA-65 public
//! key `rho || t1` whose `t1` coefficients are all 0, or all 1023, has
//! `t1 * 2^13` equal to 0 or -1 modulo q. It is the key of the public
//! secret `s1 = s2 = 0` with `t0` equal to 0 or 1. Anyone can sign for it
//! with no secret at all. A composite key with that ML-DSA-65 half rests
//! on Ed25519 alone, so the post-quantum half carries no security.
//!
//! Each test builds such a key and signs its ML-DSA-65 half with that
//! public secret through moduletto `sign_mu`, with `mu` computed from the
//! public key. These tests fail against the current code. They pass once
//! the composite decoder, or the verifier, refuses such an ML-DSA-65 half,
//! as it refuses a small-order Ed25519 half.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values and packs fixed small offsets"
)]

mod common;

use common::composite_ref::{LABEL, m_prime};
use fstp_crypto::composite;
use fstp_crypto::sig::Ed25519SigningKey;
use moduletto::dsa::ml_dsa_65;

/// FIPS 204 skEncode offsets for ML-DSA-65 (Algorithm 24).
const S1_AT: usize = 128;
const T0_AT: usize = S1_AT + (5 + 6) * 128;
const T0_POLY_BYTES: usize = 416;

/// The expanded ML-DSA-65 private key with `s1 = s2 = 0` and every `t0`
/// coefficient equal to `t0`, under the matrix seed `rho`.
fn public_secret_key(rho: [u8; 32], t0: u32) -> Vec<u8> {
    let mut sk = vec![0u8; ml_dsa_65::SK_BYTES];
    sk[..32].copy_from_slice(&rho);
    sk[32..64].copy_from_slice(&[0x17; 32]);
    // s1 and s2: each coefficient packed as eta - 0 = 4, four bits.
    for b in &mut sk[S1_AT..T0_AT] {
        *b = 0x44;
    }
    // t0: each coefficient packed as 2^12 - t0, thirteen bits.
    let packed = 4096 - t0;
    for poly in 0..6 {
        let base = T0_AT + poly * T0_POLY_BYTES;
        for i in 0..256 {
            for k in 0..13 {
                if packed >> k & 1 == 1 {
                    let bit = 13 * i + k;
                    sk[base + bit / 8] |= 1 << (bit % 8);
                }
            }
        }
    }
    sk
}

/// Forges a composite signature under a composite key whose ML-DSA-65
/// half is `rho || t1_fill^1920`, and asserts the verifier refuses it.
fn require_refused(t1_fill: u8, t0: u32) {
    let rho = [0x42u8; 32];
    let mut mldsa_pk = vec![t1_fill; ml_dsa_65::PK_BYTES];
    mldsa_pk[..32].copy_from_slice(&rho);
    let sk = public_secret_key(rho, t0);
    let ed = Ed25519SigningKey::generate().unwrap();
    let pk = [&mldsa_pk[..], &ed.public_key()[..]].concat();

    for msg in [&b"anchor"[..], &b"any other message"[..]] {
        let mp = m_prime(LABEL, b"", msg);
        let mu = ml_dsa_65::external_mu(&mldsa_pk, &mp, LABEL).unwrap();
        let mldsa_sig = ml_dsa_65::sign_mu(&sk, &mu, &[0u8; 32]).unwrap();
        // Precondition: the ML-DSA-65 half really is forged from a
        // public secret.
        assert!(
            ml_dsa_65::verify(&mldsa_pk, &mp, LABEL, &mldsa_sig),
            "precondition: the public-secret ML-DSA-65 signature verifies"
        );
        let sig = [&mldsa_sig[..], &ed.sign(&mp).unwrap()[..]].concat();
        assert!(
            composite::verify(&pk, msg, &sig).is_err(),
            "a composite with a degenerate ML-DSA-65 half verified on its Ed25519 half alone"
        );
    }
}

/// I-75, I-90: a composite key whose ML-DSA-65 half has `t1 = 0` must
/// not verify. Anyone can sign that half, so the composite would rest on
/// Ed25519 alone.
#[test]
fn review_composite_refuses_mldsa_half_with_zero_t1() {
    require_refused(0x00, 0);
}

/// I-75, I-90: the same with every `t1` coefficient 1023, so that
/// `t1 * 2^13` is -1 modulo q. A byte compare against an all-zero `t1`
/// alone does not close the gap.
#[test]
fn review_composite_refuses_mldsa_half_with_all_1023_t1() {
    require_refused(0xff, 1);
}
