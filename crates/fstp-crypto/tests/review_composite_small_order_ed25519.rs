//! Review reproducer (I-75, I-90, ADR-010 "Composite encoding", draft 19
//! sections 3.3 and 4.1).
//!
//! `CompositePublicKey::from_bytes` accepts every 1984-byte string, and
//! `composite::verify` hands the Ed25519 half to aws-lc-rs, which does
//! not refuse small-order Ed25519 public keys. Under a composite key whose
//! Ed25519 half is a small-order point, one fixed 64-byte Ed25519 value
//! verifies over every message. Such a key rests on ML-DSA-65 alone, so
//! the composite check degrades to a single-half check.
//!
//! This test fails against the current code. It passes once the
//! composite decoder or verifier refuses small-order Ed25519 halves.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::composite_ref::{LABEL, m_prime};
use fstp_crypto::composite;

/// Builds a composite public key whose Ed25519 half is `ed_pk`, and a
/// composite signature over `msg` whose ML-DSA-65 half is genuine and
/// whose Ed25519 half is the fixed value `ed_sig`.
fn forge(ed_pk: [u8; 32], ed_sig: [u8; 64], msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (mpk, msk) = fstp_crypto::mldsa::acvp::keygen(&[7u8; 32]).unwrap();
    let mp = m_prime(LABEL, b"", msg);
    let ms = fstp_crypto::mldsa::acvp::sign(&msk[..], &mp, LABEL, &[0u8; 32]).unwrap();
    (
        [&mpk[..], &ed_pk[..]].concat(),
        [&ms[..], &ed_sig[..]].concat(),
    )
}

/// I-75, I-90: a composite key whose Ed25519 half is the identity point
/// (encoding `01 00 .. 00`) must not verify a signature whose Ed25519
/// half is the constant `R = identity, S = 0`, which carries no
/// knowledge of any Ed25519 private key.
#[test]
fn review_composite_refuses_identity_ed25519_half() {
    let mut ed_pk = [0u8; 32];
    ed_pk[0] = 1;
    let mut ed_sig = [0u8; 64];
    ed_sig[0] = 1;
    for msg in [&b"anchor"[..], &b"any other message"[..]] {
        let (pk, sig) = forge(ed_pk, ed_sig, msg);
        assert!(
            composite::verify(&pk, msg, &sig).is_err(),
            "a composite with an identity Ed25519 half verified on its ML-DSA-65 half alone"
        );
    }
}
