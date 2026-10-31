//! I-75, I-90, TH-67: the composite refuses an Ed25519 half that is a
//! point of small order (ADR-010 "Composite encoding", the platform rule
//! beyond draft 19).
//!
//! aws-lc-rs does not refuse small-order Ed25519 public keys. Under such a
//! key, the constant Ed25519 value `R = identity, S = 0` verifies over
//! every message whose challenge is a multiple of the point's order. A
//! composite key with that half would rest on ML-DSA-65 alone. So the
//! decoder refuses it with `InvalidKey`, and the verifier with
//! `InvalidSignature` (draft 19 section 3.3 step 2).
//!
//! The encodings here are written out independently of the production
//! table, in hex. They are the five y-coordinates of the points of order
//! dividing 8, little-endian, and the non-canonical spellings p and p + 1.
//! Each is tested with bit 255, the sign of x, clear and set.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::composite_ref::{ED25519_PK_LEN, LABEL, m_prime};
use fstp_crypto::CryptoError;
use fstp_crypto::composite::{self, CompositePublicKey};
use fstp_crypto::sig::ed25519_verify;

/// The small-order encodings with bit 255 clear, and whether the
/// encoding is canonical.
const SMALL_ORDER_HEX: [(&str, bool); 7] = [
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        true,
    ),
    (
        "0100000000000000000000000000000000000000000000000000000000000000",
        true,
    ),
    (
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        true,
    ),
    (
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        true,
    ),
    (
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        true,
    ),
    (
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        false,
    ),
    (
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        false,
    ),
];

/// Every small-order spelling: each table row with bit 255 clear and set.
fn small_order_spellings() -> Vec<[u8; ED25519_PK_LEN]> {
    let mut out = Vec::new();
    for (h, _) in SMALL_ORDER_HEX {
        let e: [u8; ED25519_PK_LEN] = common::arr(h);
        let mut neg = e;
        neg[31] |= 0x80;
        out.push(e);
        out.push(neg);
    }
    out
}

/// The constant Ed25519 value `R = identity, S = 0`.
fn identity_signature() -> [u8; 64] {
    let mut s = [0u8; 64];
    s[0] = 1;
    s
}

/// A genuine ML-DSA-65 public key and its signature over the `M'` of
/// `msg`, with the empty context.
fn mldsa_half(msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = fstp_crypto::mldsa::acvp::keygen(&[7u8; 32]).unwrap();
    let mp = m_prime(LABEL, b"", msg);
    let s = fstp_crypto::mldsa::acvp::sign(&sk[..], &mp, LABEL, &[0u8; 32]).unwrap();
    (pk[..].to_vec(), s[..].to_vec())
}

/// I-75, I-90: the composite public key decoder refuses every
/// small-order spelling of the Ed25519 half with `InvalidKey`.
#[test]
fn i90_composite_public_key_refuses_small_order_ed25519_halves() {
    let (mpk, _) = mldsa_half(b"anchor");
    for e in small_order_spellings() {
        let pk = [&mpk[..], &e[..]].concat();
        assert_eq!(
            CompositePublicKey::from_bytes(&pk).err(),
            Some(CryptoError::InvalidKey),
            "small-order Ed25519 half {e:02x?} decoded"
        );
    }
}

/// I-75, I-90, draft 19 section 3.3 step 2: a genuine ML-DSA-65 half with
/// a small-order Ed25519 key and the constant Ed25519 value does not
/// verify, and the outcome is "Invalid signature".
#[test]
fn i90_composite_verify_refuses_small_order_ed25519_halves() {
    for msg in [&b"anchor"[..], &b"any other message"[..], &b""[..]] {
        let (mpk, ms) = mldsa_half(msg);
        let sig = [&ms[..], &identity_signature()[..]].concat();
        for e in small_order_spellings() {
            let pk = [&mpk[..], &e[..]].concat();
            assert_eq!(
                composite::verify(&pk, msg, &sig),
                Err(CryptoError::InvalidSignature),
                "small-order Ed25519 half {e:02x?} verified"
            );
        }
    }
}

/// I-90: the refusal is exact. Flipping any one bit below bit 255 of a
/// small-order encoding gives a key the decoder accepts and re-encodes,
/// so the table refuses only the listed spellings.
#[test]
fn i90_composite_public_key_refuses_only_the_small_order_spellings() {
    let (mpk, _) = mldsa_half(b"anchor");
    let table = small_order_spellings();
    for e in &table {
        for bit in 0..255 {
            let mut f = *e;
            f[bit / 8] ^= 1 << (bit % 8);
            if table.contains(&f) {
                continue;
            }
            let pk = [&mpk[..], &f[..]].concat();
            let decoded = CompositePublicKey::from_bytes(&pk)
                .unwrap_or_else(|err| panic!("{f:02x?} refused: {err:?}"));
            assert_eq!(decoded.to_bytes()[..], pk[..]);
        }
    }
}

/// I-90 teeth: the canonical table rows are weak keys for aws-lc-rs.
/// Under each, the constant `R = identity, S = 0` verifies over at least
/// one of 64 messages, so the refusal guards a gap that is real and the
/// rows are points of small order.
#[test]
fn i90_teeth_small_order_rows_are_weak_ed25519_keys_for_aws_lc() {
    let sig = identity_signature();
    for (h, canonical) in SMALL_ORDER_HEX {
        if !canonical {
            continue;
        }
        let e: [u8; ED25519_PK_LEN] = common::arr(h);
        let hits = (0u8..64)
            .filter(|i| ed25519_verify(&e, &[*i], &sig).is_ok())
            .count();
        assert!(hits > 0, "row {h} verified no message");
    }
}
