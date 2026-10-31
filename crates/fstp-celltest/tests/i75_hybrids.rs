//! I-75: moduletto is always used in a hybrid with a classical primitive:
//! ML-KEM with X25519, ML-DSA with Ed25519. Nothing relies on a moduletto
//! primitive alone (design section 14.5, T-CR-HYBRID, TH-50, TH-68).
//!
//! These tests check behaviour through the public hybrids: the shared
//! secret of the hybrid KEM depends on both halves, a sealed key needs
//! both secret halves, and a composite signature needs both signatures.
//! The source scans of the rule live with `fstp-crypto` (lane W1h).
//!
//! Lane W1d wrote these tests before the production code. The ML-KEM
//! test runs now. The ML-DSA test is red until `fstp_crypto::composite`
//! calls moduletto's ML-DSA-65 (lane dsa), and the sealed key test until
//! `fstp_keys::envelope` (lane W2f) lands.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use fstp_celltest::reference::hybrid::{self as rh, OracleMlKem};
use fstp_crypto::composite;
use fstp_crypto::hybrid_kem::{self, HybridCiphertext, HybridSecretKey};
use fstp_keys::envelope::SealContext;
use fstp_keys::{CellId, Chain, GroupId, ObjectId, Purpose};
use fstp_prop::{Gen, prop_assert, prop_assert_eq, prop_assert_ne};

/// The X25519 agreement of the raw secret `sk` with the public `e`,
/// through the aws-lc-rs oracle.
fn oracle_x25519(sk: &[u8], e: &[u8]) -> [u8; 32] {
    let k = PrivateKey::from_private_key(&X25519, sk).unwrap();
    agreement::agree(
        &k,
        UnparsedPublicKey::new(&X25519, e),
        "X25519 agreement",
        |s| {
            let mut out = [0u8; 32];
            out.copy_from_slice(s);
            Ok(out)
        },
    )
    .unwrap()
}

/// I-75, T-CR-HYBRID: the hybrid shared secret is the ADR-004 combiner
/// over both halves, as the oracles compute them. It differs from either
/// half alone, and it changes when either half of the ciphertext is
/// replaced by another valid one. So no caller of `hybrid_kem` gets a
/// secret that ML-KEM alone, or X25519 alone, decides.
#[test]
fn i75_mlkem_never_used_without_x25519() {
    fstp_prop::check("i75_mlkem_never_used_without_x25519", |_g: &mut Gen| {
        let sk = hybrid_kem::generate().map_err(|e| e.to_string())?;
        let pk = sk.public().to_bytes();
        let (ct, ss) = hybrid_kem::encapsulate(sk.public()).map_err(|e| e.to_string())?;
        let ct_bytes = ct.to_bytes();
        let (e, ct_m) = ct_bytes.split_at(32);
        let secret = sk.to_bytes();
        let (sk_x, dk_m) = secret.split_at(32);
        let ss_m = OracleMlKem::from_decaps_key(dk_m)
            .and_then(|o| o.decapsulate(ct_m))
            .map_err(|e| e.0.to_owned())?;
        let ss_x = oracle_x25519(sk_x, e);
        let (pk_x, pk_m) = pk.split_at(32);
        let want = rh::combine(
            &ss_m,
            &ss_x,
            ct_m.try_into().unwrap(),
            e.try_into().unwrap(),
            pk_x.try_into().unwrap(),
            pk_m.try_into().unwrap(),
        );
        prop_assert_eq!(*ss.expose(), want, "not the combiner over both halves");
        prop_assert_ne!(*ss.expose(), ss_m, "the ML-KEM half alone");
        prop_assert_ne!(*ss.expose(), ss_x, "the X25519 half alone");

        let (other, _) = hybrid_kem::encapsulate(sk.public()).map_err(|e| e.to_string())?;
        let other = other.to_bytes();
        let mut swap_x = ct_bytes;
        swap_x[..32].copy_from_slice(&other[..32]);
        let mut swap_m = ct_bytes;
        swap_m[32..].copy_from_slice(&other[32..]);
        for (half, bytes) in [("X25519", swap_x), ("ML-KEM", swap_m)] {
            let ct2 = HybridCiphertext::from_bytes(&bytes).map_err(|e| e.to_string())?;
            let ss2 = hybrid_kem::decapsulate(&sk, &ct2).map_err(|e| e.to_string())?;
            prop_assert!(
                ss2.expose() != ss.expose(),
                "replacing the {half} half kept the secret"
            );
        }
        Ok(())
    });
}

/// I-75, T-CR-HYBRID, TH-68: a composite signature verifies only with
/// both halves. A fresh composite key signs and verifies, and a change to
/// any byte of the signature, or a zeroed first or last 64 bytes (where
/// the Ed25519 half of a concatenated signature sits), fails to verify.
#[test]
fn i75_mldsa_never_used_without_ed25519() {
    let key = composite::generate()
        .unwrap_or_else(|e| panic!("composite::generate: {e} (ML-DSA-65 not wired yet)"));
    fstp_prop::check("i75_mldsa_never_used_without_ed25519", |g: &mut Gen| {
        let message = g.bytes(0..=64);
        let sig = key.sign(&message).map_err(|e| e.to_string())?.to_bytes();
        let pk = composite_public_key(&key)?;
        prop_assert!(
            composite::verify(&pk, &message, &sig).is_ok(),
            "own signature"
        );
        let at = g.usize_in(0..=sig.len() - 1);
        let mut flipped = sig;
        flipped[at] ^= g.u8_in(1..=255);
        prop_assert!(
            composite::verify(&pk, &message, &flipped).is_err(),
            "byte {at} changed and the signature still verifies"
        );
        let n = sig.len();
        for range in [0..64, n - 64..n] {
            let mut zeroed = sig;
            zeroed[range.clone()].fill(0);
            prop_assert!(
                composite::verify(&pk, &message, &zeroed).is_err(),
                "bytes {range:?} zeroed and the signature still verifies"
            );
        }
        Ok(())
    });
}

/// The seam of [`composite_public_key`], a test-side seam: a composite
/// signing key gives no public key yet. `fstp_crypto::composite` has
/// `CompositePublicKey::to_bytes`, but `CompositeSigningKey` has no call
/// that returns its `CompositePublicKey`. Lane dsa adds that accessor with
/// the ML-DSA-65 wiring. This helper then returns
/// `key.<accessor>().to_bytes().to_vec()`, and this test file needs that
/// one edit before the test becomes a real check.
const COMPOSITE_PK_SEAM: &str = "test-side seam: fstp_crypto::composite::CompositeSigningKey has no accessor for its CompositePublicKey yet (lane dsa); edit composite_public_key in tests/i75_hybrids.rs once it lands";

fn composite_public_key(key: &composite::CompositeSigningKey) -> Result<Vec<u8>, String> {
    let _ = key;
    Err(COMPOSITE_PK_SEAM.to_owned())
}

/// `fstp_keys::envelope::seal_key` (design section 3.2, lane W2f), as the
/// sealed key's bytes.
fn prod_seal_key(
    pk: &hybrid_kem::HybridPublicKey,
    dek: &[u8; 32],
    ctx: &SealContext,
) -> Result<Vec<u8>, String> {
    let dek = fstp_keys::envelope::DataKey::from_bytes(dek).map_err(|e| format!("{e:?}"))?;
    let sealed = fstp_keys::envelope::seal_key(pk, &dek, ctx).map_err(|e| format!("{e:?}"))?;
    fstp_keys::envelope::encode_sealed_key(&sealed).map_err(|e| format!("{e:?}"))
}

/// `fstp_keys::envelope::open_key` over the decoded bytes, as key bytes.
fn prod_open_key(
    sk: &HybridSecretKey,
    sealed: &[u8],
    ctx: &SealContext,
) -> Result<[u8; 32], String> {
    let sealed = fstp_keys::envelope::decode_sealed_key(sealed).map_err(|e| format!("{e:?}"))?;
    fstp_keys::envelope::open_key(sk, &sealed, ctx)
        .map(|k| *k.expose())
        .map_err(|e| format!("{e:?}"))
}

/// A secret key with the X25519 half of `x` and the ML-KEM half of `m`.
fn mixed(x: &HybridSecretKey, m: &HybridSecretKey) -> HybridSecretKey {
    let (xb, mb) = (x.to_bytes(), m.to_bytes());
    let mut bytes = mb.to_vec();
    bytes[..32].copy_from_slice(&xb[..32]);
    HybridSecretKey::from_bytes(&bytes).unwrap()
}

/// I-75, ADR-004 test vector plan item 6 (`i75_sealed_key_needs_both_halves`):
/// a sealed key opens with its own secret key, and fails with a key whose
/// X25519 half is wrong or whose ML-KEM half is wrong.
#[test]
fn i75_sealed_key_needs_both_halves() {
    let ctx = SealContext {
        cell: CellId([1; 16]),
        chain: Chain::App,
        purpose: Purpose::Text,
        group: GroupId([2; 16]),
        generation: 1,
        object: ObjectId([3; 16]),
    };
    fstp_prop::check("i75_sealed_key_needs_both_halves", |g: &mut Gen| {
        let sk = hybrid_kem::generate().map_err(|e| e.to_string())?;
        let other = hybrid_kem::generate().map_err(|e| e.to_string())?;
        let dek: [u8; 32] = g.bytes(32..=32).try_into().unwrap();
        let sealed = prod_seal_key(sk.public(), &dek, &ctx)?;
        prop_assert_eq!(prod_open_key(&sk, &sealed, &ctx)?, dek);
        prop_assert!(
            prod_open_key(&mixed(&other, &sk), &sealed, &ctx).is_err(),
            "opened with a wrong X25519 half"
        );
        prop_assert!(
            prod_open_key(&mixed(&sk, &other), &sealed, &ctx).is_err(),
            "opened with a wrong ML-KEM half"
        );
        Ok(())
    });
}
