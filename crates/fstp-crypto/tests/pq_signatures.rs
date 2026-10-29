//! I-75 and I-90 for the M3 `mldsa` and `composite` modules (design
//! sections 2.2 and 7.4, ADR-001 A2 "ML-DSA-65", ADR-010, T-CR-COMPOSITE
//! for TH-67, T-CR-MLDSA for TH-68).
//!
//! moduletto at the pinned commit `46754f2` has no ML-DSA-65. Its pull
//! request crabnebula-dev/moduletto#13 is open and unmerged. Until it
//! lands, every `mldsa` call refuses with `CryptoError::MlDsaUnavailable`,
//! composite key generation and signing refuse the same way, and composite
//! verification refuses too. Nothing falls back to an Ed25519-only
//! signature or to the aws-lc-rs ML-DSA, which is a test oracle only.
//!
//! The API under test, as this file expects it:
//!
//! ```text
//! fstp_crypto::CryptoError::MlDsaUnavailable
//! fstp_crypto::mldsa::PUBLIC_KEY_LEN: usize   // 1952 (FIPS 204, ML-DSA-65)
//! fstp_crypto::mldsa::SIGNATURE_LEN: usize    // 3309 (FIPS 204, ML-DSA-65)
//! fstp_crypto::mldsa::MlDsa65SigningKey
//! fstp_crypto::mldsa::generate() -> Result<MlDsa65SigningKey, CryptoError>
//! fstp_crypto::mldsa::verify(public_key: &[u8], message: &[u8], signature: &[u8])
//!     -> Result<(), CryptoError>
//! fstp_crypto::composite::PUBLIC_KEY_LEN: usize   // from draft-ietf-lamps-pq-composite-sigs-19
//! fstp_crypto::composite::SIGNATURE_LEN: usize    // from draft-ietf-lamps-pq-composite-sigs-19
//! fstp_crypto::composite::CompositeSigningKey
//! fstp_crypto::composite::generate() -> Result<CompositeSigningKey, CryptoError>
//! fstp_crypto::composite::CompositeSigningKey::sign(&self, message: &[u8])
//!     -> Result<CompositeSignature, CryptoError>
//! fstp_crypto::composite::verify(public_key: &[u8], message: &[u8], signature: &[u8])
//!     -> Result<(), CryptoError>
//! ```
//!
//! ADR-010 has not yet transcribed the composite encoding from draft 19,
//! so this file fixes no layout. It places a valid Ed25519 half at every
//! offset a concatenation could use.
//!
//! When the moduletto pull request lands and the pin moves, the `i75_*`
//! refusal tests here are replaced by the ACVP and differential ML-DSA-65
//! tests. The `i90_*` tests stay.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use fstp_crypto::CryptoError;
use fstp_crypto::composite;
use fstp_crypto::mldsa;
use fstp_crypto::sig::{Ed25519SigningKey, ed25519_verify};
use fstp_prop::{Config, check_with, prop_assert};

fn unavailable<T>(r: &Result<T, CryptoError>) -> bool {
    matches!(r, Err(CryptoError::MlDsaUnavailable))
}

/// FIPS 204 Table 2 sizes for ML-DSA-65.
#[test]
fn i75_mldsa_65_sizes() {
    assert_eq!(mldsa::PUBLIC_KEY_LEN, 1952);
    assert_eq!(mldsa::SIGNATURE_LEN, 3309);
}

/// I-75, ADR-001 A2: ML-DSA-65 key generation refuses with the typed
/// error while moduletto has no ML-DSA-65.
#[test]
fn i75_mldsa_generate_refuses_while_moduletto_has_no_mldsa() {
    assert!(unavailable(&mldsa::generate()));
}

/// I-75, ADR-001 A2: ML-DSA-65 verification refuses every input with the
/// typed error, whatever its lengths.
#[test]
fn i75_mldsa_verify_refuses_every_input() {
    check_with(
        "i75_mldsa_verify_refuses_every_input",
        Config::default().with_cases(256),
        |g| {
            let exact = g.bool();
            let pk = if exact {
                g.bytes(mldsa::PUBLIC_KEY_LEN..=mldsa::PUBLIC_KEY_LEN)
            } else {
                g.bytes(0..=64)
            };
            let sig = if exact {
                g.bytes(mldsa::SIGNATURE_LEN..=mldsa::SIGNATURE_LEN)
            } else {
                g.bytes(0..=64)
            };
            let msg = g.bytes(0..=64);
            prop_assert!(unavailable(&mldsa::verify(&pk, &msg, &sig)));
            Ok(())
        },
    );
}

/// I-75, I-90, design section 7.4: composite key generation refuses with
/// the typed error, so no composite signing key and no composite
/// signature can exist yet. No Ed25519-only key stands in for one.
#[test]
fn i90_composite_generate_refuses_while_moduletto_has_no_mldsa() {
    assert!(unavailable(&composite::generate()));
}

/// The candidate encodings of a composite public key and signature that
/// carry a valid Ed25519 half and an ML-DSA half that is not a signature:
/// the bare Ed25519 values, and the Ed25519 value at the start or at the
/// end of a composite-length buffer, the rest `fill`.
fn ed25519_only_candidates(pk: &[u8; 32], sig: &[u8; 64], fill: u8) -> Vec<(Vec<u8>, Vec<u8>)> {
    let place = |len: usize, part: &[u8], at_start: bool| {
        let mut b = vec![fill; len.max(part.len())];
        let at = if at_start { 0 } else { b.len() - part.len() };
        b[at..at + part.len()].copy_from_slice(part);
        b
    };
    let mut out = vec![(pk.to_vec(), sig.to_vec())];
    for pk_start in [true, false] {
        for sig_start in [true, false] {
            out.push((
                place(composite::PUBLIC_KEY_LEN, pk, pk_start),
                place(composite::SIGNATURE_LEN, sig, sig_start),
            ));
        }
    }
    out
}

/// I-90: a composite signature verifies only when both halves verify. A
/// valid Ed25519 signature alone, in any position a concatenation could
/// use and with any ML-DSA filler, is refused.
#[test]
fn i90_composite_verify_refuses_an_ed25519_half_alone() {
    let key = Ed25519SigningKey::generate().unwrap();
    let pk = key.public_key();
    check_with(
        "i90_composite_verify_refuses_an_ed25519_half_alone",
        Config::default().with_cases(64),
        |g| {
            let msg = g.bytes(0..=64);
            let sig = key.sign(&msg).unwrap();
            prop_assert!(ed25519_verify(&pk, &msg, &sig).is_ok());
            let fill = g.u8();
            for (cpk, csig) in ed25519_only_candidates(&pk, &sig, fill) {
                let r = composite::verify(&cpk, &msg, &csig);
                prop_assert!(
                    r.is_err(),
                    "composite verify accepted an Ed25519 half alone ({} and {} bytes)",
                    cpk.len(),
                    csig.len()
                );
            }
            Ok(())
        },
    );
}

/// I-75, ADR-001 A2: while ML-DSA-65 is unavailable, composite
/// verification refuses with the typed error, so a caller can tell the
/// seam from a bad signature. A valid Ed25519 half does not change that.
#[test]
fn i75_composite_verify_refuses_while_moduletto_has_no_mldsa() {
    let key = Ed25519SigningKey::generate().unwrap();
    let pk = key.public_key();
    let sig = key.sign(b"anchor").unwrap();
    for (cpk, csig) in ed25519_only_candidates(&pk, &sig, 0) {
        assert!(unavailable(&composite::verify(&cpk, b"anchor", &csig)));
    }
    assert!(unavailable(&composite::verify(&[], b"", &[])));
}
