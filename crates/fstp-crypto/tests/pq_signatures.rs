//! I-75 and I-90 for the M3 `mldsa` and `composite` modules (design
//! sections 2.2 and 7.4, ADR-001 A2 "ML-DSA-65", ADR-010, T-CR-COMPOSITE
//! for TH-67, T-CR-MLDSA for TH-68).
//!
//! moduletto is pinned at commit `6c1ae92`, the merge of its ML-DSA-65
//! pull request crabnebula-dev/moduletto#13 (ADR-001 A2 pin move record
//! of 2026-10-29). The W0 refusal tests of this file are therefore
//! replaced, as it announced:
//!
//! - `i75_mldsa_generate_refuses_while_moduletto_has_no_mldsa`,
//!   `i75_mldsa_verify_refuses_every_input` and
//!   `i75_composite_verify_refuses_while_moduletto_has_no_mldsa` give way
//!   to the ACVP subset in `mldsa_acvp.rs`, the draft 19 vector tests in
//!   `composite_draft19.rs` and the differential tests in the `mldsa_acvp`
//!   test module of `fstp_celltest::reference::hybrid`.
//! - `i90_composite_generate_refuses_while_moduletto_has_no_mldsa` gives
//!   way to `i90_composite_generate_gives_a_key_with_both_halves` in
//!   `composite_api.rs`. Its claim, that no Ed25519-only key stands in for
//!   a composite one, is checked there on a working key.
//!
//! The second item deviates from the plan this file recorded at W0, which
//! said the `i90_*` tests stay. The old test asserted the stub's refusal,
//! which cannot hold once composite key generation works. Its I-90 claim
//! is kept, on a working key, by the test named above. The deviation is
//! reported to Daniel in the M3 milestone report.
//!
//! What stays here is the FIPS 204 size check and the I-90 test that a
//! valid Ed25519 signature alone never verifies as a composite, in any
//! position a concatenation could put it. ADR-010 now fixes the draft 19
//! layout, `mldsaSig || tradSig`, but the test keeps every position so it
//! does not depend on the layout. The I-75 source scans are in
//! `source_scans.rs`, unchanged.
//!
//! The API under test, as this file expects it:
//!
//! ```text
//! fstp_crypto::mldsa::PUBLIC_KEY_LEN: usize   // 1952 (FIPS 204, ML-DSA-65)
//! fstp_crypto::mldsa::SIGNATURE_LEN: usize    // 3309 (FIPS 204, ML-DSA-65)
//! fstp_crypto::composite::PUBLIC_KEY_LEN: usize   // 1984, draft 19 Appendix A
//! fstp_crypto::composite::SIGNATURE_LEN: usize    // 3373, draft 19 Appendix A
//! fstp_crypto::composite::verify(public_key: &[u8], message: &[u8], signature: &[u8])
//!     -> Result<(), CryptoError>
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use fstp_crypto::composite;
use fstp_crypto::mldsa;
use fstp_crypto::sig::{Ed25519SigningKey, ed25519_verify};
use fstp_prop::{Config, check_with, prop_assert};

/// FIPS 204 Table 2 sizes for ML-DSA-65.
#[test]
fn i75_mldsa_65_sizes() {
    assert_eq!(mldsa::PUBLIC_KEY_LEN, 1952);
    assert_eq!(mldsa::SIGNATURE_LEN, 3309);
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
