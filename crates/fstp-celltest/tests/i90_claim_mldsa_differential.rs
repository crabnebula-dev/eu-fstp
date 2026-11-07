//! The M9 claim run of the ML-DSA-65 differential tests (M9 design
//! sections 1.1 and 3, lane C1, I-90, T-CR-MLDSA, TH-68).
//!
//! Each direction runs on at least [`CLAIM_CASES`] random inputs. A larger
//! `FSTP_PROP_CASES` raises the count, and a smaller one never lowers it.
//!
//! Implementations, for the exit report:
//! - code under test: moduletto at the pinned commit `6c1ae92`, reached
//!   through `fstp_crypto::mldsa::acvp`;
//! - oracle: the aws-lc-rs ML-DSA-65 of `fstp_celltest::reference::hybrid`
//!   (ADR-001 A6), a test oracle only, never a fallback (I-75).
//!
//! The ACVP vectors run in `crates/fstp-crypto/tests/mldsa_acvp.rs`
//! against moduletto, and in `reference::hybrid` against both.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::reference::hybrid::{MLDSA65_SIG_LEN, OracleMlDsa65, oracle_mldsa65_verify};
use fstp_crypto::CryptoError;
use fstp_prop::{Config, Gen, Outcome, prop_assert, prop_assert_eq, run};

/// The least number of random inputs per direction in the claim run.
const CLAIM_CASES: u32 = 1000;

/// Runs `prop` on at least [`CLAIM_CASES`] cases and fails unless every
/// case passed and the count was reached.
fn claim(name: &str, prop: impl Fn(&mut Gen) -> Result<(), String>) {
    let cfg = Config::default().with_env();
    let cases = cfg.cases.max(CLAIM_CASES);
    match run(name, cfg.with_cases(cases), prop) {
        Outcome::Passed { cases: ran } => assert!(ran >= CLAIM_CASES, "{name}: {ran} cases"),
        Outcome::Failed(f) => panic!("{f}"),
    }
}

fn random32() -> [u8; 32] {
    fstp_crypto::random_array().unwrap()
}

/// I-90, T-CR-MLDSA claim run: moduletto signs, aws-lc-rs verifies. Keys
/// derived from one random seed are equal under both. Every moduletto
/// signature over a random message verifies under the oracle, and fails
/// over the message with one bit flipped.
#[test]
fn i90_claim_moduletto_signs_aws_lc_rs_verifies_1000() {
    claim("i90_claim_moduletto_signs_aws_lc_rs_verifies_1000", |g| {
        let seed: [u8; 32] = g.bytes(32..=32).try_into().unwrap();
        let msg = g.bytes(1..=512);
        let bit = g.usize_in(0..=msg.len() * 8 - 1);
        let (pk, sk) = fstp_crypto::mldsa::acvp::keygen(&seed).unwrap();
        let oracle = OracleMlDsa65::from_seed(&seed).unwrap();
        prop_assert_eq!(pk.to_vec(), oracle.public_key());
        let sig = fstp_crypto::mldsa::acvp::sign(&sk[..], &msg, b"", &random32()).unwrap();
        prop_assert!(oracle_mldsa65_verify(&pk, &msg, &sig));
        let mut flipped = msg.clone();
        flipped[bit / 8] ^= 1 << (bit % 8);
        prop_assert!(!oracle_mldsa65_verify(&pk, &flipped, &sig));
        Ok(())
    });
}

/// I-90, T-CR-MLDSA claim run: aws-lc-rs signs, moduletto verifies. Every
/// oracle signature over a random message verifies under moduletto with
/// an empty context. One flipped bit of the signature, or a one-byte
/// context, gives `InvalidSignature`.
#[test]
fn i90_claim_aws_lc_rs_signs_moduletto_verifies_1000() {
    claim("i90_claim_aws_lc_rs_signs_moduletto_verifies_1000", |g| {
        let seed: [u8; 32] = g.bytes(32..=32).try_into().unwrap();
        let msg = g.bytes(0..=512);
        let bit = g.usize_in(0..=MLDSA65_SIG_LEN * 8 - 1);
        let oracle = OracleMlDsa65::from_seed(&seed).unwrap();
        let (pk, sig) = (oracle.public_key(), oracle.sign(&msg).unwrap());
        let verify = |ctx: &[u8], s: &[u8]| fstp_crypto::mldsa::acvp::verify(&pk, &msg, ctx, s);
        prop_assert_eq!(verify(b"", &sig), Ok(()));
        let mut flipped = sig.clone();
        flipped[bit / 8] ^= 1 << (bit % 8);
        prop_assert_eq!(verify(b"", &flipped), Err(CryptoError::InvalidSignature));
        prop_assert_eq!(verify(b"x", &sig), Err(CryptoError::InvalidSignature));
        Ok(())
    });
}
