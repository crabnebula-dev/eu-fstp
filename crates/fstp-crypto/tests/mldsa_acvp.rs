//! The ML-DSA-65 ACVP subset through `fstp_crypto::mldsa` (moduletto),
//! T-CR-MLDSA for TH-68 (M3 design section 7.4, ADR-001 A2 and
//! "Post-quantum signatures", ADR-010 "Verification of ML-DSA-65"). The
//! test module `mldsa_acvp` of `fstp_celltest::reference::hybrid` runs the
//! differential tests against the aws-lc-rs oracle (layering rule 9).
//!
//! The vectors are `tests/data/ml_dsa_65_acvp.json`. They come from NIST
//! ACVP-Server commit `975de31eb83d87039ec88934fdc47d8c312b892d`,
//! `gen-val/json-files/ML-DSA-keyGen-FIPS204`, `ML-DSA-sigGen-FIPS204` and
//! `ML-DSA-sigVer-FIPS204`. They are records moduletto extracted verbatim
//! into `tests/kat/ml_dsa_65_{keygen,siggen,sigver}_fips204.txt` at its
//! pinned commit `6c1ae92`, reformatted as JSON with the ACVP field names
//! and read here with `fstp-json`. The subset holds:
//!
//! - keyGen: all 25 ML-DSA-65 cases, tcId 26 to 50.
//! - sigGen: 11 cases of the external pure interface (FIPS 204 Algorithm
//!   2), 6 deterministic (tcId 31, 35, 37, 40, 41, 44) and 5 hedged (tcId
//!   212 to 216). tcId 44 and 216 have an empty context, tcId 41 and 214
//!   a one-byte message.
//! - sigVer: all 15 cases of the external pure interface (Algorithm 3),
//!   tcId 31 to 45: 3 that pass, and 12 with a modified message, `z`, hint
//!   or commitment.
//!
//! Only the external pure interface is used here, since it is the one the
//! composite calls (draft 19 section 3.2 step 4). The internal and
//! external-mu interfaces, and HashML-DSA, have no entry point in
//! `fstp-crypto`. moduletto's own tests run its internal and mu cases.
//!
//! The API under test, as this file expects it. The W0 stub lacks the
//! hidden `acvp` module, so this file does not compile until the
//! production lane adds it:
//!
//! ```text
//! fstp_crypto::mldsa::PUBLIC_KEY_LEN: usize   // 1952 (FIPS 204 Table 2)
//! fstp_crypto::mldsa::SIGNATURE_LEN: usize    // 3309 (FIPS 204 Table 2)
//! fstp_crypto::mldsa::SEED_LEN: usize         // 32
//! // The single-half entry points, for known answers and differential
//! // tests only, like `mlkem::acvp`. Hidden from the docs. The I-75 scans
//! // refuse them outside `fstp-crypto` and `fstp-celltest`.
//! // FIPS 204 ML-DSA.KeyGen_internal(xi): (pk, expanded sk).
//! fstp_crypto::mldsa::acvp::keygen(xi: &[u8; 32])
//!     -> Result<([u8; 1952], zeroize::Zeroizing<[u8; 4032]>), CryptoError>
//! // FIPS 204 ML-DSA.Sign(sk, M, ctx) with rnd given (Algorithm 2).
//! fstp_crypto::mldsa::acvp::sign(sk: &[u8], message: &[u8], ctx: &[u8], rnd: &[u8; 32])
//!     -> Result<[u8; 3309], CryptoError>
//! // FIPS 204 ML-DSA.Verify(pk, M, sigma, ctx) (Algorithm 3).
//! fstp_crypto::mldsa::acvp::verify(pk: &[u8], message: &[u8], ctx: &[u8], signature: &[u8])
//!     -> Result<(), CryptoError>
//! ```
//!
//! A signature that does not verify gives `CryptoError::InvalidSignature`.
//! A key of the wrong length, or a context over 255 bytes, gives an error
//! and never a signature or an acceptance.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::hex;
use fstp_crypto::CryptoError;
use fstp_crypto::mldsa::{self, acvp};
use fstp_json::Value;

const VECTORS: &str = include_str!("data/ml_dsa_65_acvp.json");

fn vectors() -> Value {
    fstp_json::parse_str(VECTORS).expect("the ACVP subset parses")
}

/// The test cases of one group, with a fixed expected count.
fn group(v: &Value, name: &str, count: usize) -> Vec<Value> {
    let cases = v
        .get(name)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("group {name} missing"));
    assert_eq!(cases.len(), count, "group {name}");
    cases.iter().cloned().collect()
}

fn field(case: &Value, name: &str) -> Vec<u8> {
    hex(case
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("field {name} missing")))
}

fn field32(case: &Value, name: &str) -> [u8; 32] {
    field(case, name).try_into().expect("32-byte field")
}

fn flag(case: &Value, name: &str) -> bool {
    case.get(name)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("field {name} missing"))
}

fn tc(case: &Value) -> u64 {
    case.get("tcId").and_then(Value::as_u64).expect("tcId")
}

/// T-CR-MLDSA: the provenance fields name the pinned ACVP-Server and
/// moduletto commits, and the subset has the documented cases.
#[test]
fn t_cr_mldsa_acvp_subset_is_the_pinned_one() {
    let v = vectors();
    let text = |name: &str| v.get(name).and_then(Value::as_str).unwrap().to_string();
    assert_eq!(text("commit"), "975de31eb83d87039ec88934fdc47d8c312b892d");
    assert_eq!(text("parameterSet"), "ML-DSA-65");
    assert_eq!(text("signatureInterface"), "external");
    assert_eq!(text("preHash"), "pure");
    assert!(
        text("extractedVia").starts_with("moduletto 6c1ae92f2bf14eb56b5d48d1e7fc6f7ca5843683 ")
    );
    let ids = |name: &str, n: usize| group(&v, name, n).iter().map(tc).collect::<Vec<_>>();
    assert_eq!(ids("keyGen", 25), (26..=50).collect::<Vec<u64>>());
    assert_eq!(
        ids("sigGen", 11),
        [31, 35, 37, 40, 41, 44, 212, 213, 214, 215, 216]
    );
    assert_eq!(ids("sigVer", 15), (31..=45).collect::<Vec<u64>>());
    assert_eq!(
        (mldsa::PUBLIC_KEY_LEN, mldsa::SIGNATURE_LEN, mldsa::SEED_LEN),
        (1952, 3309, 32)
    );
}

/// T-CR-MLDSA, TH-68: ACVP keyGen. `ML-DSA.KeyGen_internal(xi)` gives the
/// published `pk` and `sk`, through moduletto's `keygen_internal`.
#[test]
fn t_cr_mldsa_acvp_keygen() {
    for case in group(&vectors(), "keyGen", 25) {
        let (pk, sk) = acvp::keygen(&field32(&case, "seed")).unwrap();
        assert_eq!(pk.to_vec(), field(&case, "pk"), "tcId {}", tc(&case));
        assert_eq!(sk[..].to_vec(), field(&case, "sk"), "tcId {}", tc(&case));
    }
}

/// T-CR-MLDSA, TH-68: ACVP sigGen. `ML-DSA.Sign(sk, M, ctx)` with the
/// record's `rnd` (32 zero bytes for a deterministic case) gives the
/// published signature, which then verifies.
#[test]
fn t_cr_mldsa_acvp_siggen() {
    for case in group(&vectors(), "sigGen", 11) {
        let id = tc(&case);
        let rnd = field32(&case, "rnd");
        assert_eq!(
            flag(&case, "deterministic"),
            rnd == [0u8; 32],
            "tcId {id}: a deterministic case signs with zero rnd"
        );
        let (msg, ctx) = (field(&case, "message"), field(&case, "context"));
        let sig = acvp::sign(&field(&case, "sk"), &msg, &ctx, &rnd).unwrap();
        assert_eq!(sig.to_vec(), field(&case, "signature"), "tcId {id}");
        assert_eq!(
            acvp::verify(&field(&case, "pk"), &msg, &ctx, &sig),
            Ok(()),
            "tcId {id}"
        );
    }
}

/// T-CR-MLDSA, TH-68: ACVP sigVer. Exactly the cases marked as passing
/// verify. Every other case, with a modified message, `z`, hint or
/// commitment, gives `InvalidSignature`.
#[test]
fn t_cr_mldsa_acvp_sigver() {
    for case in group(&vectors(), "sigVer", 15) {
        let id = tc(&case);
        let got = acvp::verify(
            &field(&case, "pk"),
            &field(&case, "message"),
            &field(&case, "context"),
            &field(&case, "signature"),
        );
        let want = if flag(&case, "testPassed") {
            Ok(())
        } else {
            Err(CryptoError::InvalidSignature)
        };
        assert_eq!(got, want, "tcId {id}");
    }
}

/// TH-68: no single-bit flip of an ACVP sigGen signature, its message or
/// its context verifies. A bit of every byte flips, the bit position
/// rotating with the byte index.
#[test]
fn th_68_mldsa_rejects_bit_flips_of_acvp_signatures() {
    for case in group(&vectors(), "sigGen", 11).iter().take(3) {
        let id = tc(case);
        let (pk, msg, ctx) = (
            field(case, "pk"),
            field(case, "message"),
            field(case, "context"),
        );
        let sig = field(case, "signature");
        assert_eq!(acvp::verify(&pk, &msg, &ctx, &sig), Ok(()), "tcId {id}");
        for i in 0..sig.len() {
            let mut s = sig.clone();
            s[i] ^= 1 << (i % 8);
            assert!(
                acvp::verify(&pk, &msg, &ctx, &s).is_err(),
                "tcId {id} sig byte {i}"
            );
        }
        for i in 0..msg.len() {
            let mut m = msg.clone();
            m[i] ^= 1 << (i % 8);
            assert!(
                acvp::verify(&pk, &m, &ctx, &sig).is_err(),
                "tcId {id} msg byte {i}"
            );
        }
        for i in 0..ctx.len() {
            let mut c = ctx.clone();
            c[i] ^= 1 << (i % 8);
            assert!(
                acvp::verify(&pk, &msg, &c, &sig).is_err(),
                "tcId {id} ctx byte {i}"
            );
        }
    }
}

/// TH-68, FIPS 204 section 3.6.2: keys and signatures of any other length
/// are refused. A wrong-length key never signs, and a wrong-length key or
/// signature never verifies.
#[test]
fn th_68_mldsa_refuses_wrong_lengths() {
    let case = &group(&vectors(), "sigGen", 11)[0];
    let (pk, sk, sig) = (
        field(case, "pk"),
        field(case, "sk"),
        field(case, "signature"),
    );
    let (msg, ctx) = (field(case, "message"), field(case, "context"));
    let rnd = field32(case, "rnd");
    assert_eq!(acvp::verify(&pk, &msg, &ctx, &sig), Ok(()));
    for len in [
        0,
        32,
        1312,
        mldsa::PUBLIC_KEY_LEN - 1,
        mldsa::PUBLIC_KEY_LEN + 1,
        2592,
    ] {
        let mut k = pk.clone();
        k.resize(len, 0);
        assert!(
            acvp::verify(&k, &msg, &ctx, &sig).is_err(),
            "pk of {len} bytes"
        );
    }
    for len in [
        0,
        64,
        2420,
        mldsa::SIGNATURE_LEN - 1,
        mldsa::SIGNATURE_LEN + 1,
        4627,
    ] {
        let mut s = sig.clone();
        s.resize(len, 0);
        assert!(
            acvp::verify(&pk, &msg, &ctx, &s).is_err(),
            "sig of {len} bytes"
        );
    }
    for len in [0, 32, 2560, 4031, 4033, 4896] {
        let mut k = sk.clone();
        k.resize(len, 0);
        assert!(
            acvp::sign(&k, &msg, &ctx, &rnd).is_err(),
            "sk of {len} bytes"
        );
    }
}

/// TH-68, FIPS 204 Algorithms 2 and 3 line 1: a context of 255 bytes
/// signs and verifies, and one of 256 bytes is refused by both.
#[test]
fn th_68_mldsa_refuses_contexts_over_255_bytes() {
    let case = &group(&vectors(), "keyGen", 25)[0];
    let (pk, sk) = acvp::keygen(&field32(case, "seed")).unwrap();
    let rnd = [0u8; 32];
    let ctx = vec![0xa5; 255];
    let sig = acvp::sign(&sk[..], b"anchor", &ctx, &rnd).unwrap();
    assert_eq!(acvp::verify(&pk, b"anchor", &ctx, &sig), Ok(()));
    let long = vec![0xa5; 256];
    assert!(acvp::sign(&sk[..], b"anchor", &long, &rnd).is_err());
    assert!(acvp::verify(&pk, b"anchor", &long, &sig).is_err());
}

/// TH-68: hedged signing. Two signatures over the same message with
/// different `rnd` differ and both verify. With zero `rnd` signing is
/// deterministic, so the ACVP deterministic cases above are reproducible.
#[test]
fn th_68_mldsa_rnd_selects_hedged_or_deterministic_signing() {
    let case = &group(&vectors(), "keyGen", 25)[1];
    let (pk, sk) = acvp::keygen(&field32(case, "seed")).unwrap();
    let a = acvp::sign(&sk[..], b"anchor", b"", &[1; 32]).unwrap();
    let b = acvp::sign(&sk[..], b"anchor", b"", &[2; 32]).unwrap();
    assert_ne!(a, b);
    assert_eq!(acvp::verify(&pk, b"anchor", b"", &a), Ok(()));
    assert_eq!(acvp::verify(&pk, b"anchor", b"", &b), Ok(()));
    let d1 = acvp::sign(&sk[..], b"anchor", b"", &[0; 32]).unwrap();
    let d2 = acvp::sign(&sk[..], b"anchor", b"", &[0; 32]).unwrap();
    assert_eq!(d1, d2);
}
