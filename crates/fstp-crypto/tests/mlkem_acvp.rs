//! The ML-KEM-768 ACVP subset through `fstp_crypto::mlkem` (moduletto),
//! ADR-001 Verification, ADR-004 test vector plan item 9, T-CR-HYBRID for
//! TH-50. The test module of `fstp_celltest::reference::hybrid` runs two
//! of the decapsulation cases through the aws-lc-rs oracle as well, and
//! holds the differential tests against that oracle (layering rule 9).
//!
//! The vectors are `tests/data/ml_kem_768_acvp.json`. They come from NIST
//! ACVP-Server commit `975de31eb83d87039ec88934fdc47d8c312b892d`,
//! `gen-val/json-files/ML-KEM-keyGen-FIPS203` and
//! `ML-KEM-encapDecap-FIPS203`. They are the ML-KEM-768 records moduletto
//! extracted verbatim at its pinned commit `46754f2`, reformatted as JSON
//! with the ACVP field names, and read here with `fstp-json`. The subset
//! holds 25 keyGen, 25 encapsulation and 10 decapsulation cases, and 10
//! cases each of the encapsulation and decapsulation key checks.
//!
//! The API under test, as this file expects it:
//!
//! ```text
//! fstp_crypto::mlkem::ENCAPS_KEY_LEN: usize   // 1184
//! fstp_crypto::mlkem::DECAPS_KEY_LEN: usize   // 2400, the expanded FIPS 203 form
//! fstp_crypto::mlkem::CIPHERTEXT_LEN: usize   // 1088
//! fstp_crypto::mlkem::MlKem768EncapsKey::from_bytes(&[u8]) -> Result<MlKem768EncapsKey, CryptoError>
//! fstp_crypto::mlkem::MlKem768EncapsKey::as_bytes(&self) -> &[u8; 1184]
//! fstp_crypto::mlkem::MlKem768DecapsKey::from_bytes(&[u8]) -> Result<MlKem768DecapsKey, CryptoError>
//! fstp_crypto::mlkem::MlKem768DecapsKey::to_bytes(&self) -> Zeroizing<[u8; 2400]>
//! fstp_crypto::mlkem::MlKem768DecapsKey::encaps_key(&self) -> MlKem768EncapsKey
//! fstp_crypto::mlkem::SharedSecret::expose(&self) -> &[u8; 32]
//! // The single-half entry points (moduletto keygen_derand, encaps_derand and
//! // decaps), for known answers and differential tests only. The plain
//! // single-half functions are crate-private (I-75).
//! fstp_crypto::mlkem::acvp::keygen(d: &[u8; 32], z: &[u8; 32]) -> Result<MlKem768DecapsKey, CryptoError>
//! fstp_crypto::mlkem::acvp::encapsulate(&MlKem768EncapsKey, m: &[u8; 32])
//!     -> Result<([u8; 1088], mlkem::SharedSecret), CryptoError>
//! fstp_crypto::mlkem::acvp::decapsulate(&MlKem768DecapsKey, &[u8; 1088])
//!     -> Result<mlkem::SharedSecret, CryptoError>
//! ```

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
use fstp_crypto::mlkem::{
    CIPHERTEXT_LEN, DECAPS_KEY_LEN, ENCAPS_KEY_LEN, MlKem768DecapsKey, MlKem768EncapsKey, acvp,
};
use fstp_json::Value;

const VECTORS: &str = include_str!("data/ml_kem_768_acvp.json");

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

fn tc(case: &Value) -> u64 {
    case.get("tcId").and_then(Value::as_u64).expect("tcId")
}

/// The provenance fields name the pinned ACVP-Server commit.
#[test]
fn t_cr_hybrid_mlkem_acvp_subset_is_the_pinned_one() {
    let v = vectors();
    assert_eq!(
        v.get("commit").and_then(Value::as_str),
        Some("975de31eb83d87039ec88934fdc47d8c312b892d")
    );
    assert_eq!(
        v.get("parameterSet").and_then(Value::as_str),
        Some("ML-KEM-768")
    );
    assert_eq!(
        (ENCAPS_KEY_LEN, DECAPS_KEY_LEN, CIPHERTEXT_LEN),
        (1184, 2400, 1088)
    );
}

/// ACVP keyGen: `ML-KEM.KeyGen_internal(d, z)` gives the published `ek`
/// and `dk`, through moduletto's `keygen_derand`.
#[test]
fn t_cr_hybrid_mlkem_acvp_keygen() {
    for case in group(&vectors(), "keyGen", 25) {
        let dk = acvp::keygen(&field32(&case, "d"), &field32(&case, "z")).unwrap();
        assert_eq!(
            dk.encaps_key().as_bytes().to_vec(),
            field(&case, "ek"),
            "tcId {}",
            tc(&case)
        );
        assert_eq!(
            dk.to_bytes()[..].to_vec(),
            field(&case, "dk"),
            "tcId {}",
            tc(&case)
        );
    }
}

/// ACVP encapsulation: `ML-KEM.Encaps_internal(ek, m)` gives the published
/// ciphertext `c` and key `k`, through moduletto's `encaps_derand`.
#[test]
fn t_cr_hybrid_mlkem_acvp_encapsulation() {
    for case in group(&vectors(), "encapsulation", 25) {
        let ek = MlKem768EncapsKey::from_bytes(&field(&case, "ek")).unwrap();
        let (c, k) = acvp::encapsulate(&ek, &field32(&case, "m")).unwrap();
        assert_eq!(c.to_vec(), field(&case, "c"), "tcId {}", tc(&case));
        assert_eq!(k.expose().to_vec(), field(&case, "k"), "tcId {}", tc(&case));
    }
}

/// ACVP decapsulation through `fstp_crypto::mlkem`, including the modified
/// ciphertexts whose `k` is the implicit-rejection key.
#[test]
fn t_cr_hybrid_mlkem_acvp_decapsulation() {
    for case in group(&vectors(), "decapsulation", 10) {
        let dk = MlKem768DecapsKey::from_bytes(&field(&case, "dk")).unwrap();
        let c: [u8; CIPHERTEXT_LEN] = field(&case, "c").try_into().unwrap();
        let k = acvp::decapsulate(&dk, &c).unwrap();
        assert_eq!(k.expose().to_vec(), field(&case, "k"), "tcId {}", tc(&case));
    }
}

/// ACVP encapsulationKeyCheck (FIPS 203 section 7.2): import accepts
/// exactly the keys marked as passing. A failing key has a coefficient
/// that is not below q.
#[test]
fn t_cr_hybrid_mlkem_acvp_encapsulation_key_check() {
    for case in group(&vectors(), "encapsulationKeyCheck", 10) {
        let passed = case.get("testPassed").and_then(Value::as_bool).unwrap();
        let got = MlKem768EncapsKey::from_bytes(&field(&case, "ek"));
        assert_eq!(got.is_ok(), passed, "tcId {}", tc(&case));
    }
}

/// ACVP decapsulationKeyCheck (FIPS 203 section 7.3): import accepts
/// exactly the keys marked as passing. A failing key carries a wrong hash
/// of its encapsulation key.
#[test]
fn t_cr_hybrid_mlkem_acvp_decapsulation_key_check() {
    for case in group(&vectors(), "decapsulationKeyCheck", 10) {
        let passed = case.get("testPassed").and_then(Value::as_bool).unwrap();
        let got = MlKem768DecapsKey::from_bytes(&field(&case, "dk"));
        assert_eq!(got.is_ok(), passed, "tcId {}", tc(&case));
    }
}

/// Keys and ciphertexts of any other length are refused, so no other
/// parameter set or truncated value is taken for ML-KEM-768.
#[test]
fn t_cr_hybrid_mlkem_refuses_wrong_lengths() {
    let v = vectors();
    let kg = &group(&v, "keyGen", 25)[0];
    let ek = field(kg, "ek");
    let dk = field(kg, "dk");
    for len in [0, 800, ENCAPS_KEY_LEN - 1, ENCAPS_KEY_LEN + 1] {
        let mut b = ek.clone();
        b.resize(len, 0);
        assert!(
            MlKem768EncapsKey::from_bytes(&b).is_err(),
            "ek length {len}"
        );
    }
    for len in [0, 1632, DECAPS_KEY_LEN - 1, DECAPS_KEY_LEN + 1] {
        let mut b = dk.clone();
        b.resize(len, 0);
        assert!(
            MlKem768DecapsKey::from_bytes(&b).is_err(),
            "dk length {len}"
        );
    }
    assert!(MlKem768EncapsKey::from_bytes(&ek).is_ok());
    assert!(MlKem768DecapsKey::from_bytes(&dk).is_ok());
}
