//! The M3 `hybrid_kem` module (design section 3.2, ADR-004 "Completion
//! part 1", T-CR-HYBRID for TH-50, I-75).
//!
//! The comparisons that need the aws-lc-rs oracle, the cross
//! implementation round trips of ADR-004 item 4 among them, live in the
//! test module of `fstp_celltest::reference::hybrid`. `fstp-crypto`
//! cannot depend on `fstp-celltest` (design section 2.4 rules 2, 6, 7
//! and 9), so this file checks production against the frozen vectors,
//! which it regenerates itself.
//!
//! The API under test, as this file expects it:
//!
//! ```text
//! fstp_crypto::hybrid_kem::PUBLIC_KEY_LEN: usize   // 1216 = pk_X || pk_M
//! fstp_crypto::hybrid_kem::CIPHERTEXT_LEN: usize   // 1120 = E || ct_M
//! fstp_crypto::hybrid_kem::generate() -> Result<HybridSecretKey, CryptoError>
//! fstp_crypto::hybrid_kem::HybridSecretKey::from_parts(x25519::StaticSecret, mlkem::MlKem768DecapsKey)
//!     -> Result<HybridSecretKey, CryptoError>
//! fstp_crypto::hybrid_kem::HybridSecretKey::public(&self) -> &HybridPublicKey
//! fstp_crypto::hybrid_kem::SECRET_KEY_LEN: usize   // 2432 = sk_X || dk_M
//! fstp_crypto::hybrid_kem::HybridSecretKey::to_bytes(&self) -> Zeroizing<[u8; 2432]>
//! fstp_crypto::hybrid_kem::HybridSecretKey::from_bytes(&[u8]) -> Result<HybridSecretKey, CryptoError>
//! fstp_crypto::x25519::StaticSecret::to_bytes(&self) -> Zeroizing<[u8; 32]>
//! fstp_crypto::hybrid_kem::HybridPublicKey::from_bytes(&[u8]) -> Result<HybridPublicKey, CryptoError>
//! fstp_crypto::hybrid_kem::HybridPublicKey::to_bytes(&self) -> [u8; 1216]
//! fstp_crypto::hybrid_kem::HybridCiphertext::from_bytes(&[u8]) -> Result<HybridCiphertext, CryptoError>
//! fstp_crypto::hybrid_kem::HybridCiphertext::to_bytes(&self) -> [u8; 1120]
//! fstp_crypto::hybrid_kem::encapsulate(&HybridPublicKey)
//!     -> Result<(HybridCiphertext, SharedSecret), CryptoError>
//! fstp_crypto::hybrid_kem::decapsulate(&HybridSecretKey, &HybridCiphertext)
//!     -> Result<SharedSecret, CryptoError>
//! fstp_crypto::hybrid_kem::combine(ss_m: &[u8; 32], ss_x: &[u8; 32], ct_m: &[u8; 1088],
//!     e: &[u8; 32], pk_x: &[u8; 32], pk_m: &[u8; 1184]) -> Result<SharedSecret, CryptoError>
//! fstp_crypto::hybrid_kem::SharedSecret::expose(&self) -> &[u8; 32]
//! ```
//!
//! Design section 3.2 shows `combine` as private. The fixed-input vectors
//! of ADR-004 item 2 test `combine` itself, so this file needs it public
//! (it may be `#[doc(hidden)]`). The design gives no way to rebuild a
//! secret key from its halves; `from_parts` is that way, and the keystore
//! needs one to open stored group secrets.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::fs;

use common::hex;
use common::hybrid_vectors::{COUNT, EXPECTED, Input, Inputs, binding_property, vector};
use fstp_crypto::hybrid_kem::{
    self, CIPHERTEXT_LEN, HybridCiphertext, HybridPublicKey, HybridSecretKey, PUBLIC_KEY_LEN,
    SharedSecret, combine, decapsulate, encapsulate,
};
use fstp_crypto::mlkem::{self, MlKem768DecapsKey};
use fstp_crypto::x25519::StaticSecret;
use fstp_prop::{Config, check_with, prop_assert, prop_assert_eq, prop_assert_ne, run};

fn production(v: &Inputs) -> [u8; 32] {
    let ss: SharedSecret = combine(&v.ss_m, &v.ss_x, &v.ct_m, &v.e, &v.pk_x, &v.pk_m)
        .expect("combine refused fixed inputs");
    *ss.expose()
}

// ------------------------------------------------------------ combiner

/// ADR-004 test vector plan items 2 and 3: production `combine` equals the
/// frozen constants on all 80 fixed-input vectors.
#[test]
fn t_cr_hybrid_combiner_matches_reference_vectors() {
    for (n, want) in EXPECTED.iter().enumerate() {
        assert_eq!(production(&vector(n)).to_vec(), hex(want), "vector {n}");
    }
}

/// ADR-004 test vector plan item 3: this file's frozen list equals the
/// reference's `FROZEN` list in `fstp-celltest`, so the production
/// comparison here and the reference recomputation there check the same
/// values. Read from source text, since `fstp-crypto` cannot depend on
/// `fstp-celltest`.
#[test]
fn t_cr_hybrid_frozen_vectors_equal_the_reference_list() {
    let path = common::repo_root().join("crates/fstp-celltest/src/reference/hybrid.rs");
    let text = fs::read_to_string(path).unwrap();
    let start = text
        .find("pub const FROZEN")
        .expect("the reference holds no FROZEN list");
    let body = &text[start..];
    let body = &body[..body.find("];").unwrap()];
    let theirs: Vec<&str> = body
        .split('"')
        .skip(1)
        .step_by(2)
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .collect();
    assert_eq!(theirs.len(), COUNT);
    assert_eq!(theirs, EXPECTED.to_vec());
}

/// ADR-004 test vector plan item 5: flipping any single bit of any of the
/// six inputs changes production's output.
#[test]
fn t_cr_hybrid_combiner_binds_every_input() {
    check_with(
        "t_cr_hybrid_combiner_binds_every_input",
        Config::default().with_cases(512),
        |g| binding_property(&production, g),
    );
}

/// ADR-004 test vector plan item 5, teeth: production `combine` with any
/// one input held at zero fails the binding property, so the property
/// would catch a combiner that ignores that input.
#[test]
fn t_cr_hybrid_teeth_production_combiner_ignoring_an_input_is_caught() {
    for omit in Input::ALL {
        let twin = move |v: &Inputs| {
            let mut w = v.clone();
            w.field_mut(omit).fill(0);
            production(&w)
        };
        let outcome = run(
            "t_cr_hybrid_teeth_production_combiner_ignoring_an_input_is_caught",
            Config::default().with_cases(512),
            |g| binding_property(&twin, g),
        );
        assert!(!outcome.is_passed(), "passed while ignoring {omit:?}");
    }
}

/// Production round-trips with itself, and two encapsulations to one key
/// differ in both the ciphertext and the secret.
#[test]
fn adr004_hybrid_round_trip_and_fresh_encapsulations() {
    let sk = hybrid_kem::generate().unwrap();
    let (ct1, ss1) = encapsulate(sk.public()).unwrap();
    let (ct2, ss2) = encapsulate(sk.public()).unwrap();
    assert_eq!(decapsulate(&sk, &ct1).unwrap().expose(), ss1.expose());
    assert_eq!(decapsulate(&sk, &ct2).unwrap().expose(), ss2.expose());
    assert_ne!(ct1.to_bytes(), ct2.to_bytes());
    assert_ne!(ss1.expose(), ss2.expose());
    assert_ne!(ct1.to_bytes()[..32], ct2.to_bytes()[..32], "E repeated");
}

// --------------------------------------------------------- both halves

/// The bytes of one generated half, so the same half can be built twice.
fn halves() -> ([u8; 32], Vec<u8>) {
    let x: [u8; 32] = fstp_crypto::random_array().unwrap();
    let m = mlkem::generate().unwrap();
    (x, m.to_bytes()[..].to_vec())
}

fn key_from(x: &[u8; 32], m: &[u8]) -> HybridSecretKey {
    HybridSecretKey::from_parts(
        StaticSecret::from_bytes(x).unwrap(),
        MlKem768DecapsKey::from_bytes(m).unwrap(),
    )
    .unwrap()
}

/// I-75, ADR-004 test vector plan item 6 at the KEM level: a ciphertext
/// decapsulates to its secret only with both the right X25519 secret and
/// the right ML-KEM secret. Either wrong half gives a different secret or
/// a refusal, never the right one.
#[test]
fn i75_hybrid_decapsulation_needs_both_halves() {
    check_with(
        "i75_hybrid_decapsulation_needs_both_halves",
        Config::default().with_cases(32),
        |_g| {
            let (xa, ma) = halves();
            let (xb, mb) = halves();
            let right = key_from(&xa, &ma);
            let (ct, ss) = encapsulate(right.public()).unwrap();
            let back = decapsulate(&right, &ct).unwrap();
            prop_assert_eq!(back.expose(), ss.expose());
            for (name, wrong) in [
                ("wrong X25519 half", key_from(&xb, &ma)),
                ("wrong ML-KEM half", key_from(&xa, &mb)),
            ] {
                if let Ok(got) = decapsulate(&wrong, &ct) {
                    prop_assert_ne!(got.expose(), ss.expose(), "{name}");
                }
            }
            Ok(())
        },
    );
}

/// ADR-004 "Decapsulation": `from_parts` keeps both halves, and the public
/// key is `pk_X || pk_M` of those halves.
#[test]
fn adr004_hybrid_public_key_is_both_public_halves() {
    let (x, m) = halves();
    let sk = key_from(&x, &m);
    let pk = sk.public().to_bytes();
    let x_pub = StaticSecret::from_bytes(&x).unwrap().public_key();
    let m_pub = MlKem768DecapsKey::from_bytes(&m).unwrap().encaps_key();
    assert_eq!(pk[..32], x_pub);
    assert_eq!(pk[32..], m_pub.as_bytes()[..]);
}

// ----------------------------------------------------------- encodings

/// ADR-004 "Inputs": a hybrid public key is exactly 1216 bytes and
/// re-encodes byte for byte. Any other length is refused, and so is an
/// ML-KEM half that fails the FIPS 203 modulus check.
#[test]
fn adr004_hybrid_public_key_has_one_fixed_layout() {
    assert_eq!(PUBLIC_KEY_LEN, 1216);
    let sk = hybrid_kem::generate().unwrap();
    let bytes = sk.public().to_bytes();
    let again = HybridPublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(again.to_bytes(), bytes);
    for len in [0, 32, 1184, PUBLIC_KEY_LEN - 1, PUBLIC_KEY_LEN + 1] {
        let mut b = bytes.to_vec();
        b.resize(len, 0);
        assert!(HybridPublicKey::from_bytes(&b).is_err(), "length {len}");
    }
    // The first 12-bit coefficient of pk_M set to 0xfff, which is not below q.
    let mut bad = bytes;
    bad[32] = 0xff;
    bad[33] |= 0x0f;
    assert!(HybridPublicKey::from_bytes(&bad).is_err());
}

/// ADR-004 "Inputs": a hybrid ciphertext is exactly 1120 bytes, `E` first,
/// and re-encodes byte for byte. Any other length is refused.
#[test]
fn adr004_hybrid_ciphertext_has_one_fixed_layout() {
    assert_eq!(CIPHERTEXT_LEN, 1120);
    let sk = hybrid_kem::generate().unwrap();
    let (ct, _) = encapsulate(sk.public()).unwrap();
    let bytes = ct.to_bytes();
    assert_eq!(
        HybridCiphertext::from_bytes(&bytes).unwrap().to_bytes(),
        bytes
    );
    for len in [0, 32, 1088, CIPHERTEXT_LEN - 1, CIPHERTEXT_LEN + 1] {
        let mut b = bytes.to_vec();
        b.resize(len, 0);
        assert!(HybridCiphertext::from_bytes(&b).is_err(), "length {len}");
    }
}

/// ADR-004 "Decapsulation": a mutated ciphertext never decapsulates to the
/// original secret. FIPS 203 implicit rejection hides a forged `ct_M`, so
/// the result is a different secret, or a refusal for a bad `E`.
#[test]
fn adr004_hybrid_mutated_ciphertext_never_gives_the_secret() {
    let sk = hybrid_kem::generate().unwrap();
    let (ct, ss) = encapsulate(sk.public()).unwrap();
    let bytes = ct.to_bytes();
    check_with(
        "adr004_hybrid_mutated_ciphertext_never_gives_the_secret",
        Config::default().with_cases(256),
        |g| {
            let bit = g.usize_in(0..=CIPHERTEXT_LEN * 8 - 1);
            g.note("bit", &bit);
            let mut b = bytes;
            b[bit / 8] ^= 1 << (bit % 8);
            let ct = HybridCiphertext::from_bytes(&b).unwrap();
            if let Ok(got) = decapsulate(&sk, &ct) {
                prop_assert!(got.expose() != ss.expose());
            }
            Ok(())
        },
    );
}

/// ADR-004 "Decapsulation" step 2: an all-zero X25519 result is refused,
/// so a ciphertext whose `E` is a small-order point does not decapsulate.
#[test]
fn adr004_hybrid_all_zero_x25519_result_is_refused() {
    let sk = hybrid_kem::generate().unwrap();
    let (ct, _) = encapsulate(sk.public()).unwrap();
    let mut bytes = ct.to_bytes();
    bytes[..32].fill(0);
    let ct = HybridCiphertext::from_bytes(&bytes).unwrap();
    assert!(decapsulate(&sk, &ct).is_err());
}

// ------------------------------------------------- secret key bytes

/// ADR-004 part 2 and I-75: a group secret leaves as `sk_X || dk_M`, both
/// halves together, and comes back as the same key. The X25519 half is
/// the scalar its own `to_bytes` gives, and the ML-KEM half is the
/// expanded decapsulation key.
#[test]
fn i75_hybrid_secret_key_bytes_are_both_halves_and_round_trip() {
    assert_eq!(hybrid_kem::SECRET_KEY_LEN, 32 + 2400);
    let (x, m) = halves();
    let sk = key_from(&x, &m);
    let bytes = sk.to_bytes();
    assert_eq!(bytes[..32], x[..]);
    assert_eq!(bytes[32..], m[..]);
    assert_eq!(
        StaticSecret::from_bytes(&x).unwrap().to_bytes()[..],
        x[..],
        "the X25519 scalar exports as imported"
    );
    let back = HybridSecretKey::from_bytes(&bytes[..]).unwrap();
    assert_eq!(back.public(), sk.public());
    assert_eq!(back.to_bytes()[..], bytes[..]);
    let (ct, ss) = encapsulate(sk.public()).unwrap();
    assert_eq!(decapsulate(&back, &ct).unwrap().expose(), ss.expose());
    let fresh = hybrid_kem::generate().unwrap();
    let again = HybridSecretKey::from_bytes(&fresh.to_bytes()[..]).unwrap();
    assert_eq!(again.public(), fresh.public());
}

/// ADR-004 part 2: the secret key decoder takes exactly 2432 bytes, and
/// runs the FIPS 203 section 7.3 check on the ML-KEM half.
#[test]
fn adr004_hybrid_secret_key_decoder_refuses_bad_input() {
    let sk = hybrid_kem::generate().unwrap();
    let bytes = sk.to_bytes();
    for len in [0, 1, 32, 2400, 2431, 2433] {
        let mut v = bytes[..].to_vec();
        v.resize(len, 0);
        assert!(
            matches!(
                HybridSecretKey::from_bytes(&v),
                Err(fstp_crypto::CryptoError::InvalidLength)
            ),
            "length {len}"
        );
    }
    // H(ek) sits at dk offset 2336 (FIPS 203 Algorithm 16), so a flipped
    // byte there fails the section 7.3 hash check.
    let mut bad = bytes[..].to_vec();
    bad[32 + 2336] ^= 1;
    assert!(matches!(
        HybridSecretKey::from_bytes(&bad),
        Err(fstp_crypto::CryptoError::InvalidKey)
    ));
}
