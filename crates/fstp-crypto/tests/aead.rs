//! The M3 `aead` module: AES-256-GCM through
//! `aws_lc_rs::aead::RandomizedNonceKey` (design sections 2.2 and 3.2,
//! ADR-004 "Nonce rule" and "Seal-count limit", R-NF-08).
//!
//! The API under test, as this file expects it:
//!
//! ```text
//! fstp_crypto::aead::KEY_LEN: usize     // 32
//! fstp_crypto::aead::NONCE_LEN: usize   // 12
//! fstp_crypto::aead::TAG_LEN: usize     // 16
//! fstp_crypto::aead::SEAL_LIMIT: u64    // 1 << 24
//! fstp_crypto::aead::Key::generate() -> Result<Key, CryptoError>
//! fstp_crypto::aead::Key::from_bytes(&[u8; 32]) -> Result<Key, CryptoError>
//! fstp_crypto::aead::Key::from_bytes_with_count(&[u8; 32], seals_so_far: u64) -> Result<Key, CryptoError>
//! fstp_crypto::aead::Key::seal_count(&self) -> u64
//! fstp_crypto::aead::Sealed { pub nonce: [u8; 12], pub body: Vec<u8> }  // body = ciphertext || tag
//! fstp_crypto::aead::seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> Result<Sealed, CryptoError>
//! fstp_crypto::aead::open(key: &Key, nonce: &[u8; 12], aad: &[u8], body: &[u8])
//!     -> Result<Zeroizing<Vec<u8>>, CryptoError>
//! fstp_crypto::CryptoError::SealLimitReached
//! ```
//!
//! `seal` takes no nonce, so the NIST vectors run through `open` only. The
//! module has no fixed-nonce seal seam, and this file asks for none.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::collections::HashSet;

use common::{arr, hex};
use fstp_crypto::CryptoError;
use fstp_crypto::aead::{KEY_LEN, Key, NONCE_LEN, SEAL_LIMIT, Sealed, TAG_LEN, open, seal};
use fstp_prop::{Config, check_with, prop_assert, prop_assert_eq, prop_assert_ne};

// ------------------------------------------------------- known answers

struct GcmCase {
    name: &'static str,
    key: &'static str,
    iv: &'static str,
    aad: &'static str,
    plaintext: &'static str,
    ciphertext: &'static str,
    tag: &'static str,
}

const GCM_P: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                     1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
const GCM_C: &str = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                     8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
const GCM_K: &str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";

/// The AES-256 test cases 13 to 16 of McGrew and Viega, "The Galois/Counter
/// Mode of Operation (GCM)", the vectors NIST published with SP 800-38D.
/// Each was recomputed on 2026-10-28 with the AES-256-GCM of Node.js
/// 24.11.1 (OpenSSL), outside this repository.
const GCM_CASES: [GcmCase; 4] = [
    GcmCase {
        name: "test case 13",
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        iv: "000000000000000000000000",
        aad: "",
        plaintext: "",
        ciphertext: "",
        tag: "530f8afbc74536b9a963b4f1c4cb738b",
    },
    GcmCase {
        name: "test case 14",
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        iv: "000000000000000000000000",
        aad: "",
        plaintext: "00000000000000000000000000000000",
        ciphertext: "cea7403d4d606b6e074ec5d3baf39d18",
        tag: "d0d1c8a799996bf0265b98b5d48ab919",
    },
    GcmCase {
        name: "test case 15",
        key: GCM_K,
        iv: "cafebabefacedbaddecaf888",
        aad: "",
        plaintext: GCM_P,
        ciphertext: GCM_C,
        tag: "b094dac5d93471bdec1a502270e3cc6c",
    },
    GcmCase {
        name: "test case 16",
        key: GCM_K,
        iv: "cafebabefacedbaddecaf888",
        aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        // The first 60 bytes of GCM_P and GCM_C.
        plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                    1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        ciphertext: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                     8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        tag: "76fc6ece0f4e1768cddf8853bb2d551b",
    },
];

/// ADR-004 "Nonce rule": `open` takes the stored nonce. Each published
/// ciphertext and tag opens to its plaintext under its key, IV and AAD.
#[test]
fn adr004_aead_open_matches_gcm_test_cases_13_to_16() {
    assert_eq!((KEY_LEN, NONCE_LEN, TAG_LEN), (32, 12, 16));
    for c in &GCM_CASES {
        let key = Key::from_bytes(&arr::<32>(c.key)).unwrap();
        let mut body = hex(c.ciphertext);
        body.extend(hex(c.tag));
        let pt = open(&key, &arr::<12>(c.iv), &hex(c.aad), &body)
            .unwrap_or_else(|e| panic!("{}: open refused: {e:?}", c.name));
        assert_eq!(pt[..].to_vec(), hex(c.plaintext), "{}", c.name);
        let mut bad = body.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(
            open(&key, &arr::<12>(c.iv), &hex(c.aad), &bad).is_err(),
            "{}",
            c.name
        );
    }
}

// --------------------------------------------------------- round trips

/// Every plaintext and AAD seals and opens back, under the nonce `seal`
/// returned. The body is the ciphertext followed by the 16-byte tag.
#[test]
fn adr004_aead_round_trip() {
    let key = Key::generate().unwrap();
    check_with(
        "adr004_aead_round_trip",
        Config::default().with_cases(256),
        |g| {
            let aad = g.bytes(0..=64);
            let pt = g.bytes(0..=512);
            let Sealed { nonce, body } = seal(&key, &aad, &pt).unwrap();
            prop_assert_eq!(body.len(), pt.len() + TAG_LEN);
            let opened = open(&key, &nonce, &aad, &body).unwrap();
            prop_assert_eq!(opened[..].to_vec(), pt);
            Ok(())
        },
    );
}

/// A flipped bit anywhere in the nonce, the AAD or the body is refused.
#[test]
fn adr004_aead_refuses_any_flipped_bit() {
    let key = Key::generate().unwrap();
    check_with(
        "adr004_aead_refuses_any_flipped_bit",
        Config::default().with_cases(256),
        |g| {
            let aad = g.bytes(1..=32);
            let pt = g.bytes(0..=128);
            let Sealed { nonce, body } = seal(&key, &aad, &pt).unwrap();
            let (mut n, mut a, mut b) = (nonce, aad.clone(), body.clone());
            let which = g.usize_in(0..=2);
            let target: &mut [u8] = match which {
                0 => &mut n,
                1 => &mut a,
                _ => &mut b,
            };
            let bit = g.usize_in(0..=target.len() * 8 - 1);
            g.note("which", &which);
            g.note("bit", &bit);
            target[bit / 8] ^= 1 << (bit % 8);
            prop_assert!(open(&key, &n, &a, &b).is_err());
            Ok(())
        },
    );
}

/// A body opens only under its own key, and a truncated body, a body
/// shorter than the tag and an empty body are refused.
#[test]
fn adr004_aead_refuses_other_keys_and_short_bodies() {
    let key = Key::generate().unwrap();
    let other = Key::generate().unwrap();
    let Sealed { nonce, body } = seal(&key, b"row 7", b"ledger body").unwrap();
    assert!(open(&other, &nonce, b"row 7", &body).is_err());
    assert!(open(&key, &nonce, b"row 7", &body[..body.len() - 1]).is_err());
    assert!(open(&key, &nonce, b"row 7", &body[..TAG_LEN - 1]).is_err());
    assert!(open(&key, &nonce, b"row 7", &[]).is_err());
    let mut extended = body.clone();
    extended.push(0);
    assert!(open(&key, &nonce, b"row 7", &extended).is_err());
    assert!(open(&key, &nonce, b"row 7", &body).is_ok());
}

/// The same key bytes give the same key: a body sealed under one import
/// opens under another import of those bytes.
#[test]
fn adr004_aead_key_import_is_stable() {
    let bytes = [0x42u8; 32];
    let a = Key::from_bytes(&bytes).unwrap();
    let b = Key::from_bytes(&bytes).unwrap();
    let Sealed { nonce, body } = seal(&a, b"", b"text").unwrap();
    assert_eq!(
        open(&b, &nonce, b"", &body).unwrap()[..].to_vec(),
        b"text".to_vec()
    );
}

// ------------------------------------------------------------ nonces

/// R-NF-08, ADR-004 "Nonce rule": `seal` takes a key, the AAD and the
/// plaintext, and nothing else. This pins the signature at compile time:
/// a nonce parameter, or a key passed by value, breaks the build.
#[test]
fn r_nf_08_seal_signature_takes_no_nonce() {
    type SealFn = fn(&Key, &[u8], &[u8]) -> Result<Sealed, CryptoError>;
    let pinned: SealFn = seal;
    let key = Key::generate().unwrap();
    let s = pinned(&key, b"aad", b"pt").unwrap();
    assert_eq!(s.nonce.len(), NONCE_LEN);
}

/// R-NF-08, design section 3.2: two seals of one plaintext under one key
/// and one AAD use different nonces and give different bodies. A nonce
/// derived from the inputs would repeat here.
#[test]
fn r_nf_08_two_seals_of_one_plaintext_differ() {
    let key = Key::generate().unwrap();
    check_with(
        "r_nf_08_two_seals_of_one_plaintext_differ",
        Config::default().with_cases(256),
        |g| {
            let aad = g.bytes(0..=16);
            let pt = g.bytes(0..=64);
            let a = seal(&key, &aad, &pt).unwrap();
            let b = seal(&key, &aad, &pt).unwrap();
            prop_assert_ne!(a.nonce, b.nonce);
            prop_assert_ne!(a.body, b.body);
            Ok(())
        },
    );
}

/// R-NF-08: 100 000 seals under one key never repeat a nonce, and fresh
/// keys with the same bytes do not restart a sequence. A counter nonce
/// that restarts per key import would repeat across the two imports.
#[test]
fn r_nf_08_no_nonce_repeats_across_many_seals_and_imports() {
    let bytes = [7u8; 32];
    let mut seen = HashSet::new();
    for _import in 0..2 {
        let key = Key::from_bytes(&bytes).unwrap();
        for _ in 0..50_000 {
            let s = seal(&key, b"", b"").unwrap();
            assert!(seen.insert(s.nonce), "nonce repeated: {:?}", s.nonce);
        }
    }
}

// --------------------------------------------------- seal-count limit

/// ADR-004 "Seal-count limit": the hard limit is 2^24 seals per key.
#[test]
fn r_nf_08_seal_limit_is_two_to_the_24() {
    assert_eq!(SEAL_LIMIT, 1u64 << 24);
}

/// ADR-004 "Seal-count limit": a key seals exactly 2^24 times. The next
/// seal is refused with the typed error, and so is every later one. A
/// refused seal does not count. Opening still works, and another key is
/// not affected.
#[test]
fn r_nf_08_seal_count_limit_refuses_at_two_to_the_24() {
    let key = Key::generate().unwrap();
    let first = seal(&key, b"first", b"kept").unwrap();
    for i in 1..SEAL_LIMIT {
        if let Err(e) = seal(&key, b"", b"") {
            panic!("seal {} of {SEAL_LIMIT} refused: {e:?}", i + 1);
        }
    }
    assert_eq!(key.seal_count(), SEAL_LIMIT);
    for _ in 0..3 {
        assert!(matches!(
            seal(&key, b"", b""),
            Err(CryptoError::SealLimitReached)
        ));
    }
    assert_eq!(key.seal_count(), SEAL_LIMIT);
    assert_eq!(
        open(&key, &first.nonce, b"first", &first.body).unwrap()[..].to_vec(),
        b"kept".to_vec()
    );
    let other = Key::generate().unwrap();
    assert!(seal(&other, b"", b"").is_ok());
    assert_eq!(other.seal_count(), 1);
}

/// The count starts at zero and grows by one per seal. Opening does not
/// count.
#[test]
fn r_nf_08_seal_count_counts_seals_only() {
    let key = Key::generate().unwrap();
    assert_eq!(key.seal_count(), 0);
    let s = seal(&key, b"", b"x").unwrap();
    assert_eq!(key.seal_count(), 1);
    for _ in 0..5 {
        open(&key, &s.nonce, b"", &s.body).unwrap();
    }
    assert_eq!(key.seal_count(), 1);
    seal(&key, b"", b"y").unwrap();
    assert_eq!(key.seal_count(), 2);
}

/// ADR-004 "Seal-count limit": a key rebuilt from its bytes with the
/// count it already reached keeps the limit. It seals up to 2^24 in all,
/// refuses after, and still opens what the first value sealed.
#[test]
fn r_nf_08_reimport_with_count_keeps_the_seal_limit() {
    let bytes = arr::<KEY_LEN>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let first = Key::from_bytes(&bytes).unwrap();
    let kept = seal(&first, b"a", b"kept").unwrap();
    let again = Key::from_bytes_with_count(&bytes, SEAL_LIMIT - 2).unwrap();
    assert_eq!(again.seal_count(), SEAL_LIMIT - 2);
    assert!(seal(&again, b"", b"").is_ok());
    assert!(seal(&again, b"", b"").is_ok());
    assert_eq!(again.seal_count(), SEAL_LIMIT);
    assert!(matches!(
        seal(&again, b"", b""),
        Err(CryptoError::SealLimitReached)
    ));
    assert_eq!(
        open(&again, &kept.nonce, b"a", &kept.body).unwrap()[..].to_vec(),
        b"kept".to_vec()
    );
    let spent = Key::from_bytes_with_count(&bytes, u64::MAX).unwrap();
    assert!(matches!(
        seal(&spent, b"", b""),
        Err(CryptoError::SealLimitReached)
    ));
    assert_eq!(spent.seal_count(), u64::MAX);
}
