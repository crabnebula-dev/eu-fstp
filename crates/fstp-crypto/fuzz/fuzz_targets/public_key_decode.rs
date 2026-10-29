//! Fuzz target `public_key_decode` of `fstp-crypto` (TH-26, H-05, M3
//! design section 15, ADR-004 "Inputs", FIPS 203 section 7.2).
//!
//! Design checks: no panic; exact lengths; one layout. For every input:
//!
//! - `HybridPublicKey::from_bytes` never panics. It accepts an input only
//!   at exactly 1216 bytes, and then exactly when its ML-KEM-768 half
//!   `pk_M` (bytes 32 to 1215) passes `MlKem768EncapsKey::from_bytes`, the
//!   FIPS 203 modulus check. Any 32 bytes are an X25519 public key.
//! - `MlKem768EncapsKey::from_bytes` accepts only 1184-byte inputs.
//! - `composite::CompositePublicKey::from_bytes` accepts only inputs of
//!   `composite::PUBLIC_KEY_LEN` bytes, the draft 19 layout
//!   `mldsaPK || tradPK` that ADR-010 transcribes (section 4.1). It
//!   accepts such an input exactly when its Ed25519 half is not a point of
//!   small order, in any spelling, and its ML-DSA-65 `t1` is not
//!   degenerate (ADR-010 platform rules, I-75, I-90). A degenerate `t1`
//!   has every 10-bit coefficient in 0 to 255 or 768 to 1023.
//! - A composite key built from the input's first 1952 bytes and any
//!   small-order Ed25519 spelling never decodes, so the rule is checked on
//!   every input and not only when the fuzzer finds such a half.
//! - A composite key whose `t1` is the input's `t1` pushed into the band,
//!   with a genuine Ed25519 half, never decodes either. So the `t1` rule
//!   is checked on every input too.
//! - Every accepted key re-encodes byte for byte, so there is one spelling.
//! - Encapsulating to an accepted hybrid key never panics.

#![no_main]

use fstp_crypto::CryptoError;
use fstp_crypto::composite::{self, CompositePublicKey};
use fstp_crypto::hybrid_kem::{self, HybridPublicKey, PUBLIC_KEY_LEN};
use fstp_crypto::mlkem::{ENCAPS_KEY_LEN, MlKem768EncapsKey};
use fstp_crypto::sig::Ed25519SigningKey;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// Length of the ML-DSA-65 half of a composite public key (draft 19
/// section 4.1, Table 1).
const MLDSA_PK_LEN: usize = 1952;

/// The Ed25519 small-order encodings with bit 255 clear: y = 0, 1, the
/// two order 8 values, p - 1, p and p + 1, little-endian. Written out
/// here apart from the production table, which is private.
const SMALL_ORDER: [[u8; 32]; 7] = {
    let mut t = [[0u8; 32]; 7];
    t[1][0] = 1;
    t[2] = [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ];
    t[3] = [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ];
    t[4] = [0xff; 32];
    t[4][0] = 0xec;
    t[4][31] = 0x7f;
    t[5] = t[4];
    t[5][0] = 0xed;
    t[6] = t[4];
    t[6][0] = 0xee;
    t
};

/// Whether the 32 bytes are a small-order spelling, either sign bit.
fn small_order(ed: &[u8]) -> bool {
    let mut masked = [0u8; 32];
    masked.copy_from_slice(ed);
    masked[31] &= 0x7f;
    SMALL_ORDER.contains(&masked)
}

/// The 10-bit `t1` coefficients of an ML-DSA-65 public key `rho || t1`,
/// unpacked least significant bit first (FIPS 204 Algorithms 16 and 22).
/// Written here apart from the production check, which is private.
fn t1_coefficients(mldsa_pk: &[u8]) -> Vec<u16> {
    let t1 = &mldsa_pk[32..MLDSA_PK_LEN];
    (0..t1.len() * 8 / 10)
        .map(|i| {
            (0..10).fold(0u16, |c, k| {
                let bit = 10 * i + k;
                c | (u16::from(t1[bit / 8] >> (bit % 8) & 1) << k)
            })
        })
        .collect()
}

/// Whether every `t1` coefficient lies in the band 0 to 255 or 768 to
/// 1023, where `t1 * 2^13` is within 2^21 of 0 modulo q.
fn degenerate_t1(mldsa_pk: &[u8]) -> bool {
    t1_coefficients(mldsa_pk)
        .iter()
        .all(|&c| c <= 255 || c >= 768)
}

/// The input's ML-DSA-65 half with every `t1` coefficient pushed into the
/// band: the top two bits of each are set equal to its bit 9.
fn into_band(mldsa_pk: &[u8]) -> Vec<u8> {
    let mut out = mldsa_pk[..32].to_vec();
    let mut bits = vec![0u8; MLDSA_PK_LEN - 32];
    for (i, c) in t1_coefficients(mldsa_pk).into_iter().enumerate() {
        let c = if c >= 512 { c | 0x300 } else { c & 0xff };
        for k in 0..10 {
            if c >> k & 1 == 1 {
                let bit = 10 * i + k;
                bits[bit / 8] |= 1 << (bit % 8);
            }
        }
    }
    out.extend_from_slice(&bits);
    out
}

fuzz_target!(|data: &[u8]| {
    let mlkem = MlKem768EncapsKey::from_bytes(data);
    if let Ok(ek) = &mlkem {
        assert_eq!(
            data.len(),
            ENCAPS_KEY_LEN,
            "ML-KEM key of {} bytes",
            data.len()
        );
        assert_eq!(ek.as_bytes()[..], data[..], "ML-KEM key did not re-encode");
    }

    let hybrid = HybridPublicKey::from_bytes(data);
    let half_ok = data.len() == PUBLIC_KEY_LEN
        && data
            .get(32..)
            .is_some_and(|m| MlKem768EncapsKey::from_bytes(m).is_ok());
    assert_eq!(
        hybrid.is_ok(),
        half_ok,
        "hybrid key decode disagrees with its halves at {} bytes",
        data.len()
    );
    if let Ok(pk) = hybrid {
        assert_eq!(pk.to_bytes()[..], data[..], "hybrid key did not re-encode");
        let _ = hybrid_kem::encapsulate(&pk);
    }

    let composite = CompositePublicKey::from_bytes(data);
    if data.len() == composite::PUBLIC_KEY_LEN {
        let weak = data.get(MLDSA_PK_LEN..).is_some_and(small_order)
            || data.get(..MLDSA_PK_LEN).is_some_and(degenerate_t1);
        assert_eq!(
            composite.is_err(),
            weak,
            "composite key decode disagrees with the small-order and t1 rules"
        );
        if weak {
            assert_eq!(composite.err(), Some(CryptoError::InvalidKey));
        }
    }
    if let Ok(pk) = CompositePublicKey::from_bytes(data) {
        assert_eq!(
            data.len(),
            composite::PUBLIC_KEY_LEN,
            "composite key length"
        );
        assert_eq!(
            pk.to_bytes()[..],
            data[..],
            "composite key did not re-encode"
        );
    }

    if let Some(mldsa_pk) = data.get(..MLDSA_PK_LEN) {
        let sign = data.get(MLDSA_PK_LEN).map_or(0, |b| b & 0x80);
        for row in SMALL_ORDER {
            let mut ed = row;
            ed[31] |= sign;
            let pk = [mldsa_pk, &ed[..]].concat();
            assert_eq!(
                CompositePublicKey::from_bytes(&pk).err(),
                Some(CryptoError::InvalidKey),
                "a small-order Ed25519 half decoded"
            );
        }

        let banded = into_band(mldsa_pk);
        assert!(degenerate_t1(&banded), "into_band left the band");
        let pk = [&banded[..], &genuine_ed25519_half()[..]].concat();
        assert_eq!(
            CompositePublicKey::from_bytes(&pk).err(),
            Some(CryptoError::InvalidKey),
            "an ML-DSA-65 half with a degenerate t1 decoded"
        );
    }
});

/// A genuine Ed25519 public key, never of small order, made once.
fn genuine_ed25519_half() -> [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    *KEY.get_or_init(|| {
        let key = Ed25519SigningKey::from_seed(&[7u8; 32]).expect("Ed25519 key from a seed");
        let pk = key.public_key();
        assert!(!small_order(&pk), "the fixed Ed25519 key is of small order");
        pk
    })
}
