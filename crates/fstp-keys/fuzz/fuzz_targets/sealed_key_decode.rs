//! Fuzz target `sealed_key_decode` of `fstp-keys` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; accepted input re-encodes byte for byte; a
//! mutated byte never opens.
//!
//! Every accepted input must have the ADR-004 part 1 layout: exactly 1210
//! bytes, the magic `FSK1`, version 1, `kem` 1, `aead` 1 and a chain code
//! from 1 to 5. It must re-encode byte for byte. For "a mutated byte
//! never opens", the target seals one data key once, then changes the
//! byte and value the input's first three bytes name, and checks that
//! the result never decodes and opens.

#![no_main]

use std::sync::OnceLock;

use fstp_crypto::hybrid_kem::{self, HybridSecretKey};
use fstp_keys::envelope::{
    DataKey, SealContext, decode_sealed_key, encode_sealed_key, open_key, seal_key,
};
use fstp_keys::{CellId, Chain, GroupId, ObjectId, Purpose};
use libfuzzer_sys::fuzz_target;

/// The length of a sealed key (ADR-004 part 1).
const SEALED_KEY_LEN: usize = 1210;

const CTX: SealContext = SealContext {
    cell: CellId([1; 16]),
    chain: Chain::App,
    purpose: Purpose::Text,
    group: GroupId([2; 16]),
    generation: 7,
    object: ObjectId([3; 16]),
};

/// One group key and one data key sealed to it, made once.
fn sealed() -> &'static (HybridSecretKey, Vec<u8>) {
    static ONCE: OnceLock<(HybridSecretKey, Vec<u8>)> = OnceLock::new();
    ONCE.get_or_init(|| {
        let sk = hybrid_kem::generate().unwrap_or_else(|_| std::process::abort());
        let dek = DataKey::from_bytes(&[9; 32]).unwrap_or_else(|_| std::process::abort());
        let key = seal_key(sk.public(), &dek, &CTX).unwrap_or_else(|_| std::process::abort());
        let bytes = encode_sealed_key(&key).unwrap_or_else(|_| std::process::abort());
        (sk, bytes)
    })
}

fuzz_target!(|data: &[u8]| {
    match decode_sealed_key(data) {
        Ok(key) => {
            assert_eq!(data.len(), SEALED_KEY_LEN, "accepted another length");
            assert_eq!(data.get(0..4), Some(&b"FSK1"[..]), "accepted another magic");
            assert_eq!(data.get(4), Some(&1), "accepted another version");
            assert_eq!(data.get(5..7), Some(&[0u8, 1][..]), "accepted another kem");
            assert_eq!(data.get(7..9), Some(&[0u8, 1][..]), "accepted another aead");
            assert!(
                data.get(9).is_some_and(|c| (1..=5).contains(c)),
                "accepted another chain code"
            );
            assert_eq!(key.header().version, 1, "header version");
            let again = encode_sealed_key(&key);
            assert_eq!(again.as_deref().ok(), Some(data), "not one spelling");
        }
        Err(e) => assert!(!format!("{e:?}").is_empty()),
    }
    if let [hi, lo, flip, ..] = *data {
        let (sk, bytes) = sealed();
        let at = usize::from(u16::from_be_bytes([hi, lo])) % SEALED_KEY_LEN;
        let mut m = bytes.clone();
        if let Some(b) = m.get_mut(at) {
            *b ^= flip.max(1);
        }
        let opened = decode_sealed_key(&m)
            .ok()
            .and_then(|k| open_key(sk, &k, &CTX).ok());
        assert!(
            opened.is_none(),
            "a sealed key with byte {at} changed opened"
        );
    }
});
