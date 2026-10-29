//! Fuzz target `hybrid_ciphertext_decode` of `fstp-crypto` (TH-26, H-05,
//! M3 design section 15, ADR-004 "Inputs").
//!
//! Design checks: no panic; exact lengths; one layout. For every input:
//!
//! - `HybridCiphertext::from_bytes` never panics.
//! - It accepts exactly the 1120-byte inputs. `E` and `ct_M` carry no
//!   validity rule, so every input of that length is a ciphertext.
//! - An accepted input re-encodes byte for byte, so there is one spelling.
//! - Decapsulating an accepted input under a fixed key never panics. The
//!   result is a secret (FIPS 203 implicit rejection) or a refusal for an
//!   `E` that gives an all-zero X25519 result.

#![no_main]

use std::sync::OnceLock;

use fstp_crypto::hybrid_kem::{self, CIPHERTEXT_LEN, HybridCiphertext, HybridSecretKey};
use libfuzzer_sys::fuzz_target;

fn key() -> Option<&'static HybridSecretKey> {
    static KEY: OnceLock<Option<HybridSecretKey>> = OnceLock::new();
    KEY.get_or_init(|| hybrid_kem::generate().ok()).as_ref()
}

fuzz_target!(|data: &[u8]| {
    let decoded = HybridCiphertext::from_bytes(data);
    assert_eq!(
        decoded.is_ok(),
        data.len() == CIPHERTEXT_LEN,
        "accepted a ciphertext of {} bytes, or refused one of the exact length",
        data.len()
    );
    if let Ok(ct) = decoded {
        assert_eq!(
            ct.to_bytes()[..],
            data[..],
            "accepted input did not re-encode"
        );
        if let Some(sk) = key() {
            let _ = hybrid_kem::decapsulate(sk, &ct);
        }
    }
});
