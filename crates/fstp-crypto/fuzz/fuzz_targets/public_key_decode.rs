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
//!   `composite::PUBLIC_KEY_LEN` bytes. ADR-010 has not yet transcribed
//!   the draft 19 layout, so it may still refuse every input.
//! - Every accepted key re-encodes byte for byte, so there is one spelling.
//! - Encapsulating to an accepted hybrid key never panics.

#![no_main]

use fstp_crypto::composite::{self, CompositePublicKey};
use fstp_crypto::hybrid_kem::{self, HybridPublicKey, PUBLIC_KEY_LEN};
use fstp_crypto::mlkem::{ENCAPS_KEY_LEN, MlKem768EncapsKey};
use libfuzzer_sys::fuzz_target;

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
});
