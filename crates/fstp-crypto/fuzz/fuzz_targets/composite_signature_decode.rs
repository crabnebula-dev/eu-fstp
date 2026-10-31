//! Fuzz target `composite_signature_decode` of `fstp-crypto` (TH-26,
//! H-05, TH-67, M3 design sections 7.4 and 15, I-90).
//!
//! Design checks: no panic; exact lengths; one layout. For every input:
//!
//! - `composite::CompositeSignature::from_bytes` never panics, accepts
//!   only inputs of `composite::SIGNATURE_LEN` bytes, and an accepted
//!   input re-encodes byte for byte. ADR-010 transcribes the draft 19
//!   layout, `mldsaSig || tradSig` with the 3309-byte ML-DSA-65 half first
//!   (section 4.3).
//! - `composite::verify` never panics and never accepts. The input is
//!   split into a public key, a message and a signature, so an arbitrary
//!   input never carries a valid composite signature (I-90). Verification
//!   checks both halves, the ML-DSA-65 half through moduletto at the pinned
//!   commit `6c1ae92`.

#![no_main]

use fstp_crypto::composite::{self, CompositeSignature};
use libfuzzer_sys::fuzz_target;

/// Splits the input into a public key, a message and a signature. A long
/// input gives both at their exact composite lengths, so the verifier sees
/// well-formed sizes; a short one gives arbitrary sizes.
fn split(data: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let exact = composite::PUBLIC_KEY_LEN + composite::SIGNATURE_LEN;
    if data.len() >= exact {
        let (pk, rest) = data.split_at(composite::PUBLIC_KEY_LEN);
        let (sig, msg) = rest.split_at(composite::SIGNATURE_LEN);
        return (pk, msg, sig);
    }
    let (pk_len, rest) = data.split_first().map_or((0, &[][..]), |(b, r)| (*b, r));
    let (pk, rest) = rest.split_at(usize::from(pk_len).min(rest.len()));
    let (msg, sig) = rest.split_at(rest.len().min(32));
    (pk, msg, sig)
}

fuzz_target!(|data: &[u8]| {
    if let Ok(sig) = CompositeSignature::from_bytes(data) {
        assert_eq!(data.len(), composite::SIGNATURE_LEN, "signature length");
        assert_eq!(sig.to_bytes()[..], data[..], "signature did not re-encode");
    }

    let (pk, msg, sig) = split(data);
    assert!(
        composite::verify(pk, msg, sig).is_err(),
        "composite verify accepted fuzzer input"
    );
});
