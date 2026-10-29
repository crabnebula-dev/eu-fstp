//! Review reproducer (ADR-004 part 2 "Hierarchy as built", M3 design
//! section 3.1, I-75).
//!
//! A level 2 group key is X25519 plus ML-KEM-768. Its secret half is
//! sealed under `S(e)` and re-sealed under `S(e+1)` at every rotation. So
//! `fstp-keys` must turn a `HybridSecretKey` into bytes and back.
//!
//! The current API has no such route. `HybridSecretKey` has no `to_bytes`
//! or `from_bytes`, and `x25519::StaticSecret` exports nothing. The only
//! constructor, `HybridSecretKey::from_parts`, takes an
//! `fstp_crypto::mlkem::MlKem768DecapsKey`. The I-75 source scan
//! `i75_moduletto_primitives_are_reached_only_through_the_hybrids`
//! refuses that name outside `fstp-crypto` and `fstp-celltest`.
//!
//! This file fails to compile against the current code. It compiles and
//! passes once `HybridSecretKey` gains a fixed-length byte form.

use fstp_crypto::hybrid_kem::{self, HybridSecretKey};

/// The secret half of a generated hybrid key survives a byte round trip
/// and still decapsulates (ADR-004 part 2, I-75).
#[test]
fn review_hybrid_secret_key_round_trips_through_bytes() {
    let sk = hybrid_kem::generate().expect("generate");
    let bytes = sk.to_bytes();
    let back = HybridSecretKey::from_bytes(&bytes[..]).expect("reopen");
    assert_eq!(back.public(), sk.public());
    let (ct, ss) = hybrid_kem::encapsulate(sk.public()).expect("encapsulate");
    let reopened = hybrid_kem::decapsulate(&back, &ct).expect("decapsulate");
    assert_eq!(reopened.expose(), ss.expose());
}
