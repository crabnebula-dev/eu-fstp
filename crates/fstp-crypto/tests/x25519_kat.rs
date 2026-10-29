//! Known answers for the M3 `x25519` module (design section 2.2, ADR-004
//! "Inputs" and test vector plan item 8).
//!
//! The API under test, as this file expects it:
//!
//! ```text
//! fstp_crypto::x25519::StaticSecret::generate() -> Result<StaticSecret, CryptoError>
//! fstp_crypto::x25519::StaticSecret::from_bytes(&[u8; 32]) -> Result<StaticSecret, CryptoError>
//! fstp_crypto::x25519::StaticSecret::public_key(&self) -> [u8; 32]
//! fstp_crypto::x25519::StaticSecret::diffie_hellman(&self, peer: &[u8; 32])
//!     -> Result<x25519::SharedSecret, CryptoError>
//! fstp_crypto::x25519::EphemeralSecret::generate() -> Result<EphemeralSecret, CryptoError>
//! fstp_crypto::x25519::EphemeralSecret::public_key(&self) -> [u8; 32]
//! fstp_crypto::x25519::EphemeralSecret::diffie_hellman(self, peer: &[u8; 32])
//!     -> Result<x25519::SharedSecret, CryptoError>
//! fstp_crypto::x25519::SharedSecret::expose(&self) -> &[u8; 32]
//! ```
//!
//! The RFC 7748 values were checked on 2026-10-28 with the X25519 of
//! Node.js 24.11.1 (OpenSSL), outside this repository.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::arr;
use fstp_crypto::x25519::{EphemeralSecret, SharedSecret, StaticSecret};
use fstp_prop::{Config, check_with, prop_assert_eq};

const ALICE_SK: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const ALICE_PK: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const BOB_SK: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const BOB_PK: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

fn key(hex: &str) -> StaticSecret {
    StaticSecret::from_bytes(&arr::<32>(hex)).expect("RFC 7748 scalar refused")
}

/// RFC 7748 section 6.1: both public keys and the shared secret, in both
/// directions, through static keys.
#[test]
fn t_cr_hybrid_x25519_rfc7748_vectors() {
    let alice = key(ALICE_SK);
    let bob = key(BOB_SK);
    assert_eq!(alice.public_key(), arr::<32>(ALICE_PK));
    assert_eq!(bob.public_key(), arr::<32>(BOB_PK));
    let ab: SharedSecret = alice.diffie_hellman(&arr::<32>(BOB_PK)).unwrap();
    let ba: SharedSecret = bob.diffie_hellman(&arr::<32>(ALICE_PK)).unwrap();
    assert_eq!(*ab.expose(), arr::<32>(SHARED));
    assert_eq!(*ba.expose(), arr::<32>(SHARED));
}

/// RFC 7748 section 5.2, the iterated test: start with `k = u = 9`, then
/// set `k, u = X25519(k, u), k`. The values after 1 and 1 000 iterations.
/// Each step imports `k` as a static scalar and `u` as the peer key.
#[test]
fn t_cr_hybrid_x25519_rfc7748_iterated() {
    let mut k = [0u8; 32];
    k[0] = 9;
    let mut u = k;
    for i in 1..=1000 {
        let out = *key_from(&k).diffie_hellman(&u).unwrap().expose();
        u = k;
        k = out;
        if i == 1 {
            assert_eq!(
                k,
                arr::<32>("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
            );
        }
    }
    assert_eq!(
        k,
        arr::<32>("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
    );
}

fn key_from(k: &[u8; 32]) -> StaticSecret {
    StaticSecret::from_bytes(k).unwrap()
}

/// ADR-004 "Inputs": an all-zero X25519 result is refused. The point
/// `u = 0` and the point `u = 1` have small order, so every scalar maps
/// them to zero.
#[test]
fn adr004_x25519_all_zero_result_is_refused() {
    let alice = key(ALICE_SK);
    let mut one = [0u8; 32];
    one[0] = 1;
    assert!(alice.diffie_hellman(&[0u8; 32]).is_err());
    assert!(alice.diffie_hellman(&one).is_err());
    let eph = EphemeralSecret::generate().unwrap();
    assert!(eph.diffie_hellman(&[0u8; 32]).is_err());
}

/// An ephemeral key and a static key agree in both directions, which is
/// the encapsulation and decapsulation pair of ADR-004.
#[test]
fn adr004_x25519_ephemeral_and_static_keys_agree() {
    check_with(
        "adr004_x25519_ephemeral_and_static_keys_agree",
        Config::default().with_cases(64),
        |_g| {
            let recipient = StaticSecret::generate().unwrap();
            let eph = EphemeralSecret::generate().unwrap();
            let e = eph.public_key();
            let sender = eph.diffie_hellman(&recipient.public_key()).unwrap();
            let receiver = recipient.diffie_hellman(&e).unwrap();
            prop_assert_eq!(sender.expose(), receiver.expose());
            Ok(())
        },
    );
}

/// Two generated keys differ. A generator that returned a fixed key would
/// make every encapsulation share its X25519 half.
#[test]
fn adr004_x25519_generated_keys_differ() {
    let a = StaticSecret::generate().unwrap();
    let b = StaticSecret::generate().unwrap();
    assert_ne!(a.public_key(), b.public_key());
    let c = EphemeralSecret::generate().unwrap();
    let d = EphemeralSecret::generate().unwrap();
    assert_ne!(c.public_key(), d.public_key());
}
