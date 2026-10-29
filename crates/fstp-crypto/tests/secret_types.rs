//! Secret types of the M3 `fstp-crypto` modules implement no `Debug`, no
//! `Clone` and no `Copy`, and wipe themselves on drop (design section
//! 2.2, ADR-001 A1, R-NF-08).
//!
//! The checks run at compile time through `common::impls!`, which reads
//! `true` exactly when the bound holds and still compiles when it does
//! not. So a secret type that gains `Debug` makes these tests fail, not
//! the build.
//!
//! "Zeroize on drop" is checked as two facts the type system shows: the
//! type implements the `zeroize::ZeroizeOnDrop` marker (zeroize is a
//! dependency of this crate, ADR-001 A1), and it has drop glue. A type
//! that only wraps an aws-lc-rs key relies on aws-lc's own cleansing free
//! and states that with the marker. Reading freed memory to prove the
//! wipe needs `unsafe`, which the workspace forbids; the process memory
//! scan of `fstp-celltest` covers the rest (I-80).
//!
//! The secret types, as this file expects them:
//!
//! ```text
//! aead::Key, x25519::StaticSecret, x25519::EphemeralSecret, x25519::SharedSecret,
//! sig::Ed25519SigningKey, sig::EcdsaP256KeyPair, mlkem::MlKem768DecapsKey,
//! mlkem::SharedSecret, hybrid_kem::HybridSecretKey, hybrid_kem::SharedSecret,
//! mldsa::MlDsa65SigningKey, composite::CompositeSigningKey
//! ```
//!
//! Secret byte strings returned by value use `zeroize::Zeroizing`:
//! `aead::open`, `sig::EcdsaP256KeyPair::pkcs8_der`,
//! `sig::Ed25519SigningKey::seed`, `x25519::StaticSecret::to_bytes`,
//! `mlkem::MlKem768DecapsKey::to_bytes` and
//! `hybrid_kem::HybridSecretKey::to_bytes`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::impls;
use fstp_crypto::{aead, composite, hybrid_kem, mldsa, mlkem, sig, x25519};

/// One row per secret type: its name and the three facts.
struct Row {
    name: &'static str,
    debug: bool,
    clone: bool,
    copy: bool,
    zeroize_on_drop: bool,
    needs_drop: bool,
}

macro_rules! row {
    ($t:ty) => {
        Row {
            name: stringify!($t),
            debug: impls!($t: ::core::fmt::Debug),
            clone: impls!($t: ::core::clone::Clone),
            copy: impls!($t: ::core::marker::Copy),
            zeroize_on_drop: impls!($t: ::zeroize::ZeroizeOnDrop),
            needs_drop: ::core::mem::needs_drop::<$t>(),
        }
    };
}

fn rows() -> Vec<Row> {
    vec![
        row!(aead::Key),
        row!(x25519::StaticSecret),
        row!(x25519::EphemeralSecret),
        row!(x25519::SharedSecret),
        row!(sig::Ed25519SigningKey),
        row!(sig::EcdsaP256KeyPair),
        row!(mlkem::MlKem768DecapsKey),
        row!(mlkem::SharedSecret),
        row!(hybrid_kem::HybridSecretKey),
        row!(hybrid_kem::SharedSecret),
        row!(mldsa::MlDsa65SigningKey),
        row!(composite::CompositeSigningKey),
    ]
}

/// Design section 2.2: no secret type implements `Debug`, so no log line
/// or panic message can print key material.
#[test]
fn adr001_a1_secret_types_implement_no_debug() {
    let bad: Vec<&str> = rows().iter().filter(|r| r.debug).map(|r| r.name).collect();
    assert!(bad.is_empty(), "secret types with Debug: {bad:?}");
}

/// Design section 2.2: no secret type implements `Clone` or `Copy`, so a
/// key is never duplicated in memory behind the caller's back.
#[test]
fn adr001_a1_secret_types_implement_no_clone_or_copy() {
    let bad: Vec<&str> = rows()
        .iter()
        .filter(|r| r.clone || r.copy)
        .map(|r| r.name)
        .collect();
    assert!(bad.is_empty(), "secret types with Clone or Copy: {bad:?}");
}

/// Design section 2.2, ADR-001 A1: every secret type is marked
/// `ZeroizeOnDrop` and has drop glue, so dropping it runs the wipe.
#[test]
fn adr001_a1_secret_types_zeroize_on_drop() {
    let bad: Vec<&str> = rows()
        .iter()
        .filter(|r| !(r.zeroize_on_drop && r.needs_drop))
        .map(|r| r.name)
        .collect();
    assert!(
        bad.is_empty(),
        "secret types without a wipe on drop: {bad:?}"
    );
}

/// Secret byte strings returned by value are `Zeroizing`. Each function
/// is pinned to its return type, so a plain `Vec` or array breaks the
/// build.
#[test]
fn adr001_a1_returned_secret_bytes_are_zeroizing() {
    type Opened = Result<zeroize::Zeroizing<Vec<u8>>, fstp_crypto::CryptoError>;
    let _open: fn(&aead::Key, &[u8; 12], &[u8], &[u8]) -> Opened = aead::open;
    let _pkcs8: fn(&sig::EcdsaP256KeyPair) -> Opened = sig::EcdsaP256KeyPair::pkcs8_der;
    let _dk: fn(&mlkem::MlKem768DecapsKey) -> zeroize::Zeroizing<[u8; 2400]> =
        mlkem::MlKem768DecapsKey::to_bytes;
    let _seed: fn(
        &sig::Ed25519SigningKey,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, fstp_crypto::CryptoError> =
        sig::Ed25519SigningKey::seed;
    let _x: fn(&x25519::StaticSecret) -> zeroize::Zeroizing<[u8; 32]> =
        x25519::StaticSecret::to_bytes;
    let _hybrid: fn(&hybrid_kem::HybridSecretKey) -> zeroize::Zeroizing<[u8; 2432]> =
        hybrid_kem::HybridSecretKey::to_bytes;
    let key = aead::Key::generate().unwrap();
    let s = aead::seal(&key, b"", b"secret").unwrap();
    let opened = aead::open(&key, &s.nonce, b"", &s.body).unwrap();
    assert!(impls!(zeroize::Zeroizing<Vec<u8>>: ::zeroize::ZeroizeOnDrop));
    assert_eq!(opened.as_slice(), b"secret");
}

/// The probe has teeth: it sees `Debug`, `Clone` and the marker on types
/// known to have them, and not on a type known to lack them.
#[test]
fn adr001_a1_teeth_probe_sees_trait_impls() {
    struct Bare;
    assert!(impls!(String: ::core::fmt::Debug));
    assert!(impls!(String: ::core::clone::Clone));
    assert!(impls!(zeroize::Zeroizing<[u8; 32]>: ::zeroize::ZeroizeOnDrop));
    assert!(!impls!(Bare: ::core::fmt::Debug));
    assert!(!impls!(Bare: ::core::clone::Clone));
    assert!(!impls!(Bare: ::zeroize::ZeroizeOnDrop));
    assert!(!impls!([u8; 32]: ::zeroize::ZeroizeOnDrop));
    let _ = Bare;
}
