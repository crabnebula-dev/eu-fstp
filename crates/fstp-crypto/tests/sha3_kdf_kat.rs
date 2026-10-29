//! Known answers for the M3 `sha3` and `kdf` modules (design section 2.2,
//! ADR-001 Tier A, ADR-004 "Combiner bytes" and "Sealed key format").
//!
//! The API under test, as this file expects it:
//!
//! ```text
//! fstp_crypto::sha3::sha3_256(data: &[u8]) -> [u8; 32]
//! fstp_crypto::kdf::hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8])
//!     -> Result<(), CryptoError>
//! fstp_crypto::kdf::HKDF_SHA256_MAX_OUTPUT: usize   // 255 * 32
//! ```
//!
//! Every expected value was checked on 2026-10-28 with the OpenSSL 3.6.4
//! command line tool. The command sits next to each vector.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::hex;
use fstp_crypto::kdf::{HKDF_SHA256_MAX_OUTPUT, hkdf_sha256};
use fstp_crypto::sha3::sha3_256;

// ------------------------------------------------------------- SHA3-256

/// FIPS 202 SHA3-256 of the empty string.
/// `printf '' | openssl dgst -sha3-256 -r`
#[test]
fn adr001_sha3_256_empty() {
    assert_eq!(
        sha3_256(b"").to_vec(),
        hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
    );
}

/// FIPS 202 SHA3-256 of "abc", one block.
/// `printf 'abc' | openssl dgst -sha3-256 -r`
#[test]
fn adr001_sha3_256_abc() {
    assert_eq!(
        sha3_256(b"abc").to_vec(),
        hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
    );
}

/// The 448-bit message of the NIST examples.
/// `printf 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' | openssl dgst -sha3-256 -r`
#[test]
fn adr001_sha3_256_448_bits() {
    assert_eq!(
        sha3_256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").to_vec(),
        hex("41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376")
    );
}

/// The 896-bit message of the NIST examples, longer than the 136-byte rate.
/// `printf 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu' | openssl dgst -sha3-256 -r`
#[test]
fn adr001_sha3_256_896_bits() {
    assert_eq!(
        sha3_256(
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        )
        .to_vec(),
        hex("916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18")
    );
}

/// One million repetitions of "a".
/// `head -c 1000000 /dev/zero | tr '\0' 'a' | openssl dgst -sha3-256 -r`
#[test]
fn adr001_sha3_256_million_a() {
    assert_eq!(
        sha3_256(&vec![b'a'; 1_000_000]).to_vec(),
        hex("5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1")
    );
}

/// SHA3-256 is not SHA-256: the facade must not route one to the other.
#[test]
fn adr001_sha3_256_differs_from_sha256() {
    assert_ne!(sha3_256(b"abc"), fstp_crypto::sha256(b"abc"));
}

// ---------------------------------------------------------- HKDF-SHA-256

fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    hkdf_sha256(salt, ikm, info, &mut out).expect("hkdf_sha256 refused a valid length");
    out
}

fn range(lo: u8, hi: u8) -> Vec<u8> {
    (lo..=hi).collect()
}

/// RFC 5869 Appendix A.1, basic test case with SHA-256.
/// `openssl kdf -keylen 42 -kdfopt digest:SHA256 -kdfopt hexkey:0b..0b (22 bytes) -kdfopt hexsalt:000102030405060708090a0b0c -kdfopt hexinfo:f0f1f2f3f4f5f6f7f8f9 HKDF`
#[test]
fn adr004_hkdf_sha256_rfc5869_a1() {
    assert_eq!(
        hkdf(&range(0x00, 0x0c), &[0x0b; 22], &range(0xf0, 0xf9), 42),
        hex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
        )
    );
}

/// RFC 5869 Appendix A.2, longer inputs and outputs (three Expand blocks).
/// `openssl kdf -keylen 82 -kdfopt digest:SHA256 -kdfopt hexkey:00..4f -kdfopt hexsalt:60..af -kdfopt hexinfo:b0..ff HKDF`
#[test]
fn adr004_hkdf_sha256_rfc5869_a2() {
    assert_eq!(
        hkdf(
            &range(0x60, 0xaf),
            &range(0x00, 0x4f),
            &range(0xb0, 0xff),
            82
        ),
        hex(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87"
        )
    );
}

/// RFC 5869 Appendix A.3, zero-length salt and info. The sealed key format
/// of ADR-004 uses an empty salt.
/// `openssl kdf -keylen 42 -kdfopt digest:SHA256 -kdfopt hexkey:0b..0b (22 bytes) -kdfopt hexsalt: -kdfopt hexinfo: HKDF`
#[test]
fn adr004_hkdf_sha256_rfc5869_a3_empty_salt_and_info() {
    assert_eq!(
        hkdf(b"", &[0x0b; 22], b"", 42),
        hex(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8"
        )
    );
}

/// A shorter output is a prefix of a longer one with the same inputs, and a
/// 32-byte output (the combiner's `L`) is the first Expand block.
#[test]
fn adr004_hkdf_sha256_outputs_are_prefixes() {
    let long = hkdf(
        &range(0x60, 0xaf),
        &range(0x00, 0x4f),
        &range(0xb0, 0xff),
        82,
    );
    for len in [0usize, 1, 31, 32, 33, 64, 81] {
        assert_eq!(
            hkdf(
                &range(0x60, 0xaf),
                &range(0x00, 0x4f),
                &range(0xb0, 0xff),
                len
            ),
            long[..len].to_vec(),
            "length {len}"
        );
    }
}

/// RFC 5869 section 2.3: `L <= 255 * HashLen`. The longest output is
/// accepted, and one byte more is refused without writing.
#[test]
fn adr004_hkdf_sha256_refuses_output_longer_than_255_blocks() {
    assert_eq!(HKDF_SHA256_MAX_OUTPUT, 255 * 32);
    let mut max = vec![0u8; HKDF_SHA256_MAX_OUTPUT];
    assert!(hkdf_sha256(b"salt", b"ikm", b"info", &mut max).is_ok());
    let mut over = vec![0xa5u8; HKDF_SHA256_MAX_OUTPUT + 1];
    assert!(hkdf_sha256(b"salt", b"ikm", b"info", &mut over).is_err());
    assert!(
        over.iter().all(|&b| b == 0xa5),
        "a refused call wrote output"
    );
}
