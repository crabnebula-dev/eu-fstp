//! Digests computed on the shell side, through `fstp-crypto` (aws-lc-rs).
//!
//! The digest value and its stored spelling live in `fstp-contract-core`,
//! which computes none. This module hashes bytes and hands the value in.

pub use fstp_contract_core::digest::Digest;

/// The SHA-256 of `data`, through `fstp-crypto` (aws-lc-rs).
#[must_use]
pub fn sha256(data: &[u8]) -> Digest {
    Digest::from_bytes(fstp_crypto::sha256(data))
}
