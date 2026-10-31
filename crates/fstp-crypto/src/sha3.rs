//! SHA3-256 (FIPS 202) through aws-lc-rs (ADR-001 Tier A, M3 design
//! section 2.2).

use aws_lc_rs::digest;

/// Length of a SHA3-256 digest in bytes.
pub const SHA3_256_LEN: usize = 32;

/// Computes the SHA3-256 digest of `data`.
#[must_use]
pub fn sha3_256(data: &[u8]) -> [u8; SHA3_256_LEN] {
    crate::to_array32(digest::digest(&digest::SHA3_256, data).as_ref())
}
