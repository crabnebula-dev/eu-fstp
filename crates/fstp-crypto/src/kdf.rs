//! HKDF-SHA-256 (RFC 5869) through the aws-lc-rs `hkdf` module (ADR-001
//! Tier A, ADR-004 "Combiner bytes" and "Sealed key format").

use aws_lc_rs::hkdf;

use crate::CryptoError;

/// Largest output HKDF-SHA-256 defines: 255 blocks of 32 bytes (RFC 5869
/// section 2.3).
pub const HKDF_SHA256_MAX_OUTPUT: usize = 255 * crate::SHA256_LEN;

/// The output length handed to aws-lc-rs.
struct OutLen(usize);

impl hkdf::KeyType for OutLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Fills `out` with HKDF-SHA-256 output: Extract with `salt` over `ikm`,
/// then Expand with `info` to `out.len()` bytes.
///
/// # Errors
///
/// Returns [`CryptoError::OutputTooLong`] when `out` is longer than
/// [`HKDF_SHA256_MAX_OUTPUT`]. `out` is left unchanged then. Returns
/// [`CryptoError::Unspecified`] when aws-lc-rs fails.
pub fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    if out.len() > HKDF_SHA256_MAX_OUTPUT {
        return Err(CryptoError::OutputTooLong);
    }
    expand(&extract(salt, ikm), &[info], out)
}

/// HKDF-Extract under `salt`. The pseudorandom key stays inside aws-lc-rs.
pub(crate) fn extract(salt: &[u8], ikm: &[u8]) -> hkdf::Prk {
    hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm)
}

/// HKDF-Expand of `prk` over the concatenation of `info` into `out`.
pub(crate) fn expand(prk: &hkdf::Prk, info: &[&[u8]], out: &mut [u8]) -> Result<(), CryptoError> {
    prk.expand(info, OutLen(out.len()))
        .map_err(|_| CryptoError::OutputTooLong)?
        .fill(out)
        .map_err(|_| CryptoError::Unspecified)
}
