//! Facade over the ADR-001 cryptography crates. No primitive is implemented here.
//!
//! Every function in this crate forwards to aws-lc-rs (ADR-001 Tier A) or,
//! for the post-quantum half, to moduletto (ADR-001 Tier B, A2). The facade
//! exists so that the rest of the platform names one small, reviewed
//! surface instead of reaching into either crate directly. moduletto is
//! reachable only through this crate (M3 design section 2.4, rule 8).
//!
//! What it offers at the crate root:
//!
//! - SHA-256, one-shot ([`sha256`]) and streaming ([`Sha256`]).
//! - HMAC-SHA-256, one-shot ([`hmac_sha256`]), streaming ([`HmacSha256`]) and
//!   constant-time verification ([`hmac_sha256_verify`]).
//! - PBKDF2 with HMAC-SHA-256 ([`pbkdf2_hmac_sha256`]).
//! - Constant-time comparison of byte strings ([`constant_time_eq`]).
//! - System randomness ([`random_bytes`]).
//!
//! The M3 modules (M3 design section 2.2):
//!
//! - [`aead`]: AES-256-GCM with random nonces only, and a seal-count limit.
//! - [`kdf`]: HKDF-SHA-256. [`sha3`]: SHA3-256.
//! - [`x25519`]: static and ephemeral X25519 keys.
//! - [`sig`]: Ed25519, ECDSA P-256 and RSA PKCS#1 SHA-256 verification.
//! - [`mlkem`]: ML-KEM-768 from moduletto. [`hybrid_kem`]: X25519 plus
//!   ML-KEM-768 with the ADR-004 combiner.
//! - [`mldsa`] and [`composite`]: ML-DSA-65 and the Ed25519 plus ML-DSA-65
//!   composite. moduletto has no ML-DSA-65 at its pinned commit, so both
//!   refuse every call with [`CryptoError::MlDsaUnavailable`] (I-75, I-90).
//!
//! Secret types implement no `Debug`, `Clone` or `Copy`, and wipe their
//! bytes on drop (ADR-001 A1). Types that wrap an aws-lc-rs key rely on
//! AWS-LC's cleansing free, and carry the `zeroize::ZeroizeOnDrop` marker.
//!
//! The decoders here accept fixed-length byte strings only. Their fuzz
//! targets live in `crates/fstp-crypto/fuzz` (M3 design section 15).

use std::fmt;
use std::num::NonZeroU32;

use aws_lc_rs::{constant_time, digest, hmac, pbkdf2, rand};

pub mod aead;
pub mod composite;
pub mod hybrid_kem;
pub mod kdf;
pub mod mldsa;
pub mod mlkem;
pub mod sha3;
pub mod sig;
pub mod x25519;

/// Length of a SHA-256 digest in bytes.
pub const SHA256_LEN: usize = 32;

/// Length of an HMAC-SHA-256 tag in bytes.
pub const HMAC_SHA256_LEN: usize = 32;

/// Largest output that [`try_pbkdf2_hmac_sha256`] accepts, in bytes.
///
/// PBKDF2 defines at most `2^32 - 1` output blocks of the PRF output length.
pub const PBKDF2_HMAC_SHA256_MAX_OUTPUT: u64 = (u32::MAX as u64) * (SHA256_LEN as u64);

/// Errors reported by this crate.
///
/// No variant carries key material or input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// The system random number generator could not produce output.
    RandomUnavailable,
    /// The requested output is longer than the algorithm allows.
    OutputTooLong,
    /// The underlying library reported a failure without further detail.
    Unspecified,
    /// An input had a length the algorithm does not accept.
    InvalidLength,
    /// Key bytes were refused, for example by the FIPS 203 key checks.
    InvalidKey,
    /// A signature did not verify.
    InvalidSignature,
    /// An AEAD body did not open: wrong key, nonce, AAD or body.
    OpenFailed,
    /// An X25519 agreement gave the all-zero result (ADR-004 "Inputs").
    ZeroSharedSecret,
    /// The key has sealed [`aead::SEAL_LIMIT`] times (ADR-004 "Seal-count
    /// limit"). It seals no more.
    SealLimitReached,
    /// ML-DSA-65 is not available: moduletto at the pinned commit has no
    /// ML-DSA-65 (ADR-001 A2). Nothing falls back to a classical-only
    /// signature (I-75, I-90).
    MlDsaUnavailable,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomUnavailable => f.write_str("system randomness unavailable"),
            Self::OutputTooLong => f.write_str("requested output too long"),
            Self::Unspecified => f.write_str("cryptographic operation failed"),
            Self::InvalidLength => f.write_str("input has the wrong length"),
            Self::InvalidKey => f.write_str("key refused"),
            Self::InvalidSignature => f.write_str("signature did not verify"),
            Self::OpenFailed => f.write_str("sealed body did not open"),
            Self::ZeroSharedSecret => f.write_str("X25519 agreement gave the all-zero result"),
            Self::SealLimitReached => f.write_str("key reached its seal-count limit"),
            Self::MlDsaUnavailable => f.write_str("ML-DSA-65 is not available yet"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Copies an aws-lc-rs digest or tag into a fixed array.
///
/// Both SHA-256 digests and HMAC-SHA-256 tags are exactly 32 bytes, so the
/// copy always fills the array. A shorter input would leave trailing zeros,
/// which cannot happen for the algorithms used here.
fn to_array32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (dst, src) in out.iter_mut().zip(bytes) {
        *dst = *src;
    }
    out
}

/// Computes the SHA-256 digest of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; SHA256_LEN] {
    to_array32(digest::digest(&digest::SHA256, data).as_ref())
}

/// Streaming SHA-256.
///
/// Feeding the same bytes through any sequence of [`Sha256::update`] calls
/// gives the same digest as [`sha256`] over their concatenation.
#[derive(Clone)]
pub struct Sha256 {
    ctx: digest::Context,
}

impl Sha256 {
    /// Starts a new digest computation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ctx: digest::Context::new(&digest::SHA256),
        }
    }

    /// Adds `data` to the digest input.
    pub fn update(&mut self, data: &[u8]) {
        self.ctx.update(data);
    }

    /// Finishes the computation and returns the digest.
    #[must_use]
    pub fn finish(self) -> [u8; SHA256_LEN] {
        to_array32(self.ctx.finish().as_ref())
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sha256").finish_non_exhaustive()
    }
}

/// Computes HMAC-SHA-256 of `data` under `key`.
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; HMAC_SHA256_LEN] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    to_array32(hmac::sign(&key, data).as_ref())
}

/// Verifies an HMAC-SHA-256 `tag` over `data` under `key` in constant time.
///
/// Returns `false` when the tag differs or has the wrong length. The
/// comparison time does not depend on the tag contents.
#[must_use]
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::verify(&key, data, tag).is_ok()
}

/// Streaming HMAC-SHA-256.
///
/// The key is fixed at construction. The tag equals [`hmac_sha256`] over the
/// concatenation of every [`HmacSha256::update`] input.
#[derive(Clone)]
pub struct HmacSha256 {
    ctx: hmac::Context,
}

impl HmacSha256 {
    /// Starts a new HMAC computation under `key`.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        Self {
            ctx: hmac::Context::with_key(&key),
        }
    }

    /// Adds `data` to the HMAC input.
    pub fn update(&mut self, data: &[u8]) {
        self.ctx.update(data);
    }

    /// Finishes the computation and returns the tag.
    #[must_use]
    pub fn finish(self) -> [u8; HMAC_SHA256_LEN] {
        to_array32(self.ctx.sign().as_ref())
    }
}

impl fmt::Debug for HmacSha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material or intermediate state.
        f.debug_struct("HmacSha256").finish_non_exhaustive()
    }
}

/// Derives `out.len()` bytes with PBKDF2-HMAC-SHA-256 (RFC 8018).
///
/// `password` is the PBKDF2 secret `P`, `salt` is `S` and `iterations` is `c`.
/// The derived key length `dkLen` is `out.len()`.
///
/// # Panics
///
/// aws-lc-rs panics when `out` is longer than [`PBKDF2_HMAC_SHA256_MAX_OUTPUT`]
/// bytes (about 137 GB). Callers that take the output length from untrusted
/// input use [`try_pbkdf2_hmac_sha256`] instead, which returns an error.
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: NonZeroU32, out: &mut [u8]) {
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, iterations, salt, password, out);
}

/// Fallible form of [`pbkdf2_hmac_sha256`].
///
/// # Errors
///
/// Returns [`CryptoError::OutputTooLong`] when `out` is longer than
/// [`PBKDF2_HMAC_SHA256_MAX_OUTPUT`] bytes. `out` is left unchanged then.
pub fn try_pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: NonZeroU32,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let len = u64::try_from(out.len()).map_err(|_| CryptoError::OutputTooLong)?;
    if len > PBKDF2_HMAC_SHA256_MAX_OUTPUT {
        return Err(CryptoError::OutputTooLong);
    }
    pbkdf2_hmac_sha256(password, salt, iterations, out);
    Ok(())
}

/// Compares two byte strings in constant time with respect to their contents.
///
/// The running time depends on the lengths, which are treated as public.
/// Strings of different lengths compare unequal.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// Fills `out` with bytes from the system's cryptographically secure
/// random number generator.
///
/// # Errors
///
/// Returns [`CryptoError::RandomUnavailable`] when the generator fails. `out`
/// must not be used then.
pub fn random_bytes(out: &mut [u8]) -> Result<(), CryptoError> {
    rand::fill(out).map_err(|_| CryptoError::RandomUnavailable)
}

/// Returns a fixed-size array of system randomness.
///
/// # Errors
///
/// Returns [`CryptoError::RandomUnavailable`] when the generator fails.
pub fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut out = [0u8; N];
    random_bytes(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_pbkdf2_accepts_normal_lengths() {
        let mut out = [0u8; 64];
        let iterations = NonZeroU32::new(1).unwrap();
        assert!(try_pbkdf2_hmac_sha256(b"p", b"s", iterations, &mut out).is_ok());
        let mut direct = [0u8; 64];
        pbkdf2_hmac_sha256(b"p", b"s", iterations, &mut direct);
        assert_eq!(out, direct);
    }

    #[test]
    fn debug_output_hides_state() {
        let mac = HmacSha256::new(b"secret key");
        let rendered = format!("{mac:?}");
        assert!(!rendered.contains("secret"));
        assert_eq!(format!("{:?}", Sha256::new()), "Sha256 { .. }");
    }

    #[test]
    fn error_display_is_stable() {
        assert_eq!(
            CryptoError::RandomUnavailable.to_string(),
            "system randomness unavailable"
        );
        assert_eq!(
            CryptoError::OutputTooLong.to_string(),
            "requested output too long"
        );
        assert_eq!(
            CryptoError::Unspecified.to_string(),
            "cryptographic operation failed"
        );
    }
}
