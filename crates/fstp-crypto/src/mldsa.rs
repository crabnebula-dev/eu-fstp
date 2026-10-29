//! ML-DSA-65 (FIPS 204), the seam to moduletto (ADR-001 A2, M3 design
//! sections 2.2 and 7.4, I-75).
//!
//! moduletto at the pinned commit `46754f2` has no ML-DSA-65. It is added
//! on the pull request crabnebula-dev/moduletto#13, which Daniel reviews
//! and merges (Q1, design section 21.0). Until the pin moves to a commit
//! with it, every call here refuses with [`CryptoError::MlDsaUnavailable`].
//!
//! No call falls back to anything. The aws-lc-rs ML-DSA is a test oracle
//! only and is never reached from here (ADR-001 A6). Only
//! [`crate::composite`] uses this module, so ML-DSA never stands alone.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CryptoError;

/// Length of an ML-DSA-65 public key in bytes (FIPS 204 Table 2).
pub const PUBLIC_KEY_LEN: usize = 1952;

/// Length of an ML-DSA-65 signature in bytes (FIPS 204 Table 2).
pub const SIGNATURE_LEN: usize = 3309;

/// Length of the ML-DSA-65 key generation seed `xi` in bytes (FIPS 204).
pub const SEED_LEN: usize = 32;

/// An ML-DSA-65 signing key, held as its 32-byte seed. Wiped on drop.
///
/// No value of this type can exist yet: [`generate`] refuses.
pub struct MlDsa65SigningKey {
    seed: [u8; SEED_LEN],
}

impl Drop for MlDsa65SigningKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl ZeroizeOnDrop for MlDsa65SigningKey {}

impl MlDsa65SigningKey {
    /// An ML-DSA-65 signature over `message`.
    ///
    /// # Errors
    ///
    /// Always [`CryptoError::MlDsaUnavailable`] at the pinned moduletto
    /// commit.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], CryptoError> {
        let _ = (&self.seed, message);
        Err(CryptoError::MlDsaUnavailable)
    }

    /// The public key.
    ///
    /// # Errors
    ///
    /// Always [`CryptoError::MlDsaUnavailable`] at the pinned moduletto
    /// commit.
    pub fn public_key(&self) -> Result<[u8; PUBLIC_KEY_LEN], CryptoError> {
        Err(CryptoError::MlDsaUnavailable)
    }
}

/// A fresh ML-DSA-65 signing key.
///
/// # Errors
///
/// Always [`CryptoError::MlDsaUnavailable`] at the pinned moduletto
/// commit.
pub fn generate() -> Result<MlDsa65SigningKey, CryptoError> {
    Err(CryptoError::MlDsaUnavailable)
}

/// Verifies an ML-DSA-65 `signature` over `message` under `public_key`.
///
/// # Errors
///
/// Always [`CryptoError::MlDsaUnavailable`] at the pinned moduletto
/// commit, whatever the input. Nothing is accepted.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let _ = (public_key, message, signature);
    Err(CryptoError::MlDsaUnavailable)
}
