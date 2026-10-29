//! Composite signatures: Ed25519 plus ML-DSA-65 (ADR-001 "Post-quantum
//! signatures", M3 design section 7.4, ADR-010, I-75, I-90).
//!
//! The format is draft-ietf-lamps-pq-composite-sigs version 19, as ADR-001
//! pins. ADR-010 transcribes its encoding from the draft text before any
//! code relies on it, and has not done so yet (ADR-010 open point 1). So
//! no layout is fixed here, and the decoders refuse every input.
//!
//! Ed25519 comes from aws-lc-rs and ML-DSA-65 from moduletto (I-75).
//! moduletto has no ML-DSA-65 at its pinned commit, so key generation,
//! signing and verification all refuse with
//! [`CryptoError::MlDsaUnavailable`]. Nothing signs or verifies with the
//! Ed25519 half alone (I-90), and nothing falls back to the aws-lc-rs
//! ML-DSA, which is a test oracle only.

use zeroize::ZeroizeOnDrop;

use crate::CryptoError;
use crate::mldsa::{self, MlDsa65SigningKey};
use crate::sig::{self, Ed25519SigningKey};

/// Length of a composite public key in bytes: the ML-DSA-65 and Ed25519
/// public keys together. Any framing draft 19 adds is not transcribed yet
/// (ADR-010), and [`CompositePublicKey::from_bytes`] refuses every input.
pub const PUBLIC_KEY_LEN: usize = mldsa::PUBLIC_KEY_LEN + sig::ED25519_PUBLIC_KEY_LEN;

/// Length of a composite signature in bytes: the ML-DSA-65 and Ed25519
/// signatures together. Any framing draft 19 adds is not transcribed yet
/// (ADR-010), and [`CompositeSignature::from_bytes`] refuses every input.
pub const SIGNATURE_LEN: usize = mldsa::SIGNATURE_LEN + sig::ED25519_SIGNATURE_LEN;

/// A composite signing key: both halves. Wiped on drop.
///
/// No value of this type can exist yet: [`generate`] refuses.
pub struct CompositeSigningKey {
    ed25519: Ed25519SigningKey,
    mldsa: MlDsa65SigningKey,
}

impl ZeroizeOnDrop for CompositeSigningKey {}

impl CompositeSigningKey {
    /// A composite signature over `message`.
    ///
    /// The ML-DSA-65 half signs first. It refuses, so the Ed25519 half
    /// never signs alone.
    ///
    /// # Errors
    ///
    /// Always [`CryptoError::MlDsaUnavailable`] at the pinned moduletto
    /// commit.
    pub fn sign(&self, message: &[u8]) -> Result<CompositeSignature, CryptoError> {
        let _mldsa = self.mldsa.sign(message)?;
        let _ed25519 = self.ed25519.sign(message)?;
        Err(CryptoError::MlDsaUnavailable)
    }
}

/// A composite public key.
#[derive(Clone, PartialEq, Eq)]
pub struct CompositePublicKey {
    bytes: Box<[u8; PUBLIC_KEY_LEN]>,
}

impl std::fmt::Debug for CompositePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositePublicKey").finish_non_exhaustive()
    }
}

impl CompositePublicKey {
    /// Decodes a composite public key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] unless `bytes` is
    /// [`PUBLIC_KEY_LEN`] bytes long. Otherwise returns
    /// [`CryptoError::MlDsaUnavailable`], since neither the draft 19
    /// layout nor an ML-DSA-65 key check exists yet.
    pub fn from_bytes(bytes: &[u8]) -> Result<CompositePublicKey, CryptoError> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidLength);
        }
        Err(CryptoError::MlDsaUnavailable)
    }

    /// Encodes the key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        *self.bytes
    }
}

/// A composite signature.
#[derive(Clone, PartialEq, Eq)]
pub struct CompositeSignature {
    bytes: Box<[u8; SIGNATURE_LEN]>,
}

impl std::fmt::Debug for CompositeSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeSignature").finish_non_exhaustive()
    }
}

impl CompositeSignature {
    /// Decodes a composite signature.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] unless `bytes` is
    /// [`SIGNATURE_LEN`] bytes long. Otherwise returns
    /// [`CryptoError::MlDsaUnavailable`], since the draft 19 layout is not
    /// transcribed yet.
    pub fn from_bytes(bytes: &[u8]) -> Result<CompositeSignature, CryptoError> {
        if bytes.len() != SIGNATURE_LEN {
            return Err(CryptoError::InvalidLength);
        }
        Err(CryptoError::MlDsaUnavailable)
    }

    /// Encodes the signature.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        *self.bytes
    }
}

/// A fresh composite signing key.
///
/// # Errors
///
/// Always [`CryptoError::MlDsaUnavailable`] at the pinned moduletto
/// commit. No Ed25519-only key stands in for a composite one.
pub fn generate() -> Result<CompositeSigningKey, CryptoError> {
    let mldsa = mldsa::generate()?;
    let ed25519 = Ed25519SigningKey::generate()?;
    Ok(CompositeSigningKey { ed25519, mldsa })
}

/// Verifies a composite `signature` over `message` under `public_key`.
/// It accepts only when both halves verify (I-90).
///
/// # Errors
///
/// Always [`CryptoError::MlDsaUnavailable`] at the pinned moduletto
/// commit, whatever the input. The Ed25519 half is not checked on its
/// own, so a valid Ed25519 half changes nothing.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let _ = (public_key, message, signature);
    Err(CryptoError::MlDsaUnavailable)
}
