//! X25519 (RFC 7748) through aws-lc-rs: static keys for recipients and
//! ephemeral keys for senders (M3 design section 2.2, ADR-004 "Inputs").
//!
//! Every agreement refuses the all-zero result with
//! [`CryptoError::ZeroSharedSecret`]. AWS-LC already refuses it, and this
//! module checks again in constant time, so the rule does not rest on one
//! library detail.

use aws_lc_rs::agreement::{self, EphemeralPrivateKey, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::constant_time;
use aws_lc_rs::encoding::{AsBigEndian as _, Curve25519SeedBin};
use aws_lc_rs::rand::SystemRandom;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::CryptoError;

/// Length of an X25519 public key, private key or shared secret in bytes.
pub const KEY_LEN: usize = 32;

/// A static X25519 private key and its public key.
///
/// The scalar lives inside AWS-LC, which cleanses it when the key is
/// freed. A copy is also kept in a wiped buffer, so a keystore can seal
/// the key with [`StaticSecret::to_bytes`] without a fallible export.
pub struct StaticSecret {
    key: PrivateKey,
    scalar: Zeroizing<[u8; KEY_LEN]>,
    public: [u8; KEY_LEN],
}

impl ZeroizeOnDrop for StaticSecret {}

impl StaticSecret {
    /// A fresh key from the system generator.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::RandomUnavailable`] when aws-lc-rs cannot
    /// generate a key.
    pub fn generate() -> Result<StaticSecret, CryptoError> {
        let key = PrivateKey::generate(&X25519).map_err(|_| CryptoError::RandomUnavailable)?;
        let raw: Curve25519SeedBin<'static> =
            key.as_be_bytes().map_err(|_| CryptoError::Unspecified)?;
        let scalar = scalar_bytes(raw.as_ref())?;
        StaticSecret::with_key(key, scalar)
    }

    /// Imports a 32-byte scalar. aws-lc-rs clamps it as RFC 7748 defines.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] when aws-lc-rs refuses it.
    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> Result<StaticSecret, CryptoError> {
        let key =
            PrivateKey::from_private_key(&X25519, bytes).map_err(|_| CryptoError::InvalidKey)?;
        StaticSecret::with_key(key, scalar_bytes(&bytes[..])?)
    }

    fn with_key(
        key: PrivateKey,
        scalar: Zeroizing<[u8; KEY_LEN]>,
    ) -> Result<StaticSecret, CryptoError> {
        let public = key
            .compute_public_key()
            .map_err(|_| CryptoError::InvalidKey)?;
        let public = public_bytes(public.as_ref())?;
        Ok(StaticSecret {
            key,
            scalar,
            public,
        })
    }

    /// The 32-byte scalar, as [`StaticSecret::from_bytes`] takes it back.
    /// Wiped on drop.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; KEY_LEN]> {
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        out.copy_from_slice(&self.scalar[..]);
        out
    }

    /// The public key `X25519(k, 9)`.
    #[must_use]
    pub fn public_key(&self) -> [u8; KEY_LEN] {
        self.public
    }

    /// The shared secret with `peer`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::ZeroSharedSecret`] when the result is all
    /// zero, which a small-order `peer` gives, or when aws-lc-rs refuses.
    pub fn diffie_hellman(&self, peer: &[u8; KEY_LEN]) -> Result<SharedSecret, CryptoError> {
        agreement::agree(
            &self.key,
            UnparsedPublicKey::new(&X25519, peer),
            CryptoError::ZeroSharedSecret,
            SharedSecret::from_agreement,
        )
    }
}

/// An ephemeral X25519 private key. It agrees once and is consumed.
pub struct EphemeralSecret {
    key: EphemeralPrivateKey,
    public: [u8; KEY_LEN],
}

impl ZeroizeOnDrop for EphemeralSecret {}

impl EphemeralSecret {
    /// A fresh ephemeral key from the system generator.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::RandomUnavailable`] when aws-lc-rs cannot
    /// generate a key.
    pub fn generate() -> Result<EphemeralSecret, CryptoError> {
        let key = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new())
            .map_err(|_| CryptoError::RandomUnavailable)?;
        let public = key
            .compute_public_key()
            .map_err(|_| CryptoError::InvalidKey)?;
        let public = public_bytes(public.as_ref())?;
        Ok(EphemeralSecret { key, public })
    }

    /// The public key `E` that travels with the ciphertext.
    #[must_use]
    pub fn public_key(&self) -> [u8; KEY_LEN] {
        self.public
    }

    /// The shared secret with `peer`. The key is consumed.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::ZeroSharedSecret`] when the result is all
    /// zero, or when aws-lc-rs refuses.
    pub fn diffie_hellman(self, peer: &[u8; KEY_LEN]) -> Result<SharedSecret, CryptoError> {
        agreement::agree_ephemeral(
            self.key,
            UnparsedPublicKey::new(&X25519, peer),
            CryptoError::ZeroSharedSecret,
            SharedSecret::from_agreement,
        )
    }
}

fn public_bytes(bytes: &[u8]) -> Result<[u8; KEY_LEN], CryptoError> {
    bytes.try_into().map_err(|_| CryptoError::InvalidKey)
}

fn scalar_bytes(bytes: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    if bytes.len() != KEY_LEN {
        return Err(CryptoError::Unspecified);
    }
    out.copy_from_slice(bytes);
    Ok(out)
}

/// An X25519 shared secret. Wiped on drop.
pub struct SharedSecret {
    bytes: Zeroizing<[u8; KEY_LEN]>,
}

impl ZeroizeOnDrop for SharedSecret {}

impl SharedSecret {
    /// Copies the agreement output and refuses the all-zero value.
    fn from_agreement(raw: &[u8]) -> Result<SharedSecret, CryptoError> {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        if raw.len() != KEY_LEN {
            return Err(CryptoError::Unspecified);
        }
        bytes.copy_from_slice(raw);
        if constant_time::verify_slices_are_equal(&bytes[..], &[0u8; KEY_LEN]).is_ok() {
            return Err(CryptoError::ZeroSharedSecret);
        }
        Ok(SharedSecret { bytes })
    }

    /// The secret bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}
