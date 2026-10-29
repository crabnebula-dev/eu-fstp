//! AES-256-GCM with random nonces only (M3 design sections 2.2 and 3.2,
//! ADR-004 "Nonce rule" and "Seal-count limit", R-NF-08).
//!
//! Every AES-256-GCM seal in the workspace goes through [`seal`]. It wraps
//! `aws_lc_rs::aead::RandomizedNonceKey`, which draws a fresh 96-bit nonce
//! from the system generator for each seal and returns it. No function
//! here takes a nonce from its caller, and none derives one from a
//! sequence number, row id, counter or time. [`open`] takes the nonce that
//! [`seal`] returned and the caller stored beside the body.
//!
//! Each [`Key`] value counts its own seals in memory and refuses at
//! [`SEAL_LIMIT`]. The count includes seals whose transaction later
//! aborts. The count belongs to the value, not to the key bytes: two
//! values built from the same bytes count apart. So this module does not
//! enforce the limit per key material by itself. ADR-004 "Seal-count
//! limit" gives the authoritative count to `fstp-keys`, which keeps one
//! [`Key`] per data key per process, or carries its count across a
//! re-import with [`Key::from_bytes_with_count`]. A count kept in memory
//! is lost at a crash, so callers draw a new key at every process start.

use std::sync::atomic::{AtomicU64, Ordering};

use aws_lc_rs::aead::{AES_256_GCM, Aad, Nonce, RandomizedNonceKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::CryptoError;

/// Length of an AES-256-GCM key in bytes.
pub const KEY_LEN: usize = 32;

/// Length of a nonce in bytes (96 bits).
pub const NONCE_LEN: usize = 12;

/// Length of the authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// The hard limit of seals per key: 2^24 (ADR-004 "Seal-count limit").
///
/// At this limit the chance of any nonce repeat under one key is about
/// 2^-49, far below the 2^32 bound of NIST SP 800-38D.
pub const SEAL_LIMIT: u64 = 1 << 24;

/// An AES-256-GCM key and its seal count.
///
/// The key bytes live inside AWS-LC, which cleanses them when the key is
/// freed. The type implements no `Debug`, `Clone` or `Copy`.
pub struct Key {
    inner: RandomizedNonceKey,
    seals: AtomicU64,
}

impl ZeroizeOnDrop for Key {}

impl Key {
    /// A fresh key from the system generator.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::RandomUnavailable`] when the generator fails.
    pub fn generate() -> Result<Key, CryptoError> {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        crate::random_bytes(&mut bytes[..])?;
        Key::from_bytes(&bytes)
    }

    /// Imports a key. The seal count of the new value starts at zero.
    ///
    /// The count is per [`Key`] value. Importing the same bytes again
    /// gives a second value with a fresh budget. A caller that rebuilds a
    /// key it already sealed with uses [`Key::from_bytes_with_count`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unspecified`] when aws-lc-rs refuses the key.
    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> Result<Key, CryptoError> {
        Key::from_bytes_with_count(bytes, 0)
    }

    /// Imports a key that has already sealed `seals_so_far` times, so the
    /// limit holds across a re-import (ADR-004 "Seal-count limit"). At or
    /// above [`SEAL_LIMIT`] the key opens but refuses every seal.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unspecified`] when aws-lc-rs refuses the key.
    pub fn from_bytes_with_count(
        bytes: &[u8; KEY_LEN],
        seals_so_far: u64,
    ) -> Result<Key, CryptoError> {
        let inner =
            RandomizedNonceKey::new(&AES_256_GCM, bytes).map_err(|_| CryptoError::Unspecified)?;
        Ok(Key {
            inner,
            seals: AtomicU64::new(seals_so_far),
        })
    }

    /// The seals counted for this value: the count it was imported with,
    /// plus the seals it has made. Refused seals are not counted.
    #[must_use]
    pub fn seal_count(&self) -> u64 {
        self.seals.load(Ordering::SeqCst)
    }

    /// Takes one seal from the budget, or refuses at the limit. A refused
    /// seal leaves the count unchanged.
    fn reserve_seal(&self) -> Result<(), CryptoError> {
        let mut count = self.seals.load(Ordering::SeqCst);
        loop {
            if count >= SEAL_LIMIT {
                return Err(CryptoError::SealLimitReached);
            }
            let next = count.checked_add(1).ok_or(CryptoError::SealLimitReached)?;
            match self
                .seals
                .compare_exchange_weak(count, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Ok(()),
                Err(actual) => count = actual,
            }
        }
    }
}

/// A sealed body and the nonce it was sealed under.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Sealed {
    /// The random nonce, stored beside the body.
    pub nonce: [u8; NONCE_LEN],
    /// The ciphertext followed by the 16-byte tag.
    pub body: Vec<u8>,
}

/// Seals `plaintext` under `key` with `aad`, under a fresh random nonce.
///
/// # Errors
///
/// Returns [`CryptoError::SealLimitReached`] once `key` has sealed
/// [`SEAL_LIMIT`] times. Returns [`CryptoError::OutputTooLong`] for a
/// plaintext whose body length overflows, and [`CryptoError::Unspecified`]
/// when aws-lc-rs fails.
pub fn seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> Result<Sealed, CryptoError> {
    let capacity = plaintext
        .len()
        .checked_add(TAG_LEN)
        .ok_or(CryptoError::OutputTooLong)?;
    key.reserve_seal()?;
    let mut body = Vec::with_capacity(capacity);
    body.extend_from_slice(plaintext);
    match key
        .inner
        .seal_in_place_append_tag(Aad::from(aad), &mut body)
    {
        Ok(nonce) => Ok(Sealed {
            nonce: *nonce.as_ref(),
            body,
        }),
        Err(_) => {
            body.zeroize();
            Err(CryptoError::Unspecified)
        }
    }
}

/// Opens `body` (ciphertext followed by tag) under `key`, the stored
/// `nonce` and `aad`. Opening does not count as a seal.
///
/// # Errors
///
/// Returns [`CryptoError::OpenFailed`] when the body is shorter than the
/// tag or does not authenticate under these inputs.
pub fn open(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if body.len() < TAG_LEN {
        return Err(CryptoError::OpenFailed);
    }
    let mut buf = Zeroizing::new(body.to_vec());
    let len = key
        .inner
        .open_in_place(Nonce::from(nonce), Aad::from(aad), &mut buf[..])
        .map_err(|_| CryptoError::OpenFailed)?
        .len();
    buf.truncate(len);
    Ok(buf)
}
