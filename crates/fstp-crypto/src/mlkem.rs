//! ML-KEM-768 (FIPS 203) from moduletto (ADR-001 Tier B, A2; M3 design
//! section 2.2).
//!
//! moduletto 0.1.0 at commit `46754f2fccb0a501be278fb2fab63b670101a33d`,
//! with its default features. The calls used are
//! `kem::ml_kem_768::{keygen_derand, encaps_derand, decaps,
//! check_encapsulation_key, check_decapsulation_key}`. moduletto has no
//! random source without its `getrandom` feature, so the randomness `d`,
//! `z` and `m` comes from aws-lc-rs ([`crate::random_bytes`]).
//!
//! Record at first use (ADR-004): moduletto checks encapsulation keys as
//! FIPS 203 section 7.2 requires, in `encaps_derand` and in
//! `check_encapsulation_key`. Decapsulation keys are held in their
//! expanded 2400-byte FIPS 203 form, not as a seed.
//!
//! I-75: nothing outside `fstp-crypto` and the test-only `fstp-celltest`
//! names this module. [`crate::hybrid_kem`] is the one user inside it, so
//! ML-KEM never stands alone. The single-half encapsulation and
//! decapsulation are crate-private. Only the hidden [`acvp`] module
//! reaches them from outside, for known answers and differential tests. aws-lc-rs ML-KEM is a test oracle only and is not used here.

use moduletto::kem::ml_kem_768;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::CryptoError;

/// Length of an ML-KEM-768 encapsulation key in bytes.
pub const ENCAPS_KEY_LEN: usize = ml_kem_768::EK_BYTES;

/// Length of an ML-KEM-768 decapsulation key in bytes, expanded form.
pub const DECAPS_KEY_LEN: usize = ml_kem_768::DK_BYTES;

/// Length of an ML-KEM-768 ciphertext in bytes.
pub const CIPHERTEXT_LEN: usize = ml_kem_768::CT_BYTES;

/// Length of the shared secret in bytes.
pub const SHARED_SECRET_LEN: usize = moduletto::kem::SS_BYTES;

/// Where the encapsulation key sits inside the expanded decapsulation key
/// (FIPS 203 Algorithm 16: `dk = dk_PKE || ek || H(ek) || z`).
const EK_OFFSET_IN_DK: usize = 1152;

/// An ML-KEM-768 encapsulation key that passed the FIPS 203 section 7.2
/// modulus check.
#[derive(Clone, PartialEq, Eq)]
pub struct MlKem768EncapsKey {
    bytes: [u8; ENCAPS_KEY_LEN],
}

impl std::fmt::Debug for MlKem768EncapsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlKem768EncapsKey").finish_non_exhaustive()
    }
}

impl MlKem768EncapsKey {
    /// Imports an encapsulation key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] unless `bytes` is 1184 bytes
    /// long, and [`CryptoError::InvalidKey`] when a coefficient is not
    /// below q.
    pub fn from_bytes(bytes: &[u8]) -> Result<MlKem768EncapsKey, CryptoError> {
        let bytes: [u8; ENCAPS_KEY_LEN] =
            bytes.try_into().map_err(|_| CryptoError::InvalidLength)?;
        ml_kem_768::check_encapsulation_key(&bytes).map_err(|_| CryptoError::InvalidKey)?;
        Ok(MlKem768EncapsKey { bytes })
    }

    /// The key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ENCAPS_KEY_LEN] {
        &self.bytes
    }
}

/// An ML-KEM-768 decapsulation key in its expanded form. Wiped on drop.
pub struct MlKem768DecapsKey {
    bytes: Zeroizing<[u8; DECAPS_KEY_LEN]>,
    ek: MlKem768EncapsKey,
}

impl ZeroizeOnDrop for MlKem768DecapsKey {}

impl MlKem768DecapsKey {
    /// Imports an expanded decapsulation key.
    ///
    /// The FIPS 203 section 7.3 check runs (the embedded hash of `ek`),
    /// and so does the section 7.2 check of the embedded `ek`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] unless `bytes` is 2400 bytes
    /// long, and [`CryptoError::InvalidKey`] when either check fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<MlKem768DecapsKey, CryptoError> {
        if bytes.len() != DECAPS_KEY_LEN {
            return Err(CryptoError::InvalidLength);
        }
        let mut dk = Zeroizing::new([0u8; DECAPS_KEY_LEN]);
        dk.copy_from_slice(bytes);
        MlKem768DecapsKey::from_array(dk)
    }

    fn from_array(dk: Zeroizing<[u8; DECAPS_KEY_LEN]>) -> Result<MlKem768DecapsKey, CryptoError> {
        ml_kem_768::check_decapsulation_key(&dk[..]).map_err(|_| CryptoError::InvalidKey)?;
        let ek = dk
            .get(EK_OFFSET_IN_DK..)
            .and_then(|rest| rest.get(..ENCAPS_KEY_LEN))
            .ok_or(CryptoError::InvalidKey)?;
        let ek = MlKem768EncapsKey::from_bytes(ek).map_err(|_| CryptoError::InvalidKey)?;
        Ok(MlKem768DecapsKey { bytes: dk, ek })
    }

    /// A copy of the expanded key bytes, wiped when dropped.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; DECAPS_KEY_LEN]> {
        let mut out = Zeroizing::new([0u8; DECAPS_KEY_LEN]);
        out.copy_from_slice(&self.bytes[..]);
        out
    }

    /// The encapsulation key embedded in this key.
    #[must_use]
    pub fn encaps_key(&self) -> MlKem768EncapsKey {
        self.ek.clone()
    }
}

/// An ML-KEM-768 shared secret. Wiped on drop.
pub struct SharedSecret {
    bytes: Zeroizing<[u8; SHARED_SECRET_LEN]>,
}

impl ZeroizeOnDrop for SharedSecret {}

impl SharedSecret {
    fn new(ss: [u8; SHARED_SECRET_LEN]) -> SharedSecret {
        SharedSecret {
            bytes: Zeroizing::new(ss),
        }
    }

    /// The secret bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.bytes
    }
}

/// A fresh key pair, with `d` and `z` from the system generator.
///
/// # Errors
///
/// Returns [`CryptoError::RandomUnavailable`] when the generator fails.
pub fn generate() -> Result<MlKem768DecapsKey, CryptoError> {
    let mut d = Zeroizing::new([0u8; 32]);
    let mut z = Zeroizing::new([0u8; 32]);
    crate::random_bytes(&mut d[..])?;
    crate::random_bytes(&mut z[..])?;
    keygen_from(&d, &z)
}

fn keygen_from(d: &[u8; 32], z: &[u8; 32]) -> Result<MlKem768DecapsKey, CryptoError> {
    let (_ek, dk) = ml_kem_768::keygen_derand(d, z);
    MlKem768DecapsKey::from_array(Zeroizing::new(dk))
}

/// Encapsulates to `ek`, with `m` from the system generator. Returns the
/// ciphertext and the shared secret.
///
/// Crate-private: only [`crate::hybrid_kem`] calls it, so ML-KEM never
/// stands alone (I-75).
///
/// # Errors
///
/// Returns [`CryptoError::RandomUnavailable`] when the generator fails,
/// and [`CryptoError::InvalidKey`] when moduletto refuses the key.
pub(crate) fn encapsulate(
    ek: &MlKem768EncapsKey,
) -> Result<([u8; CIPHERTEXT_LEN], SharedSecret), CryptoError> {
    let mut m = Zeroizing::new([0u8; 32]);
    crate::random_bytes(&mut m[..])?;
    encapsulate_with(ek, &m)
}

fn encapsulate_with(
    ek: &MlKem768EncapsKey,
    m: &[u8; 32],
) -> Result<([u8; CIPHERTEXT_LEN], SharedSecret), CryptoError> {
    let (ct, ss) =
        ml_kem_768::encaps_derand(ek.as_bytes(), m).map_err(|_| CryptoError::InvalidKey)?;
    Ok((ct, SharedSecret::new(ss)))
}

/// Decapsulates `ct` with `dk`. A forged ciphertext gives the FIPS 203
/// implicit-rejection key, not an error.
///
/// Crate-private: only [`crate::hybrid_kem`] calls it, so no public
/// function decapsulates with one half only (ADR-004, I-75).
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] when moduletto refuses the key,
/// which a key built by this module never causes.
pub(crate) fn decapsulate(
    dk: &MlKem768DecapsKey,
    ct: &[u8; CIPHERTEXT_LEN],
) -> Result<SharedSecret, CryptoError> {
    let ss = ml_kem_768::decaps(&dk.bytes[..], ct).map_err(|_| CryptoError::InvalidKey)?;
    Ok(SharedSecret::new(ss))
}

/// The single-half ML-KEM-768 entry points, for the NIST ACVP known
/// answers and the differential tests only (ADR-004 test vector plan
/// items 9 and 10). They wrap moduletto's `keygen_derand`,
/// `encaps_derand` and `decaps`.
///
/// This is the one exception to the ADR-004 rule that no function in
/// `fstp-crypto` decapsulates with one half only (I-75). It is hidden
/// from the docs, and the I-75 source scan refuses it, and every other
/// name of this module, outside `fstp-crypto` and `fstp-celltest`.
/// Production code never calls it: a caller that picks `d`, `z` or `m`
/// picks the key or the shared secret. It uses [`crate::hybrid_kem`].
#[doc(hidden)]
pub mod acvp {
    use super::{CIPHERTEXT_LEN, MlKem768DecapsKey, MlKem768EncapsKey, SharedSecret};
    use crate::CryptoError;

    /// FIPS 203 `ML-KEM.KeyGen_internal(d, z)`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] if the result fails its own
    /// checks, which a correct moduletto never causes.
    pub fn keygen(d: &[u8; 32], z: &[u8; 32]) -> Result<MlKem768DecapsKey, CryptoError> {
        super::keygen_from(d, z)
    }

    /// FIPS 203 `ML-KEM.Encaps_internal(ek, m)`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] when moduletto refuses the key.
    pub fn encapsulate(
        ek: &MlKem768EncapsKey,
        m: &[u8; 32],
    ) -> Result<([u8; CIPHERTEXT_LEN], SharedSecret), CryptoError> {
        super::encapsulate_with(ek, m)
    }

    /// FIPS 203 `ML-KEM.Decaps_internal(dk, c)`, with one half only. A
    /// forged ciphertext gives the implicit-rejection key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] when moduletto refuses the key.
    pub fn decapsulate(
        dk: &MlKem768DecapsKey,
        ct: &[u8; CIPHERTEXT_LEN],
    ) -> Result<SharedSecret, CryptoError> {
        super::decapsulate(dk, ct)
    }
}
