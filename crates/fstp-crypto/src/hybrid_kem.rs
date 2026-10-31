//! The hybrid KEM: X25519 plus ML-KEM-768 with the HKDF-SHA-256 combiner
//! of ADR-004 "Completion part 1" (M3 design section 3.2, Q2 option A,
//! T-CR-HYBRID for TH-50, I-75).
//!
//! ```text
//! salt = "fstp-hkem-v1"                                   12 bytes
//! ikm  = ss_M || ss_X                                     64 bytes
//! prk  = HKDF-SHA-256-Extract(salt, ikm)
//! info = SHA-256(ct_M) || E || pk_X || SHA-256(pk_M)     128 bytes
//! ss   = HKDF-SHA-256-Expand(prk, info, L = 32)
//! ```
//!
//! A hybrid public key is `pk_X || pk_M` (1216 bytes). A hybrid ciphertext
//! is `E || ct_M` (1120 bytes). Every length is fixed, and each decoder
//! accepts exactly one spelling.
//!
//! No function here decapsulates with one half only (I-75). Both halves
//! always run, even when one fails, so timing does not tell which failed.
//! The published combiner bytes never change (ADR-004 "Freeze rule"): a
//! change needs a new `kem` code, a new salt label and an ADR amendment.

use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::CryptoError;
use crate::mlkem::{self, MlKem768DecapsKey, MlKem768EncapsKey};
use crate::x25519::{self, EphemeralSecret, StaticSecret};

/// The HKDF salt of the combiner, `"fstp-hkem-v1"` without a terminator.
pub const SALT: &[u8; 12] = b"fstp-hkem-v1";

/// Length of a hybrid public key: `pk_X || pk_M`.
pub const PUBLIC_KEY_LEN: usize = X_LEN + mlkem::ENCAPS_KEY_LEN;

/// Length of a hybrid ciphertext: `E || ct_M`.
pub const CIPHERTEXT_LEN: usize = X_LEN + mlkem::CIPHERTEXT_LEN;

/// Length of a hybrid secret key: `sk_X || dk_M`, with `dk_M` in its
/// expanded FIPS 203 form.
pub const SECRET_KEY_LEN: usize = X_LEN + mlkem::DECAPS_KEY_LEN;

/// Length of the combined shared secret.
pub const SHARED_SECRET_LEN: usize = 32;

const X_LEN: usize = x25519::KEY_LEN;

/// A hybrid public key: the recipient's static X25519 key and its
/// ML-KEM-768 encapsulation key.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridPublicKey {
    x: [u8; X_LEN],
    m: MlKem768EncapsKey,
}

impl std::fmt::Debug for HybridPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridPublicKey").finish_non_exhaustive()
    }
}

impl HybridPublicKey {
    /// Decodes `pk_X || pk_M`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] unless `bytes` is exactly
    /// 1216 bytes, and [`CryptoError::InvalidKey`] when `pk_M` fails the
    /// FIPS 203 modulus check. Any 32 bytes are an X25519 public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<HybridPublicKey, CryptoError> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidLength);
        }
        let (x, m) = bytes.split_at(X_LEN);
        let x: [u8; X_LEN] = x.try_into().map_err(|_| CryptoError::InvalidLength)?;
        let m = MlKem768EncapsKey::from_bytes(m)?;
        Ok(HybridPublicKey { x, m })
    }

    /// Encodes `pk_X || pk_M`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        let mut out = [0u8; PUBLIC_KEY_LEN];
        let (x, m) = out.split_at_mut(X_LEN);
        x.copy_from_slice(&self.x);
        m.copy_from_slice(self.m.as_bytes());
        out
    }
}

/// A hybrid secret key: both secret halves and the public key they make.
/// The halves are wiped on drop.
pub struct HybridSecretKey {
    x: StaticSecret,
    m: MlKem768DecapsKey,
    public: HybridPublicKey,
}

impl ZeroizeOnDrop for HybridSecretKey {}

impl HybridSecretKey {
    /// Builds a secret key from its two halves, as a keystore opens a
    /// stored group secret.
    ///
    /// # Errors
    ///
    /// Infallible for halves this crate built. The public half is always
    /// recomputed from the two secret halves, never taken from storage.
    pub fn from_parts(
        x: StaticSecret,
        m: MlKem768DecapsKey,
    ) -> Result<HybridSecretKey, CryptoError> {
        let public = HybridPublicKey {
            x: x.public_key(),
            m: m.encaps_key(),
        };
        Ok(HybridSecretKey { x, m, public })
    }

    /// Decodes `sk_X || dk_M`, the form [`HybridSecretKey::to_bytes`]
    /// writes. A keystore opens a sealed level 2 group secret with it
    /// (ADR-004 part 2). The public half is recomputed from both halves.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] unless `bytes` is exactly
    /// [`SECRET_KEY_LEN`] bytes. Returns [`CryptoError::InvalidKey`] when
    /// aws-lc-rs refuses the X25519 scalar, or when `dk_M` fails the FIPS
    /// 203 section 7.2 or 7.3 check.
    pub fn from_bytes(bytes: &[u8]) -> Result<HybridSecretKey, CryptoError> {
        if bytes.len() != SECRET_KEY_LEN {
            return Err(CryptoError::InvalidLength);
        }
        let (x, m) = bytes.split_at(X_LEN);
        let mut scalar = Zeroizing::new([0u8; X_LEN]);
        scalar.copy_from_slice(x);
        let x = StaticSecret::from_bytes(&scalar)?;
        let m = MlKem768DecapsKey::from_bytes(m)?;
        HybridSecretKey::from_parts(x, m)
    }

    /// Encodes `sk_X || dk_M`: the 32-byte X25519 scalar, then the
    /// expanded 2400-byte ML-KEM-768 decapsulation key. Both halves always
    /// travel together (I-75). Wiped on drop.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; SECRET_KEY_LEN]> {
        let mut out = Zeroizing::new([0u8; SECRET_KEY_LEN]);
        let (x, m) = out.split_at_mut(X_LEN);
        x.copy_from_slice(&self.x.to_bytes()[..]);
        m.copy_from_slice(&self.m.to_bytes()[..]);
        out
    }

    /// The public key `pk_X || pk_M` of both halves.
    #[must_use]
    pub fn public(&self) -> &HybridPublicKey {
        &self.public
    }
}

/// A hybrid ciphertext: the sender's ephemeral X25519 key `E` and the
/// ML-KEM-768 ciphertext `ct_M`.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridCiphertext {
    e: [u8; X_LEN],
    m: [u8; mlkem::CIPHERTEXT_LEN],
}

impl std::fmt::Debug for HybridCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridCiphertext").finish_non_exhaustive()
    }
}

impl HybridCiphertext {
    /// Decodes `E || ct_M`. Every 1120-byte input is a ciphertext.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] unless `bytes` is exactly
    /// 1120 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<HybridCiphertext, CryptoError> {
        if bytes.len() != CIPHERTEXT_LEN {
            return Err(CryptoError::InvalidLength);
        }
        let (e, m) = bytes.split_at(X_LEN);
        Ok(HybridCiphertext {
            e: e.try_into().map_err(|_| CryptoError::InvalidLength)?,
            m: m.try_into().map_err(|_| CryptoError::InvalidLength)?,
        })
    }

    /// Encodes `E || ct_M`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CIPHERTEXT_LEN] {
        let mut out = [0u8; CIPHERTEXT_LEN];
        let (e, m) = out.split_at_mut(X_LEN);
        e.copy_from_slice(&self.e);
        m.copy_from_slice(&self.m);
        out
    }
}

/// The combined shared secret `ss`. It is never a key itself: it feeds
/// the key derivation of the sealed key format (ADR-004). Wiped on drop.
pub struct SharedSecret {
    bytes: Zeroizing<[u8; SHARED_SECRET_LEN]>,
}

impl ZeroizeOnDrop for SharedSecret {}

impl SharedSecret {
    /// The secret bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.bytes
    }
}

/// A fresh hybrid key pair from the system generator.
///
/// # Errors
///
/// Returns [`CryptoError::RandomUnavailable`] when the generator fails.
pub fn generate() -> Result<HybridSecretKey, CryptoError> {
    HybridSecretKey::from_parts(StaticSecret::generate()?, mlkem::generate()?)
}

/// Encapsulates to `pk`: a fresh ML-KEM-768 encapsulation to `pk_M` and a
/// fresh ephemeral X25519 key against `pk_X`, then [`combine`].
///
/// # Errors
///
/// Returns [`CryptoError::RandomUnavailable`] when the generator fails,
/// and [`CryptoError::ZeroSharedSecret`] when `pk_X` gives the all-zero
/// X25519 result.
pub fn encapsulate(pk: &HybridPublicKey) -> Result<(HybridCiphertext, SharedSecret), CryptoError> {
    let (ct_m, ss_m) = mlkem::encapsulate(&pk.m)?;
    let eph = EphemeralSecret::generate()?;
    let e = eph.public_key();
    let ss_x = eph.diffie_hellman(&pk.x)?;
    let ss = combine(
        ss_m.expose(),
        ss_x.expose(),
        &ct_m,
        &e,
        &pk.x,
        pk.m.as_bytes(),
    )?;
    Ok((HybridCiphertext { e, m: ct_m }, ss))
}

/// Decapsulates `ct` with both halves of `sk`. `pk_X` and `pk_M` come from
/// the stored public half, never from the ciphertext.
///
/// Both halves run before either result is looked at. A forged `ct_M`
/// gives an unrelated secret (FIPS 203 implicit rejection), so the failure
/// shows at the AEAD step that uses it.
///
/// # Errors
///
/// Returns [`CryptoError::ZeroSharedSecret`] when `E` gives the all-zero
/// X25519 result.
pub fn decapsulate(
    sk: &HybridSecretKey,
    ct: &HybridCiphertext,
) -> Result<SharedSecret, CryptoError> {
    let ss_m = mlkem::decapsulate(&sk.m, &ct.m);
    let ss_x = sk.x.diffie_hellman(&ct.e);
    let (ss_m, ss_x) = (ss_m?, ss_x?);
    combine(
        ss_m.expose(),
        ss_x.expose(),
        &ct.m,
        &ct.e,
        &sk.public.x,
        sk.public.m.as_bytes(),
    )
}

/// The ADR-004 combiner. Every input it names is a parameter, and no
/// input is read from ambient state.
///
/// Public so the fixed-input vectors of ADR-004 test vector plan item 2
/// can test it. Callers use [`encapsulate`] and [`decapsulate`].
///
/// # Errors
///
/// Returns [`CryptoError::Unspecified`] when aws-lc-rs HKDF fails.
#[doc(hidden)]
pub fn combine(
    ss_m: &[u8; 32],
    ss_x: &[u8; 32],
    ct_m: &[u8; mlkem::CIPHERTEXT_LEN],
    e: &[u8; X_LEN],
    pk_x: &[u8; X_LEN],
    pk_m: &[u8; mlkem::ENCAPS_KEY_LEN],
) -> Result<SharedSecret, CryptoError> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    let (first, second) = ikm.split_at_mut(32);
    first.copy_from_slice(ss_m);
    second.copy_from_slice(ss_x);
    let prk = crate::kdf::extract(SALT, &ikm[..]);
    let ct_hash = crate::sha256(ct_m);
    let pk_hash = crate::sha256(pk_m);
    let info: [&[u8]; 4] = [&ct_hash, e, pk_x, &pk_hash];
    let mut bytes = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
    crate::kdf::expand(&prk, &info, &mut bytes[..]).map_err(|_| CryptoError::Unspecified)?;
    Ok(SharedSecret { bytes })
}
