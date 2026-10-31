//! ML-DSA-65 (FIPS 204), the seam to moduletto (ADR-001 A2, M3 design
//! sections 2.2 and 7.4, I-75).
//!
//! moduletto is pinned at commit `6c1ae92`, the merge of its ML-DSA-65
//! pull request crabnebula-dev/moduletto#13 (ADR-001 A2 pin move record
//! of 2026-10-29). Every call here forwards to `moduletto::dsa::ml_dsa_65`.
//! Nothing here implements a primitive of its own.
//!
//! ML-DSA-65 never stands alone (I-75). This module is hidden from the
//! docs. Its key type, key generation, signing and verification are
//! visible to this crate only, and only [`crate::composite`] uses them.
//! The one exception is the hidden [`acvp`] module, for known answers and
//! differential tests, like `mlkem::acvp`. The I-75 source scans refuse
//! every name of this module outside `fstp-crypto` and `fstp-celltest`.
//!
//! Signing is hedged: each signature draws a fresh 32-byte `rnd` from
//! aws-lc-rs (FIPS 204 Algorithm 2). moduletto's `getrandom` and
//! `ct-bench` features stay off. No call falls back to anything. The
//! aws-lc-rs ML-DSA is a test oracle only and is never reached from here
//! (ADR-001 A6).

#![doc(hidden)]

use moduletto::dsa::{DsaError, ml_dsa_65};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::CryptoError;

/// Length of an ML-DSA-65 public key in bytes (FIPS 204 Table 2).
pub const PUBLIC_KEY_LEN: usize = 1952;

/// Length of an ML-DSA-65 signature in bytes (FIPS 204 Table 2).
pub const SIGNATURE_LEN: usize = 3309;

/// Length of the ML-DSA-65 key generation seed `xi` in bytes (FIPS 204).
pub const SEED_LEN: usize = 32;

/// Length of an expanded ML-DSA-65 private key in bytes (FIPS 204 Table
/// 2).
pub const EXPANDED_KEY_LEN: usize = 4032;

/// Length of the signing randomness `rnd` in bytes (FIPS 204 Algorithm
/// 2).
const RND_LEN: usize = 32;

/// Maps a moduletto refusal to the crate error. A wrong key length and a
/// context over 255 bytes are both inputs of a length FIPS 204 refuses.
fn refused(e: DsaError) -> CryptoError {
    match e {
        DsaError::Length | DsaError::Context => CryptoError::InvalidLength,
        DsaError::Randomness => CryptoError::RandomUnavailable,
    }
}

/// An ML-DSA-65 signing key: its 32-byte seed `xi`, the expanded private
/// key and the public key that `ML-DSA.KeyGen_internal(xi)` gives. The
/// seed and the expanded key are wiped on drop. It has no `Debug`, `Clone`
/// or `Copy`.
pub struct MlDsa65SigningKey {
    seed: Zeroizing<[u8; SEED_LEN]>,
    expanded: Box<Zeroizing<[u8; EXPANDED_KEY_LEN]>>,
    public: Box<[u8; PUBLIC_KEY_LEN]>,
}

impl ZeroizeOnDrop for MlDsa65SigningKey {}

impl MlDsa65SigningKey {
    /// The key that FIPS 204 `ML-DSA.KeyGen_internal(xi)` (Algorithm 6)
    /// derives from `seed`. The expanded key is written straight into its
    /// wiped box, so no copy of it is left in this frame.
    pub(crate) fn from_seed(seed: &[u8; SEED_LEN]) -> MlDsa65SigningKey {
        let mut expanded = Box::new(Zeroizing::new([0u8; EXPANDED_KEY_LEN]));
        let mut public = Box::new([0u8; PUBLIC_KEY_LEN]);
        ml_dsa_65::keygen_internal_into(seed, &mut public, &mut expanded);
        MlDsa65SigningKey {
            seed: Zeroizing::new(*seed),
            expanded,
            public,
        }
    }

    /// The 32-byte seed `xi`, the ML-DSA half of a draft 19 composite
    /// private key. Wiped on drop.
    pub(crate) fn seed(&self) -> Zeroizing<[u8; SEED_LEN]> {
        Zeroizing::new(*self.seed)
    }

    /// The public key.
    pub(crate) fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        *self.public
    }

    /// FIPS 204 `ML-DSA.Sign(sk, message, ctx)` (Algorithm 2), hedged,
    /// with a fresh `rnd` from aws-lc-rs.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] when `ctx` is longer than
    /// 255 bytes, and [`CryptoError::RandomUnavailable`] when aws-lc-rs
    /// gives no randomness.
    pub(crate) fn sign(
        &self,
        message: &[u8],
        ctx: &[u8],
    ) -> Result<[u8; SIGNATURE_LEN], CryptoError> {
        let rnd = Zeroizing::new(crate::random_array::<RND_LEN>()?);
        ml_dsa_65::sign(&self.expanded[..], message, ctx, &rnd).map_err(refused)
    }
}

/// A fresh ML-DSA-65 signing key, from a 32-byte seed `xi` drawn from
/// aws-lc-rs (FIPS 204 Algorithm 1).
///
/// # Errors
///
/// Returns [`CryptoError::RandomUnavailable`] when aws-lc-rs gives no
/// randomness.
pub(crate) fn generate() -> Result<MlDsa65SigningKey, CryptoError> {
    let seed = Zeroizing::new(crate::random_array::<SEED_LEN>()?);
    Ok(MlDsa65SigningKey::from_seed(&seed))
}

/// Length of the matrix seed `rho` that opens a public key, before the
/// packed `t1` (FIPS 204 Algorithm 22, `pkEncode`).
const RHO_LEN: usize = 32;

/// Bytes of one group of four packed 10-bit `t1` coefficients.
const T1_GROUP_LEN: usize = 5;

/// The masks of the top two bits, bits 8 and 9, of the four coefficients
/// in a group of five `t1` bytes, applied to bytes 1 to 4. `pkEncode`
/// packs each coefficient as 10 bits, least significant bit first
/// (FIPS 204 Algorithms 16 and 22). So coefficient k of a group fills
/// stream bits 10k to 10k + 9, and its bits 8 and 9 land in byte k + 1.
const T1_TOP_BITS: [u8; 4] = [0x03, 0x0c, 0x30, 0xc0];

/// Whether the public key's `t1` is degenerate: every 10-bit coefficient
/// lies in 0 to 255 or in 768 to 1023, so its top two bits are equal.
///
/// The band holds exactly the coefficients for which `t1 * 2^13` lies
/// within 2^21 of 0 modulo q. A `t1` of only 0 and 1023 has the public
/// secret `s1 = s2 = 0`, with each `t0` coefficient 0 or 1. Anyone can
/// sign under such a key. A `t1` with a few small values among them may
/// still be forged for by a signer that takes `s1 = 0`. The whole band is
/// refused, so those keys need no finer test. An honest `t1` is close to
/// uniform, so it falls in the band with probability about 2^-1536.
///
/// This is a byte check on the FIPS 204 `pkEncode` layout, not lattice
/// arithmetic. It is the platform rule of the ADR-010 "Composite
/// encoding" table, beyond draft 19 and FIPS 204. Public keys are
/// public, so it need not run in constant time.
pub(crate) fn has_degenerate_t1(public_key: &[u8; PUBLIC_KEY_LEN]) -> bool {
    public_key
        .get(RHO_LEN..)
        .unwrap_or_default()
        .chunks_exact(T1_GROUP_LEN)
        .all(|group| {
            group.iter().skip(1).zip(T1_TOP_BITS).all(|(b, mask)| {
                let top = b & mask;
                top == 0 || top == mask
            })
        })
}

/// FIPS 204 `ML-DSA.Verify(pk, message, signature, ctx)` (Algorithm 3).
///
/// # Errors
///
/// Returns [`CryptoError::InvalidLength`] when `public_key` or
/// `signature` has another length than FIPS 204 Table 2 gives, or `ctx`
/// is longer than 255 bytes. Returns [`CryptoError::InvalidSignature`]
/// when a signature of the right length does not verify.
pub(crate) fn verify(
    public_key: &[u8],
    message: &[u8],
    ctx: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    if public_key.len() != PUBLIC_KEY_LEN
        || signature.len() != SIGNATURE_LEN
        || ctx.len() > usize::from(u8::MAX)
    {
        return Err(CryptoError::InvalidLength);
    }
    if ml_dsa_65::verify(public_key, message, ctx, signature) {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}

/// The single-half ML-DSA-65 entry points, for the ACVP known answers and
/// the differential tests against the aws-lc-rs oracle only (M3 design
/// section 7.4, ADR-010 "Verification of ML-DSA-65"). They wrap
/// moduletto's `keygen_internal_into`, `sign` and `verify`.
///
/// This is the one exception to I-75 for signatures. It is hidden from
/// the docs, and the I-75 source scan refuses it, and every other name of
/// this module, outside `fstp-crypto` and `fstp-celltest`. Production
/// code never calls it: a caller that picks `xi` or `rnd` picks the key
/// or the signature. It uses [`crate::composite`].
#[doc(hidden)]
pub mod acvp {
    use moduletto::dsa::ml_dsa_65;
    use zeroize::Zeroizing;

    use super::{EXPANDED_KEY_LEN, PUBLIC_KEY_LEN, SEED_LEN, SIGNATURE_LEN, refused};
    use crate::CryptoError;

    /// FIPS 204 `ML-DSA.KeyGen_internal(xi)` (Algorithm 6): the public key
    /// and the expanded private key.
    ///
    /// # Errors
    ///
    /// None today. The result type leaves room for a key check.
    pub fn keygen(
        xi: &[u8; SEED_LEN],
    ) -> Result<([u8; PUBLIC_KEY_LEN], Zeroizing<[u8; EXPANDED_KEY_LEN]>), CryptoError> {
        let mut pk = [0u8; PUBLIC_KEY_LEN];
        let mut sk = Zeroizing::new([0u8; EXPANDED_KEY_LEN]);
        ml_dsa_65::keygen_internal_into(xi, &mut pk, &mut sk);
        Ok((pk, sk))
    }

    /// FIPS 204 `ML-DSA.Sign(sk, message, ctx)` (Algorithm 2) with the
    /// given `rnd`. Zero `rnd` is the deterministic variant.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] when `sk` is not an
    /// expanded ML-DSA-65 key of 4032 bytes, or `ctx` is longer than 255
    /// bytes.
    pub fn sign(
        sk: &[u8],
        message: &[u8],
        ctx: &[u8],
        rnd: &[u8; 32],
    ) -> Result<[u8; SIGNATURE_LEN], CryptoError> {
        if sk.len() != EXPANDED_KEY_LEN {
            return Err(CryptoError::InvalidLength);
        }
        ml_dsa_65::sign(sk, message, ctx, rnd).map_err(refused)
    }

    /// FIPS 204 `ML-DSA.Verify(pk, message, signature, ctx)` (Algorithm
    /// 3).
    ///
    /// # Errors
    ///
    /// As [`super::verify`]: [`CryptoError::InvalidLength`] for a wrong
    /// length, [`CryptoError::InvalidSignature`] for a signature that does
    /// not verify.
    pub fn verify(
        pk: &[u8],
        message: &[u8],
        ctx: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        super::verify(pk, message, ctx, signature)
    }
}
