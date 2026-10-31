//! Composite signatures: Ed25519 plus ML-DSA-65 (ADR-001 "Post-quantum
//! signatures", M3 design sections 3.9 and 7.4, ADR-010, I-75, I-90).
//!
//! The format is id-MLDSA65-Ed25519-SHA512 of
//! draft-ietf-lamps-pq-composite-sigs version 19, as ADR-001 pins. The
//! encoding follows the ADR-010 "Composite encoding" table, which
//! transcribes the draft text:
//!
//! - The message representative is `M' = Prefix || Label || len(ctx) ||
//!   ctx || SHA-512(M)` (draft sections 2.2 and 3.2). `ctx` is the
//!   application context of at most 255 bytes, empty by default.
//! - The ML-DSA-65 half signs `M'` with the label as its ML-DSA context,
//!   and the Ed25519 half signs `M'` (section 3.2 step 4).
//! - Public key `mldsaPK || tradPK`, 1984 bytes (section 4.1). Private
//!   key `mldsaSeed || tradSK`, 64 bytes (section 4.2). Signature
//!   `mldsaSig || tradSig`, 3373 bytes (section 4.3).
//!
//! Ed25519 and SHA-512 come from aws-lc-rs, and ML-DSA-65 from moduletto
//! (I-75). Verification accepts only when both halves verify (I-90,
//! section 3.3). Nothing signs or verifies with the Ed25519 half alone,
//! and nothing falls back to the aws-lc-rs ML-DSA, which is a test
//! oracle only (ADR-001 A6). The ML-DSA-65 half signs hedged, with fresh
//! randomness from aws-lc-rs.
//!
//! Two platform rules go beyond draft 19, as the ADR-010 table records.
//! A composite public key whose Ed25519 half encodes a point of small
//! order is refused. Under such a key a fixed Ed25519 value verifies over
//! many messages, so the composite would rest on ML-DSA-65 alone. A key
//! whose ML-DSA-65 half has a degenerate `t1` is refused too. That half
//! has the public secret `s1 = s2 = 0`, or lies near it, so the composite
//! would rest on Ed25519 alone (I-75, I-90).

use aws_lc_rs::digest::{SHA512, digest};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::CryptoError;
use crate::mldsa::{self, MlDsa65SigningKey};
use crate::sig::{self, Ed25519SigningKey};

/// Length of a composite public key in bytes: `mldsaPK || tradPK` (draft
/// 19 section 4.1, Appendix A Table 4).
pub const PUBLIC_KEY_LEN: usize = mldsa::PUBLIC_KEY_LEN + sig::ED25519_PUBLIC_KEY_LEN;

/// Length of a composite private key in bytes: the 32-byte ML-DSA-65 seed
/// then the 32-byte Ed25519 private key (draft 19 section 4.2, Appendix A
/// Table 4).
pub const PRIVATE_KEY_LEN: usize = mldsa::SEED_LEN + sig::ED25519_SEED_LEN;

/// Length of a composite signature in bytes: `mldsaSig || tradSig` (draft
/// 19 section 4.3, Appendix A Table 4).
pub const SIGNATURE_LEN: usize = mldsa::SIGNATURE_LEN + sig::ED25519_SIGNATURE_LEN;

/// Length of the ML-DSA-65 half that opens a composite signature (draft 19
/// section 4.3: `mldsaSig = bytes[:3309]`). Code outside this crate splits
/// a composite signature with it and never names the `mldsa` module (I-75).
pub const MLDSA_SIGNATURE_LEN: usize = mldsa::SIGNATURE_LEN;

/// Longest application context in bytes (draft 19 section 3.2 step 1).
pub const MAX_CONTEXT_LEN: usize = 255;

/// Draft 19 section 2.2: the ASCII string
/// "CompositeAlgorithmSignatures2025".
const PREFIX: &[u8; 32] = b"CompositeAlgorithmSignatures2025";

/// Draft 19 section 6: the label of id-MLDSA65-Ed25519-SHA512, as ASCII
/// bytes. It is also the ML-DSA context of the ML-DSA-65 half.
const LABEL: &[u8; 30] = b"COMPSIG-MLDSA65-Ed25519-SHA512";

/// Length of a SHA-512 digest, the pre-hash `PH` of draft 19 section 6.
const PH_LEN: usize = 64;

/// Longest message representative: prefix, label, length byte, context
/// and pre-hash.
const M_PRIME_MAX_LEN: usize = PREFIX.len() + LABEL.len() + 1 + MAX_CONTEXT_LEN + PH_LEN;

/// The Ed25519 public key encodings of the points of small order, with
/// bit 255 (the sign of x) cleared. These are the eight points of order
/// dividing 8. Their y-coordinates, little-endian, are 0, 1, p - 1 and two
/// values of order 8. The two values below 19 also have the non-canonical
/// spellings p and p + 1. The two order 8 rows were checked against the
/// affine y-coordinates of `EIGHT_TORSION` in curve25519-dalek 4.1.3. The
/// list has the shape of libsodium's `ge25519_has_small_order`. It is a
/// table comparison, not a curve operation: the curve arithmetic stays
/// in aws-lc-rs.
const ED25519_SMALL_ORDER: [[u8; sig::ED25519_PUBLIC_KEY_LEN]; 7] = [
    // y = 0: the two points of order 4.
    [0; 32],
    // y = 1: the identity, of order 1.
    [
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ],
    // Order 8.
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    // Order 8.
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    // y = p - 1: the point of order 2.
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // y = p, a non-canonical spelling of y = 0.
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // y = p + 1, a non-canonical spelling of y = 1.
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// Whether `public_key` encodes an Ed25519 point of small order, in any
/// spelling: either sign bit, canonical or not. Public keys are public,
/// so the comparison need not run in constant time.
fn ed25519_has_small_order(public_key: &[u8; sig::ED25519_PUBLIC_KEY_LEN]) -> bool {
    let mut masked = *public_key;
    if let Some(last) = masked.last_mut() {
        *last &= 0x7f;
    }
    ED25519_SMALL_ORDER.contains(&masked)
}

/// The message representative of draft 19 sections 2.2 and 3.2:
/// `Prefix || Label || len(ctx) || ctx || SHA-512(message)`.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidLength`] when `ctx` is longer than
/// [`MAX_CONTEXT_LEN`] bytes (section 3.2 step 1).
fn message_representative(message: &[u8], ctx: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let len = u8::try_from(ctx.len()).map_err(|_| CryptoError::InvalidLength)?;
    let mut out = Vec::with_capacity(M_PRIME_MAX_LEN);
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(LABEL);
    out.push(len);
    out.extend_from_slice(ctx);
    out.extend_from_slice(digest(&SHA512, message).as_ref());
    Ok(out)
}

/// A composite signing key: both halves. Wiped on drop. It has no
/// `Debug`, `Clone` or `Copy`.
pub struct CompositeSigningKey {
    ed25519: Ed25519SigningKey,
    mldsa: MlDsa65SigningKey,
}

impl ZeroizeOnDrop for CompositeSigningKey {}

impl CompositeSigningKey {
    /// Loads a draft 19 private key `mldsaSeed || tradSK` (section 4.2).
    /// The ML-DSA-65 key is regenerated from its seed with
    /// `ML-DSA.KeyGen_internal` (section 3.1). The Ed25519 key comes from
    /// its raw 32-byte RFC 8032 private key (section 4, EdDSA encoding).
    ///
    /// The bytes are for reopening one composite key that
    /// [`CompositeSigningKey::to_bytes`] gave and a keystore sealed. They
    /// are never built from a standalone Ed25519 seed. Section 3.1 says
    /// compliant parties "MUST NOT use, import or export component keys
    /// that are used in other contexts, combinations, or by themselves as
    /// keys for standalone algorithm use".
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] unless `bytes` is
    /// [`PRIVATE_KEY_LEN`] bytes long, and [`CryptoError::InvalidKey`]
    /// when aws-lc-rs refuses the Ed25519 half.
    pub fn from_bytes(bytes: &[u8]) -> Result<CompositeSigningKey, CryptoError> {
        if bytes.len() != PRIVATE_KEY_LEN {
            return Err(CryptoError::InvalidLength);
        }
        let (mldsa_seed, ed_seed) = bytes
            .split_first_chunk::<{ mldsa::SEED_LEN }>()
            .ok_or(CryptoError::InvalidLength)?;
        let ed_seed: &[u8; sig::ED25519_SEED_LEN] =
            ed_seed.try_into().map_err(|_| CryptoError::InvalidLength)?;
        let ed25519 = Ed25519SigningKey::from_seed(ed_seed)?;
        let mldsa = MlDsa65SigningKey::from_seed(mldsa_seed);
        Ok(CompositeSigningKey { ed25519, mldsa })
    }

    /// The draft 19 private key `mldsaSeed || tradSK` (section 4.2), so a
    /// keystore can seal it and reopen it with
    /// [`CompositeSigningKey::from_bytes`]. Wiped on drop.
    ///
    /// The bytes are for sealing and reopening this one composite key
    /// only. Callers never split them, and never load bytes 32 to 63 as a
    /// standalone Ed25519 key or the first 32 as an ML-DSA-65 seed (draft
    /// 19 section 3.1, I-75).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unspecified`] when aws-lc-rs cannot export
    /// the Ed25519 half.
    pub fn to_bytes(&self) -> Result<Zeroizing<[u8; PRIVATE_KEY_LEN]>, CryptoError> {
        let ed_seed = self.ed25519.seed()?;
        let mldsa_seed = self.mldsa.seed();
        let mut out = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
        let (a, b) = out.split_at_mut(mldsa::SEED_LEN);
        a.copy_from_slice(&mldsa_seed[..]);
        b.copy_from_slice(&ed_seed[..]);
        Ok(out)
    }

    /// The composite public key `mldsaPK || tradPK` (section 4.1).
    #[must_use]
    pub fn public_key(&self) -> CompositePublicKey {
        let mut bytes = Box::new([0u8; PUBLIC_KEY_LEN]);
        let (a, b) = bytes.split_at_mut(mldsa::PUBLIC_KEY_LEN);
        a.copy_from_slice(&self.mldsa.public_key());
        b.copy_from_slice(&self.ed25519.public_key());
        CompositePublicKey { bytes }
    }

    /// A composite signature over `message` with the empty application
    /// context, the draft's default (section 3.2).
    ///
    /// # Errors
    ///
    /// As [`CompositeSigningKey::sign_with_context`].
    pub fn sign(&self, message: &[u8]) -> Result<CompositeSignature, CryptoError> {
        self.sign_with_context(message, &[])
    }

    /// `Composite-ML-DSA.Sign(sk, message, ctx)` (draft 19 section 3.2).
    /// Both halves sign the message representative `M'`, the ML-DSA-65
    /// half with the label as its ML-DSA context. The result is
    /// `mldsaSig || tradSig`. A failure of either half gives no
    /// signature.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] when `ctx` is longer than
    /// [`MAX_CONTEXT_LEN`] bytes, [`CryptoError::RandomUnavailable`] when
    /// aws-lc-rs gives no randomness for the ML-DSA-65 half, and
    /// [`CryptoError::Unspecified`] when the Ed25519 half fails.
    pub fn sign_with_context(
        &self,
        message: &[u8],
        ctx: &[u8],
    ) -> Result<CompositeSignature, CryptoError> {
        let m_prime = message_representative(message, ctx)?;
        let mldsa_sig = self.mldsa.sign(&m_prime, LABEL)?;
        let ed_sig = self.ed25519.sign(&m_prime)?;
        let mut bytes = Box::new([0u8; SIGNATURE_LEN]);
        let (a, b) = bytes.split_at_mut(mldsa::SIGNATURE_LEN);
        a.copy_from_slice(&mldsa_sig);
        b.copy_from_slice(&ed_sig);
        Ok(CompositeSignature { bytes })
    }
}

/// A composite public key `mldsaPK || tradPK` (draft 19 section 4.1).
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
    /// Decodes a composite public key `mldsaPK || tradPK` (draft 19
    /// section 4.1). An accepted key re-encodes byte for byte. Two halves
    /// that anyone can sign for are refused, under platform rules beyond
    /// draft 19 (ADR-010 "Composite encoding", I-75, I-90). One is an
    /// Ed25519 half that encodes a point of small order, in any spelling.
    /// The other is an ML-DSA-65 half whose `t1` coefficients all lie in
    /// 0 to 255 or 768 to 1023, which covers the public secret
    /// `s1 = s2 = 0`. Whether the halves are otherwise usable keys is
    /// checked when a signature is verified.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] unless `bytes` is
    /// [`PUBLIC_KEY_LEN`] bytes long, and [`CryptoError::InvalidKey`]
    /// when the Ed25519 half is a point of small order or the ML-DSA-65
    /// half has a degenerate `t1`.
    pub fn from_bytes(bytes: &[u8]) -> Result<CompositePublicKey, CryptoError> {
        let bytes: [u8; PUBLIC_KEY_LEN] =
            bytes.try_into().map_err(|_| CryptoError::InvalidLength)?;
        let (mldsa_pk, ed_pk) = bytes
            .split_first_chunk::<{ mldsa::PUBLIC_KEY_LEN }>()
            .ok_or(CryptoError::InvalidLength)?;
        let ed_pk: &[u8; sig::ED25519_PUBLIC_KEY_LEN] =
            ed_pk.try_into().map_err(|_| CryptoError::InvalidLength)?;
        if ed25519_has_small_order(ed_pk) || mldsa::has_degenerate_t1(mldsa_pk) {
            return Err(CryptoError::InvalidKey);
        }
        Ok(CompositePublicKey {
            bytes: Box::new(bytes),
        })
    }

    /// Encodes the key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        *self.bytes
    }
}

/// A composite signature `mldsaSig || tradSig` (draft 19 section 4.3).
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
    /// Decodes a composite signature `mldsaSig || tradSig` (draft 19
    /// section 4.3). Every byte string of the right length is accepted
    /// and re-encodes byte for byte. Validity is checked by [`verify`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] unless `bytes` is
    /// [`SIGNATURE_LEN`] bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<CompositeSignature, CryptoError> {
        let bytes: [u8; SIGNATURE_LEN] =
            bytes.try_into().map_err(|_| CryptoError::InvalidLength)?;
        Ok(CompositeSignature {
            bytes: Box::new(bytes),
        })
    }

    /// Encodes the signature.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        *self.bytes
    }
}

/// A fresh composite signing key (draft 19 section 3.1). Both halves are
/// generated fresh: the ML-DSA-65 seed and the Ed25519 key come from
/// aws-lc-rs. No Ed25519-only key stands in for a composite one.
///
/// # Errors
///
/// Returns [`CryptoError::RandomUnavailable`] when aws-lc-rs gives no
/// randomness for either half.
pub fn generate() -> Result<CompositeSigningKey, CryptoError> {
    let mldsa = mldsa::generate()?;
    let ed25519 = Ed25519SigningKey::generate()?;
    Ok(CompositeSigningKey { ed25519, mldsa })
}

/// Verifies a composite `signature` over `message` under `public_key`,
/// with the empty application context, the draft's default (section 3.3).
///
/// # Errors
///
/// As [`verify_with_context`].
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    verify_with_context(public_key, message, &[], signature)
}

/// `Composite-ML-DSA.Verify(pk, message, signature, ctx)` (draft 19
/// section 3.3). It accepts only when both halves verify over the message
/// representative `M'` (I-90): the ML-DSA-65 half under `mldsaPK` with the
/// label as its ML-DSA context, and the Ed25519 half under `tradPK`. Both
/// halves are always checked, so a valid half of either kind changes
/// nothing on its own.
///
/// The two refusals of the draft stay apart. Section 3.3 step 1 checks the
/// context first, and its outcome is "return error". Step 2 turns a key or
/// signature that does not deserialize into "Invalid signature". A public
/// key with a small-order Ed25519 half or a degenerate ML-DSA-65 `t1`
/// counts as one that does not deserialize, under the platform rules of
/// [`CompositePublicKey::from_bytes`].
///
/// # Errors
///
/// Returns [`CryptoError::InvalidLength`] when `ctx` is longer than
/// [`MAX_CONTEXT_LEN`] bytes (section 3.3 step 1), whatever the other
/// inputs. Returns [`CryptoError::InvalidSignature`] when `public_key` or
/// `signature` does not decode (step 2), or when either half does not
/// verify (step 4).
pub fn verify_with_context(
    public_key: &[u8],
    message: &[u8],
    ctx: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let m_prime = message_representative(message, ctx)?;
    let public_key =
        CompositePublicKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidSignature)?;
    let signature =
        CompositeSignature::from_bytes(signature).map_err(|_| CryptoError::InvalidSignature)?;
    let (mldsa_pk, ed_pk) = public_key.bytes.split_at(mldsa::PUBLIC_KEY_LEN);
    let (mldsa_sig, ed_sig) = signature.bytes.split_at(mldsa::SIGNATURE_LEN);
    let mldsa_ok = mldsa::verify(mldsa_pk, &m_prime, LABEL, mldsa_sig).is_ok();
    let ed_ok = sig::ed25519_verify(ed_pk, &m_prime, ed_sig).is_ok();
    if mldsa_ok && ed_ok {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}
