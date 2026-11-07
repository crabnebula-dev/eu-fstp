//! Classical signatures through aws-lc-rs (M3 design section 2.2):
//!
//! - Ed25519 sign and verify (RFC 8032), for tickets and licence tokens.
//! - ECDSA P-256 with SHA-256, for the certificate authorities and proofs
//!   of possession of design section 1.3 (ADR-005). Signatures are the DER
//!   `ECDSA-Sig-Value` that X.509 carries, so `fstp_pki::cert::assemble`
//!   takes them as they are.
//! - RSA PKCS#1 v1.5 with SHA-256: verify for WebAuthn RS256 (ADR-008),
//!   and sign for DKIM rsa-sha256 (ADR-001, M6 lane L6-MAIL). Moduli
//!   below 2048 bits are refused.
//!
//! Nothing here signs with Ed25519 in place of a composite signature
//! (I-75, I-90). That rule lives in [`crate::composite`].

use aws_lc_rs::digest::{Digest, SHA256};
use aws_lc_rs::encoding::{AsDer as _, Pkcs8V1Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize as RsaKeySize;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, ED25519, EcdsaKeyPair, Ed25519KeyPair,
    KeyPair as _, ParsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256, RsaKeyPair,
    RsaPublicKeyComponents, UnparsedPublicKey,
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::CryptoError;

/// Length of an Ed25519 public key in bytes.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Length of an Ed25519 signature in bytes.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Length of an Ed25519 seed (the RFC 8032 private key) in bytes.
pub const ED25519_SEED_LEN: usize = 32;

/// The PKCS#8 v1 prefix of an Ed25519 private key (RFC 8410): version 0,
/// the id-Ed25519 identifier, then the 32-byte seed as an OCTET STRING
/// inside an OCTET STRING.
const ED25519_PKCS8_V1_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// The DER prefix of a P-256 SubjectPublicKeyInfo (RFC 5480): the
/// id-ecPublicKey and prime256v1 identifiers, then a 66-byte BIT STRING
/// with no unused bits. A P-256 SPKI is this prefix and the uncompressed
/// point, so a caller holding raw COSE `x` and `y` can use
/// [`ecdsa_p256_sha256_verify_point`] instead of building it.
pub const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Length of an uncompressed P-256 point: `0x04 || x || y`.
pub const P256_POINT_LEN: usize = 65;

/// Length of a P-256 SubjectPublicKeyInfo with an uncompressed point.
pub const P256_SPKI_LEN: usize = 91;

// ---------------------------------------------------------------- Ed25519

/// An Ed25519 signing key. The seed lives inside AWS-LC, which cleanses
/// it when the key is freed.
pub struct Ed25519SigningKey {
    key: Ed25519KeyPair,
}

impl ZeroizeOnDrop for Ed25519SigningKey {}

impl Ed25519SigningKey {
    /// A fresh key from the system generator.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::RandomUnavailable`] when aws-lc-rs cannot
    /// generate a key.
    pub fn generate() -> Result<Ed25519SigningKey, CryptoError> {
        let key = Ed25519KeyPair::generate().map_err(|_| CryptoError::RandomUnavailable)?;
        Ok(Ed25519SigningKey { key })
    }

    /// The key whose RFC 8032 private key is `seed`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] when aws-lc-rs refuses it.
    pub fn from_seed(seed: &[u8; ED25519_SEED_LEN]) -> Result<Ed25519SigningKey, CryptoError> {
        let key = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Ed25519SigningKey { key })
    }

    /// The 32-byte public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; ED25519_PUBLIC_KEY_LEN] {
        let mut out = [0u8; ED25519_PUBLIC_KEY_LEN];
        for (dst, src) in out.iter_mut().zip(self.key.public_key().as_ref()) {
            *dst = *src;
        }
        out
    }

    /// The RFC 8032 private key (the seed), so a keystore can seal it and
    /// reopen it with [`Ed25519SigningKey::from_seed`]. Wiped on drop.
    ///
    /// The seed is read from the PKCS#8 v1 export of aws-lc-rs, whose
    /// buffer is wiped on drop. The `seed` accessor of aws-lc-rs is not
    /// used, because its buffer is not wiped.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unspecified`] when aws-lc-rs cannot export
    /// the key, or exports another layout than RFC 8410 PKCS#8 v1.
    pub fn seed(&self) -> Result<Zeroizing<[u8; ED25519_SEED_LEN]>, CryptoError> {
        let doc = self
            .key
            .to_pkcs8v1()
            .map_err(|_| CryptoError::Unspecified)?;
        let (prefix, seed) = doc
            .as_ref()
            .split_at_checked(ED25519_PKCS8_V1_PREFIX.len())
            .ok_or(CryptoError::Unspecified)?;
        if prefix != ED25519_PKCS8_V1_PREFIX || seed.len() != ED25519_SEED_LEN {
            return Err(CryptoError::Unspecified);
        }
        let mut out = Zeroizing::new([0u8; ED25519_SEED_LEN]);
        out.copy_from_slice(seed);
        Ok(out)
    }

    /// The deterministic RFC 8032 signature over `message`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unspecified`] when AWS-LC cannot sign, which
    /// only an internal failure such as an allocation failure causes.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; ED25519_SIGNATURE_LEN], CryptoError> {
        let sig = self
            .key
            .try_sign(message)
            .map_err(|_| CryptoError::Unspecified)?;
        sig.as_ref()
            .try_into()
            .map_err(|_| CryptoError::Unspecified)
    }
}

/// Verifies an Ed25519 `signature` over `message` under `public_key`.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidLength`] unless the key is 32 bytes and
/// the signature 64. Returns [`CryptoError::InvalidSignature`] when the
/// signature does not verify.
pub fn ed25519_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    if public_key.len() != ED25519_PUBLIC_KEY_LEN || signature.len() != ED25519_SIGNATURE_LEN {
        return Err(CryptoError::InvalidLength);
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

// ------------------------------------------------------------ ECDSA P-256

/// An ECDSA P-256 key pair for SHA-256 signatures. The private scalar
/// lives inside AWS-LC, which cleanses it when the key is freed.
pub struct EcdsaP256KeyPair {
    key: EcdsaKeyPair,
}

impl ZeroizeOnDrop for EcdsaP256KeyPair {}

impl EcdsaP256KeyPair {
    /// A fresh key pair from the system generator.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::RandomUnavailable`] when aws-lc-rs cannot
    /// generate a key.
    pub fn generate() -> Result<EcdsaP256KeyPair, CryptoError> {
        let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)
            .map_err(|_| CryptoError::RandomUnavailable)?;
        Ok(EcdsaP256KeyPair { key })
    }

    /// Imports a PKCS#8 document that holds a P-256 key, as a key daemon
    /// reloads a stored CA key at start (ADR-004 part 2). aws-lc-rs checks
    /// that the private scalar and the public point belong together.
    ///
    /// Only the exact spelling that [`EcdsaP256KeyPair::pkcs8_der`] writes
    /// is accepted. The loaded key is exported again, and the export must
    /// equal the input byte for byte. So trailing bytes, another DER
    /// length form or a PKCS#8 v2 document are refused, and one key has
    /// one stored spelling.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] when aws-lc-rs refuses the
    /// document, for example a key on another curve or a malformed one,
    /// and when the document is not the exact PKCS#8 v1 export of the key.
    pub fn from_pkcs8(pkcs8_der: &[u8]) -> Result<EcdsaP256KeyPair, CryptoError> {
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_der)
            .map_err(|_| CryptoError::InvalidKey)?;
        let canonical = key.to_pkcs8v1().map_err(|_| CryptoError::InvalidKey)?;
        if !crate::constant_time_eq(canonical.as_ref(), pkcs8_der) {
            return Err(CryptoError::InvalidKey);
        }
        Ok(EcdsaP256KeyPair { key })
    }

    /// The public key as a DER SubjectPublicKeyInfo with an uncompressed
    /// point, 91 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unspecified`] when aws-lc-rs cannot encode it.
    pub fn spki_der(&self) -> Result<Vec<u8>, CryptoError> {
        let der = self
            .key
            .public_key()
            .as_der()
            .map_err(|_| CryptoError::Unspecified)?;
        let der = der.as_ref().to_vec();
        if p256_point(&der).is_none() {
            return Err(CryptoError::Unspecified);
        }
        Ok(der)
    }

    /// The private key as a PKCS#8 v1 DER document.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unspecified`] when aws-lc-rs cannot encode it.
    pub fn pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let doc = self
            .key
            .to_pkcs8v1()
            .map_err(|_| CryptoError::Unspecified)?;
        Ok(Zeroizing::new(doc.as_ref().to_vec()))
    }

    /// An ECDSA P-256 SHA-256 signature over `message`, as a DER
    /// `ECDSA-Sig-Value`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unspecified`] when aws-lc-rs fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sig = self
            .key
            .sign(&SystemRandom::new(), message)
            .map_err(|_| CryptoError::Unspecified)?;
        Ok(sig.as_ref().to_vec())
    }

    /// An ECDSA P-256 signature over a precomputed SHA-256 `digest`, as a
    /// DER `ECDSA-Sig-Value`. This is the custody `sign` of ADR-004 part 2,
    /// which signs the digest of the certificate bytes `fstp-pki` built.
    ///
    /// The result verifies with [`ecdsa_p256_sha256_verify`] over the
    /// message whose SHA-256 is `digest`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unspecified`] when aws-lc-rs fails.
    pub fn sign_digest(&self, digest: &[u8; crate::SHA256_LEN]) -> Result<Vec<u8>, CryptoError> {
        let digest =
            Digest::import_less_safe(digest, &SHA256).map_err(|_| CryptoError::Unspecified)?;
        let sig = self
            .key
            .sign_digest(&digest)
            .map_err(|_| CryptoError::Unspecified)?;
        Ok(sig.as_ref().to_vec())
    }
}

/// The uncompressed point of a P-256 SubjectPublicKeyInfo, or `None` for
/// any other byte string. Only the one DER spelling with an uncompressed
/// point is accepted. The point is not checked against the curve here.
fn p256_point(spki_der: &[u8]) -> Option<&[u8; P256_POINT_LEN]> {
    let (prefix, point) = spki_der.split_at_checked(P256_SPKI_PREFIX.len())?;
    let point: &[u8; P256_POINT_LEN] = point.try_into().ok()?;
    if prefix != P256_SPKI_PREFIX || point.first() != Some(&0x04) {
        return None;
    }
    Some(point)
}

/// The P-256 public key `point`, parsed and checked to lie on the curve.
fn parse_p256_point(point: &[u8; P256_POINT_LEN]) -> Result<ParsedPublicKey, CryptoError> {
    if point.first() != Some(&0x04) {
        return Err(CryptoError::InvalidKey);
    }
    ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point).map_err(|_| CryptoError::InvalidKey)
}

/// Checks that `point` is an uncompressed P-256 public key `0x04 || x ||
/// y` that lies on the curve. A WebAuthn registration can refuse a bad
/// COSE key with it before any assertion arrives.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] when the first byte is not `0x04`
/// or the point is not on the curve.
pub fn p256_point_check(point: &[u8; P256_POINT_LEN]) -> Result<(), CryptoError> {
    parse_p256_point(point).map(|_| ())
}

/// Checks that `spki_der` is a P-256 SubjectPublicKeyInfo with an
/// uncompressed point that lies on the curve.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] for any other byte string.
pub fn p256_spki_check(spki_der: &[u8]) -> Result<(), CryptoError> {
    let point = p256_point(spki_der).ok_or(CryptoError::InvalidKey)?;
    p256_point_check(point)
}

/// Verifies an ECDSA P-256 SHA-256 `signature_der` (a DER
/// `ECDSA-Sig-Value`) over `message` under the key in `spki_der`.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] when `spki_der` is not a P-256
/// SubjectPublicKeyInfo with an uncompressed point on the curve. Returns
/// [`CryptoError::InvalidSignature`] when the signature does not verify.
pub fn ecdsa_p256_sha256_verify(
    spki_der: &[u8],
    message: &[u8],
    signature_der: &[u8],
) -> Result<(), CryptoError> {
    let point = p256_point(spki_der).ok_or(CryptoError::InvalidKey)?;
    ecdsa_p256_sha256_verify_point(point, message, signature_der)
}

/// Verifies an ECDSA P-256 SHA-256 `signature_der` (a DER
/// `ECDSA-Sig-Value`) over `message` under the uncompressed `point`
/// `0x04 || x || y`. This is WebAuthn ES256 with the raw COSE
/// coordinates (ADR-008).
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] when `point` is not an uncompressed
/// point on the curve. Returns [`CryptoError::InvalidSignature`] when the
/// signature does not verify.
pub fn ecdsa_p256_sha256_verify_point(
    point: &[u8; P256_POINT_LEN],
    message: &[u8],
    signature_der: &[u8],
) -> Result<(), CryptoError> {
    parse_p256_point(point)?
        .verify_sig(message, signature_der)
        .map_err(|_| CryptoError::InvalidSignature)
}

// ------------------------------------------------- RSA PKCS#1 SHA-256

/// An RSA key pair for PKCS#1 v1.5 SHA-256 signatures, the DKIM
/// `rsa-sha256` algorithm of RFC 6376 (ADR-001, "DKIM"). The private key
/// lives inside AWS-LC, which cleanses it when the key is freed. Moduli
/// below 2048 bits are refused.
pub struct RsaPkcs1Sha256KeyPair {
    key: RsaKeyPair,
}

impl ZeroizeOnDrop for RsaPkcs1Sha256KeyPair {}

impl RsaPkcs1Sha256KeyPair {
    /// A fresh 2048-bit key pair from the system generator.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::RandomUnavailable`] when aws-lc-rs cannot
    /// generate a key.
    pub fn generate_2048() -> Result<RsaPkcs1Sha256KeyPair, CryptoError> {
        let key = RsaKeyPair::generate(RsaKeySize::Rsa2048)
            .map_err(|_| CryptoError::RandomUnavailable)?;
        Ok(RsaPkcs1Sha256KeyPair { key })
    }

    /// Imports a PKCS#8 v1 document that holds an RSA key of at least
    /// 2048 bits.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] when aws-lc-rs refuses the
    /// document or the modulus is shorter than 2048 bits.
    pub fn from_pkcs8(pkcs8_der: &[u8]) -> Result<RsaPkcs1Sha256KeyPair, CryptoError> {
        let key = RsaKeyPair::from_pkcs8(pkcs8_der).map_err(|_| CryptoError::InvalidKey)?;
        if key.public_modulus_len() < 256 {
            return Err(CryptoError::InvalidKey);
        }
        Ok(RsaPkcs1Sha256KeyPair { key })
    }

    /// The private key as a PKCS#8 v1 DER document.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unspecified`] when aws-lc-rs cannot encode it.
    pub fn pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let doc: Pkcs8V1Der<'static> = self.key.as_der().map_err(|_| CryptoError::Unspecified)?;
        Ok(Zeroizing::new(doc.as_ref().to_vec()))
    }

    /// The public key as a DER SubjectPublicKeyInfo, the DKIM `p=` value.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unspecified`] when aws-lc-rs cannot encode it.
    pub fn spki_der(&self) -> Result<Vec<u8>, CryptoError> {
        let der = self
            .key
            .public_key()
            .as_der()
            .map_err(|_| CryptoError::Unspecified)?;
        Ok(der.as_ref().to_vec())
    }

    /// An RSA PKCS#1 v1.5 SHA-256 signature over `message`. The scheme is
    /// deterministic, so equal input gives an equal signature.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unspecified`] when aws-lc-rs fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut sig = vec![0u8; self.key.public_modulus_len()];
        self.key
            .sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), message, &mut sig)
            .map_err(|_| CryptoError::Unspecified)?;
        Ok(sig)
    }
}

/// Verifies an RSA PKCS#1 v1.5 SHA-256 `signature` over `message` under
/// the public key with modulus `n` and exponent `e`, both big-endian.
/// This is WebAuthn RS256 (ADR-008).
///
/// # Errors
///
/// Returns [`CryptoError::InvalidSignature`] when the signature does not
/// verify, or when the modulus is shorter than 2048 or longer than 8192
/// bits.
pub fn rsa_pkcs1_sha256_verify(
    n: &[u8],
    e: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    RsaPublicKeyComponents { n, e }
        .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

/// Verifies an RSA PKCS#1 v1.5 SHA-256 `signature` over `message` under
/// the public key in `spki_der`, a DER SubjectPublicKeyInfo as
/// [`RsaPkcs1Sha256KeyPair::spki_der`] writes it and a DKIM `p=` tag holds.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidSignature`] when the key does not parse,
/// its modulus is shorter than 2048 or longer than 8192 bits, or the
/// signature does not verify.
pub fn rsa_pkcs1_sha256_verify_spki(
    spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, spki_der)
        .verify(message, signature)
        .map_err(|_| CryptoError::InvalidSignature)
}
