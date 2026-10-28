//! ECDSA P-256 keys for the tests, from aws-lc-rs. The tests sign as a
//! caller of `fstp-pki` would (design section 1.3). No primitive is written
//! here.

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _,
};

/// The reference key identifier of the P-256 SPKI `spki_der`: the leftmost
/// 160 bits of SHA-256 over the subjectPublicKey BIT STRING value, which is
/// the 65-byte point after the 26-byte header (RFC 7093 section 2, method
/// 1). The digest comes from aws-lc-rs, independent of `fstp-pki`.
pub(crate) fn key_id_of(spki_der: &[u8]) -> [u8; 20] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &spki_der[26..]);
    digest.as_ref()[..20]
        .try_into()
        .expect("20 of 32 digest bytes")
}

/// A fresh ECDSA P-256 key pair.
pub(crate) struct EcKey {
    pair: EcdsaKeyPair,
    pkcs8: Vec<u8>,
}

impl EcKey {
    /// Generates a new key pair.
    pub(crate) fn generate() -> EcKey {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("aws-lc-rs generates a P-256 key");
        let pkcs8 = doc.as_ref().to_vec();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8)
            .expect("aws-lc-rs reads its own PKCS#8 document");
        EcKey { pair, pkcs8 }
    }

    /// The DER SubjectPublicKeyInfo.
    pub(crate) fn spki_der(&self) -> Vec<u8> {
        self.pair
            .public_key()
            .as_der()
            .expect("aws-lc-rs encodes the SPKI")
            .as_ref()
            .to_vec()
    }

    /// The reference key identifier of this key (see [`key_id_of`]).
    pub(crate) fn key_id(&self) -> [u8; 20] {
        key_id_of(&self.spki_der())
    }

    /// A raw `r || s` ECDSA P-256 signature with SHA-256 over `msg`, as a
    /// custody backend that returns the fixed form would give it.
    pub(crate) fn sign_fixed(&self, msg: &[u8]) -> [u8; 64] {
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &self.pkcs8)
            .expect("aws-lc-rs reads its own PKCS#8 document");
        let sig = pair
            .sign(&SystemRandom::new(), msg)
            .expect("aws-lc-rs signs");
        sig.as_ref()
            .try_into()
            .expect("a fixed P-256 signature is 64 bytes")
    }

    /// The PKCS#8 private key document, DER.
    pub(crate) fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8
    }

    /// An ASN.1 DER ECDSA signature with SHA-256 over `msg`.
    pub(crate) fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        self.pair
            .sign(&rng, msg)
            .expect("aws-lc-rs signs")
            .as_ref()
            .to_vec()
    }
}

/// The DER SPKI of the P-256 base point G, a fixed synthetic public key.
/// Its private key is 1, so it never protects anything.
pub(crate) const P256_G_SPKI: [u8; 91] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1,
    0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
    0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe,
    0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b,
    0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

/// The DER SPKI of an Ed25519 key with all-zero bytes. It is not a P-256
/// key, so a P-256 proof of possession over it must be refused.
pub(crate) const ED25519_ZERO_SPKI: [u8; 44] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
