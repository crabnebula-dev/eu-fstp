//! Certificate templates, the to-be-signed bytes and assembly.

use crate::PkiError;

/// A subject or issuer name. Only the common name is written in M3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistinguishedName {
    /// The common name.
    pub common_name: String,
}

/// The validity period, in UTC seconds since the Unix epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validity {
    /// The first second the certificate is valid.
    pub not_before: i64,
    /// The last second the certificate is valid.
    pub not_after: i64,
}

/// The signature algorithms the writer supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ECDSA over P-256 with SHA-256.
    EcdsaP256Sha256,
    /// Ed25519.
    Ed25519,
}

/// Everything a certificate states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertSpec {
    /// The serial number, positive and at most 20 bytes.
    pub serial: Vec<u8>,
    /// The issuer.
    pub issuer: DistinguishedName,
    /// The subject.
    pub subject: DistinguishedName,
    /// The validity period.
    pub validity: Validity,
    /// The subject public key info, DER.
    pub spki_der: Vec<u8>,
    /// Whether the certificate is a CA certificate.
    pub ca: bool,
    /// The algorithm the issuer signs with.
    pub algorithm: SignatureAlgorithm,
}

/// The DER `TBSCertificate` bytes, which the caller signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TbsCertificate {
    der: Vec<u8>,
}

impl TbsCertificate {
    /// The DER bytes to sign.
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }
}

/// Encodes the to-be-signed part of the certificate `spec` describes.
pub fn tbs(spec: &CertSpec) -> Result<TbsCertificate, PkiError> {
    let _ = spec;
    Err(PkiError::NotImplemented("fstp_pki::cert::tbs"))
}

/// Assembles the DER certificate from its to-be-signed part and the
/// issuer's signature over it.
pub fn assemble(tbs: &TbsCertificate, signature: &[u8]) -> Result<Vec<u8>, PkiError> {
    let _ = (tbs, signature);
    Err(PkiError::NotImplemented("fstp_pki::cert::assemble"))
}
