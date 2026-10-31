//! X.509 v3 DER certificate writer, lifetimes and proof of possession
//! (M3 design sections 1.3 and 2.1).
//!
//! The crate is pure. It returns the bytes to sign and assembles the
//! certificate from a signature, so the caller signs through aws-lc-rs or
//! custody. It reaches no I/O crate and parses nothing (layering rule 1).
//! PEM is written in-house, since `rustls-pki-types` only decodes it.

pub mod cert;
mod der;
pub mod pem;
pub mod pop;
mod time;

pub use cert::{
    CertKind, CertSpec, ClusterKindOu, DistinguishedName, KeyIdentifier, SignatureAlgorithm,
    TbsCertificate, Validity,
};

/// Why a PKI operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PkiError {
    /// The operation waits on a seam outside this crate. It names the seam.
    NotImplemented(&'static str),
    /// The serial is zero or empty, so it is not positive.
    SerialNotPositive,
    /// The serial INTEGER would need more than 20 octets.
    SerialTooLong,
    /// A common name is empty or longer than 64 characters.
    CommonNameLength,
    /// An organizational unit is empty or longer than 64 characters.
    OrganizationalUnitLength,
    /// An instant lies outside 1950-01-01 to 9999-12-31.
    TimeOutOfRange,
    /// `not_before` is after `not_after`.
    ValidityInverted,
    /// A client certificate would live longer than 7 days.
    LifetimeTooLong,
    /// The subject public key is not an uncompressed P-256 key.
    SpkiNotP256,
    /// A subjectAltName entry is not a lowercase LDH DNS name.
    DnsNameInvalid,
    /// A CA certificate was given subjectAltName entries.
    SubjectAltNameOnCa,
    /// The signature to assemble is empty.
    EmptySignature,
    /// The DER to write as PEM is empty.
    EmptyDer,
    /// A proof of possession does not verify.
    PopSignatureInvalid,
    /// A certificate other than a self-signed CA has no issuer key
    /// identifier, so it would lack the authorityKeyIdentifier.
    IssuerKeyIdMissing,
    /// A server certificate's subject OU is not a cluster kind marker.
    ServerOuNotClusterKind,
    /// The request context of a proof of possession is outside its
    /// layout: the role or component name is not 1 to 64 bytes.
    PopContextInvalid,
}

impl std::fmt::Display for PkiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            PkiError::NotImplemented(op) => return write!(f, "{op} is not implemented yet"),
            PkiError::SerialNotPositive => "the serial is not positive",
            PkiError::SerialTooLong => "the serial needs more than 20 octets",
            PkiError::CommonNameLength => "the common name is not 1 to 64 characters",
            PkiError::OrganizationalUnitLength => {
                "the organizational unit is not 1 to 64 characters"
            }
            PkiError::TimeOutOfRange => "an instant lies outside 1950 to 9999",
            PkiError::ValidityInverted => "notBefore is after notAfter",
            PkiError::LifetimeTooLong => "a client certificate lives longer than 7 days",
            PkiError::SpkiNotP256 => "the public key is not an uncompressed P-256 key",
            PkiError::DnsNameInvalid => "a DNS name is not lowercase LDH",
            PkiError::SubjectAltNameOnCa => "a CA certificate has no subjectAltName",
            PkiError::EmptySignature => "the signature is empty",
            PkiError::EmptyDer => "the DER is empty",
            PkiError::PopSignatureInvalid => "the proof of possession does not verify",
            PkiError::IssuerKeyIdMissing => "an issued certificate has no issuer key identifier",
            PkiError::ServerOuNotClusterKind => "a server OU is not a cluster kind marker",
            PkiError::PopContextInvalid => "the proof of possession context is malformed",
        };
        f.write_str(text)
    }
}

impl std::error::Error for PkiError {}
