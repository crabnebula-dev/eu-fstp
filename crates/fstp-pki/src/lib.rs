//! X.509 v3 DER certificate writer, lifetimes and proof of possession
//! (M3 design sections 1.3 and 2.1).
//!
//! The crate is pure. It returns the bytes to sign and assembles the
//! certificate from a signature, so the caller signs through aws-lc-rs or
//! custody. PEM is written in-house, since `rustls-pki-types` only decodes
//! it.
//!
//! Status: W0 stub. Every operation refuses with
//! [`PkiError::NotImplemented`]. Lane W1i fills the crate.

pub mod cert;
pub mod pem;
pub mod pop;

pub use cert::{CertSpec, DistinguishedName, SignatureAlgorithm, TbsCertificate, Validity};

/// Why a PKI operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PkiError {
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

impl std::fmt::Display for PkiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PkiError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for PkiError {}
