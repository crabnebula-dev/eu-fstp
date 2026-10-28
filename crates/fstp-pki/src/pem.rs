//! The in-house PEM writer (M3 design section 1.3).

use crate::PkiError;

/// The PEM labels the writer emits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PemLabel {
    /// `CERTIFICATE`.
    Certificate,
    /// `CERTIFICATE REQUEST`.
    CertificateRequest,
}

/// Writes `der` as one PEM block with `label`.
pub fn encode(label: PemLabel, der: &[u8]) -> Result<String, PkiError> {
    let _ = (label, der);
    Err(PkiError::NotImplemented("fstp_pki::pem::encode"))
}
