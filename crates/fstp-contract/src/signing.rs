//! One signature over a verified increment (M5 design section 3.1, steps
//! 4 to 8, I-30).
//!
//! [`sign_increment`] runs the strict increment verifier of `fstp-pdf`,
//! asks the port for the signer's chain, encodes the PAdES signed
//! attributes, asks the port for the value, assembles the CMS (which
//! verifies the value first), embeds it, and validates the new revision
//! again from its bytes through `fstp-sigval`. Only then does it return
//! the revision and the digests that `SignatureApplied` records.

use fstp_pdf::{IncrementError, embed_signature, verify_increment};
use fstp_pki::cms::{CmsError, signed_attributes, signed_data};
use fstp_sigval::{Level, SigvalError, TrustedList, ValidationReport, verify_signed_revision};

use crate::digest::Digest;
use crate::model::Route;
use crate::port::{SignatureError, SignaturePort, SignerRef};

/// Why a signature could not be applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningError {
    /// The increment does not have the one accepted shape (ADR-016).
    Increment(IncrementError),
    /// The port gave no chain or value.
    Port(SignatureError),
    /// The port gave an empty chain.
    EmptyChain,
    /// The CMS could not be built, or the value does not verify.
    Cms(CmsError),
    /// The new revision does not validate.
    Validation(SigvalError),
    /// A revision is not an exact byte prefix of the next one (I-30).
    NotPrefix,
    /// The number of revisions and parties differ.
    Count,
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "signature not applied: {self:?}")
    }
}

impl std::error::Error for SigningError {}

/// A validated signed revision and what `SignatureApplied` records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    /// The new revision: the base, then the increment with `/Contents`
    /// filled.
    pub revision: Vec<u8>,
    /// SHA-256 of the new revision.
    pub revision_digest: Digest,
    /// SHA-256 of the signer certificate.
    pub signer_certificate: Digest,
    /// The validation report.
    pub report: ValidationReport,
    /// The digest of the report.
    pub report_digest: Digest,
}

/// Signs the field `party` of `base` with `increment` through `port`, at
/// `at` (Unix seconds), and validates the result against `trust`.
///
/// # Errors
///
/// A [`SigningError`] naming the first fault. Nothing is returned that
/// did not validate.
#[allow(
    clippy::too_many_arguments,
    reason = "one step of the signing flow, kept flat"
)]
pub fn sign_increment(
    base: &[u8],
    increment: &[u8],
    party: &str,
    route: Route,
    signer: &SignerRef,
    at: i64,
    port: &dyn SignaturePort,
    trust: &dyn TrustedList,
) -> Result<Signed, SigningError> {
    let verified = verify_increment(base, increment, party).map_err(SigningError::Increment)?;
    let chain = port
        .certificate_chain(route, signer, at)
        .map_err(SigningError::Port)?;
    let signer_cert = chain.first().ok_or(SigningError::EmptyChain)?;
    let attrs = signed_attributes(&verified.digest, signer_cert).map_err(SigningError::Cms)?;
    let value = port
        .sign(route, signer, attrs.der(), at)
        .map_err(SigningError::Port)?;
    let refs: Vec<&[u8]> = chain.iter().map(Vec::as_slice).collect();
    let cms = signed_data(&attrs, &value, &refs).map_err(SigningError::Cms)?;
    let revision =
        embed_signature(base, increment, &verified, &cms).map_err(SigningError::Increment)?;
    let report = verify_signed_revision(base, &revision, party, at, route.required_level(), trust)
        .map_err(SigningError::Validation)?;
    Ok(Signed {
        revision_digest: Digest::of(&revision),
        signer_certificate: Digest::of(signer_cert),
        report_digest: Digest::from_bytes(report.digest()),
        report,
        revision,
    })
}

/// Validates a whole chain of stored revisions: revision 0, then one per
/// party in `parties` order. Each revision must be an exact byte prefix
/// of the next (I-30), and each signature must validate at `at`.
///
/// # Errors
///
/// A [`SigningError`] naming the first fault.
pub fn verify_revision_chain(
    revisions: &[Vec<u8>],
    parties: &[&str],
    at: i64,
    required: Level,
    trust: &dyn TrustedList,
) -> Result<Vec<ValidationReport>, SigningError> {
    if revisions.len() != parties.len().saturating_add(1) {
        return Err(SigningError::Count);
    }
    let mut out = Vec::with_capacity(parties.len());
    for (pair, party) in revisions.windows(2).zip(parties) {
        let [base, next] = pair else {
            return Err(SigningError::Count);
        };
        if !next.starts_with(base) {
            return Err(SigningError::NotPrefix);
        }
        out.push(
            verify_signed_revision(base, next, party, at, required, trust)
                .map_err(SigningError::Validation)?,
        );
    }
    Ok(out)
}
