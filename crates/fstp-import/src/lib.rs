//! Document import (I-65, M4 design section 3.3).
//!
//! Import proposals live in a store that the creator and the domain
//! cannot name (layering rule A3). An imported document is untrusted data
//! under `SPEC/04-llm-assessment/assessment.md`. It travels only in the
//! data channel and is never concatenated into instructions. The only
//! `fstp-findings` name this crate uses is
//! `fstp_findings::text::UntrustedText` (rule A4).
//!
//! M4 imports UTF-8 `text/plain` and `text/markdown` only.
//!
//! Status: W0 stub. Lane W2b (L-IMPORT) owns this crate and writes the
//! designed types. Every operation refuses with
//! [`ImportError::NotImplemented`].

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

use fstp_findings::text::UntrustedText;

/// Why an import operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportError {
    /// The W0 stub of the named operation refuses.
    NotImplemented(&'static str),
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for ImportError {}

/// The media types M4 imports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImportMedia {
    /// UTF-8 `text/plain`.
    TextPlain,
    /// UTF-8 `text/markdown`, normalised as text and never rendered.
    TextMarkdown,
}

/// Limits on one import (Q24).
///
/// W0 placeholder with no fields. Lane W2b writes the limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportLimits {
    _w0: (),
}

impl ImportLimits {
    /// The default limits.
    ///
    /// The stub refuses, so no import runs under made-up limits.
    pub fn standard() -> Result<ImportLimits, ImportError> {
        Err(ImportError::NotImplemented(
            "fstp_import::ImportLimits::standard",
        ))
    }
}

/// Normalised document text. It is untrusted. It has no `Display` and no
/// `Deref<Target = str>`.
pub struct ExtractedText(UntrustedText);

impl ExtractedText {
    /// The text as untrusted data. Pass it only through a data channel.
    pub fn untrusted(&self) -> &UntrustedText {
        &self.0
    }
}

impl std::fmt::Debug for ExtractedText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExtractedText(..)")
    }
}

/// A proposal as the proposer returned it.
///
/// W0 placeholder with no fields. Lane W2b writes `ImportProposal` and
/// `UntrustedValue`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportProposal {
    _w0: (),
}

/// An import ledger record.
///
/// W0 placeholder with no fields. Lane W2b writes the variants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportRecord {
    _w0: (),
}

/// Validates and normalises an uploaded document. Fuzzed
/// (`import_text_decode`, T-FUZZ-IMPORT, T-FUZZ-UPLOAD).
pub fn normalise(
    bytes: &[u8],
    media: ImportMedia,
    limits: ImportLimits,
) -> Result<ExtractedText, ImportError> {
    let _ = (bytes, media, limits);
    Err(ImportError::NotImplemented("fstp_import::normalise"))
}

/// Decodes proposer output. Fuzzed (`proposal_decode`).
pub fn decode_proposal(bytes: &[u8]) -> Result<ImportProposal, ImportError> {
    let _ = bytes;
    Err(ImportError::NotImplemented("fstp_import::decode_proposal"))
}

/// Decodes a stored import record. Fuzzed (`import_record_decode`).
pub fn decode_record(bytes: &[u8]) -> Result<ImportRecord, ImportError> {
    let _ = bytes;
    Err(ImportError::NotImplemented("fstp_import::decode_record"))
}
