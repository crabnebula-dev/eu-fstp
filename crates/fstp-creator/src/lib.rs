//! The programme creator (M4 design section 3.2).
//!
//! A draft is an M2 programme in `Draft` status plus the creator records
//! of this crate. The crate holds the creator commands and records, field
//! provenance, invitations, probes, acknowledgements, the
//! `ValidationReport`, and the two witnesses of activation: `CleanReport`
//! (I-66) and `ActivationClearance` (I-67). `ActivationApproved` is built
//! only from an `ActivationClearance`.
//!
//! The crate has no dependency path to `fstp-import` (I-65, layering rule
//! A3) or to `fstp-findings` (I-10, rule A4).
//!
//! Status: W0 stub. Lane W2a (L-CREATOR) owns this crate and writes the
//! designed types. Every operation refuses with
//! [`CreatorError::NotImplemented`].

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

/// Why a creator operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreatorError {
    /// The W0 stub of the named operation refuses.
    NotImplemented(&'static str),
}

impl std::fmt::Display for CreatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CreatorError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for CreatorError {}

/// A creator command.
///
/// W0 placeholder with no fields. Lane W2a writes the variants of design
/// section 3.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatorCommand {
    _w0: (),
}

/// A creator ledger record.
///
/// W0 placeholder with no fields. Lane W2a writes the variants of design
/// section 3.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatorRecord {
    _w0: (),
}

/// One draft with its creator state and inputs, as `validate` reads it.
///
/// W0 placeholder with no fields. Lane W2a writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftInput {
    _w0: (),
}

/// The validation report of one draft revision.
///
/// W0 placeholder with no fields. Lane W2a writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationReport {
    _w0: (),
}

/// Decodes a creator command from its JSON text. Fuzzed
/// (`creator_command_decode`).
pub fn decode_command(bytes: &[u8]) -> Result<CreatorCommand, CreatorError> {
    let _ = bytes;
    Err(CreatorError::NotImplemented("fstp_creator::decode_command"))
}

/// Decodes a creator record from its stored JSON text. Fuzzed
/// (`creator_record_decode`).
pub fn decode_record(bytes: &[u8]) -> Result<CreatorRecord, CreatorError> {
    let _ = bytes;
    Err(CreatorError::NotImplemented("fstp_creator::decode_record"))
}

/// Decodes a draft and its inputs, for the `validate_total` fuzz target.
pub fn decode_draft(bytes: &[u8]) -> Result<DraftInput, CreatorError> {
    let _ = bytes;
    Err(CreatorError::NotImplemented("fstp_creator::decode_draft"))
}

/// Validates one draft. The design makes this total. The stub returns a
/// `Result`, so it never answers with a made-up report. Fuzzed
/// (`validate_total`).
pub fn validate(draft: &DraftInput) -> Result<ValidationReport, CreatorError> {
    let _ = draft;
    Err(CreatorError::NotImplemented("fstp_creator::validate"))
}
