//! Errors of normalising, binding and decoding (TH-16, TH-26).
//!
//! No error holds input content (R-NF-02). A decoding error names the
//! schema member or the rule that failed, never a value or a member name
//! taken from the input.

use core::fmt;

/// Why an import operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportError {
    /// The W0 refusal of the named operation. Kept because the lane test
    /// suites match on it. No operation of this crate returns it.
    NotImplemented(&'static str),
    /// The limits are outside `1..=MAX_IMPORT_BYTES`.
    InvalidLimits,
    /// The document is above the size limit, before or after
    /// normalisation (Q24).
    TooLarge {
        /// The limit in bytes.
        limit: usize,
    },
    /// The document is not valid UTF-8. `offset` is the length of the
    /// valid prefix.
    InvalidUtf8 {
        /// The first byte that is not part of valid UTF-8.
        offset: usize,
    },
    /// The document holds no text after normalisation.
    EmptyDocument,
    /// The input is not JSON within the decoder's limits.
    NotJson,
    /// The JSON does not have the required shape. The text names the
    /// schema member or rule, never input content.
    Malformed(&'static str),
    /// A value is above the size, depth or node limits of an
    /// `UntrustedValue`.
    ValueOutOfBounds,
    /// The field key names no field of the `FIELDS` table.
    UnknownField,
    /// The field is not importable (`FieldSpec::importable`).
    NotImportable,
    /// A proposal has no evidence span, or more than `MAX_SPANS`.
    EvidenceCount,
    /// An evidence span is empty, out of order, outside the normalised
    /// text or not on a character boundary.
    BadSpan,
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
            ImportError::InvalidLimits => f.write_str("the import limits are out of range"),
            ImportError::TooLarge { limit } => {
                write!(f, "the document is above the limit of {limit} bytes")
            }
            ImportError::InvalidUtf8 { offset } => {
                write!(f, "the document is not valid UTF-8 at byte {offset}")
            }
            ImportError::EmptyDocument => f.write_str("the document holds no text"),
            ImportError::NotJson => f.write_str("the input is not JSON within the limits"),
            ImportError::Malformed(what) => write!(f, "malformed import JSON: {what}"),
            ImportError::ValueOutOfBounds => {
                f.write_str("the value is above the size, depth or node limits")
            }
            ImportError::UnknownField => f.write_str("the field key names no field"),
            ImportError::NotImportable => f.write_str("the field is not importable"),
            ImportError::EvidenceCount => f.write_str("a proposal needs 1 to 8 evidence spans"),
            ImportError::BadSpan => f.write_str("an evidence span is not valid"),
        }
    }
}

impl std::error::Error for ImportError {}
