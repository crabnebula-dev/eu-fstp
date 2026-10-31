//! Text store commands and records (design section 5.6, ADR-007).

/// A text command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextCommand {
    /// Store a text.
    PutText {
        /// The text reference.
        id: [u8; 16],
    },
    /// Erase texts.
    EraseTexts {
        /// The text references.
        ids: Vec<[u8; 16]>,
        /// The cause, as a closed code.
        cause: u16,
    },
}

/// A text record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextRecord {
    /// A text was stored.
    TextPut {
        /// The text reference.
        id: [u8; 16],
    },
    /// Texts were erased.
    TextsErased {
        /// The text references.
        ids: Vec<[u8; 16]>,
    },
    /// The erasure of texts was requested: the erasure-log entry of each
    /// text, with its cause and the account that authorised it (ADR-007,
    /// design section 5.6). The request time is the entry time, and the
    /// `TextsErased` record of the same texts gives `completed_at`.
    ErasureRequested {
        /// The text references.
        ids: Vec<[u8; 16]>,
        /// The cause, as a closed code.
        cause: u16,
        /// The account that authorised the erasure.
        by: fstp_domain::id::AccountId,
    },
}
