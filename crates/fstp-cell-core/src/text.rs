//! Text store commands and records (design section 5.6, ADR-007).
//!
//! Issue 6 M9, ADR-025 (interim, pending Daniel): a session holder puts a
//! text with [`TextCommand::PutOwnedText`], which names an owner the
//! caller may write and a declared length. One account puts at most
//! [`DAILY_TEXT_BYTES`] of declared text per UTC day.

use fstp_domain::id::AccountId;

/// The longest declared text, in UTF-8 bytes: 64 KiB. Interim, pending
/// Daniel (ADR-025).
pub const MAX_TEXT_LEN: u32 = 64 * 1024;

/// The most declared text bytes one account puts per UTC day: 1 MiB.
/// Interim, pending Daniel (ADR-025).
pub const DAILY_TEXT_BYTES: u64 = 1 << 20;

/// The object a text belongs to (ADR-025). One form for now; texts of
/// other objects get theirs by amendment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TextOwner {
    /// An account. The account itself or a tenant admin may write it.
    Account(AccountId),
}

/// A text command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextCommand {
    /// Store a text. The cell's own tasks use it. A session route refuses
    /// it and takes [`TextCommand::PutOwnedText`] (ADR-025).
    PutText {
        /// The text reference.
        id: [u8; 16],
    },
    /// Store a text owned by `owner`, of `len` declared UTF-8 bytes
    /// (issue 6 M9, ADR-025).
    PutOwnedText {
        /// The text reference.
        id: [u8; 16],
        /// The object the text belongs to.
        owner: TextOwner,
        /// The declared length, from 1 to [`MAX_TEXT_LEN`].
        len: u32,
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
    /// A text owned by `owner` was stored by `by`, with `len` declared
    /// bytes (ADR-025).
    OwnedTextPut {
        /// The text reference.
        id: [u8; 16],
        /// The object the text belongs to.
        owner: TextOwner,
        /// The account that put it, which the daily bound charges.
        by: AccountId,
        /// The declared length.
        len: u32,
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
