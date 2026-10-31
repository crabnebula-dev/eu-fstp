//! Import documents, proposals, commands and records (M4 design
//! section 3.3).

use fstp_programme::FieldId;

use crate::ids::{
    AccountRef, BlobAddress, ImportConfigId, ImportDocumentId, ImportProposalId, ProgrammeRef,
    TextDigest, ValueDigest, ValueTextRef,
};
use crate::text::{ImportMedia, Span};
use crate::value::UntrustedValue;

/// The metadata of one uploaded document. The bytes live in the blob
/// store, and the normalised text stays with the shell.
///
/// Interim, pending Daniel: `text_bytes` is not in the design's field
/// list. It lets the import store check that every evidence span lies
/// inside the normalised text without holding the text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ImportDocument {
    /// The document.
    pub id: ImportDocumentId,
    /// The draft programme it was uploaded to.
    pub programme: ProgrammeRef,
    /// Where the uploaded bytes are stored.
    pub blob: BlobAddress,
    /// The media type.
    pub media: ImportMedia,
    /// The salted digest of the normalised text.
    pub digest: TextDigest,
    /// The length of the normalised text in bytes.
    pub text_bytes: u32,
    /// The programme manager who uploaded it.
    pub uploaded_by: AccountRef,
}

/// A rule of the funder profile a proposed value conflicts with. A
/// conflict is flagged, never adjusted (L-10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConflictRule {
    /// I-50: P-05 at most the Data Sheet ceiling P-58.
    I50,
}

impl ConflictRule {
    /// Every rule, in order.
    pub const ALL: [ConflictRule; 1] = [ConflictRule::I50];

    /// The rule's identifier, as stored.
    pub const fn as_str(self) -> &'static str {
        match self {
            ConflictRule::I50 => "I-50",
        }
    }

    /// The rule with identifier `s`.
    pub fn from_name(s: &str) -> Option<ConflictRule> {
        ConflictRule::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

/// One proposed value, as the shell hands it to `RecordProposals`.
///
/// It holds the value itself, for the store's memory, and the reference
/// under which the shell stored the value's normal text. The record the
/// store appends is the [`RecordedProposal`] of it, which holds the
/// reference only (ADR-007, design 4.2).
///
/// Interim, pending Daniel: `text` is not in the design's field list. It
/// keeps the value out of the ledger body, so erasure by key destruction
/// works without rewriting an append-only body (I-23, I-81).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ImportProposal {
    /// The proposal.
    pub id: ImportProposalId,
    /// The document it was read from.
    pub document: ImportDocumentId,
    /// The proposed field.
    pub field: FieldId,
    /// The proposed value, untrusted and unchanged. It stays in memory and
    /// never enters a ledger body.
    pub value: UntrustedValue,
    /// Where the shell stored `value.as_data()` in the text store, with
    /// its salted digest.
    pub text: ValueTextRef,
    /// Where the document states it.
    pub evidence: Vec<Span>,
    /// The proposer configuration.
    pub config: ImportConfigId,
    /// The funder profile rules the value conflicts with, in ascending
    /// order. The engine computes them against the draft at recording.
    pub conflicts_with_profile: Vec<ConflictRule>,
}

impl ImportProposal {
    /// The proposal as a ledger body holds it: everything but the value.
    pub fn recorded(&self) -> RecordedProposal {
        RecordedProposal {
            id: self.id,
            document: self.document,
            field: self.field,
            text: self.text,
            evidence: self.evidence.clone(),
            config: self.config,
            conflicts_with_profile: self.conflicts_with_profile.clone(),
        }
    }
}

/// One proposed value, as an import record holds it. The value itself is
/// behind `text` (ADR-007).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RecordedProposal {
    /// The proposal.
    pub id: ImportProposalId,
    /// The document it was read from.
    pub document: ImportDocumentId,
    /// The proposed field.
    pub field: FieldId,
    /// Where the value's normal text is stored, with its salted digest.
    pub text: ValueTextRef,
    /// Where the document states it.
    pub evidence: Vec<Span>,
    /// The proposer configuration.
    pub config: ImportConfigId,
    /// The funder profile rules the value conflicts with, in ascending
    /// order.
    pub conflicts_with_profile: Vec<ConflictRule>,
}

/// An import command.
///
/// `RegisterDocument` is the `import.upload` operation of a programme
/// manager. `RecordProposals` never comes from a person: the shell runs
/// the proposer and issues it as the system (`SYSTEM_ONLY_OTHER`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ImportCommand {
    /// Registers an uploaded document.
    RegisterDocument(ImportDocument),
    /// Records the proposer's output for one document.
    RecordProposals {
        /// The document.
        document: ImportDocumentId,
        /// The proposals.
        proposals: Vec<ImportProposal>,
    },
}

/// How a programme manager resolved a proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImportResolution {
    /// Confirmed as proposed.
    Confirmed,
    /// Edited to another value.
    Edited,
    /// Dismissed. No value enters the draft.
    Dismissed,
}

impl ImportResolution {
    /// Every resolution, in order.
    pub const ALL: [ImportResolution; 3] = [
        ImportResolution::Confirmed,
        ImportResolution::Edited,
        ImportResolution::Dismissed,
    ];

    /// The stored name.
    pub const fn as_str(self) -> &'static str {
        match self {
            ImportResolution::Confirmed => "confirmed",
            ImportResolution::Edited => "edited",
            ImportResolution::Dismissed => "dismissed",
        }
    }

    /// The resolution with stored name `s`.
    pub fn from_name(s: &str) -> Option<ImportResolution> {
        ImportResolution::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

/// An import ledger record. It holds no proposed value, only references
/// to the stored texts (ADR-007, design 4.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ImportRecord {
    /// A document was registered.
    DocumentRegistered(ImportDocument),
    /// The proposer's output for one document was recorded.
    ProposalsRecorded {
        /// The document.
        document: ImportDocumentId,
        /// The proposals, in the proposer's order.
        proposals: Vec<RecordedProposal>,
    },
    /// A programme manager resolved one proposal (I-65). Only the engine
    /// bridge emits it.
    ProposalResolved {
        /// The proposal.
        proposal: ImportProposalId,
        /// How it was resolved.
        resolution: ImportResolution,
        /// The programme manager.
        by: AccountRef,
    },
}

/// A resolution as the client sends it, decoded by the API core.
///
/// Confirm and Edit carry a value, Dismiss carries none. The client sends
/// the value it displayed. The API core hashes a confirmed or edited
/// value's normal text at decoding, for the creator's save. The client
/// never sends that digest.
///
/// Interim, pending Daniel: `Confirm` carries that digest too. The import
/// body holds only a salted digest, which the creator's save cannot use.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ClientResolution {
    /// Confirm the proposal, with the value the client believes is
    /// proposed.
    Confirm {
        /// The value.
        value: UntrustedValue,
        /// The shell's SHA-256 of `value.as_data()`.
        digest: ValueDigest,
    },
    /// Replace the proposed value.
    Edit {
        /// The new value.
        value: UntrustedValue,
        /// The shell's SHA-256 of `value.as_data()`.
        digest: ValueDigest,
    },
    /// Dismiss the proposal.
    Dismiss,
}
