//! Document import (I-65, M4 design section 3.3).
//!
//! Import proposals live in a store that the creator and the domain
//! cannot name (layering rule A3). An imported document is untrusted data
//! under `SPEC/04-llm-assessment/assessment.md`. It travels only in the
//! data channel and is never concatenated into instructions. The only
//! `fstp-findings` name this crate uses is
//! `fstp_findings::text::UntrustedText` (rule A4).
//!
//! M4 imports UTF-8 `text/plain` and `text/markdown` only (Q24). The crate
//! is pure: no I/O, no clock, no hashing, no floats (rule A10).
//!
//! # How an import runs
//!
//! 1. The shell [`normalise`]s the upload into an [`ExtractedText`],
//!    stores the bytes in the blob store and takes the text's salted
//!    digest. A programme manager's `import.upload` becomes
//!    [`ImportCommand::RegisterDocument`].
//! 2. The shell runs a [`Proposer`] over the text with the `FIELDS`
//!    schema. The shell stores each value's normal text in the text store,
//!    under its own data key, and gets a [`ValueTextRef`] back (ADR-007).
//!    Each [`RawProposal`] is checked and bound to its ids and reference
//!    with [`RawProposal::bind`]. The engine flags profile conflicts
//!    against the draft and records the batch with
//!    [`ImportCommand::RecordProposals`] as the system.
//! 3. [`decide_import`] decides both commands over the [`ImportStore`].
//!    Its records hold documents and proposals, never a draft value. So an
//!    import proposal never alters a draft by itself (I-65). A recorded
//!    proposal names its value by reference only, so no ledger body holds
//!    imported text (ADR-007, design 4.2). After it appends a batch, the
//!    engine hands the values to [`ImportStore::hold_recorded`]. After a
//!    replay, the shell resolves each reference and calls
//!    [`ImportStore::hold`].
//! 4. A programme manager resolves one proposal at a time through the
//!    engine bridge (`fstp_engine::bridge`). The bridge checks the binding,
//!    calls [`check_resolution`] for the import side, and emits
//!    [`ImportRecord::ProposalResolved`] and the creator's save with
//!    import provenance in one entry. A dismissal emits only the import
//!    record.
//!
//! Every value a proposer returns is an [`UntrustedValue`]: no `Display`,
//! no `Deref`, a `Debug` that shows the length only, and one normal text.
//!
//! # Interim readings, pending Daniel
//!
//! Each is reversible, and each is marked where it is built.
//!
//! - The ids of programmes and accounts are [`ProgrammeRef`] and
//!   [`AccountRef`], raw values of the domain ids (`ids` module).
//! - [`ImportDocument::text_bytes`] and [`ImportProposal::text`] are
//!   additions to the design's field lists. The first lets the store check
//!   spans without the text. The second keeps the value out of the body.
//! - The client's `shown` is the [`SaltedDigest`] of the stored text, not
//!   the `ValueDigest` design 3.3 names, since no body holds an unkeyed
//!   digest of a value. A confirmation, like an edit, carries the API
//!   core's [`ValueDigest`] for the creator's save.
//! - Recording accepts any JSON value within the bounds of
//!   [`UntrustedValue`]. Strict per-field decoding runs when a value
//!   enters the draft, in the bridge.
//! - A batch with a proposal for a field that is not importable is refused
//!   whole.
//! - The standard size limit is 1 MiB, and the value and batch bounds are
//!   [`MAX_VALUE_BYTES`], [`MAX_VALUE_DEPTH`], [`MAX_VALUE_NODES`],
//!   [`MAX_SPANS`] and [`MAX_BATCH`].
//! - The text class and owner under which the shell stores a value text
//!   are the lead's, with the M3 text store. This crate holds only the
//!   reference.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

mod codec;
mod error;
mod ids;
mod model;
mod proposer;
mod store;
mod text;
mod value;

#[cfg(test)]
mod tests;

pub use codec::{
    decode_fixture, decode_proposal, decode_record, encode_fixture, encode_proposal, encode_record,
};
pub use error::ImportError;
pub use ids::{
    AccountRef, BlobAddress, ImportConfigId, ImportDocumentId, ImportProposalId, ProgrammeRef,
    SaltedDigest, TextDigest, ValueDigest, ValueTextId, ValueTextRef,
};
pub use model::{
    ClientResolution, ConflictRule, ImportCommand, ImportDocument, ImportProposal, ImportRecord,
    ImportResolution, RecordedProposal,
};
pub use proposer::{
    BindIds, FakeProposer, FixtureEntry, HavocProposer, ImportConfig, NoProposer, Proposer,
    ProposerError, RawProposal,
};
pub use store::{
    AppliedValue, CheckedResolution, HoldError, ImportActor, ImportFoldError, ImportRefusal,
    ImportStore, MAX_BATCH, ResolveRequest, StoredProposal, check_resolution, decide_import,
    importable,
};
pub use text::{
    ExtractedText, ImportLimits, ImportMedia, MAX_IMPORT_BYTES, MAX_SPANS, Span, normalise,
};
pub use value::{MAX_VALUE_BYTES, MAX_VALUE_DEPTH, MAX_VALUE_NODES, UntrustedValue};
