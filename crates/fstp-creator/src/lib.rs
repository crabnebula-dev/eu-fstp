//! The programme creator (M4 design section 3.2).
//!
//! A draft is an M2 programme plus the creator records of this crate. The
//! crate holds the creator commands and records, field provenance,
//! invitations, probes, acknowledgements and activation requests. It holds
//! the [`ValidationReport`] with its check catalogue [`CHECKS`], and the
//! two witnesses of activation: [`CleanReport`] (I-66) and
//! [`ActivationClearance`] (I-67). [`ActivationApproved`] is built only
//! from an [`ActivationClearance`].
//!
//! The crate has no dependency path to `fstp-import` (I-65, layering rule
//! A3) or to `fstp-findings` (I-10, rule A4). It is pure: no I/O, no
//! clock, no floats (rule A10).
//!
//! # How the pieces fit
//!
//! - [`decide_creator`] decides one [`CreatorCommand`] over the core state
//!   and the [`CreatorState`]. It returns creator records and the core
//!   commands the engine decides in the same entry.
//! - [`CreatorState::apply`] folds a creator record, and
//!   [`CreatorState::observe_core`] folds the core records that name a
//!   draft, the binding records among them. One ledger entry bumps a
//!   draft's [`DraftRevision`] once.
//! - [`CreatorState::observe_import_resolution`] and
//!   [`CreatorState::observe_invitation_accepted`] fold what other lanes
//!   record about a draft: every import resolution, the dismissal
//!   included, and the acceptance of an invitation (interim, pending
//!   Daniel).
//! - [`decide_import_save`] is the engine bridge's save of one import
//!   resolution with [`Provenance::Import`]. No client reaches it.
//! - [`validate`] computes the report of a draft from the core state, the
//!   creator state, the funder profile and the [`CreatorInputs`] the
//!   engine passes in.
//! - [`clean`] turns a report and the live acknowledgements into a
//!   [`CleanReport`], or says why it does not clear.
//! - [`clear_activation`] checks the approver against the builder set and
//!   the vault answers, and yields the [`ActivationClearance`].
//!
//! # The draft spec
//!
//! - A start and every save that touches a policy field compile the draft
//!   spec with `fstp_programme::compile` into one core `EditPolicy`, so the
//!   core head policy is the compiled draft policy (I-51). The head is read
//!   back with `fstp_programme::policy_spec`.
//! - A save records each value's digest, never the value (ADR-007). The
//!   shell holds the values outside the ledger with
//!   [`CreatorState::hold_saved`] and [`CreatorState::hold_import`], as the
//!   import store holds proposal values. A saved value that is not held
//!   fails its checks closed.
//!
//! # Seams to parallel lanes
//!
//! Each seam refuses or fails closed. None answers with a made-up value.
//!
//! - `fstp-guide` (lane m4guide) parses and renders the Guide. Until
//!   `fstp_guide::parse_template` and `fstp_guide::render` succeed, the
//!   checks `GuideSectionMissing` and `GuideBindingUnresolved` fail closed
//!   with [`CheckDetail::Unavailable`], naming `fstp_guide`.
//! - The engine driver holds the values of an appended save. Until it calls
//!   [`CreatorState::hold_saved`], the checks that read an artefact value,
//!   such as `FlowDownMissing`, fail closed.
//! - A start from a tenant-private template needs the shell's template
//!   spec store, and refuses with [`CreatorRefusal::Unavailable`] until
//!   then.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

mod check;
mod codec;
mod decide;
mod draft;
mod guide;
mod ids;
mod inputs;
mod model;
mod probe;
mod state;
mod theme;
mod validate;
mod witness;

#[cfg(test)]
mod tests;

pub use check::{
    CHECKS, CallPackageElement, CheckDetail, CheckId, CheckResult, CheckSpec, CheckSubject,
    Severity, WarningKey,
};
pub use codec::{
    CreatorError, DraftInput, decode_command, decode_draft, decode_record, encode_command,
    encode_record, validate_draft,
};
pub use decide::{CreatorDecision, CreatorRefusal, decide_creator, decide_import_save};
pub use guide::{GuideScan, guide_scan};
pub use ids::{ImportDocumentId, ImportProposalId, InvitationId, TemplateId};
pub use inputs::{
    CreatorInputs, PortPresence, PreviewOutcome, PreviewTarget, SodPreview, VaultChecks,
    VaultQuestions, preview_targets, vault_questions,
};
pub use model::{
    CreatorCommand, CreatorRecord, DraftRevision, FieldEdit, ImportFieldEdit, ImportResolution,
    Invitee, Provenance, ReportDigest, StartingPoint, ValueDigest,
};
pub use probe::{ProbeKind, ProbeOutcome, ProbeSet};
pub use state::{ActivationRequest, CreatorFoldError, CreatorState, Draft, Invitation};
pub use theme::{
    ColourPair, MandatoryElement, Rgb, TextRole, Theme, ThemeMode, linear_bounds, meets_aa,
};
pub use validate::{ValidationReport, validate};
pub use witness::{
    AckSet, ActivationApproved, ActivationClearance, CleanReport, Uncleared, clean,
    clear_activation,
};

// I-66 and I-67 compile-fail twins. Doc comments only, owned by the test
// author of lane W2a.
#[cfg(doctest)]
mod twins;
