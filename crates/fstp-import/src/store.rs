//! The import store: its fold, the import decide and the import side of a
//! resolution (I-65, M4 design sections 3.3 and 4.2).
//!
//! The import decide sees neither the core nor the creator. It never
//! writes a draft: its records hold documents, proposals and resolutions
//! only. A recorded proposal names its value by reference, never by
//! content (ADR-007). A value enters a draft only through the engine bridge, which
//! calls [`check_resolution`] and then the creator in one entry.
//!
//! What the engine checks before it calls in here, because this crate
//! cannot see it:
//!
//! - an upload is by an account with an active programme manager binding
//!   on a draft programme (interim reading, pending Daniel);
//! - a resolution is by such an account at that instant, and its `base` is
//!   the draft's head revision;
//! - a confirmed or edited value passes its field's strict decoder;
//! - the profile conflicts of each proposal are computed against the
//!   draft at recording.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use fstp_programme::FieldId;

use crate::ids::{
    AccountRef, ImportDocumentId, ImportProposalId, ProgrammeRef, SaltedDigest, ValueDigest,
    ValueTextId, ValueTextRef,
};
use crate::model::{
    ClientResolution, ImportCommand, ImportDocument, ImportProposal, ImportRecord,
    ImportResolution, RecordedProposal,
};
use crate::text::{MAX_IMPORT_BYTES, check_evidence};
use crate::value::UntrustedValue;

/// The most proposals one `RecordProposals` may hold. Interim, pending
/// Daniel: it keeps one batch within one ledger entry of a few MiB.
pub const MAX_BATCH: usize = 64;

/// Whether import may propose a value for `field` (`FieldSpec::importable`).
pub fn importable(field: FieldId) -> bool {
    field.spec().is_some_and(|s| s.importable)
}

/// One proposal in the store, with its resolution once resolved.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StoredProposal {
    proposal: RecordedProposal,
    resolution: Option<(ImportResolution, AccountRef)>,
}

impl StoredProposal {
    /// The recorded proposal.
    pub fn proposal(&self) -> &RecordedProposal {
        &self.proposal
    }

    /// How it was resolved, if it was.
    pub fn resolution(&self) -> Option<ImportResolution> {
        self.resolution.map(|(r, _)| r)
    }

    /// Who resolved it, if anyone did.
    pub fn resolved_by(&self) -> Option<AccountRef> {
        self.resolution.map(|(_, a)| a)
    }

    /// Whether it is resolved.
    pub fn is_resolved(&self) -> bool {
        self.resolution.is_some()
    }
}

/// The import store: the projection of the import records, and the
/// proposed values the shell holds in memory.
///
/// The records name each value by its [`ValueTextRef`] only (ADR-007). The
/// shell resolves a reference through the text store and hands the value
/// to [`ImportStore::hold`]. The engine does so for each batch it records,
/// with [`ImportStore::hold_recorded`], and the shell does so after a
/// replay. A value that is not held, because it is not resolved yet or
/// its text was erased, cannot be confirmed or edited. It can still be
/// dismissed.
///
/// Equality and hashing compare the folded records only. The held values
/// are a cache of the text store, keyed by reference, so a replayed store
/// equals the live one.
#[derive(Clone, Debug, Default)]
pub struct ImportStore {
    documents: BTreeMap<ImportDocumentId, ImportDocument>,
    proposals: BTreeMap<ImportProposalId, StoredProposal>,
    /// The text of every recorded proposal, by text id. Derived from
    /// `proposals`.
    texts: BTreeMap<ValueTextId, ValueTextRef>,
    values: BTreeMap<ValueTextRef, UntrustedValue>,
}

impl PartialEq for ImportStore {
    fn eq(&self, other: &ImportStore) -> bool {
        self.documents == other.documents && self.proposals == other.proposals
    }
}

impl Eq for ImportStore {}

impl core::hash::Hash for ImportStore {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.documents.hash(state);
        self.proposals.hash(state);
    }
}

/// Why the store does not hold a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HoldError {
    /// No recorded proposal names this reference, with this id and digest.
    UnknownText,
    /// Another value is already held under this reference.
    ConflictingValue,
}

/// Why an import record does not fold. The fold is structural and never
/// re-runs a guard, but it refuses a record that contradicts the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ImportFoldError {
    /// The document id is already registered.
    DuplicateDocument,
    /// The record names a document that is not registered.
    UnknownDocument,
    /// A proposal id is already recorded, or repeated in the record.
    DuplicateProposal,
    /// A value text is already named by a recorded proposal, or repeated
    /// in the record.
    DuplicateText,
    /// A proposal names another document than its record.
    ForeignDocument,
    /// The resolution names a proposal that is not recorded.
    UnknownProposal,
    /// The proposal is already resolved.
    AlreadyResolved,
}

impl ImportStore {
    /// The store before any record.
    pub fn genesis() -> ImportStore {
        ImportStore::default()
    }

    /// The document `id`, if registered.
    pub fn document(&self, id: ImportDocumentId) -> Option<&ImportDocument> {
        self.documents.get(&id)
    }

    /// Every registered document, by id.
    pub fn documents(&self) -> impl Iterator<Item = &ImportDocument> {
        self.documents.values()
    }

    /// The proposal `id`, if recorded.
    pub fn proposal(&self, id: ImportProposalId) -> Option<&StoredProposal> {
        self.proposals.get(&id)
    }

    /// Every recorded proposal, by id.
    pub fn proposals(&self) -> impl Iterator<Item = &StoredProposal> {
        self.proposals.values()
    }

    /// The programme a proposal was imported into, if it is recorded.
    pub fn programme_of(&self, id: ImportProposalId) -> Option<ProgrammeRef> {
        let p = self.proposals.get(&id)?;
        self.documents
            .get(&p.proposal.document)
            .map(|d| d.programme)
    }

    /// The proposals of `programme`, by id.
    pub fn proposals_of(
        &self,
        programme: ProgrammeRef,
    ) -> impl Iterator<Item = &StoredProposal> + '_ {
        self.proposals.values().filter(move |p| {
            self.documents
                .get(&p.proposal.document)
                .is_some_and(|d| d.programme == programme)
        })
    }

    /// The number of unresolved proposals of `programme`, saturating. The
    /// engine passes it to the creator as `CreatorInputs::unresolved_imports`
    /// (Q30).
    pub fn unresolved(&self, programme: ProgrammeRef) -> u32 {
        let n = self
            .proposals_of(programme)
            .filter(|p| !p.is_resolved())
            .count();
        u32::try_from(n).unwrap_or(u32::MAX)
    }

    /// The held value of the proposal `id`, if it is recorded and its text
    /// is resolved. The review page shows it.
    pub fn value_of(&self, id: ImportProposalId) -> Option<&UntrustedValue> {
        let p = self.proposals.get(&id)?;
        self.values.get(&p.proposal.text)
    }

    /// Whether a recorded proposal names `text`, with its id and digest.
    fn names_text(&self, text: ValueTextRef) -> bool {
        self.texts.get(&text.id()) == Some(&text)
    }

    /// Whether a recorded proposal names the text `id`, with any digest.
    fn knows_text(&self, id: ValueTextId) -> bool {
        self.texts.contains_key(&id)
    }

    /// Holds `value` under `text`, as the shell resolved it from the text
    /// store. A recorded proposal must name `text`, and no other value may
    /// be held under it. Holding the same value again changes nothing.
    pub fn hold(&mut self, text: ValueTextRef, value: UntrustedValue) -> Result<(), HoldError> {
        if !self.names_text(text) {
            return Err(HoldError::UnknownText);
        }
        match self.values.get(&text) {
            Some(held) if *held != value => Err(HoldError::ConflictingValue),
            Some(_) => Ok(()),
            None => {
                self.values.insert(text, value);
                Ok(())
            }
        }
    }

    /// Holds the value of every proposal of a batch the engine just
    /// recorded. On an error nothing is held.
    pub fn hold_recorded(&mut self, proposals: &[ImportProposal]) -> Result<(), HoldError> {
        let mut batch: BTreeMap<ValueTextRef, &UntrustedValue> = BTreeMap::new();
        for p in proposals {
            if !self.names_text(p.text) {
                return Err(HoldError::UnknownText);
            }
            let held = self.values.get(&p.text).or(batch.get(&p.text).copied());
            if held.is_some_and(|h| *h != p.value) {
                return Err(HoldError::ConflictingValue);
            }
            batch.insert(p.text, &p.value);
        }
        for (text, value) in batch {
            self.values.entry(text).or_insert_with(|| value.clone());
        }
        Ok(())
    }

    /// Drops every held value whose text is `id`, as erasure of that text
    /// requires (I-81). The records are unchanged (I-23).
    pub fn forget(&mut self, id: ValueTextId) {
        self.values.retain(|text, _| text.id() != id);
    }

    /// Folds one record. On an error the store is unchanged.
    pub fn apply(&mut self, record: &ImportRecord) -> Result<(), ImportFoldError> {
        match record {
            ImportRecord::DocumentRegistered(d) => {
                if self.documents.contains_key(&d.id) {
                    return Err(ImportFoldError::DuplicateDocument);
                }
                self.documents.insert(d.id, *d);
            }
            ImportRecord::ProposalsRecorded {
                document,
                proposals,
            } => {
                if !self.documents.contains_key(document) {
                    return Err(ImportFoldError::UnknownDocument);
                }
                let mut ids = BTreeSet::new();
                let mut texts = BTreeSet::new();
                for p in proposals {
                    if p.document != *document {
                        return Err(ImportFoldError::ForeignDocument);
                    }
                    if self.proposals.contains_key(&p.id) || !ids.insert(p.id) {
                        return Err(ImportFoldError::DuplicateProposal);
                    }
                    if self.knows_text(p.text.id()) || !texts.insert(p.text.id()) {
                        return Err(ImportFoldError::DuplicateText);
                    }
                }
                for p in proposals {
                    self.texts.insert(p.text.id(), p.text);
                    self.proposals.insert(
                        p.id,
                        StoredProposal {
                            proposal: p.clone(),
                            resolution: None,
                        },
                    );
                }
            }
            ImportRecord::ProposalResolved {
                proposal,
                resolution,
                by,
            } => {
                let p = self
                    .proposals
                    .get_mut(proposal)
                    .ok_or(ImportFoldError::UnknownProposal)?;
                if p.resolution.is_some() {
                    return Err(ImportFoldError::AlreadyResolved);
                }
                p.resolution = Some((*resolution, *by));
            }
        }
        Ok(())
    }
}

/// Who issues an import command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ImportActor {
    /// A person's account.
    Account(AccountRef),
    /// The system: the shell running a proposer.
    System,
}

/// Why the import store refuses a command or a resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ImportRefusal {
    /// The command needs an account, and the system issued it.
    AccountOnly,
    /// The command comes only from the system (the proposer).
    SystemOnly,
    /// An upload by an account other than the document's uploader.
    NotTheUploader,
    /// The document id is already registered.
    DuplicateDocument,
    /// The document's text length is 0 or above `MAX_IMPORT_BYTES`.
    TextLength,
    /// The document is not registered.
    UnknownDocument,
    /// The batch is empty.
    EmptyBatch,
    /// The batch holds more than [`MAX_BATCH`] proposals.
    BatchTooLarge,
    /// A proposal names another document than the batch.
    ForeignDocument,
    /// A proposal id is already recorded, or repeated in the batch.
    DuplicateProposal,
    /// A value text is already named by a recorded proposal, or repeated
    /// in the batch. Each value is stored under its own text and key.
    DuplicateText,
    /// A proposal names a field that is not importable. The whole batch
    /// is refused (interim reading, pending Daniel).
    NotImportable,
    /// A proposal's evidence is missing, too long, out of order, empty or
    /// outside the document's text.
    BadEvidence,
    /// A proposal's conflicts are not in strictly ascending order.
    BadConflicts,
    /// The proposal does not exist.
    UnknownProposal,
    /// The proposal belongs to another programme.
    ForeignProgramme,
    /// The proposal is already resolved.
    AlreadyResolved,
    /// `shown` is not the salted digest of the stored value (I-65).
    ShownMismatch,
    /// A confirmation or an edit of a value the store does not hold: its
    /// text is not resolved yet, or it was erased.
    ValueUnavailable,
    /// A confirmation names a value other than the proposal's.
    ConfirmDiffers,
    /// An edit keeps the proposal's own value.
    EditUnchanged,
    /// A flagged conflict without `conflict_acknowledged: true`.
    ConflictNotAcknowledged,
}

/// Decides one import command over the store. The records it returns hold
/// no draft value (I-65).
pub fn decide_import(
    store: &ImportStore,
    cmd: &ImportCommand,
    actor: ImportActor,
) -> Result<Vec<ImportRecord>, ImportRefusal> {
    match cmd {
        ImportCommand::RegisterDocument(d) => {
            let ImportActor::Account(a) = actor else {
                return Err(ImportRefusal::AccountOnly);
            };
            if a != d.uploaded_by {
                return Err(ImportRefusal::NotTheUploader);
            }
            if store.documents.contains_key(&d.id) {
                return Err(ImportRefusal::DuplicateDocument);
            }
            let len_ok =
                usize::try_from(d.text_bytes).is_ok_and(|n| (1..=MAX_IMPORT_BYTES).contains(&n));
            if !len_ok {
                return Err(ImportRefusal::TextLength);
            }
            Ok(vec![ImportRecord::DocumentRegistered(*d)])
        }
        ImportCommand::RecordProposals {
            document,
            proposals,
        } => {
            if actor != ImportActor::System {
                return Err(ImportRefusal::SystemOnly);
            }
            let doc = store
                .documents
                .get(document)
                .ok_or(ImportRefusal::UnknownDocument)?;
            if proposals.is_empty() {
                return Err(ImportRefusal::EmptyBatch);
            }
            if proposals.len() > MAX_BATCH {
                return Err(ImportRefusal::BatchTooLarge);
            }
            let mut ids = BTreeSet::new();
            let mut texts = BTreeSet::new();
            for p in proposals {
                if p.document != *document {
                    return Err(ImportRefusal::ForeignDocument);
                }
                if store.proposals.contains_key(&p.id) || !ids.insert(p.id) {
                    return Err(ImportRefusal::DuplicateProposal);
                }
                if store.knows_text(p.text.id()) || !texts.insert(p.text.id()) {
                    return Err(ImportRefusal::DuplicateText);
                }
                if !importable(p.field) {
                    return Err(ImportRefusal::NotImportable);
                }
                if check_evidence(&p.evidence, doc.text_bytes).is_err() {
                    return Err(ImportRefusal::BadEvidence);
                }
                let ascending = p
                    .conflicts_with_profile
                    .windows(2)
                    .all(|w| matches!(w, [a, b] if a < b));
                if !ascending {
                    return Err(ImportRefusal::BadConflicts);
                }
            }
            Ok(vec![ImportRecord::ProposalsRecorded {
                document: *document,
                proposals: proposals.iter().map(ImportProposal::recorded).collect(),
            }])
        }
    }
}

/// The import side of one resolution, as the engine bridge passes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolveRequest<'a> {
    /// The draft programme the client names.
    pub programme: ProgrammeRef,
    /// The proposal.
    pub proposal: ImportProposalId,
    /// The salted digest of the value the client displayed, as the review
    /// page showed it.
    pub shown: SaltedDigest,
    /// The client's resolution.
    pub resolution: &'a ClientResolution,
    /// Whether the client acknowledged the flagged profile conflicts.
    pub conflict_acknowledged: bool,
    /// The programme manager, whose binding the engine checked.
    pub by: AccountRef,
}

/// The value one confirmation or edit puts into the draft, for the
/// creator's save with `Provenance::Import`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AppliedValue {
    /// The field.
    pub field: FieldId,
    /// The value: the stored proposal's for a confirmation, the edited one
    /// for an edit. Untrusted until its field's strict decoder accepts it.
    pub value: UntrustedValue,
    /// The API core's digest of `value.as_data()`, from the client's
    /// resolution.
    pub digest: ValueDigest,
    /// The resolved proposal.
    pub proposal: ImportProposalId,
    /// `Confirmed` or `Edited`.
    pub resolution: ImportResolution,
}

/// What a resolution that passed the import checks appends.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CheckedResolution {
    /// The `ProposalResolved` record.
    pub record: ImportRecord,
    /// The value to save, for a confirmation or an edit. `None` for a
    /// dismissal, which emits only the import record.
    pub applied: Option<AppliedValue>,
}

/// The import checks of one resolution (I-65, design 3.3). The proposal
/// exists, belongs to `programme` and is unresolved. `shown` equals the
/// stored value's salted digest, and the field is importable. A
/// confirmation names the proposal's value, and an edit another value.
/// Both need the value held in the store. A flagged conflict is
/// acknowledged for a confirmation or an edit.
///
/// One call resolves one proposal: M4 has no bulk accept (Q30).
pub fn check_resolution(
    store: &ImportStore,
    req: &ResolveRequest<'_>,
) -> Result<CheckedResolution, ImportRefusal> {
    let stored = store
        .proposals
        .get(&req.proposal)
        .ok_or(ImportRefusal::UnknownProposal)?;
    if store.programme_of(req.proposal) != Some(req.programme) {
        return Err(ImportRefusal::ForeignProgramme);
    }
    if stored.is_resolved() {
        return Err(ImportRefusal::AlreadyResolved);
    }
    let p = &stored.proposal;
    if req.shown != p.text.digest() {
        return Err(ImportRefusal::ShownMismatch);
    }
    if !importable(p.field) {
        return Err(ImportRefusal::NotImportable);
    }
    let applied = match req.resolution {
        ClientResolution::Confirm { value, digest } => {
            let held = store
                .values
                .get(&p.text)
                .ok_or(ImportRefusal::ValueUnavailable)?;
            if value != held {
                return Err(ImportRefusal::ConfirmDiffers);
            }
            Some((held.clone(), *digest, ImportResolution::Confirmed))
        }
        ClientResolution::Edit { value, digest } => {
            let held = store
                .values
                .get(&p.text)
                .ok_or(ImportRefusal::ValueUnavailable)?;
            if value == held {
                return Err(ImportRefusal::EditUnchanged);
            }
            Some((value.clone(), *digest, ImportResolution::Edited))
        }
        ClientResolution::Dismiss => None,
    };
    if applied.is_some() && !p.conflicts_with_profile.is_empty() && !req.conflict_acknowledged {
        return Err(ImportRefusal::ConflictNotAcknowledged);
    }
    let resolution = applied
        .as_ref()
        .map_or(ImportResolution::Dismissed, |(_, _, r)| *r);
    Ok(CheckedResolution {
        record: ImportRecord::ProposalResolved {
            proposal: req.proposal,
            resolution,
            by: req.by,
        },
        applied: applied.map(|(value, digest, resolution)| AppliedValue {
            field: p.field,
            value,
            digest,
            proposal: req.proposal,
            resolution,
        }),
    })
}
