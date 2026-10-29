//! Creator commands, records, revisions and provenance (M4 design
//! section 3.2).

use fstp_domain::id::{
    AccountId, ContentDigest, DecisionId, OrganisationId, PolicyVersionId, ProgrammeId, TextRef,
};
use fstp_domain::policy::FunderProfileRef;
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_ledger::Seq;
use fstp_programme::{FieldId, FieldValue};

use crate::check::WarningKey;
use crate::ids::{ImportDocumentId, ImportProposalId, InvitationId, TemplateId};
use crate::probe::{ProbeKind, ProbeOutcome};
use crate::witness::ActivationApproved;

/// One revision of a draft. Monotone per draft.
///
/// `seq` counts the ledger entries that hold a record on the draft, from
/// 1 at the opening. One entry bumps it once, whether it holds one record
/// or several (design 3.2 "Bound to a revision").
///
/// Interim, pending Daniel: the design gives a revision a content digest.
/// The pure crates compute no hashes, and the engine fold sees no entry
/// hash. So a revision names the ledger entry that made it instead. In
/// one cell ledger the entry pins the revision exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DraftRevision {
    seq: u32,
    entry: Seq,
}

impl DraftRevision {
    /// The revision `seq` made by ledger entry `entry`.
    pub const fn new(seq: u32, entry: Seq) -> DraftRevision {
        DraftRevision { seq, entry }
    }

    /// The count of entries on the draft up to this revision.
    pub const fn seq(self) -> u32 {
        self.seq
    }

    /// The ledger entry that made this revision.
    pub const fn entry(self) -> Seq {
        self.entry
    }
}

/// A fingerprint of a validation report: its programme, its revision and
/// the key of every row, in catalogue order.
///
/// Interim, pending Daniel: the design names a report digest. The pure
/// crates compute no hashes, so the fingerprint keeps the keys
/// themselves. A row's severity follows from its check, so the keys pin
/// it. The fingerprint leaves out each row's detail. So two reports at
/// one revision can differ in detail and still share a fingerprint, for
/// example a probe at `Fail` against `Absent`. The D2e pairing matches
/// records of one entry, made from one report, where the keys suffice.
/// Reconcile with the domain `ReportDigest` of lane W1b at merge.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReportDigest {
    programme: ProgrammeId,
    revision: DraftRevision,
    rows: Vec<WarningKey>,
}

impl ReportDigest {
    pub(crate) fn new(
        programme: ProgrammeId,
        revision: DraftRevision,
        rows: Vec<WarningKey>,
    ) -> ReportDigest {
        ReportDigest {
            programme,
            revision,
            rows,
        }
    }

    /// The programme.
    pub fn programme(&self) -> ProgrammeId {
        self.programme
    }

    /// The revision of the report.
    pub fn revision(&self) -> DraftRevision {
        self.revision
    }

    /// The key of every row, in catalogue order.
    pub fn rows(&self) -> &[WarningKey] {
        &self.rows
    }
}

/// The digest of one field value, computed by the shell over the value's
/// canonical text. The ledger body holds the digest, not the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValueDigest(ContentDigest);

impl ValueDigest {
    /// The digest with these bytes.
    pub const fn new(digest: ContentDigest) -> ValueDigest {
        ValueDigest(digest)
    }

    /// The content digest.
    pub const fn digest(self) -> ContentDigest {
        self.0
    }
}

/// Where a draft starts.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum StartingPoint {
    /// A blank programme with funder profile defaults.
    Blank {
        /// The funder profile (P-53).
        profile: FunderProfileRef,
    },
    /// A clone of a programme of the same tenant (I-19).
    Clone {
        /// The source programme.
        source: ProgrammeId,
    },
    /// A shipped or tenant-private template.
    Template {
        /// The template.
        template: TemplateId,
        /// Its version.
        version: u32,
    },
    /// An uploaded document. Its values arrive as proposals (I-65).
    Import {
        /// The document.
        document: ImportDocumentId,
    },
}

/// How a programme manager resolved an import proposal (I-65).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImportResolution {
    /// The proposed value was confirmed unchanged.
    Confirmed,
    /// The proposed value was edited.
    Edited,
}

/// Where a field value came from.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Provenance {
    /// Typed by the programme manager.
    Manual,
    /// A funder profile default.
    Default {
        /// The funder profile.
        profile: FunderProfileRef,
    },
    /// A template value.
    Template {
        /// The template.
        template: TemplateId,
        /// Its version.
        version: u32,
    },
    /// A cloned value.
    Clone {
        /// The source programme.
        source: ProgrammeId,
        /// The source policy version.
        version: PolicyVersionId,
    },
    /// A resolved import proposal (I-65).
    Import {
        /// The proposal.
        proposal: ImportProposalId,
        /// How it was resolved.
        resolution: ImportResolution,
    },
}

/// One field edit of a save.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldEdit {
    /// The field.
    pub field: FieldId,
    /// The new value, decoded by the field's strict decoder.
    pub value: FieldValue,
    /// The shell's digest of the value's canonical text.
    pub digest: ValueDigest,
    /// Where the value came from.
    pub provenance: Provenance,
}

/// The field edit of one import resolution (I-65, design 3.3).
///
/// Only the engine bridge builds it, after `resolve_import` checked the
/// proposal, the shown digest and the resolution. It is not a
/// [`CreatorCommand`], and no codec decodes it, so no client can send it.
/// Its provenance is [`Provenance::Import`] by construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportFieldEdit {
    /// The field.
    pub field: FieldId,
    /// The confirmed or edited value, decoded by the field's strict
    /// decoder.
    pub value: FieldValue,
    /// The shell's digest of the value's canonical text.
    pub digest: ValueDigest,
    /// The resolved proposal.
    pub proposal: ImportProposalId,
    /// How it was resolved.
    pub resolution: ImportResolution,
}

impl ImportFieldEdit {
    /// The provenance the save records.
    pub fn provenance(&self) -> Provenance {
        Provenance::Import {
            proposal: self.proposal,
            resolution: self.resolution,
        }
    }
}

/// Who an invitation is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Invitee {
    /// An existing tenant account.
    Account(AccountId),
    /// A person without an account yet. The contact address is free text
    /// held outside the ledger body (ADR-007).
    Pending {
        /// The contact address, as a text reference.
        contact: TextRef,
    },
}

/// A creator command (design section 3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreatorCommand {
    /// Open a draft. Issued by a tenant admin with core `CreateProgramme`.
    OpenDraft {
        /// The new programme.
        programme: ProgrammeId,
        /// Its first policy version.
        version: PolicyVersionId,
        /// The funder profile.
        profile: FunderProfileRef,
    },
    /// Apply a starting point.
    ApplyStart {
        /// The draft.
        programme: ProgrammeId,
        /// The revision the client saw.
        base: DraftRevision,
        /// The starting point.
        start: StartingPoint,
    },
    /// Save field values.
    SaveFields {
        /// The draft.
        programme: ProgrammeId,
        /// The revision the client saw.
        base: DraftRevision,
        /// The edits.
        fields: Vec<FieldEdit>,
    },
    /// Accept template narrative text, which is never applied silently.
    AcceptNarrative {
        /// The draft.
        programme: ProgrammeId,
        /// The revision the client saw.
        base: DraftRevision,
        /// The narrative field.
        field: FieldId,
    },
    /// Invite a person to a role (creator step 9).
    Invite {
        /// The draft.
        programme: ProgrammeId,
        /// The new invitation.
        invitation: InvitationId,
        /// The role.
        role: Role,
        /// Who is invited.
        invitee: Invitee,
        /// The committee organisation, for committee roles (I-34).
        organisation: Option<OrganisationId>,
    },
    /// Withdraw an invitation.
    WithdrawInvitation {
        /// The draft.
        programme: ProgrammeId,
        /// The invitation.
        invitation: InvitationId,
    },
    /// Acknowledge one warning of the current report.
    AcknowledgeWarning {
        /// The draft.
        programme: ProgrammeId,
        /// The revision the client saw.
        revision: DraftRevision,
        /// The warning.
        warning: WarningKey,
    },
    /// Request activation.
    RequestActivation {
        /// The draft.
        programme: ProgrammeId,
        /// The revision the client saw.
        revision: DraftRevision,
    },
    /// Approve activation. High-risk, with step-up (I-78).
    ApproveActivation {
        /// The draft.
        programme: ProgrammeId,
        /// The revision the client saw.
        revision: DraftRevision,
        /// The decision id the shell drew.
        decision: DecisionId,
    },
    /// Save the draft as a tenant-private template (Q17).
    SaveAsTenantTemplate {
        /// The draft.
        programme: ProgrammeId,
        /// The new template.
        template: TemplateId,
    },
}

impl CreatorCommand {
    /// The programme the command acts on.
    pub fn programme(&self) -> ProgrammeId {
        match self {
            CreatorCommand::OpenDraft { programme, .. }
            | CreatorCommand::ApplyStart { programme, .. }
            | CreatorCommand::SaveFields { programme, .. }
            | CreatorCommand::AcceptNarrative { programme, .. }
            | CreatorCommand::Invite { programme, .. }
            | CreatorCommand::WithdrawInvitation { programme, .. }
            | CreatorCommand::AcknowledgeWarning { programme, .. }
            | CreatorCommand::RequestActivation { programme, .. }
            | CreatorCommand::ApproveActivation { programme, .. }
            | CreatorCommand::SaveAsTenantTemplate { programme, .. } => *programme,
        }
    }

    /// Whether the command is high-risk and needs a fresh step-up (I-78):
    /// opening a draft and approving activation (Q10, interim, pending
    /// Daniel).
    pub fn high_risk(&self) -> bool {
        matches!(
            self,
            CreatorCommand::OpenDraft { .. } | CreatorCommand::ApproveActivation { .. }
        )
    }
}

/// A creator ledger record (design section 3.2).
///
/// Records that name a `revision` name the head revision the command was
/// decided at. The entry that holds the record then bumps the head.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CreatorRecord {
    /// A draft was opened.
    DraftOpened {
        /// The draft.
        programme: ProgrammeId,
        /// The funder profile.
        profile: FunderProfileRef,
        /// The tenant admin who opened it.
        by: AccountId,
    },
    /// A starting point was applied.
    StartApplied {
        /// The draft.
        programme: ProgrammeId,
        /// The revision it was decided at.
        revision: DraftRevision,
        /// The starting point.
        start: StartingPoint,
        /// The author.
        by: AccountId,
    },
    /// Field values were saved.
    FieldsSaved {
        /// The draft.
        programme: ProgrammeId,
        /// The revision it was decided at.
        revision: DraftRevision,
        /// Each field with its value digest and provenance.
        fields: Vec<(FieldId, ValueDigest, Provenance)>,
        /// The author.
        by: AccountId,
    },
    /// Template narrative was accepted.
    NarrativeAccepted {
        /// The draft.
        programme: ProgrammeId,
        /// The revision it was decided at.
        revision: DraftRevision,
        /// The field.
        field: FieldId,
        /// The author.
        by: AccountId,
    },
    /// An invitation was recorded.
    InvitationRecorded {
        /// The draft.
        programme: ProgrammeId,
        /// The invitation.
        invitation: InvitationId,
        /// The role.
        role: Role,
        /// Who is invited.
        invitee: Invitee,
        /// The committee organisation.
        organisation: Option<OrganisationId>,
        /// The author.
        by: AccountId,
    },
    /// An invitation was withdrawn.
    InvitationWithdrawn {
        /// The draft.
        programme: ProgrammeId,
        /// The invitation.
        invitation: InvitationId,
        /// The author.
        by: AccountId,
    },
    /// A probe result. An approval records every probe in its entry.
    ProbeRecorded {
        /// The draft.
        programme: ProgrammeId,
        /// The probe.
        probe: ProbeKind,
        /// The outcome.
        outcome: ProbeOutcome,
        /// When the shell ran it.
        at: Timestamp,
    },
    /// A warning was acknowledged.
    WarningAcknowledged {
        /// The draft.
        programme: ProgrammeId,
        /// The revision acknowledged.
        revision: DraftRevision,
        /// The warning.
        warning: WarningKey,
        /// The author.
        by: AccountId,
    },
    /// Activation was requested.
    ActivationRequested {
        /// The draft.
        programme: ProgrammeId,
        /// The revision requested.
        revision: DraftRevision,
        /// The report at the request.
        report: ReportDigest,
        /// The author.
        by: AccountId,
    },
    /// Activation was approved. Built only from an `ActivationClearance`.
    ActivationApproved(ActivationApproved),
    /// The draft was saved as a tenant-private template.
    ///
    /// Interim, pending Daniel: the record names its programme, which the
    /// design leaves out, so the saver joins the builder set (Q1).
    TemplateSaved {
        /// The template.
        template: TemplateId,
        /// The draft it was saved from.
        programme: ProgrammeId,
        /// The digest of the template spec.
        spec: ContentDigest,
        /// The author.
        by: AccountId,
    },
}

impl CreatorRecord {
    /// The programme the record is on.
    pub fn programme(&self) -> ProgrammeId {
        match self {
            CreatorRecord::DraftOpened { programme, .. }
            | CreatorRecord::StartApplied { programme, .. }
            | CreatorRecord::FieldsSaved { programme, .. }
            | CreatorRecord::NarrativeAccepted { programme, .. }
            | CreatorRecord::InvitationRecorded { programme, .. }
            | CreatorRecord::InvitationWithdrawn { programme, .. }
            | CreatorRecord::ProbeRecorded { programme, .. }
            | CreatorRecord::WarningAcknowledged { programme, .. }
            | CreatorRecord::ActivationRequested { programme, .. }
            | CreatorRecord::TemplateSaved { programme, .. } => *programme,
            CreatorRecord::ActivationApproved(a) => a.programme(),
        }
    }

    /// The author of the record, if it has one.
    pub fn author(&self) -> Option<AccountId> {
        match self {
            CreatorRecord::DraftOpened { by, .. }
            | CreatorRecord::StartApplied { by, .. }
            | CreatorRecord::FieldsSaved { by, .. }
            | CreatorRecord::NarrativeAccepted { by, .. }
            | CreatorRecord::InvitationRecorded { by, .. }
            | CreatorRecord::InvitationWithdrawn { by, .. }
            | CreatorRecord::WarningAcknowledged { by, .. }
            | CreatorRecord::ActivationRequested { by, .. }
            | CreatorRecord::TemplateSaved { by, .. } => Some(*by),
            CreatorRecord::ActivationApproved(a) => Some(a.approver()),
            CreatorRecord::ProbeRecorded { .. } => None,
        }
    }

    /// Whether the record changes the draft content (reading R1, interim,
    /// pending Daniel). An edit voids every earlier acknowledgement and
    /// activation request.
    pub fn is_edit(&self) -> bool {
        matches!(
            self,
            CreatorRecord::DraftOpened { .. }
                | CreatorRecord::StartApplied { .. }
                | CreatorRecord::FieldsSaved { .. }
                | CreatorRecord::NarrativeAccepted { .. }
                | CreatorRecord::InvitationRecorded { .. }
                | CreatorRecord::InvitationWithdrawn { .. }
        )
    }
}
