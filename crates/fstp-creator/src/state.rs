//! The creator projection and its fold (M4 design section 3.2).
//!
//! The fold never re-runs a guard. It refuses only record sequences that
//! cannot come from `decide_creator`, such as a second opening of a draft.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

use fstp_domain::id::{AccountId, BindingId, ContentDigest, OrganisationId, ProgrammeId, TextRef};
use fstp_domain::policy::FunderProfileRef;
use fstp_domain::record::Record;
use fstp_domain::roles::Role;
use fstp_ledger::Seq;
use fstp_programme::{FieldId, FieldValue};

use crate::check::WarningKey;
use crate::ids::{InvitationId, TemplateId};
use crate::model::{
    CreatorRecord, DraftRevision, FieldEdit, ImportFieldEdit, Invitee, Provenance, ReportDigest,
    StartingPoint, ValueDigest,
};
use crate::probe::ProbeSet;

/// Why the fold refused a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CreatorFoldError {
    /// The record names a programme with no draft.
    UnknownDraft,
    /// A draft was opened twice.
    DraftExists,
    /// A draft record arrived after the activation.
    AlreadyActive,
    /// An invitation id was used twice.
    InvitationExists,
    /// The record names an invitation the draft does not hold.
    UnknownInvitation,
    /// A template id was used twice.
    TemplateExists,
    /// The ledger sequence ran backwards within the draft.
    OutOfOrder,
    /// An acceptance names an account other than the invited one.
    InviteeMismatch,
}

impl std::fmt::Display for CreatorFoldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            CreatorFoldError::UnknownDraft => "the record names a programme with no draft",
            CreatorFoldError::DraftExists => "the draft is open already",
            CreatorFoldError::AlreadyActive => "the draft is active",
            CreatorFoldError::InvitationExists => "the invitation id is taken",
            CreatorFoldError::UnknownInvitation => "the draft holds no such invitation",
            CreatorFoldError::TemplateExists => "the template id is taken",
            CreatorFoldError::OutOfOrder => "the ledger sequence ran backwards",
            CreatorFoldError::InviteeMismatch => "the acceptance names another account",
        };
        f.write_str(s)
    }
}

impl std::error::Error for CreatorFoldError {}

/// One invitation of a draft.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Invitation {
    /// The role.
    pub role: Role,
    /// Who is invited.
    pub invitee: Invitee,
    /// The committee organisation.
    pub organisation: Option<OrganisationId>,
    /// The author.
    pub by: AccountId,
    /// Whether it was withdrawn.
    pub withdrawn: bool,
    /// The account that accepted the invitation, once the acceptance flow
    /// (J2, `people.accept_invitation`) reported it through
    /// [`CreatorState::observe_invitation_accepted`].
    pub accepted: Option<AccountId>,
    /// The confidentiality terms the accepting account accepted: their
    /// version and the stored text, from the core `TermsAccepted` (J2,
    /// lane inv). `None` before the acceptance.
    pub terms: Option<(u32, TextRef)>,
}

impl Invitation {
    /// The account the invitation is for: the invited account, or the
    /// account that accepted an invitation by contact address. `None`
    /// while an invitation by contact address waits for its acceptance.
    pub fn account(&self) -> Option<AccountId> {
        match self.invitee {
            Invitee::Account(a) => Some(a),
            Invitee::Pending { .. } => self.accepted,
        }
    }
}

/// The latest activation request of a draft.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ActivationRequest {
    /// The revision requested.
    pub revision: DraftRevision,
    /// The report at the request.
    pub report: ReportDigest,
    /// The requester.
    pub by: AccountId,
}

/// One draft as the creator sees it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Draft {
    profile: FunderProfileRef,
    opener: AccountId,
    head: DraftRevision,
    last_edit: u32,
    builders: BTreeSet<AccountId>,
    fields: BTreeMap<FieldId, (ValueDigest, Provenance)>,
    start: Option<StartingPoint>,
    start_fields: BTreeSet<FieldId>,
    narratives: BTreeSet<FieldId>,
    invitations: BTreeMap<InvitationId, Invitation>,
    acks: BTreeMap<WarningKey, u32>,
    request: Option<ActivationRequest>,
    probes: ProbeSet,
    active: Option<DraftRevision>,
}

impl Draft {
    /// The funder profile.
    pub fn profile(&self) -> &FunderProfileRef {
        &self.profile
    }

    /// The tenant admin who opened the draft.
    pub fn opener(&self) -> AccountId {
        self.opener
    }

    /// The head revision.
    pub fn head(&self) -> DraftRevision {
        self.head
    }

    /// The revision count of the latest edit (reading R1).
    pub fn last_edit(&self) -> u32 {
        self.last_edit
    }

    /// The builder set (Q1, interim, pending Daniel): the author of every
    /// creator record on the draft, of every import resolution on it, and
    /// of every core `CreateProgramme`, `EditPolicy`, `GrantRole` and
    /// binding reinstatement on it before activation.
    pub fn builders(&self) -> &BTreeSet<AccountId> {
        &self.builders
    }

    /// Each field saved since the latest start, with its value digest and
    /// provenance.
    pub fn fields(&self) -> &BTreeMap<FieldId, (ValueDigest, Provenance)> {
        &self.fields
    }

    /// The latest starting point.
    pub fn start(&self) -> Option<&StartingPoint> {
        self.start.as_ref()
    }

    /// The fields the latest start set, P-53 aside. A template start sets
    /// every template value but the narrative that waits for
    /// `AcceptNarrative`. A blank or import start sets none.
    pub fn start_fields(&self) -> &BTreeSet<FieldId> {
        &self.start_fields
    }

    /// The fields that hold a value: P-53, which the opening sets, the
    /// fields of the latest start, every field saved since and every
    /// accepted narrative. Every other field is a gap, which the report
    /// shows as `FieldUnset` (design 3.1).
    pub fn set_fields(&self) -> BTreeSet<FieldId> {
        let mut out = self.start_fields.clone();
        out.insert(FieldId::P53);
        out.extend(self.fields.keys().copied());
        out.extend(self.narratives.iter().copied());
        out
    }

    /// The narrative fields whose template text was accepted.
    pub fn narratives(&self) -> &BTreeSet<FieldId> {
        &self.narratives
    }

    /// Every invitation, withdrawn ones included.
    pub fn invitations(&self) -> &BTreeMap<InvitationId, Invitation> {
        &self.invitations
    }

    /// The invitations not withdrawn.
    pub fn live_invitations(&self) -> impl Iterator<Item = (InvitationId, &Invitation)> {
        self.invitations
            .iter()
            .filter(|(_, i)| !i.withdrawn)
            .map(|(id, i)| (*id, i))
    }

    /// Whether the acknowledgement of `key` is live: it names a revision
    /// that no edit follows (reading R1).
    pub fn ack_live(&self, key: &WarningKey) -> bool {
        self.acks.get(key).is_some_and(|r| *r >= self.last_edit)
    }

    /// The keys with a live acknowledgement.
    pub fn live_acks(&self) -> BTreeSet<WarningKey> {
        self.acks
            .iter()
            .filter(|(_, r)| **r >= self.last_edit)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// The latest activation request.
    pub fn request(&self) -> Option<&ActivationRequest> {
        self.request.as_ref()
    }

    /// Whether an activation request is live: no edit follows it (reading
    /// R6, interim, pending Daniel).
    pub fn request_live(&self) -> bool {
        self.request
            .as_ref()
            .is_some_and(|r| r.revision.seq() >= self.last_edit)
    }

    /// The latest recorded probe results.
    pub fn probes(&self) -> &ProbeSet {
        &self.probes
    }

    /// The revision the activation approved, once active.
    pub fn active(&self) -> Option<DraftRevision> {
        self.active
    }

    /// Bumps the head once per ledger entry.
    fn bump(&mut self, seq: Seq) -> Result<(), CreatorFoldError> {
        if seq < self.head.entry() {
            return Err(CreatorFoldError::OutOfOrder);
        }
        if seq != self.head.entry() {
            self.head = DraftRevision::new(self.head.seq().saturating_add(1), seq);
        }
        Ok(())
    }

    fn edit(&mut self) {
        self.last_edit = self.head.seq();
    }

    fn open_for_records(&self) -> Result<(), CreatorFoldError> {
        if self.active.is_some() {
            Err(CreatorFoldError::AlreadyActive)
        } else {
            Ok(())
        }
    }
}

/// The creator projection of one cell: every draft and every
/// tenant-private template.
///
/// It also holds the value of each saved field outside the ledger, keyed
/// by the digest the save recorded, as the import store holds proposal
/// values. The held values are a cache of the shell's value store and
/// take no part in the state's equality, so a replayed state equals the
/// live one.
#[derive(Clone, Debug, Default)]
pub struct CreatorState {
    drafts: BTreeMap<ProgrammeId, Draft>,
    invitations: BTreeSet<InvitationId>,
    templates: BTreeMap<TemplateId, (ProgrammeId, ContentDigest, AccountId)>,
    /// The programme of every binding granted on a draft. The later
    /// binding records carry only the binding id.
    bindings: BTreeMap<BindingId, ProgrammeId>,
    /// The held value of each saved field, with the digest it was held
    /// under.
    held: BTreeMap<(ProgrammeId, FieldId), (ValueDigest, FieldValue)>,
}

impl PartialEq for CreatorState {
    fn eq(&self, other: &CreatorState) -> bool {
        self.drafts == other.drafts
            && self.invitations == other.invitations
            && self.templates == other.templates
            && self.bindings == other.bindings
    }
}

impl Eq for CreatorState {}

impl Hash for CreatorState {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.drafts.hash(state);
        self.invitations.hash(state);
        self.templates.hash(state);
        self.bindings.hash(state);
    }
}

impl CreatorState {
    /// Holds `value` as the value of `field` on the draft of `programme`,
    /// saved under `digest`. Returns whether it is held.
    ///
    /// The draft's field table must hold `digest` for `field`, so a value
    /// is held only for the save that recorded it, and `value` must be a
    /// value of `field`. A later save of the field records another digest,
    /// and the earlier value stops counting until its own save is the
    /// latest again.
    ///
    /// The shell calls it after the entry of a save is appended, from the
    /// command's values, and after a replay from its value store. Until
    /// it does, every check that reads the value fails closed.
    pub fn hold(
        &mut self,
        programme: ProgrammeId,
        field: FieldId,
        digest: ValueDigest,
        value: FieldValue,
    ) -> bool {
        if value.field() != field {
            return false;
        }
        let saved = self
            .drafts
            .get(&programme)
            .and_then(|d| d.fields.get(&field))
            .map(|(d, _)| *d);
        if saved != Some(digest) {
            return false;
        }
        self.held.insert((programme, field), (digest, value));
        true
    }

    /// Holds every value of a `SaveFields` the engine just appended on
    /// `programme`. Returns whether each is held. A value whose field
    /// the same save edits again later is not held.
    pub fn hold_saved(&mut self, programme: ProgrammeId, fields: &[FieldEdit]) -> bool {
        let mut all = true;
        for f in fields {
            all &= self.hold(programme, f.field, f.digest, f.value.clone());
        }
        all
    }

    /// Holds the value of an import resolution the engine just appended
    /// on `programme` (I-65). Returns whether it is held.
    pub fn hold_import(&mut self, programme: ProgrammeId, edit: &ImportFieldEdit) -> bool {
        self.hold(programme, edit.field, edit.digest, edit.value.clone())
    }

    /// Whether the value of `field` on the draft of `programme` is held
    /// under the digest of the field's latest save. The engine reads it
    /// before it holds a value again after a replay.
    pub fn is_held(&self, programme: ProgrammeId, field: FieldId) -> bool {
        self.drafts
            .get(&programme)
            .and_then(|d| d.fields.get(&field))
            .is_some_and(|(digest, _)| self.held(programme, field, *digest).is_some())
    }

    /// The held value of `field` on `programme` under `digest`.
    pub(crate) fn held(
        &self,
        programme: ProgrammeId,
        field: FieldId,
        digest: ValueDigest,
    ) -> Option<&FieldValue> {
        self.held
            .get(&(programme, field))
            .filter(|(d, _)| *d == digest)
            .map(|(_, v)| v)
    }

    /// The state before any record.
    pub fn genesis() -> CreatorState {
        CreatorState::default()
    }

    /// The draft of `programme`.
    pub fn draft(&self, programme: ProgrammeId) -> Option<&Draft> {
        self.drafts.get(&programme)
    }

    /// Every draft.
    pub fn drafts(&self) -> impl Iterator<Item = (ProgrammeId, &Draft)> {
        self.drafts.iter().map(|(p, d)| (*p, d))
    }

    /// The head revision of `programme`.
    pub fn head(&self, programme: ProgrammeId) -> Option<DraftRevision> {
        self.drafts.get(&programme).map(Draft::head)
    }

    /// Whether `invitation` is taken in this cell.
    pub fn invitation_taken(&self, invitation: InvitationId) -> bool {
        self.invitations.contains(&invitation)
    }

    /// Whether `template` is taken in this cell.
    pub fn template_taken(&self, template: TemplateId) -> bool {
        self.templates.contains_key(&template)
    }

    /// Folds one creator record of the ledger entry `seq`.
    pub fn apply(&mut self, seq: Seq, record: &CreatorRecord) -> Result<(), CreatorFoldError> {
        let programme = record.programme();
        if let CreatorRecord::DraftOpened { profile, by, .. } = record {
            if self.drafts.contains_key(&programme) {
                return Err(CreatorFoldError::DraftExists);
            }
            let mut builders = BTreeSet::new();
            builders.insert(*by);
            self.drafts.insert(
                programme,
                Draft {
                    profile: profile.clone(),
                    opener: *by,
                    head: DraftRevision::new(1, seq),
                    last_edit: 1,
                    builders,
                    fields: BTreeMap::new(),
                    start: None,
                    start_fields: BTreeSet::new(),
                    narratives: BTreeSet::new(),
                    invitations: BTreeMap::new(),
                    acks: BTreeMap::new(),
                    request: None,
                    probes: ProbeSet::absent(),
                    active: None,
                },
            );
            return Ok(());
        }
        if let CreatorRecord::InvitationRecorded { invitation, .. } = record
            && self.invitations.contains(invitation)
        {
            return Err(CreatorFoldError::InvitationExists);
        }
        if let CreatorRecord::TemplateSaved { template, .. } = record
            && self.templates.contains_key(template)
        {
            return Err(CreatorFoldError::TemplateExists);
        }
        // The fields a start sets read other drafts for a clone, so they
        // are computed before the draft is borrowed.
        let started = match record {
            CreatorRecord::StartApplied { start, .. } => crate::draft::start_fields(self, start),
            _ => BTreeSet::new(),
        };
        let draft = self
            .drafts
            .get_mut(&programme)
            .ok_or(CreatorFoldError::UnknownDraft)?;
        // Interim, pending Daniel (Q17): a programme can be saved as a
        // tenant-private template after activation too, as
        // `decide_creator` admits. Every other creator record stops at
        // activation.
        if !matches!(record, CreatorRecord::TemplateSaved { .. }) {
            draft.open_for_records()?;
        }
        if let CreatorRecord::InvitationWithdrawn { invitation, .. } = record
            && !draft
                .invitations
                .get(invitation)
                .is_some_and(|i| !i.withdrawn)
        {
            return Err(CreatorFoldError::UnknownInvitation);
        }
        draft.bump(seq)?;
        if record.is_edit() {
            draft.edit();
        }
        if let Some(by) = record.author()
            && !matches!(record, CreatorRecord::ActivationApproved(_))
            && draft.active.is_none()
        {
            draft.builders.insert(by);
        }
        match record {
            CreatorRecord::DraftOpened { .. } => {}
            CreatorRecord::StartApplied { start, .. } => {
                // A start replaces the draft content (interim, pending
                // Daniel), so earlier saves and acceptances no longer
                // hold a value.
                draft.start = Some(start.clone());
                draft.start_fields = started;
                draft.fields.clear();
                draft.narratives.clear();
            }
            CreatorRecord::FieldsSaved { fields, .. } => {
                for (f, d, p) in fields {
                    draft.fields.insert(*f, (*d, p.clone()));
                }
            }
            CreatorRecord::NarrativeAccepted { field, .. } => {
                draft.narratives.insert(*field);
            }
            CreatorRecord::InvitationRecorded {
                invitation,
                role,
                invitee,
                organisation,
                by,
                ..
            } => {
                draft.invitations.insert(
                    *invitation,
                    Invitation {
                        role: *role,
                        invitee: *invitee,
                        organisation: *organisation,
                        by: *by,
                        withdrawn: false,
                        accepted: None,
                        terms: None,
                    },
                );
                self.invitations.insert(*invitation);
            }
            CreatorRecord::InvitationWithdrawn { invitation, .. } => {
                if let Some(i) = draft.invitations.get_mut(invitation) {
                    i.withdrawn = true;
                }
            }
            CreatorRecord::ProbeRecorded { probe, outcome, .. } => {
                draft.probes.set(*probe, *outcome)
            }
            CreatorRecord::WarningAcknowledged {
                revision, warning, ..
            } => {
                draft.acks.insert(warning.clone(), revision.seq());
            }
            CreatorRecord::ActivationRequested {
                revision,
                report,
                by,
                ..
            } => {
                draft.request = Some(ActivationRequest {
                    revision: *revision,
                    report: report.clone(),
                    by: *by,
                });
            }
            CreatorRecord::ActivationApproved(a) => draft.active = Some(a.revision()),
            CreatorRecord::TemplateSaved {
                template, spec, by, ..
            } => {
                self.templates.insert(*template, (programme, *spec, *by));
            }
        }
        Ok(())
    }

    /// Folds one core record of the ledger entry `seq` that names a draft.
    ///
    /// The records are `ProgrammeCreated`, `PolicyVersionRecorded`,
    /// `BindingGranted`, and every later record of a binding granted on a
    /// draft: `BindingEnded`, `BindingSuspended`, `BindingVoided`,
    /// `BindingReinstated` and `BindingEndScheduled`. The later binding
    /// records carry only the binding id, so the fold keeps the programme
    /// of each grant it saw on a draft.
    ///
    /// Each bumps the draft's revision once per entry (design 3.2 "Bound
    /// to a revision"). Before activation each is an edit (reading R1):
    /// a binding change alters the roster and the manager set that the
    /// report and the acknowledgements were made over. Interim, pending
    /// Daniel.
    ///
    /// Before activation the author joins the builder set (Q1): the
    /// author of `CreateProgramme`, `EditPolicy` and `GrantRole`, and the
    /// author of a reinstatement, which restores a grant. The other
    /// binding records name no author. Interim, pending Daniel.
    ///
    /// Records on programmes with no draft, and other core records,
    /// change nothing here.
    pub fn observe_core(&mut self, seq: Seq, record: &Record) -> Result<(), CreatorFoldError> {
        if let Record::TermsAccepted {
            account,
            programme,
            role,
            invitation,
            version,
            terms,
        } = record
        {
            return self.observe_terms_accepted(
                seq,
                *programme,
                InvitationId::from_raw(invitation.raw()),
                *account,
                *role,
                (*version, *terms),
            );
        }
        let (programme, author) = match record {
            Record::ProgrammeCreated { programme, by, .. } => (*programme, Some(*by)),
            Record::PolicyVersionRecorded { version, author } => (version.programme, Some(*author)),
            Record::BindingGranted(g) => {
                if self.drafts.contains_key(&g.programme) {
                    self.bindings.insert(g.binding, g.programme);
                }
                (g.programme, Some(g.granted_by))
            }
            Record::BindingReinstated(r) => match self.bindings.get(&r.binding) {
                Some(p) => (*p, Some(r.by)),
                None => return Ok(()),
            },
            Record::BindingEnded(fstp_domain::record::BindingEnded { binding, .. })
            | Record::BindingSuspended(fstp_domain::record::BindingSuspended { binding, .. })
            | Record::BindingVoided(fstp_domain::record::BindingVoided { binding, .. })
            | Record::BindingEndScheduled { binding, .. } => match self.bindings.get(binding) {
                Some(p) => (*p, None),
                None => return Ok(()),
            },
            _ => return Ok(()),
        };
        let Some(draft) = self.drafts.get_mut(&programme) else {
            return Ok(());
        };
        draft.bump(seq)?;
        if draft.active.is_none() {
            draft.edit();
            if let Some(a) = author {
                draft.builders.insert(a);
            }
        }
        Ok(())
    }

    /// Folds the resolution of an import proposal on `programme` by `by`
    /// in the ledger entry `seq` (I-65, Q1).
    ///
    /// The engine calls it for every `ImportRecord::ProposalResolved` on
    /// a draft: confirm, edit and dismiss alike. A dismissal emits no
    /// creator record (design 3.3), so this hook is the only place the
    /// creator sees its author. A confirm or an edit also carries a
    /// `FieldsSaved` in the same entry, and one entry bumps the revision
    /// once.
    ///
    /// The resolution bumps the revision. Before activation it is an edit
    /// (reading R1) and its author joins the builder set (Q1: "any import
    /// resolution"). Interim, pending Daniel. A programme with no draft
    /// changes nothing here.
    pub fn observe_import_resolution(
        &mut self,
        seq: Seq,
        programme: ProgrammeId,
        by: AccountId,
    ) -> Result<(), CreatorFoldError> {
        let Some(draft) = self.drafts.get_mut(&programme) else {
            return Ok(());
        };
        draft.bump(seq)?;
        if draft.active.is_none() {
            draft.edit();
            draft.builders.insert(by);
        }
        Ok(())
    }

    /// Whether the acceptance of `invitation` on `programme` by `account`
    /// can be folded. The acceptance flow checks this before it records
    /// the acceptance, so the fold never refuses what was decided.
    ///
    /// The draft must hold the invitation, not withdrawn. An invitation
    /// of an account is accepted only by that account. An invitation by
    /// contact address is accepted by one account; the same account may
    /// accept it again.
    pub fn check_invitation_acceptance(
        &self,
        programme: ProgrammeId,
        invitation: InvitationId,
        account: AccountId,
    ) -> Result<(), CreatorFoldError> {
        let draft = self
            .drafts
            .get(&programme)
            .ok_or(CreatorFoldError::UnknownDraft)?;
        let i = draft
            .invitations
            .get(&invitation)
            .filter(|i| !i.withdrawn)
            .ok_or(CreatorFoldError::UnknownInvitation)?;
        match i.account() {
            Some(a) if a != account => Err(CreatorFoldError::InviteeMismatch),
            _ => Ok(()),
        }
    }

    /// Folds the acceptance of `invitation` on `programme` by `account`
    /// in the ledger entry `seq` (J2, `people.accept_invitation`).
    ///
    /// Interim, pending Daniel: design 3.2 lists no acceptance record.
    /// The acceptance flow records the acceptance in its own lane, and
    /// the engine calls this hook when it folds that record. From then on
    /// an invitation by contact address names the account, so the report
    /// previews its SoD guards (`InviteeRefused`) instead of the warning
    /// `InviteeWithoutAccount`.
    ///
    /// The acceptance bumps the revision. Before activation it is an edit
    /// (reading R1), because it changes what the report reads. The
    /// invitee does not join the builder set: an acceptance builds
    /// nothing, and Q1 does not list it. Acceptances after activation
    /// are folded too, since people accept their roles later.
    pub fn observe_invitation_accepted(
        &mut self,
        seq: Seq,
        programme: ProgrammeId,
        invitation: InvitationId,
        account: AccountId,
    ) -> Result<(), CreatorFoldError> {
        self.check_invitation_acceptance(programme, invitation, account)?;
        let draft = self
            .drafts
            .get_mut(&programme)
            .ok_or(CreatorFoldError::UnknownDraft)?;
        draft.bump(seq)?;
        if draft.active.is_none() {
            draft.edit();
        }
        if let Some(i) = draft.invitations.get_mut(&invitation) {
            i.accepted = Some(account);
        }
        Ok(())
    }

    /// Folds the core `TermsAccepted` of `invitation` on `programme` by
    /// `account` in the ledger entry `seq` (J2, lane inv): the acceptance
    /// of [`CreatorState::observe_invitation_accepted`], with the version
    /// and the stored text of the accepted terms. The record must name the
    /// invited role, or the fold refuses it as `InviteeMismatch`.
    pub fn observe_terms_accepted(
        &mut self,
        seq: Seq,
        programme: ProgrammeId,
        invitation: InvitationId,
        account: AccountId,
        role: Role,
        terms: (u32, TextRef),
    ) -> Result<(), CreatorFoldError> {
        let invited = self
            .drafts
            .get(&programme)
            .and_then(|d| d.invitations.get(&invitation))
            .map(|i| i.role)
            .ok_or(CreatorFoldError::UnknownInvitation)?;
        if invited != role {
            return Err(CreatorFoldError::InviteeMismatch);
        }
        self.observe_invitation_accepted(seq, programme, invitation, account)?;
        if let Some(i) = self
            .drafts
            .get_mut(&programme)
            .and_then(|d| d.invitations.get_mut(&invitation))
        {
            i.terms = Some(terms);
        }
        Ok(())
    }
}
