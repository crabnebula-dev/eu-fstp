//! The creator decider (M4 design section 3.2).
//!
//! [`decide_creator`] is pure. It reads the core state, the creator state,
//! the command context and the [`CreatorInputs`]. It returns the creator
//! records and the core commands the engine decides in the same entry, or
//! a refusal. Nothing is recorded on a refusal.

use std::collections::BTreeSet;

use fstp_domain::command::{Actor, Command, Ctx};
use fstp_domain::id::{AccountId, ProgrammeId};
use fstp_domain::roles::{Group, Role};
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_money::NonNegAmount;
use fstp_programme::{CompileIds, FieldId, FieldKind, FieldValue, FunderProfile, compile};

use crate::check::{CheckId, Severity};
use crate::draft;
use crate::inputs::CreatorInputs;
use crate::model::{
    CreatorCommand, CreatorRecord, DraftRevision, ImportFieldEdit, Provenance, StartingPoint,
    ValueDigest,
};
use crate::probe::ProbeKind;
use crate::state::{CreatorState, Draft};
use crate::validate::{OwnFacts, ReadFacts, validate_at};
use crate::witness::{AckSet, ActivationApproved, Uncleared, clean, clear_activation};

/// What one creator command decides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatorDecision {
    /// The creator records of the entry.
    pub records: Vec<CreatorRecord>,
    /// Core commands the engine decides in the same entry, with the same
    /// actor and context.
    ///
    /// An approval leaves this empty. The engine composes the core
    /// `ActivateProgramme` from the [`ActivationApproved`] record, and
    /// refuses the command from anywhere else (D2e, lane W2e). The core
    /// command itself is change D2 of lane W1b.
    pub core: Vec<Command>,
}

/// Why the creator refused a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CreatorRefusal {
    /// The programme has no draft.
    UnknownDraft,
    /// The programme exists already, as a draft or in the core.
    DraftExists,
    /// The draft is active. Interim, pending Daniel: the draft commands
    /// stop at activation in this lane.
    AlreadyActive,
    /// The command names a revision other than the head. The client
    /// reloads.
    StaleRevision,
    /// The actor is not a named account.
    NotAnAccount,
    /// The actor is not a tenant admin in the attested admin set (Q31,
    /// interim, pending Daniel).
    NotTenantAdmin,
    /// The actor holds no active programme manager binding on the draft
    /// and is not a tenant admin. Interim, pending Daniel: readings R5
    /// and R6 let a tenant admin acknowledge and request too.
    NotProgrammeManager,
    /// A save named no field, or holds nothing that can be saved: an
    /// edit whose value is not of its field, a value that does not compile
    /// under the draft's funder profile, P-09 wording that is still inline
    /// (ADR-007), a start that names another funder profile, or an
    /// acceptance of a field that holds no template narrative waiting for
    /// it. Interim, pending Daniel: one refusal for every invalid save.
    NothingToSave,
    /// I-50, R-PG-01 AC: the save would put P-05 above P-58. A cap above
    /// the ceiling is refused when the draft is saved, so no draft holds
    /// one (Daniel's answer of 2026-10-31, M4 design section 15.0). The
    /// refusal names both values.
    CapAboveCeiling {
        /// P-05 as the save would leave it.
        p05: NonNegAmount,
        /// P-58 as the save would leave it.
        p58: NonNegAmount,
    },
    /// A save from a client claims a provenance other than `Manual`.
    /// Import provenance arrives only through the engine bridge (I-65).
    ProvenanceNotManual,
    /// The clone source is not a programme of this cell (I-19).
    UnknownSource,
    /// The invitation id is taken.
    InvitationExists,
    /// The draft holds no live invitation with this id.
    UnknownInvitation,
    /// The role cannot be invited from the creator: a Receiving role, or
    /// tenant admin, which onboarding invites.
    RoleNotInvitable,
    /// The template id is taken.
    TemplateExists,
    /// The acknowledged key is not a warning the current report shows
    /// (reading R5, interim, pending Daniel).
    NotAWarning,
    /// No activation request is live (reading R6, interim, pending
    /// Daniel).
    NoLiveRequest,
    /// I-67 under Q1 (interim, pending Daniel): the approver built the
    /// draft.
    ApproverIsBuilder,
    /// I-67 under Q2 (interim, pending Daniel): the vault does not verify
    /// the approver.
    ApproverUnverified,
    /// I-67 under Q2 (interim, pending Daniel): the approver shares a
    /// verified identity with a builder.
    SameIdentity,
    /// I-67 under Q2 (interim, pending Daniel): a builder is unverified.
    BuilderUnverified,
    /// The engine passed no vault answer the decision needs.
    VaultAnswerMissing,
    /// I-66: the recomputed report does not clear.
    Uncleared(Uncleared),
    /// The command needs a parallel lane's code that is not there yet.
    /// The text names it.
    Unavailable(&'static str),
}

impl std::fmt::Display for CreatorRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CreatorRefusal::Uncleared(Uncleared::Failure(c)) => {
                write!(f, "I-66: the report shows the failure {}", c.name())
            }
            CreatorRefusal::Uncleared(Uncleared::Unacknowledged(c)) => {
                write!(f, "I-66: the warning {} is not acknowledged", c.name())
            }
            CreatorRefusal::CapAboveCeiling { p05, p58 } => write!(
                f,
                "I-50: P-05 {} is above P-58 {}",
                p05.amount(),
                p58.amount()
            ),
            CreatorRefusal::Unavailable(what) => write!(f, "{what} is not implemented yet"),
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::error::Error for CreatorRefusal {}

/// Decides one creator command (design section 3.2). The draft facts,
/// which hold the Guide preview, are computed only by the commands that
/// read a report, after their cheaper guards.
pub fn decide_creator(
    core: &State,
    creator: &CreatorState,
    cmd: &CreatorCommand,
    ctx: &Ctx,
    ext: &CreatorInputs,
) -> Result<CreatorDecision, CreatorRefusal> {
    decide_with(core, creator, cmd, ctx, ext, &OwnFacts)
}

/// The decision over explicit draft facts. Crate-private, so no caller
/// outside the crate can feed made-up facts into an approval.
pub(crate) fn decide_with<F: ReadFacts + ?Sized>(
    core: &State,
    creator: &CreatorState,
    cmd: &CreatorCommand,
    ctx: &Ctx,
    ext: &CreatorInputs,
    facts: &F,
) -> Result<CreatorDecision, CreatorRefusal> {
    let actor = account(ctx)?;
    let records = |records: Vec<CreatorRecord>| {
        Ok(CreatorDecision {
            records,
            core: Vec::new(),
        })
    };
    match cmd {
        CreatorCommand::OpenDraft {
            programme,
            version,
            profile,
        } => {
            if !is_admin(actor, ctx, ext) {
                return Err(CreatorRefusal::NotTenantAdmin);
            }
            if creator.draft(*programme).is_some() || core.policy().programme(*programme).is_some()
            {
                return Err(CreatorRefusal::DraftExists);
            }
            // The profile-default policy: the blank spec of the funder
            // profile, compiled with the ids the command names (design
            // 3.2). The programme starts in `Draft` status (D1).
            let p = FunderProfile::for_policy_ref(profile)
                .ok_or(CreatorRefusal::Unavailable(draft::NO_PROFILE))?;
            let compiled = compile(&p.blank(), &p, CompileIds::new(*programme, *version, None))
                .map_err(|_| CreatorRefusal::Unavailable(draft::NO_PROFILE))?;
            Ok(CreatorDecision {
                records: vec![CreatorRecord::DraftOpened {
                    programme: *programme,
                    profile: profile.clone(),
                    by: actor,
                }],
                core: vec![Command::CreateProgramme {
                    policy: Box::new(compiled.policy),
                }],
            })
        }
        CreatorCommand::ApplyStart {
            programme,
            base,
            start,
        } => {
            manager(core, *programme, actor, ctx.now)?;
            let d = open_draft(creator, *programme)?;
            at_head(d, *base)?;
            if let StartingPoint::Clone { source } = start
                && core.policy().programme(*source).is_none()
            {
                return Err(CreatorRefusal::UnknownSource);
            }
            // A start writes the whole draft policy in one core
            // `EditPolicy` (design 3.2).
            let head =
                fstp_domain::policy::head(core, *programme).ok_or(CreatorRefusal::UnknownDraft)?;
            let version = draft::fresh_version(core, ctx)?;
            let policy = draft::start_policy(core, creator, d, head, start, version)?;
            Ok(CreatorDecision {
                records: vec![CreatorRecord::StartApplied {
                    programme: *programme,
                    revision: *base,
                    start: start.clone(),
                    by: actor,
                }],
                core: vec![Command::EditPolicy {
                    base: head.id,
                    version: Box::new(policy),
                }],
            })
        }
        CreatorCommand::SaveFields {
            programme,
            base,
            fields,
        } => {
            manager(core, *programme, actor, ctx.now)?;
            let d = open_draft(creator, *programme)?;
            at_head(d, *base)?;
            if fields.is_empty() {
                return Err(CreatorRefusal::NothingToSave);
            }
            if fields.iter().any(|f| f.provenance != Provenance::Manual) {
                return Err(CreatorRefusal::ProvenanceNotManual);
            }
            let edits: Vec<Edit<'_>> = fields
                .iter()
                .map(|f| Edit {
                    field: f.field,
                    value: &f.value,
                    digest: f.digest,
                    provenance: f.provenance.clone(),
                })
                .collect();
            save(core, d, *programme, *base, actor, ctx, &edits)
        }
        CreatorCommand::AcceptNarrative {
            programme,
            base,
            field,
        } => {
            manager(core, *programme, actor, ctx.now)?;
            let d = open_draft(creator, *programme)?;
            at_head(d, *base)?;
            accept_narrative(d, *field)?;
            records(vec![CreatorRecord::NarrativeAccepted {
                programme: *programme,
                revision: *base,
                field: *field,
                by: actor,
            }])
        }
        CreatorCommand::Invite {
            programme,
            invitation,
            role,
            invitee,
            organisation,
        } => {
            manager_or_admin(core, *programme, actor, ctx, ext)?;
            open_draft(creator, *programme)?;
            if creator.invitation_taken(*invitation) {
                return Err(CreatorRefusal::InvitationExists);
            }
            // A signatory role is tenant-wide (NOTE 5), so a programme
            // invitation never names it.
            if role.group() == Group::Receiving
                || *role == Role::TenantAdmin
                || role.tenant_wide_signatory()
            {
                return Err(CreatorRefusal::RoleNotInvitable);
            }
            records(vec![CreatorRecord::InvitationRecorded {
                programme: *programme,
                invitation: *invitation,
                role: *role,
                invitee: *invitee,
                organisation: *organisation,
                by: actor,
            }])
        }
        CreatorCommand::WithdrawInvitation {
            programme,
            invitation,
        } => {
            manager_or_admin(core, *programme, actor, ctx, ext)?;
            let d = open_draft(creator, *programme)?;
            if !d
                .invitations()
                .get(invitation)
                .is_some_and(|i| !i.withdrawn)
            {
                return Err(CreatorRefusal::UnknownInvitation);
            }
            records(vec![CreatorRecord::InvitationWithdrawn {
                programme: *programme,
                invitation: *invitation,
                by: actor,
            }])
        }
        CreatorCommand::AcknowledgeWarning {
            programme,
            revision,
            warning,
        } => {
            manager_or_admin(core, *programme, actor, ctx, ext)?;
            let d = open_draft(creator, *programme)?;
            let head = at_head(d, *revision)?;
            let facts = facts.read(core, creator, *programme, ext.profile.as_ref());
            let report = validate_at(core, creator, *programme, &facts, ext);
            if warning.check.severity() != Severity::Warning || !report.shows_warning(warning) {
                return Err(CreatorRefusal::NotAWarning);
            }
            records(vec![CreatorRecord::WarningAcknowledged {
                programme: *programme,
                revision: head,
                warning: warning.clone(),
                by: actor,
            }])
        }
        CreatorCommand::RequestActivation {
            programme,
            revision,
        } => {
            manager_or_admin(core, *programme, actor, ctx, ext)?;
            let d = open_draft(creator, *programme)?;
            let head = at_head(d, *revision)?;
            let facts = facts.read(core, creator, *programme, ext.profile.as_ref());
            let report = validate_at(core, creator, *programme, &facts, ext);
            records(vec![CreatorRecord::ActivationRequested {
                programme: *programme,
                revision: head,
                report: report.digest(),
                by: actor,
            }])
        }
        CreatorCommand::ApproveActivation {
            programme,
            revision,
            decision,
        } => {
            approver_checks(creator, *programme, *revision, ctx, ext)?;
            // Fresh probes: the report reads the probe results of this
            // request, which the entry records (design 3.2).
            let facts = facts.read(core, creator, *programme, ext.profile.as_ref());
            let report = validate_at(core, creator, *programme, &facts, ext);
            let acks = AckSet::live(creator, *programme);
            let cleaned = clean(&report, &acks).map_err(CreatorRefusal::Uncleared)?;
            let clearance =
                clear_activation(core, creator, *programme, cleaned, ctx, ext, *decision)?;
            let mut out: Vec<CreatorRecord> = ProbeKind::ALL
                .into_iter()
                .map(|probe| CreatorRecord::ProbeRecorded {
                    programme: *programme,
                    probe,
                    outcome: ext.probes.get(probe),
                    at: ctx.now,
                })
                .collect();
            out.push(CreatorRecord::ActivationApproved(ActivationApproved::new(
                &clearance,
            )));
            records(out)
        }
        CreatorCommand::SaveAsTenantTemplate {
            programme,
            template,
        } => {
            // Interim, pending Daniel (Q17): an active programme can be
            // saved as a template too, and the fold admits its record
            // after activation. Its saver joins the builder set only
            // before activation.
            manager_or_admin(core, *programme, actor, ctx, ext)?;
            let d = creator
                .draft(*programme)
                .ok_or(CreatorRefusal::UnknownDraft)?;
            // A shipped template keeps its id, so a tenant-private one
            // cannot take it.
            if creator.template_taken(*template) || draft::is_shipped(*template) {
                return Err(CreatorRefusal::TemplateExists);
            }
            records(vec![CreatorRecord::TemplateSaved {
                template: *template,
                programme: *programme,
                spec: draft::spec_ref(*programme, d.head()),
                by: actor,
            }])
        }
    }
}

/// Decides the save of one import resolution (I-65, design 3.3). Only the
/// engine bridge calls it, inside `resolve_import`, after its own checks.
///
/// A client save goes through [`CreatorCommand::SaveFields`], which
/// admits only [`Provenance::Manual`]. This entry is the one path for
/// [`Provenance::Import`]. The API layer cannot reach it: it is not a
/// [`CreatorCommand`], and no codec decodes an [`ImportFieldEdit`]. One
/// call saves one value, since M4 has no bulk accept (Q30).
///
/// It applies the guards of a save: the actor holds an active programme
/// manager binding on the draft, the draft is open and `base` is the head.
/// The resolver becomes a builder through the `FieldsSaved` record and
/// through [`CreatorState::observe_import_resolution`].
///
/// The value then takes the path of a client save: one `FieldsSaved`
/// with [`ImportFieldEdit::provenance`], and one core `EditPolicy` when
/// the field is a policy field. After the entry is appended, the engine
/// holds the value with [`CreatorState::hold_import`].
pub fn decide_import_save(
    core: &State,
    creator: &CreatorState,
    programme: ProgrammeId,
    base: DraftRevision,
    edit: &ImportFieldEdit,
    ctx: &Ctx,
) -> Result<CreatorDecision, CreatorRefusal> {
    let actor = account(ctx)?;
    manager(core, programme, actor, ctx.now)?;
    let d = open_draft(creator, programme)?;
    at_head(d, base)?;
    let edits = [Edit {
        field: edit.field,
        value: &edit.value,
        digest: edit.digest,
        provenance: edit.provenance(),
    }];
    save(core, d, programme, base, actor, ctx, &edits)
}

/// One field edit of a save, from a client or from the import bridge.
struct Edit<'a> {
    field: FieldId,
    value: &'a FieldValue,
    digest: ValueDigest,
    provenance: Provenance,
}

/// Decides a save of `edits` on the draft `d` of `programme` at `base`
/// by `actor` (design 3.2, "How a save becomes policy").
///
/// The save records one `FieldsSaved` with each digest and provenance.
/// When it touches a policy field, it composes exactly one core
/// `EditPolicy` on the head: the head policy with the saved policy values,
/// compiled as the next version. The core decides it with the same actor,
/// so `validate` (I-50 and the M2 checks), authorship and I-23 apply
/// unchanged. An artefact-only save composes no core command.
///
/// Each edit must carry a value of its own field. A value that does not
/// compile under the draft's profile, or P-09 wording that is still inline
/// (ADR-007), is refused as an invalid save.
fn save(
    core: &State,
    d: &Draft,
    programme: ProgrammeId,
    base: DraftRevision,
    actor: AccountId,
    ctx: &Ctx,
    edits: &[Edit<'_>],
) -> Result<CreatorDecision, CreatorRefusal> {
    if edits.is_empty() || edits.iter().any(|e| e.value.field() != e.field) {
        return Err(CreatorRefusal::NothingToSave);
    }
    let policy_values: Vec<&FieldValue> = edits
        .iter()
        .filter(|e| draft::kind(e.field) == Some(FieldKind::Policy))
        .map(|e| e.value)
        .collect();
    let mut composed = Vec::new();
    if !policy_values.is_empty() {
        let head =
            fstp_domain::policy::head(core, programme).ok_or(CreatorRefusal::UnknownDraft)?;
        let profile = draft::profile_of(d)?;
        let version = draft::fresh_version(core, ctx)?;
        let policy = draft::edited_policy(head, &profile, &policy_values, version)?;
        cap_within_ceiling(&policy)?;
        composed.push(Command::EditPolicy {
            base: head.id,
            version: Box::new(policy),
        });
    }
    Ok(CreatorDecision {
        records: vec![CreatorRecord::FieldsSaved {
            programme,
            revision: base,
            fields: edits
                .iter()
                .map(|e| (e.field, e.digest, e.provenance.clone()))
                .collect(),
            by: actor,
        }],
        core: composed,
    })
}

/// I-50 at save (Daniel's answer of 2026-10-31, M4 design section 15.0):
/// refuses a policy whose P-05 is above its P-58, naming both values
/// (R-PG-01 AC). Amounts of different currencies are refused too, as
/// `fstp_domain::policy::validate` refuses them. The core `EditPolicy`
/// checks I-50 again, and the report's `CapAboveCeiling` row stays a
/// second line of defence.
fn cap_within_ceiling(policy: &fstp_domain::policy::PolicyVersion) -> Result<(), CreatorRefusal> {
    let Some(p58) = policy.live.p58 else {
        return Ok(());
    };
    let p05 = policy.live.p05;
    match p05.amount().cmp_same(p58.amount()) {
        Ok(std::cmp::Ordering::Greater) | Err(_) => {
            Err(CreatorRefusal::CapAboveCeiling { p05, p58 })
        }
        Ok(_) => Ok(()),
    }
}

/// Checks that `field` holds template narrative the programme manager can
/// accept: the latest start is a shipped template whose value of `field`
/// waits for acceptance, and no save or acceptance of the field followed.
///
/// Only artefact narrative can be accepted. P-09 wording from a template
/// is inline text, which no ledger body may hold (ADR-007), so the
/// programme manager saves it as stored text instead. Interim, pending
/// Daniel.
fn accept_narrative(d: &Draft, field: FieldId) -> Result<(), CreatorRefusal> {
    match draft::pending_narrative(d, field) {
        Some(_) => Ok(()),
        None => Err(CreatorRefusal::NothingToSave),
    }
}

/// The checks an approval of `programme` at `revision` needs before its
/// report, in this order: the actor is a tenant admin outside the builder
/// set, the draft is open, the revision is the head, the actor is
/// verified and shares no verified identity with a builder, and a request
/// is live. The actor comes before the draft's state, so a denied actor
/// is denied in every state (`07-test-plan/test-plan.md`, authorisation
/// matrix row). Returns the approver and the builder set.
///
/// Interim, pending Daniel: the approver rule is the Q1 reading (a tenant
/// admin outside the builder set), the vault rule is the Q2 reading, and
/// the live request is reading R6.
pub(crate) fn approver_checks(
    creator: &CreatorState,
    programme: ProgrammeId,
    revision: DraftRevision,
    ctx: &Ctx,
    ext: &CreatorInputs,
) -> Result<(AccountId, BTreeSet<AccountId>), CreatorRefusal> {
    let actor = account(ctx)?;
    if !is_admin(actor, ctx, ext) {
        return Err(CreatorRefusal::NotTenantAdmin);
    }
    let d = creator
        .draft(programme)
        .ok_or(CreatorRefusal::UnknownDraft)?;
    if d.builders().contains(&actor) {
        return Err(CreatorRefusal::ApproverIsBuilder);
    }
    open_draft(creator, programme)?;
    at_head(d, revision)?;
    match ext.vault.is_verified.get(&actor) {
        Some(true) => {}
        Some(false) => return Err(CreatorRefusal::ApproverUnverified),
        None => return Err(CreatorRefusal::VaultAnswerMissing),
    }
    match ext.vault.same_identity.get(&actor) {
        Some(false) => {}
        Some(true) => return Err(CreatorRefusal::SameIdentity),
        None => return Err(CreatorRefusal::VaultAnswerMissing),
    }
    if !d.request_live() {
        return Err(CreatorRefusal::NoLiveRequest);
    }
    Ok((actor, d.builders().clone()))
}

fn account(ctx: &Ctx) -> Result<AccountId, CreatorRefusal> {
    match ctx.actor {
        Actor::Account(a) => Ok(a),
        Actor::System(_) => Err(CreatorRefusal::NotAnAccount),
    }
}

fn open_draft(creator: &CreatorState, programme: ProgrammeId) -> Result<&Draft, CreatorRefusal> {
    let d = creator
        .draft(programme)
        .ok_or(CreatorRefusal::UnknownDraft)?;
    if d.active().is_some() {
        return Err(CreatorRefusal::AlreadyActive);
    }
    Ok(d)
}

fn at_head(d: &Draft, base: DraftRevision) -> Result<DraftRevision, CreatorRefusal> {
    if base == d.head() {
        Ok(base)
    } else {
        Err(CreatorRefusal::StaleRevision)
    }
}

/// Whether the shell attests the actor as a tenant admin and the admin
/// set holds it. Interim, pending Daniel (Q1 and Q31): both must hold.
fn is_admin(actor: AccountId, ctx: &Ctx, ext: &CreatorInputs) -> bool {
    ctx.tenant_admin && ext.tenant_admins.contains(&actor)
}

/// Whether `account` holds an active programme manager binding on
/// `programme` at `now`.
pub(crate) fn holds_manager(
    core: &State,
    programme: ProgrammeId,
    account: AccountId,
    now: Timestamp,
) -> bool {
    core.roster().bindings().any(|(_, b)| {
        b.account == account
            && b.programme == programme
            && b.role == Role::ProgrammeManager
            && b.active_at(now)
    })
}

/// Every draft command checks its actor with this or
/// [`manager_or_admin`] before the draft's state and revision, so a
/// denied actor is denied in every state (`07-test-plan/test-plan.md`,
/// authorisation matrix row).
fn manager(
    core: &State,
    programme: ProgrammeId,
    actor: AccountId,
    now: Timestamp,
) -> Result<(), CreatorRefusal> {
    if holds_manager(core, programme, actor, now) {
        Ok(())
    } else {
        Err(CreatorRefusal::NotProgrammeManager)
    }
}

/// A programme manager on the draft or a tenant admin. Interim, pending
/// Daniel: readings R5 and R6 let either acknowledge a warning and
/// request activation. J1 needs a tenant admin to invite the first
/// programme manager, so either may invite and withdraw.
fn manager_or_admin(
    core: &State,
    programme: ProgrammeId,
    actor: AccountId,
    ctx: &Ctx,
    ext: &CreatorInputs,
) -> Result<(), CreatorRefusal> {
    if is_admin(actor, ctx, ext) || holds_manager(core, programme, actor, ctx.now) {
        Ok(())
    } else {
        Err(CreatorRefusal::NotProgrammeManager)
    }
}

/// The check an uncleared approval names, for callers that map refusals.
impl CreatorRefusal {
    /// The check of an I-66 refusal, if it is one.
    pub fn check(&self) -> Option<CheckId> {
        match self {
            CreatorRefusal::Uncleared(Uncleared::Failure(c) | Uncleared::Unacknowledged(c)) => {
                Some(*c)
            }
            _ => None,
        }
    }
}
