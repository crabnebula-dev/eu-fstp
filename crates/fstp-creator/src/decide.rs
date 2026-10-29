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

use crate::check::{CheckId, Severity};
use crate::inputs::CreatorInputs;
use crate::model::{CreatorCommand, CreatorRecord, DraftRevision, ImportFieldEdit, Provenance};
use crate::probe::ProbeKind;
use crate::state::{CreatorState, Draft};
use crate::validate::{DraftFacts, draft_facts, validate_at};
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
    /// A save named no field.
    NothingToSave,
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
            CreatorRefusal::Unavailable(what) => write!(f, "{what} is not implemented yet"),
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::error::Error for CreatorRefusal {}

/// Opening needs the profile-default policy, compiled from the funder
/// profile.
const OPEN_SEAM: &str = "OpenDraft: the profile-default policy from fstp_programme::compile over the funder profile (design 3.1; lanes W1a and W2c)";

/// Saves and starts compile the draft spec into a core `EditPolicy`.
const COMPILE_SEAM: &str = "the draft spec, the field table and fstp_programme::compile with its core EditPolicy (design 3.1 and 3.2; lane W1a)";

/// A template holds the draft spec and its digest.
const TEMPLATE_SEAM: &str = "SaveAsTenantTemplate: the draft spec and its digest from fstp_programme (design 3.1; lane W1a)";

/// Decides one creator command (design section 3.2).
pub fn decide_creator(
    core: &State,
    creator: &CreatorState,
    cmd: &CreatorCommand,
    ctx: &Ctx,
    ext: &CreatorInputs,
) -> Result<CreatorDecision, CreatorRefusal> {
    let facts = draft_facts(core, creator, cmd.programme(), ext.profile.as_ref());
    decide_with(core, creator, cmd, ctx, ext, &facts)
}

/// The decision over explicit draft facts. Crate-private, so no caller
/// outside the crate can feed made-up facts into an approval.
pub(crate) fn decide_with(
    core: &State,
    creator: &CreatorState,
    cmd: &CreatorCommand,
    ctx: &Ctx,
    ext: &CreatorInputs,
    facts: &DraftFacts,
) -> Result<CreatorDecision, CreatorRefusal> {
    let actor = account(ctx)?;
    let records = |records: Vec<CreatorRecord>| {
        Ok(CreatorDecision {
            records,
            core: Vec::new(),
        })
    };
    match cmd {
        CreatorCommand::OpenDraft { programme, .. } => {
            if !is_admin(actor, ctx, ext) {
                return Err(CreatorRefusal::NotTenantAdmin);
            }
            if creator.draft(*programme).is_some() || core.policy().programme(*programme).is_some()
            {
                return Err(CreatorRefusal::DraftExists);
            }
            Err(CreatorRefusal::Unavailable(OPEN_SEAM))
        }
        CreatorCommand::ApplyStart {
            programme,
            base,
            start,
        } => {
            let d = open_draft(creator, *programme)?;
            at_head(d, *base)?;
            manager(core, *programme, actor, ctx.now)?;
            if let crate::model::StartingPoint::Clone { source } = start
                && core.policy().programme(*source).is_none()
            {
                return Err(CreatorRefusal::UnknownSource);
            }
            Err(CreatorRefusal::Unavailable(COMPILE_SEAM))
        }
        CreatorCommand::SaveFields {
            programme,
            base,
            fields,
        } => {
            let d = open_draft(creator, *programme)?;
            at_head(d, *base)?;
            manager(core, *programme, actor, ctx.now)?;
            if fields.is_empty() {
                return Err(CreatorRefusal::NothingToSave);
            }
            if fields.iter().any(|f| f.provenance != Provenance::Manual) {
                return Err(CreatorRefusal::ProvenanceNotManual);
            }
            Err(CreatorRefusal::Unavailable(COMPILE_SEAM))
        }
        CreatorCommand::AcceptNarrative {
            programme, base, ..
        } => {
            let d = open_draft(creator, *programme)?;
            at_head(d, *base)?;
            manager(core, *programme, actor, ctx.now)?;
            Err(CreatorRefusal::Unavailable(COMPILE_SEAM))
        }
        CreatorCommand::Invite {
            programme,
            invitation,
            role,
            invitee,
            organisation,
        } => {
            open_draft(creator, *programme)?;
            manager_or_admin(core, *programme, actor, ctx, ext)?;
            if creator.invitation_taken(*invitation) {
                return Err(CreatorRefusal::InvitationExists);
            }
            if role.group() == Group::Receiving || *role == Role::TenantAdmin {
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
            let d = open_draft(creator, *programme)?;
            manager_or_admin(core, *programme, actor, ctx, ext)?;
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
            let d = open_draft(creator, *programme)?;
            let head = at_head(d, *revision)?;
            manager_or_admin(core, *programme, actor, ctx, ext)?;
            let report = validate_at(core, creator, *programme, facts, ext);
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
            let d = open_draft(creator, *programme)?;
            let head = at_head(d, *revision)?;
            manager_or_admin(core, *programme, actor, ctx, ext)?;
            let report = validate_at(core, creator, *programme, facts, ext);
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
            let report = validate_at(core, creator, *programme, facts, ext);
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
            if creator.draft(*programme).is_none() {
                return Err(CreatorRefusal::UnknownDraft);
            }
            manager_or_admin(core, *programme, actor, ctx, ext)?;
            if creator.template_taken(*template) {
                return Err(CreatorRefusal::TemplateExists);
            }
            Err(CreatorRefusal::Unavailable(TEMPLATE_SEAM))
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
/// It applies the guards of a save: the draft is open, `base` is the head
/// and the actor holds an active programme manager binding on the draft.
/// The resolver becomes a builder through the `FieldsSaved` record and
/// through [`CreatorState::observe_import_resolution`].
pub fn decide_import_save(
    core: &State,
    creator: &CreatorState,
    programme: ProgrammeId,
    base: DraftRevision,
    edit: &ImportFieldEdit,
    ctx: &Ctx,
) -> Result<CreatorDecision, CreatorRefusal> {
    let actor = account(ctx)?;
    let d = open_draft(creator, programme)?;
    at_head(d, base)?;
    manager(core, programme, actor, ctx.now)?;
    // The edit compiles into the draft spec once lane W1a lands, as a
    // client save does. Until then the save refuses with the seam.
    let _ = edit;
    Err(CreatorRefusal::Unavailable(COMPILE_SEAM))
}

/// The checks an approval of `programme` at `revision` needs before its
/// report, in this order: the draft is open, the revision is the head, the
/// actor is a tenant admin, outside the builder set, verified, sharing no
/// verified identity with a builder, and a request is live. Returns the
/// approver and the builder set.
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
    let d = open_draft(creator, programme)?;
    at_head(d, revision)?;
    if !is_admin(actor, ctx, ext) {
        return Err(CreatorRefusal::NotTenantAdmin);
    }
    if d.builders().contains(&actor) {
        return Err(CreatorRefusal::ApproverIsBuilder);
    }
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
