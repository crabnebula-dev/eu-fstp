//! The engine compositions of the creator, activation and publication
//! (I-51, I-52, I-66, I-67, M4 design sections 3.2 and 3.4, change D2e).
//!
//! # The creator path
//!
//! `Command::Creator` carries one `fstp_creator::CreatorCommand`, the
//! command a person issued and a step-up names. The facts the shell
//! supplies beside it come from a [`CreatorEnvironment`].
//! [`creator_queries`] lists the vault questions of the command, and
//! [`decide_creator_command`] decides it in one entry:
//!
//! 1. The environment gives the shell's [`CreatorInputs`]: the probes it
//!    ran in the same request, the SoD previews, the Q35 vault answers,
//!    the attested tenant admin set, the ports present, the theme and the
//!    profile. The engine then replaces the inputs it owns: the count of
//!    unresolved import proposals, read from the import store (Q30), and
//!    the `IsVerified` and `SameIdentityAsAny` answers, read from the vault
//!    answers the driver obtained. The environment's values for these are
//!    never read.
//! 2. `fstp_creator::decide_creator` returns the creator records and the
//!    core commands of the same entry.
//! 3. Each core command is decided by `fstp_domain::decide` with the same
//!    actor and context, on the core state after the earlier ones.
//! 4. An `ActivationApproved` record composes the core `ActivateProgramme`
//!    through [`activate_command`], the only place that builds it (D2e).
//!    The entry then holds the probe results, the approval, the vault
//!    outcomes of the approval, and the core activation records.
//!
//! The engine fold refuses an entry with a `ProgrammeActivated` of
//! any programme without its `ActivationApproved`, and the reverse
//! (crate root, `apply_in`).
//!
//! # Readings, interim, pending Daniel
//!
//! - The SoD previews are the shell's input. The shell runs
//!   `fstp_domain::roles::preview_grant` over
//!   `fstp_creator::preview_targets` and records every vault answer in
//!   the audit log (`overview.md` NOTE 5, lane W3b). A preview is
//!   advisory: the grant checks the SoD guards again (enforcement point
//!   1). A missing outcome fails closed as `InviteeRefused`.
//! - The creator's vault questions are asked for the commands that read
//!   the validation report: acknowledging a warning, requesting
//!   activation and approving it. The `IsVerified` answers of an approval
//!   are recorded as core `VaultOutcome` records in its entry.
//! - The core `ActivateProgramme` names the creator's report through
//!   [`report_ref`]: the programme, the revision and the row count, as
//!   bytes. The crates on this path compute no hash, so it is a
//!   reference, not a digest. The fold pairs it with the approval of the
//!   same entry.
//! - The core questions of the composed commands are asked with the
//!   creator questions. They are predicted from the creator decision
//!   without vault answers, which the composing commands never read
//!   (opening a draft and saving fields), and for an approval from the
//!   approver and the draft's builders. A composed command whose questions
//!   were not asked is refused with `FactsIncomplete`, so a wrong
//!   prediction fails closed.
//! - [`NoEnvironment`] is the environment of `DomainDecider`. It supplies
//!   no shell fact, so every creator command that needs one fails closed.
//!   A shell passes its own through `CreatorDecider`.
//!
//! # Publication
//!
//! [`publication`] fails closed. The `GuidePublished` record comes from
//! the Guide renderer of lane W2c, which is not built, so no publication
//! is composed here yet.

use std::collections::{BTreeMap, BTreeSet};

use fstp_creator::{
    ActivationApproved, CreatorCommand, CreatorDecision, CreatorInputs, CreatorRecord,
    CreatorRefusal, DraftRevision, PortPresence, ProbeSet, SodPreview, Theme, VaultChecks,
    vault_questions,
};
use fstp_domain::command::{Actor, Ctx};
use fstp_domain::id::{AccountId, CallId, ProgrammeId};
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::policy::activation::ReportDigest;
use fstp_domain::programme::CallStatus;
use fstp_domain::refusal::{Refusal, RefusalDetail, RefusalReason, RuleRef};
use fstp_domain::state::State;
use fstp_domain::{Record as CoreRecord, Via};
use fstp_ledger::Seq;

use crate::{Command, EngineState, Record};

/// The facts the shell supplies for one creator decision, beyond the
/// command (design 3.2, `CreatorInputs`).
pub trait CreatorEnvironment {
    /// The shell's inputs for `cmd` in `state`. The engine replaces the
    /// parts it owns (module documentation).
    fn creator_inputs(&self, state: &EngineState, cmd: &CreatorCommand, ctx: &Ctx)
    -> CreatorInputs;
}

impl<E: CreatorEnvironment + ?Sized> CreatorEnvironment for &E {
    fn creator_inputs(
        &self,
        state: &EngineState,
        cmd: &CreatorCommand,
        ctx: &Ctx,
    ) -> CreatorInputs {
        (**self).creator_inputs(state, cmd, ctx)
    }
}

/// No shell facts: every probe absent, no SoD preview, no Q35 answer, no
/// attested tenant admin, no port, the M4 default theme and no profile.
/// Every check that needs a shell fact fails closed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoEnvironment;

impl CreatorEnvironment for NoEnvironment {
    fn creator_inputs(
        &self,
        _state: &EngineState,
        _cmd: &CreatorCommand,
        _ctx: &Ctx,
    ) -> CreatorInputs {
        CreatorInputs {
            unresolved_imports: 0,
            probes: ProbeSet::absent(),
            sod: SodPreview::default(),
            vault: VaultChecks::default(),
            tenant_admins: BTreeSet::new(),
            ports: PortPresence::default(),
            theme: Theme::m4_default(),
            profile: None,
        }
    }
}

/// The position of a creator command's kind, for hashing an engine
/// command.
pub(crate) fn creator_kind(cmd: &CreatorCommand) -> u8 {
    match cmd {
        CreatorCommand::OpenDraft { .. } => 0,
        CreatorCommand::ApplyStart { .. } => 1,
        CreatorCommand::SaveFields { .. } => 2,
        CreatorCommand::AcceptNarrative { .. } => 3,
        CreatorCommand::Invite { .. } => 4,
        CreatorCommand::WithdrawInvitation { .. } => 5,
        CreatorCommand::AcknowledgeWarning { .. } => 6,
        CreatorCommand::RequestActivation { .. } => 7,
        CreatorCommand::ApproveActivation { .. } => 8,
        CreatorCommand::SaveAsTenantTemplate { .. } => 9,
    }
}

/// Why a creator command failed, with the creator's own reason where it
/// has one. [`Refusal`] is the engine's form of it, through
/// [`CreatorFailure::refusal`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CreatorFailure {
    /// The creator refused the command.
    Creator(CreatorRefusal),
    /// The core refused a composed command, or the engine refused the
    /// command before the creator read it.
    Core(Refusal),
}

impl CreatorFailure {
    /// The engine refusal of this failure. A creator refusal maps to the
    /// rule it serves. I-66 refusals name `RuleRef::I66`, and I-67
    /// refusals `RuleRef::I67`.
    pub fn refusal(self) -> Refusal {
        match self {
            CreatorFailure::Core(r) => r,
            CreatorFailure::Creator(c) => creator_refusal(c),
        }
    }
}

/// The engine refusal of a creator refusal.
pub fn creator_refusal(c: CreatorRefusal) -> Refusal {
    use CreatorRefusal as C;
    use RefusalReason as Why;
    let (rule, why) = match c {
        C::UnknownDraft | C::UnknownSource | C::UnknownInvitation => {
            (RuleRef::Input, Why::UnknownEntity)
        }
        C::DraftExists | C::InvitationExists | C::TemplateExists => {
            (RuleRef::Ledger, Why::IdReused)
        }
        C::AlreadyActive | C::NoLiveRequest => (RuleRef::I66, Why::WrongState),
        C::StaleRevision => (RuleRef::Input, Why::WrongState),
        C::NotAnAccount | C::NotTenantAdmin => (RuleRef::Actor, Why::WrongActor),
        C::NotProgrammeManager => (RuleRef::Actor, Why::BindingInactive),
        C::NothingToSave | C::RoleNotInvitable => (RuleRef::Input, Why::InvalidValue),
        C::CapAboveCeiling { .. } => (RuleRef::I50, Why::InvalidValue),
        C::ProvenanceNotManual => (RuleRef::I65, Why::InvalidValue),
        C::NotAWarning => (RuleRef::I66, Why::InvalidValue),
        C::Uncleared(_) => (RuleRef::I66, Why::GuardFailed),
        C::ApproverIsBuilder => (RuleRef::I67, Why::GuardFailed),
        C::ApproverUnverified | C::SameIdentity | C::BuilderUnverified => {
            (RuleRef::I67, Why::VaultRefused)
        }
        C::VaultAnswerMissing => (RuleRef::FactsIncomplete, Why::AnswerMissing),
        C::Unavailable(_) => (RuleRef::NotImplemented, Why::NotImplemented),
    };
    let refusal = Refusal::new(rule, why);
    match c {
        // I-50 at save names both values (Daniel's answer of 2026-10-31,
        // M4 design section 15.0), so every caller of the engine, the API
        // included, can show them.
        C::CapAboveCeiling { p05, p58 } => {
            refusal.naming(RefusalDetail::CapAboveCeiling { p05, p58 })
        }
        _ => refusal,
    }
}

/// Whether the creator command reads the validation report, and so the
/// vault answers of its builders.
fn reads_report(cmd: &CreatorCommand) -> bool {
    matches!(
        cmd,
        CreatorCommand::AcknowledgeWarning { .. }
            | CreatorCommand::RequestActivation { .. }
            | CreatorCommand::ApproveActivation { .. }
    )
}

/// The account of the actor, if any.
fn actor_account(ctx: &Ctx) -> Option<AccountId> {
    match ctx.actor {
        Actor::Account(a) => Some(a),
        Actor::System(_) => None,
    }
}

/// The approver an approval names: the actor of an `ApproveActivation`.
fn approver(cmd: &CreatorCommand, ctx: &Ctx) -> Option<AccountId> {
    match cmd {
        CreatorCommand::ApproveActivation { .. } => actor_account(ctx),
        _ => None,
    }
}

/// The creator's own vault questions of `cmd`.
fn creator_questions(state: &EngineState, cmd: &CreatorCommand, ctx: &Ctx) -> Vec<Query> {
    if !reads_report(cmd) {
        return Vec::new();
    }
    let q = vault_questions(&state.creator, cmd.programme(), approver(cmd, ctx));
    let mut out: Vec<Query> = q
        .is_verified
        .iter()
        .map(|a| Query::IsVerified { account: *a })
        .collect();
    if let Some((subject, others)) = q.same_identity {
        out.push(Query::SameIdentityAsAny { subject, others });
    }
    out
}

/// The refusal of a high-risk creator command that arrives through MCP
/// (I-85). The composed core commands are refused by the core too.
fn mcp_guard(cmd: &CreatorCommand, ctx: &Ctx) -> Result<(), Refusal> {
    if ctx.via == Via::Mcp && cmd.high_risk() {
        return Err(Refusal::new(RuleRef::I85, RefusalReason::NotThroughMcp));
    }
    Ok(())
}

/// The inputs the creator reads: the environment's, with the engine's own
/// facts in place of the parts the engine owns.
fn engine_inputs(
    state: &EngineState,
    cmd: &CreatorCommand,
    ctx: &Ctx,
    answers: &Answers,
    env: &dyn CreatorEnvironment,
) -> CreatorInputs {
    let programme = cmd.programme();
    let mut inputs = env.creator_inputs(state, cmd, ctx);
    inputs.unresolved_imports = state
        .import
        .unresolved(fstp_import::ProgrammeRef::from_raw(programme.raw()));
    let mut is_verified = BTreeMap::new();
    let mut same_identity = BTreeMap::new();
    if reads_report(cmd) {
        let q = vault_questions(&state.creator, programme, approver(cmd, ctx));
        for a in &q.is_verified {
            if let Some(ans) = answers.get(&Query::IsVerified { account: *a }) {
                is_verified.insert(*a, ans.holds);
            }
        }
        if let Some((subject, others)) = q.same_identity {
            let query = Query::SameIdentityAsAny { subject, others };
            if let Some(ans) = answers.get(&query) {
                same_identity.insert(subject, ans.holds);
            }
        }
    }
    inputs.vault.is_verified = is_verified;
    inputs.vault.same_identity = same_identity;
    inputs
}

/// The vault questions of `cmd` (module documentation): the creator's
/// own, then the predicted questions of the composed core commands.
pub fn creator_queries(
    state: &EngineState,
    cmd: &CreatorCommand,
    ctx: &Ctx,
    env: &dyn CreatorEnvironment,
) -> Result<Vec<Query>, Refusal> {
    mcp_guard(cmd, ctx)?;
    let mut out = creator_questions(state, cmd, ctx);
    for c in predicted_core(state, cmd, ctx, env) {
        // A core refusal here is left to the decision, which gives the
        // creator's reason first.
        let asked = if cmd_is_approval(cmd) {
            fstp_domain::queries(&state.core, &c, ctx)
        } else {
            fstp_domain::queries_creator_save(&state.core, &c, ctx)
        };
        if let Ok(qs) = asked {
            for q in qs {
                if !out.contains(&q) {
                    out.push(q);
                }
            }
        }
    }
    Ok(out)
}

/// The core commands `cmd` composes, predicted before the vault answers.
fn predicted_core(
    state: &EngineState,
    cmd: &CreatorCommand,
    ctx: &Ctx,
    env: &dyn CreatorEnvironment,
) -> Vec<fstp_domain::Command> {
    match cmd {
        CreatorCommand::ApproveActivation {
            programme,
            revision,
            decision,
        } => {
            let Some(d) = state.creator.draft(*programme) else {
                return Vec::new();
            };
            if actor_account(ctx).is_none() {
                return Vec::new();
            }
            vec![fstp_domain::Command::ActivateProgramme {
                programme: *programme,
                decision: *decision,
                report: ReportDigest::from_bytes([0; 32]),
                revision: revision.seq(),
                creator_builders: d.builders().clone(),
            }]
        }
        c if reads_report(c) => Vec::new(),
        _ => {
            let inputs = engine_inputs(state, cmd, ctx, &Answers::new(), env);
            match fstp_creator::decide_creator(&state.core, &state.creator, cmd, ctx, &inputs) {
                Ok(d) => d.core,
                Err(_) => Vec::new(),
            }
        }
    }
}

/// The reference the core `ActivateProgramme` keeps for the creator's
/// report (module documentation): the programme id, the revision count,
/// the revision's ledger entry and the row count, big-endian.
pub fn report_ref(report: &fstp_creator::ReportDigest) -> ReportDigest {
    let mut b = [0u8; 32];
    let rev: DraftRevision = report.revision();
    let rows = u32::try_from(report.rows().len()).unwrap_or(u32::MAX);
    let parts: [&[u8]; 4] = [
        &report.programme().raw().to_be_bytes(),
        &rev.seq().to_be_bytes(),
        &rev.entry().raw().to_be_bytes(),
        &rows.to_be_bytes(),
    ];
    for (slot, byte) in b.iter_mut().zip(parts.into_iter().flatten()) {
        *slot = *byte;
    }
    ReportDigest::from_bytes(b)
}

/// The core `ActivateProgramme` of an approval (D2e). The approver is the
/// actor of the entry, and the creator's builders are its
/// `creator_builders`, so the core guard checks them again (I-67).
pub fn activate_command(approved: &ActivationApproved) -> fstp_domain::Command {
    fstp_domain::Command::ActivateProgramme {
        programme: approved.programme(),
        decision: approved.decision(),
        report: report_ref(approved.report()),
        revision: approved.revision().seq(),
        creator_builders: approved.builders().clone(),
    }
}

/// Whether the core `ProgrammeActivated` `pa` is the activation of the
/// approval `approved` (D2e): the same programme, decision, revision,
/// report and approver, with the creator's builders among its own.
pub fn pairs_with(
    approved: &ActivationApproved,
    pa: &fstp_domain::record::ProgrammeActivated,
) -> bool {
    pa.programme() == approved.programme()
        && pa.decision() == approved.decision()
        && pa.revision() == approved.revision().seq()
        && pa.report() == report_ref(approved.report())
        && pa.approver() == approved.approver()
        && approved.builders().is_subset(pa.builders())
}

/// Whether the creator command is the approval, whose composed core
/// command is the activation. Every other creator command composes the
/// core commands of a save on the draft.
fn cmd_is_approval(cmd: &CreatorCommand) -> bool {
    matches!(cmd, CreatorCommand::ApproveActivation { .. })
}

/// Decides `cmd` on `core` and folds its records into `core`, as one
/// composed command of the entry. Its questions must be among `answers`.
pub(crate) fn decide_core(
    core: &mut State,
    cmd: &fstp_domain::Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<CoreRecord>, Refusal> {
    decide_composed(core, cmd, ctx, answers, false)
}

/// [`decide_core`] of a core command composed from a creator save on a
/// draft when `save` holds. The domain then counts an `EditPolicy` of a
/// draft programme as drafting under P-77 (Daniel's answer of
/// 2026-10-31, M4 design section 15.0), so an agent may save draft
/// fields through MCP under "draft only".
fn decide_composed(
    core: &mut State,
    cmd: &fstp_domain::Command,
    ctx: &Ctx,
    answers: &Answers,
    save: bool,
) -> Result<Vec<CoreRecord>, Refusal> {
    let asked = if save {
        fstp_domain::queries_creator_save(core, cmd, ctx)?
    } else {
        fstp_domain::queries(core, cmd, ctx)?
    };
    if asked.iter().any(|q| answers.get(q).is_none()) {
        return Err(Refusal::new(
            RuleRef::FactsIncomplete,
            RefusalReason::AnswerMissing,
        ));
    }
    let records = if save {
        fstp_domain::decide_creator_save(core, cmd, ctx, answers)?
    } else {
        fstp_domain::decide(core, cmd, ctx, answers)?
    };
    for r in &records {
        fstp_domain::apply(core, Seq::from_raw(1), ctx.now, r)
            .map_err(|_| Refusal::new(RuleRef::Ledger, RefusalReason::WrongState))?;
    }
    Ok(records)
}

/// Decides a creator command in one entry (module documentation). Nothing
/// is recorded on a failure.
pub fn decide_creator_command(
    state: &EngineState,
    cmd: &CreatorCommand,
    ctx: &Ctx,
    answers: &Answers,
    env: &dyn CreatorEnvironment,
) -> Result<Vec<Record>, CreatorFailure> {
    mcp_guard(cmd, ctx).map_err(CreatorFailure::Core)?;
    let inputs = engine_inputs(state, cmd, ctx, answers, env);
    let CreatorDecision { records, core } =
        fstp_creator::decide_creator(&state.core, &state.creator, cmd, ctx, &inputs)
            .map_err(CreatorFailure::Creator)?;
    let mut scratch = state.core.clone();
    let mut out: Vec<Record> = Vec::new();
    let mut tail: Vec<Record> = Vec::new();
    for r in records {
        if let CreatorRecord::ActivationApproved(a) = &r {
            for (q, ans) in approval_outcomes(state, cmd, ctx, answers) {
                tail.push(Record::Core(CoreRecord::VaultOutcome {
                    kind: q.kind(),
                    digest: ans.digest,
                    holds: ans.holds,
                    epoch: ans.epoch,
                }));
            }
            let records = decide_core(&mut scratch, &activate_command(a), ctx, answers)
                .map_err(CreatorFailure::Core)?;
            tail.extend(records.into_iter().map(Record::Core));
        }
        out.push(Record::Creator(r));
    }
    for c in &core {
        if matches!(c, fstp_domain::Command::ActivateProgramme { .. }) {
            // Only an approval composes the activation (D2e).
            return Err(CreatorFailure::Core(Refusal::new(
                RuleRef::I66,
                RefusalReason::WrongActor,
            )));
        }
        let records = decide_composed(&mut scratch, c, ctx, answers, !cmd_is_approval(cmd))
            .map_err(CreatorFailure::Core)?;
        out.extend(records.into_iter().map(Record::Core));
    }
    out.extend(tail);
    Ok(out)
}

/// The `IsVerified` answers an approval read, in account order.
fn approval_outcomes(
    state: &EngineState,
    cmd: &CreatorCommand,
    ctx: &Ctx,
    answers: &Answers,
) -> Vec<(Query, fstp_domain::oracle::Answer)> {
    let q = vault_questions(&state.creator, cmd.programme(), approver(cmd, ctx));
    q.is_verified
        .iter()
        .filter_map(|a| {
            let query = Query::IsVerified { account: *a };
            answers.get(&query).map(|ans| (query.clone(), ans.clone()))
        })
        .collect()
}

/// Why a composition failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ComposeError {
    /// Kept for the lanes that code against the W0 stub. Neither
    /// composition of this crate returns it.
    NotImplemented(&'static str),
    /// No programme with this id exists in the core state.
    UnknownProgramme,
    /// The programme has no approved creator decision: no
    /// `ActivationApproved` built from an `ActivationClearance` (I-66,
    /// I-67).
    NoApprovedDecision,
    /// No call with this id exists in the core state.
    UnknownCall,
    /// The call is already published, so a second Guide would follow
    /// (I-52, design section 3.10).
    AlreadyPublished,
    /// The recomputed validation report of the call's programme is not
    /// clean, or no report can be computed (I-51, I-52).
    NoCleanReport,
}

impl core::fmt::Display for ComposeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ComposeError::NotImplemented(op) => write!(f, "{op} is not implemented"),
            ComposeError::UnknownProgramme => f.write_str("unknown programme"),
            ComposeError::NoApprovedDecision => {
                f.write_str("the programme has no approved creator decision")
            }
            ComposeError::UnknownCall => f.write_str("unknown call"),
            ComposeError::AlreadyPublished => f.write_str("the call is already published"),
            ComposeError::NoCleanReport => {
                f.write_str("the programme has no clean validation report")
            }
        }
    }
}

impl std::error::Error for ComposeError {}

/// Composes the activation of a draft programme from a folded approval
/// (I-66, I-67).
///
/// It refuses an unknown programme with
/// [`ComposeError::UnknownProgramme`]. An approval folds only in the entry
/// that activates its programme, so the folded state never holds an
/// approval still to compose. Every other programme is refused with
/// [`ComposeError::NoApprovedDecision`]. The engine composes the
/// activation inside the approval's own entry, through
/// [`decide_creator_command`] and [`activate_command`].
pub fn activation(state: &EngineState, programme: ProgrammeId) -> Result<Command, ComposeError> {
    if state.core.policy().programme(programme).is_none() {
        return Err(ComposeError::UnknownProgramme);
    }
    Err(ComposeError::NoApprovedDecision)
}

/// Composes the publication of a call with its Guide record (I-51, I-52,
/// R-GA-01).
///
/// It refuses an unknown call with [`ComposeError::UnknownCall`] and a
/// published one with [`ComposeError::AlreadyPublished`]. It refuses every
/// other call with [`ComposeError::NoCleanReport`]: the Guide renderer
/// that yields the `GuidePublished` record is a W0 stub (module
/// documentation). Whether the call's publication is approved stays the
/// core `PublishCall` guard's question (R-PC-03).
pub fn publication(state: &EngineState, call: CallId) -> Result<Command, ComposeError> {
    let view = fstp_domain::programme::call(&state.core, call).ok_or(ComposeError::UnknownCall)?;
    if view.status() == CallStatus::Published {
        return Err(ComposeError::AlreadyPublished);
    }
    Err(ComposeError::NoCleanReport)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I-66, D2e: the empty state has no programme to activate.
    #[test]
    fn i66_genesis_activation_names_the_unknown_programme() {
        assert_eq!(
            activation(&EngineState::genesis(), ProgrammeId::from_raw(1)),
            Err(ComposeError::UnknownProgramme)
        );
    }

    /// I-52, D2e: the empty state has no call to publish.
    #[test]
    fn i52_genesis_publication_names_the_unknown_call() {
        assert_eq!(
            publication(&EngineState::genesis(), CallId::from_raw(1)),
            Err(ComposeError::UnknownCall)
        );
    }

    /// I-66: every I-66 and I-67 creator refusal names its rule.
    #[test]
    fn i66_i67_creator_refusals_name_their_rule() {
        use fstp_creator::{CheckId, Uncleared};
        for (c, rule) in [
            (
                CreatorRefusal::Uncleared(Uncleared::Failure(CheckId::FieldUnset)),
                RuleRef::I66,
            ),
            (CreatorRefusal::NoLiveRequest, RuleRef::I66),
            (CreatorRefusal::ApproverIsBuilder, RuleRef::I67),
            (CreatorRefusal::SameIdentity, RuleRef::I67),
            (CreatorRefusal::BuilderUnverified, RuleRef::I67),
            (CreatorRefusal::ApproverUnverified, RuleRef::I67),
            (CreatorRefusal::ProvenanceNotManual, RuleRef::I65),
        ] {
            assert_eq!(creator_refusal(c).rule, rule, "{c:?}");
        }
    }
}
