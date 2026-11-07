//! `decide` and the questions it puts to the shell (design section 3.5).
//!
//! `decide` is pure. The shell first asks [`queries`] what the command
//! needs from outside, answers each question from the vault, the control
//! plane, the domain and the prober, and passes the answers in. A missing
//! answer fails closed (Q5).

use std::collections::BTreeMap;

use fstp_domain::Via;
use fstp_domain::id::AccountId;

use crate::command::{TenantCommand, TenantCtx, TenantRecord};
use crate::refusal::TenantRefusal;
use crate::rules::{ProbeKind, agreements_confirmed, probe_for, setting_valid, values_check};
use crate::state::TenantState;
use crate::types::{AgreementVersions, OnboardingStep, StepFailure, StepOutcome, StepValues};

/// A question `decide` needs answered.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TenantQuery {
    /// Whether the vault reports the account's identity as verified for
    /// the purpose `AdminIdentity` (design 6.1 item 13, Q2).
    AdminVerified(AccountId),
    /// The outcome of one prober check.
    Probe(ProbeKind),
    /// The agreement versions the control plane recorded as accepted by
    /// the tenant (Q22). Interim, pending Daniel.
    Agreements,
    /// Whether the account holds a Receiving binding in any programme of
    /// the tenant. A tenant admin counts as holding Operations in every
    /// programme (`Ctx::binds_tenant_admin`), and SoD-03 bars Operations
    /// with Receiving. Interim, pending Daniel.
    HoldsReceiving(AccountId),
}

/// What a prober check gave.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProbeOutcome {
    /// The check passed.
    Passed,
    /// The check ran and failed.
    Failed,
    /// No prober exists in this cell, as in every M4 production cell.
    Absent,
}

/// The shell's answers to [`queries`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TenantAnswers {
    verified: BTreeMap<AccountId, bool>,
    probes: BTreeMap<ProbeKind, ProbeOutcome>,
    agreements: Option<AgreementVersions>,
    receiving: BTreeMap<AccountId, bool>,
}

impl TenantAnswers {
    /// No answers.
    pub fn new() -> TenantAnswers {
        TenantAnswers::default()
    }

    /// Records whether the vault reports `account` as verified.
    pub fn verified(&mut self, account: AccountId, verified: bool) {
        self.verified.insert(account, verified);
    }

    /// Records the outcome of the prober check `kind`.
    pub fn probe(&mut self, kind: ProbeKind, outcome: ProbeOutcome) {
        self.probes.insert(kind, outcome);
    }

    /// Records the agreement versions the control plane holds as accepted.
    pub fn agreements(&mut self, recorded: AgreementVersions) {
        self.agreements = Some(recorded);
    }

    /// Records whether `account` holds a Receiving binding.
    pub fn holds_receiving(&mut self, account: AccountId, holds: bool) {
        self.receiving.insert(account, holds);
    }

    fn is_verified(&self, account: AccountId) -> bool {
        self.verified.get(&account).copied().unwrap_or(false)
    }

    fn probe_outcome(&self, kind: &ProbeKind) -> ProbeOutcome {
        self.probes
            .get(kind)
            .copied()
            .unwrap_or(ProbeOutcome::Absent)
    }
}

/// The questions `cmd` needs answered in `state`.
pub fn queries(state: &TenantState, cmd: &TenantCommand) -> Vec<TenantQuery> {
    match cmd {
        TenantCommand::SaveStep { values, .. } => {
            let mut out: Vec<TenantQuery> = probe_for(values)
                .map(TenantQuery::Probe)
                .into_iter()
                .collect();
            if values.step() == OnboardingStep::Agreements
                && values.step().required_in(state.cell())
            {
                out.push(TenantQuery::Agreements);
            }
            out
        }
        TenantCommand::AcceptAdminInvitation { invitation, .. } => state
            .invitation(*invitation)
            .map(|i| TenantQuery::HoldsReceiving(i.invitee))
            .into_iter()
            .collect(),
        TenantCommand::Complete | TenantCommand::RequestActivation { .. } => state
            .admins()
            .iter()
            .map(|a| TenantQuery::AdminVerified(*a))
            .collect(),
        // A signatory role is an Operations role in every programme of
        // the tenant, as tenant admin is, so SoD-03 bars a holder of a
        // Receiving binding (interim, pending Daniel).
        TenantCommand::GrantSignatory { account, .. } => {
            vec![TenantQuery::HoldsReceiving(*account)]
        }
        _ => Vec::new(),
    }
}

/// Decides `cmd` in `state`. On acceptance it returns the records to
/// append, in order. It never reads a clock or any state but its
/// arguments.
///
/// - A web-only command through MCP is refused (I-85, I-78). That covers
///   every high-risk command, and the two that complete a grant.
/// - Every command but [`TenantCommand::AcceptAdminInvitation`] needs a
///   tenant admin as actor (Q31).
pub fn decide(
    state: &TenantState,
    ctx: &TenantCtx,
    cmd: &TenantCommand,
    answers: &TenantAnswers,
) -> Result<Vec<TenantRecord>, TenantRefusal> {
    let kind = cmd.kind();
    if ctx.via == Via::Mcp {
        if kind.high_risk() {
            return Err(TenantRefusal::HighRiskViaMcp);
        }
        if kind.web_only() {
            return Err(TenantRefusal::WebOnlyViaMcp);
        }
    }
    let by = ctx.actor;
    if kind.admin_only() && !state.is_admin(by) {
        return Err(TenantRefusal::NotTenantAdmin);
    }
    match cmd {
        TenantCommand::SaveStep { values, base } => {
            if *base != state.revision() {
                return Err(TenantRefusal::StaleRevision);
            }
            let step = values.step();
            state.check_saveable(step)?;
            let outcome = match step_check(state, values, answers) {
                Ok(()) => StepOutcome::Validated,
                Err(f) => StepOutcome::Failed(f),
            };
            let mut out = vec![TenantRecord::StepSaved {
                values: values.clone(),
                by,
                outcome,
            }];
            if outcome == StepOutcome::Validated {
                out.push(TenantRecord::StepValidated { step, by });
            }
            Ok(out)
        }
        TenantCommand::InviteAdmin {
            invitation,
            invitee,
            token_digest,
        } => {
            state.check_invite(*invitation, *invitee)?;
            Ok(vec![TenantRecord::AdminInvited {
                invitation: *invitation,
                invitee: *invitee,
                token_digest: *token_digest,
                by,
            }])
        }
        TenantCommand::AcceptAdminInvitation {
            invitation,
            token_digest,
        } => {
            state.check_accept(*invitation, by, *token_digest)?;
            match answers.receiving.get(&by) {
                Some(false) => {}
                Some(true) => return Err(TenantRefusal::HoldsReceiving),
                None => return Err(TenantRefusal::AnswerMissing),
            }
            Ok(vec![TenantRecord::AdminAdded {
                account: by,
                invitation: *invitation,
            }])
        }
        TenantCommand::ApproveSelfGrant { approval, grant } => {
            state.check_approval(*approval, grant, by)?;
            state.approval_expiry(ctx.at)?;
            Ok(vec![TenantRecord::SelfGrantApproved {
                approval: *approval,
                grant: *grant,
                by,
                at: ctx.at,
            }])
        }
        TenantCommand::UseSelfGrantApproval { approval, grant } => {
            state.check_use(*approval, grant, by, ctx.at)?;
            Ok(vec![TenantRecord::SelfGrantApprovalUsed {
                approval: *approval,
                by,
                at: ctx.at,
            }])
        }
        TenantCommand::SetSetting { value } => {
            if !setting_valid(value) {
                return Err(TenantRefusal::InvalidSetting(value.param()));
            }
            Ok(vec![TenantRecord::SettingChanged {
                value: value.clone(),
                by,
            }])
        }
        TenantCommand::SetGuideNotice { notice } => {
            // R-GA-01: only an https address stands in the Guide.
            if notice
                .as_ref()
                .is_some_and(|n| !crate::rules::https_address(&n.privacy_statement_url))
            {
                return Err(TenantRefusal::InvalidAddress);
            }
            Ok(vec![TenantRecord::GuideNoticeSet {
                notice: notice.clone(),
                by,
            }])
        }
        TenantCommand::RecordInferenceConfig {
            config,
            primary,
            fallbacks,
        } => {
            state.check_inference_record(*config, primary, fallbacks)?;
            Ok(vec![TenantRecord::InferenceConfigRecorded {
                config: *config,
                primary: primary.clone(),
                fallbacks: fallbacks.clone(),
                by,
            }])
        }
        TenantCommand::Complete => {
            state.check_completion()?;
            if !state.admins().iter().all(|a| answers.is_verified(*a)) {
                return Err(TenantRefusal::AdminNotVerified);
            }
            Ok(vec![TenantRecord::OnboardingCompleted { by }])
        }
        TenantCommand::GrantSignatory { role, account } => {
            state.check_grant_signatory(by, *role, *account)?;
            match answers.receiving.get(account) {
                Some(false) => {}
                Some(true) => return Err(TenantRefusal::HoldsReceiving),
                None => return Err(TenantRefusal::AnswerMissing),
            }
            Ok(vec![TenantRecord::SignatoryGranted {
                role: *role,
                account: *account,
                by,
                at: ctx.at,
            }])
        }
        TenantCommand::EndSignatory { role, account } => {
            state.check_end_signatory(*role, *account)?;
            Ok(vec![TenantRecord::SignatoryEnded {
                role: *role,
                account: *account,
                by,
                at: ctx.at,
            }])
        }
        TenantCommand::RequestActivation { request } => {
            state.check_request()?;
            if !state.admins().iter().all(|a| answers.is_verified(*a)) {
                return Err(TenantRefusal::AdminNotVerified);
            }
            Ok(vec![TenantRecord::ActivationRequested {
                request: *request,
                by,
                at: ctx.at,
            }])
        }
        TenantCommand::ApproveActivation { request } => {
            state.check_approve(*request, by)?;
            Ok(vec![TenantRecord::ActivationApproved {
                request: *request,
                by,
                at: ctx.at,
            }])
        }
        TenantCommand::SetBranding { tokens, digest } => {
            check_branding(tokens)?;
            Ok(vec![TenantRecord::BrandingSet {
                tokens: tokens.clone(),
                digest: *digest,
                by,
            }])
        }
    }
}

/// Whether a save of `values` validates its step: the step's own checks,
/// then the control plane's confirmation of the agreements (Q22), then
/// the prober check (Q5: an absent prober fails closed), then the
/// two-admin rule for the Administrators step (SoD-07) and its holders
/// of each signatory role (SoD-14, SoD-15).
fn step_check(
    state: &TenantState,
    values: &StepValues,
    answers: &TenantAnswers,
) -> Result<(), StepFailure> {
    values_check(values, state)?;
    if let StepValues::Agreements {
        saas_terms,
        dpa,
        sub_processors,
    } = values
        && !agreements_confirmed(*saas_terms, *dpa, *sub_processors, answers.agreements)
    {
        return Err(StepFailure::AgreementsNotRecorded);
    }
    if let Some(kind) = probe_for(values) {
        match answers.probe_outcome(&kind) {
            ProbeOutcome::Passed => {}
            ProbeOutcome::Failed => return Err(StepFailure::ProbeFailed),
            ProbeOutcome::Absent => return Err(StepFailure::ProberAbsent),
        }
    }
    if values.step() == OnboardingStep::Administrators {
        if state.admins().len() < 2 {
            return Err(StepFailure::TooFewAdmins);
        }
        // SoD-14, SoD-15 (`programme-creator.md`, onboarding table).
        if let Some(role) = state.missing_signatory() {
            return Err(role.missing());
        }
    }
    Ok(())
}

/// I-70: every pair of the table meets AA in both modes. A refusal lists
/// the failing pairs (M9 design section 2.2).
pub(crate) fn check_branding(tokens: &fstp_brand::BrandTokens) -> Result<(), TenantRefusal> {
    let failing = fstp_brand::failing_pairs(tokens);
    if failing.is_empty() {
        Ok(())
    } else {
        Err(TenantRefusal::BrandingContrast(failing))
    }
}
