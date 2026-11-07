//! Tenant commands, records and the command context (design section 3.5).

use fstp_brand::BrandTokens;
use fstp_domain::Via;
use fstp_domain::id::{AccountId, ContentDigest, LlmConfigId};
use fstp_domain::time::Timestamp;

use crate::types::{
    ActivationRequestId, ApprovalId, GrantRef, GuideNoticeOverride, InvitationId, ModelRef,
    OnboardingStep, SettingValue, SignatoryRole, StepOutcome, StepValues, TenantParam,
    TenantRevision, TokenDigest,
};

/// The context of one tenant command, supplied by the shell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TenantCtx {
    /// The account that issues the command, from its session or token.
    pub actor: AccountId,
    /// The channel the command arrived through.
    pub via: Via,
    /// The instant of the command, read once by the shell. `decide` never
    /// reads a clock. SoD-07 approvals expire from it.
    pub at: Timestamp,
}

/// A tenant command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantCommand {
    /// Save the values of one onboarding step. The step is the one the
    /// values belong to.
    SaveStep {
        /// The values.
        values: StepValues,
        /// The revision the values were edited against.
        base: TenantRevision,
    },
    /// Invite a further tenant admin. High-risk: it grants tenant admin.
    ///
    /// Interim, pending Daniel: the invitation names its invitee, as an M3
    /// invitation names its account. It records only the digest of the
    /// invitation token, never the token.
    InviteAdmin {
        /// The invitation, drawn by the shell.
        invitation: InvitationId,
        /// The account the invitation is for.
        invitee: AccountId,
        /// The digest of the invitation token.
        token_digest: TokenDigest,
    },
    /// The invitee, enrolled through M3, takes the invitation and becomes
    /// a tenant admin. Design section 3.5 has the `AdminAdded` record but
    /// no command for it, so this one is added (interim, pending Daniel).
    /// It completes a tenant admin grant, so it is web only (I-85).
    AcceptAdminInvitation {
        /// The invitation.
        invitation: InvitationId,
        /// The digest the shell computed of the token the invitee
        /// presented.
        token_digest: TokenDigest,
    },
    /// A second tenant admin approves another admin's self-grant (SoD-07).
    /// High-risk.
    ApproveSelfGrant {
        /// The approval, drawn by the shell.
        approval: ApprovalId,
        /// The self-grant it approves.
        grant: GrantRef,
    },
    /// The self-grant that a SoD-07 approval admits consumes it, once and
    /// before it expires (TH-05). The shell issues it with the role grant
    /// it admits. Web only (I-85). Interim, pending Daniel (Q31 A).
    UseSelfGrantApproval {
        /// The approval.
        approval: ApprovalId,
        /// The self-grant, which must be the approved one.
        grant: GrantRef,
    },
    /// Change one tenant setting. High-risk, one operation per parameter.
    SetSetting {
        /// The new value, which names its parameter.
        value: SettingValue,
    },
    /// Set or clear the tenant's override of the Guide's data protection
    /// texts (R-GA-01; section 15.0 of the M4 design, 2026-11-06). `None`
    /// brings back the platform default. High-risk by the strict reading
    /// of settings, so web only (interim, pending Daniel).
    SetGuideNotice {
        /// The override, or `None` for the platform default.
        notice: Option<GuideNoticeOverride>,
    },
    /// Record the inference configuration that `call.publish` uses. It
    /// records the models of the validated Inference step (design 3.5:
    /// "The Inference step also records an `InferenceConfigRecorded`
    /// entry"). Interim, pending Daniel.
    RecordInferenceConfig {
        /// The pinned LLM configuration.
        config: LlmConfigId,
        /// The primary model.
        primary: ModelRef,
        /// The ordered fallbacks (P-21 NOTE 10).
        fallbacks: Vec<ModelRef>,
    },
    /// Finish onboarding (`tenant.complete`, design section 2.2 J0).
    /// Section 3.5 lists no command for it, so this one is added. It does
    /// not activate the organisation: activation needs a request and a
    /// second tenant admin's approval (SoD-18).
    Complete,
    /// Grant a tenant-wide signatory role (NOTE 5). High-risk: it grants an
    /// Operations role (`authentication.md`, I-78).
    GrantSignatory {
        /// The role.
        role: SignatoryRole,
        /// The account the role binds.
        account: AccountId,
    },
    /// End an account's binding of a signatory role. High-risk: it changes
    /// an Operations role (I-78).
    EndSignatory {
        /// The role.
        role: SignatoryRole,
        /// The account whose binding ends.
        account: AccountId,
    },
    /// Request activation of the organisation (SoD-14, SoD-15, SoD-18).
    RequestActivation {
        /// The request, drawn by the shell.
        request: ActivationRequestId,
    },
    /// Approve the open activation request as a tenant admin other than
    /// its requester (SoD-18).
    ApproveActivation {
        /// The request approved, which must be the open one.
        request: ActivationRequestId,
    },
    /// Set the tenant brand tokens (`tenant.branding.set`, M9 lane B1).
    /// High-risk. Refused with the failing pairs listed when any pair of
    /// the I-70 table fails.
    SetBranding {
        /// The typed tokens (I-68).
        tokens: BrandTokens,
        /// The digest of their canonical text, computed by the shell.
        digest: ContentDigest,
    },
}

/// The kind of a tenant command, as the operation registry names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TenantKind {
    /// `tenant.save_step`.
    SaveStep,
    /// `tenant.invite_admin`.
    InviteAdmin,
    /// `tenant.accept_admin_invitation`.
    AcceptAdminInvitation,
    /// `tenant.approve_self_grant`.
    ApproveSelfGrant,
    /// `tenant.use_self_grant_approval`.
    UseSelfGrantApproval,
    /// One `tenant.set_*` operation per parameter.
    SetSetting(TenantParam),
    /// `tenant.set_guide_notice` (R-GA-01).
    SetGuideNotice,
    /// `tenant.record_inference_config`.
    RecordInferenceConfig,
    /// `tenant.complete`.
    Complete,
    /// `tenant.grant_signatory`.
    GrantSignatory,
    /// `tenant.end_signatory`.
    EndSignatory,
    /// `tenant.request_activation`.
    RequestActivation,
    /// `tenant.approve_activation`.
    ApproveActivation,
    /// `tenant.branding.set`.
    SetBranding,
}

impl TenantKind {
    /// Every kind.
    pub const ALL: [TenantKind; 19] = [
        TenantKind::SaveStep,
        TenantKind::InviteAdmin,
        TenantKind::AcceptAdminInvitation,
        TenantKind::ApproveSelfGrant,
        TenantKind::UseSelfGrantApproval,
        TenantKind::SetSetting(TenantParam::P20),
        TenantKind::SetSetting(TenantParam::P69),
        TenantKind::SetSetting(TenantParam::P70),
        TenantKind::SetSetting(TenantParam::P71),
        TenantKind::SetSetting(TenantParam::P72),
        TenantKind::SetSetting(TenantParam::P74),
        TenantKind::SetGuideNotice,
        TenantKind::RecordInferenceConfig,
        TenantKind::Complete,
        TenantKind::GrantSignatory,
        TenantKind::EndSignatory,
        TenantKind::RequestActivation,
        TenantKind::ApproveActivation,
        TenantKind::SetBranding,
    ];

    /// Whether the kind is high-risk and needs a fresh step-up (R-LG-03).
    ///
    /// - Inviting an admin grants tenant admin (`authentication.md`).
    /// - A SoD-07 approval is high-risk, as M3 lists it.
    /// - Every setting change: P-70 by `authentication.md`, the others by
    ///   the strict reading (`STRICT_EXTRA_HIGH_RISK`, design 3.6).
    /// - Granting or ending a signatory role changes an Operations role
    ///   (`authentication.md`).
    /// - Not the request or the approval of the organisation's activation:
    ///   the high-risk table names programme activation only (interim,
    ///   pending Daniel).
    /// - Setting the brand tokens changes what every interface shows
    ///   (M9 design section 2.2).
    pub const fn high_risk(self) -> bool {
        matches!(
            self,
            TenantKind::InviteAdmin
                | TenantKind::ApproveSelfGrant
                | TenantKind::SetSetting(_)
                | TenantKind::SetGuideNotice
                | TenantKind::GrantSignatory
                | TenantKind::EndSignatory
                | TenantKind::SetBranding
        )
    }

    /// Whether the kind may arrive through the web only (I-85).
    ///
    /// - Every high-risk kind.
    /// - Taking an admin invitation, whose `AdminAdded` record completes a
    ///   tenant admin grant. It runs in the M3 enrolment ceremony, whose
    ///   new passkey stands for the step-up (design J0).
    /// - Using a SoD-07 approval, which completes a role grant.
    pub const fn web_only(self) -> bool {
        self.high_risk()
            || matches!(
                self,
                TenantKind::AcceptAdminInvitation | TenantKind::UseSelfGrantApproval
            )
    }

    /// Whether only a tenant admin may issue the kind. Only taking an
    /// invitation is open to an account outside the admin set.
    pub const fn admin_only(self) -> bool {
        !matches!(self, TenantKind::AcceptAdminInvitation)
    }
}

impl TenantCommand {
    /// The command's kind.
    pub fn kind(&self) -> TenantKind {
        match self {
            TenantCommand::SaveStep { .. } => TenantKind::SaveStep,
            TenantCommand::InviteAdmin { .. } => TenantKind::InviteAdmin,
            TenantCommand::AcceptAdminInvitation { .. } => TenantKind::AcceptAdminInvitation,
            TenantCommand::ApproveSelfGrant { .. } => TenantKind::ApproveSelfGrant,
            TenantCommand::UseSelfGrantApproval { .. } => TenantKind::UseSelfGrantApproval,
            TenantCommand::SetSetting { value } => TenantKind::SetSetting(value.param()),
            TenantCommand::SetGuideNotice { .. } => TenantKind::SetGuideNotice,
            TenantCommand::RecordInferenceConfig { .. } => TenantKind::RecordInferenceConfig,
            TenantCommand::Complete => TenantKind::Complete,
            TenantCommand::GrantSignatory { .. } => TenantKind::GrantSignatory,
            TenantCommand::EndSignatory { .. } => TenantKind::EndSignatory,
            TenantCommand::RequestActivation { .. } => TenantKind::RequestActivation,
            TenantCommand::ApproveActivation { .. } => TenantKind::ApproveActivation,
            TenantCommand::SetBranding { .. } => TenantKind::SetBranding,
        }
    }

    /// Whether the command is high-risk ([`TenantKind::high_risk`]).
    pub fn high_risk(&self) -> bool {
        self.kind().high_risk()
    }

    /// Whether the command is web only ([`TenantKind::web_only`]).
    pub fn web_only(&self) -> bool {
        self.kind().web_only()
    }
}

/// A tenant ledger record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantRecord {
    /// A step was saved. The step is the one the values belong to.
    StepSaved {
        /// The values.
        values: StepValues,
        /// The saving admin.
        by: AccountId,
        /// Whether the save validated the step, and why not.
        outcome: StepOutcome,
    },
    /// The save just before validated its step.
    StepValidated {
        /// The step.
        step: OnboardingStep,
        /// The saving admin.
        by: AccountId,
    },
    /// An admin invitation was issued.
    AdminInvited {
        /// The invitation.
        invitation: InvitationId,
        /// The account the invitation is for.
        invitee: AccountId,
        /// The digest of the invitation token. The token is never stored.
        token_digest: TokenDigest,
        /// The inviting admin.
        by: AccountId,
    },
    /// The invitee took the invitation and became a tenant admin.
    AdminAdded {
        /// The new admin, who is the invitee.
        account: AccountId,
        /// The invitation taken.
        invitation: InvitationId,
    },
    /// A second admin approved a self-grant (SoD-07). The approval lapses
    /// P-71 after `at`.
    SelfGrantApproved {
        /// The approval.
        approval: ApprovalId,
        /// The approved self-grant.
        grant: GrantRef,
        /// The approving admin.
        by: AccountId,
        /// The instant of the approval.
        at: Timestamp,
    },
    /// The approved self-grant consumed its approval (TH-05).
    SelfGrantApprovalUsed {
        /// The approval.
        approval: ApprovalId,
        /// The granting admin, who is the grantee.
        by: AccountId,
        /// The instant of the use.
        at: Timestamp,
    },
    /// A tenant setting changed.
    SettingChanged {
        /// The new value, which names its parameter.
        value: SettingValue,
        /// The admin who changed it.
        by: AccountId,
    },
    /// The tenant's override of the Guide's data protection texts was
    /// set, or cleared with `None`.
    GuideNoticeSet {
        /// The override, or `None` for the platform default.
        notice: Option<GuideNoticeOverride>,
        /// The admin who set it.
        by: AccountId,
    },
    /// An inference configuration was recorded.
    InferenceConfigRecorded {
        /// The pinned LLM configuration.
        config: LlmConfigId,
        /// The primary model.
        primary: ModelRef,
        /// The ordered fallbacks.
        fallbacks: Vec<ModelRef>,
        /// The recording admin.
        by: AccountId,
    },
    /// Onboarding was completed.
    OnboardingCompleted {
        /// The completing admin.
        by: AccountId,
    },
    /// A tenant admin granted a signatory role (NOTE 5). The binding starts
    /// at `at` and names no programme.
    SignatoryGranted {
        /// The role.
        role: SignatoryRole,
        /// The account the role binds.
        account: AccountId,
        /// The granting admin, never `account` (SoD-07).
        by: AccountId,
        /// The start of the binding.
        at: Timestamp,
    },
    /// A tenant admin ended a signatory binding at `at`.
    SignatoryEnded {
        /// The role.
        role: SignatoryRole,
        /// The account whose binding ended.
        account: AccountId,
        /// The ending admin.
        by: AccountId,
        /// The end of the binding.
        at: Timestamp,
    },
    /// A tenant admin requested activation of the organisation.
    ActivationRequested {
        /// The request.
        request: ActivationRequestId,
        /// The requesting admin.
        by: AccountId,
        /// The instant of the request.
        at: Timestamp,
    },
    /// A second tenant admin approved the open request, so the
    /// organisation is active (SoD-18).
    ActivationApproved {
        /// The approved request.
        request: ActivationRequestId,
        /// The approving admin.
        by: AccountId,
        /// The instant of the approval.
        at: Timestamp,
    },
    /// A tenant admin set the brand tokens (M9 design section 2.1). Every
    /// pair of the I-70 table passes.
    BrandingSet {
        /// The typed tokens.
        tokens: BrandTokens,
        /// The digest of their canonical text.
        digest: ContentDigest,
        /// The setting admin.
        by: AccountId,
    },
}
