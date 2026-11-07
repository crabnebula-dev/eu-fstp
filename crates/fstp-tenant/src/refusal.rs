//! Refusals and errors. None of them carries input content or names an
//! account (R-NF-02, `overview.md` NOTE 5).

use std::fmt;

use crate::types::TenantParam;

/// Why `decide` refused a tenant command, or why a record did not fold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TenantRefusal {
    /// A high-risk tenant command arrived through MCP. The registry
    /// already turns it into a prepared action, and the tenant core
    /// refuses it as a second line of defence (I-85, interim pending
    /// Daniel).
    HighRiskViaMcp,
    /// A web-only tenant command that is not itself high-risk arrived
    /// through MCP: taking an admin invitation, or using a SoD-07 approval.
    /// Each completes a grant (I-85).
    WebOnlyViaMcp,
    /// The actor is not a tenant admin (Q31).
    NotTenantAdmin,
    /// The save names a revision older than the state.
    StaleRevision,
    /// An earlier step is not validated (R-TN-01).
    StepLocked,
    /// The tenant does not go through this step in this kind of cell.
    StepSkipped,
    /// The invitation id was issued before.
    InvitationTaken,
    /// The invitation was never issued, or was taken.
    InvitationNotOpen,
    /// The actor is not the invitee, or the token digest differs.
    InvitationMismatch,
    /// The account is a tenant admin already.
    AlreadyAdmin,
    /// The account holds a Receiving binding, and a tenant admin counts as
    /// holding Operations in every programme (SoD-03).
    HoldsReceiving,
    /// A question the command needs was not answered, so it fails closed.
    AnswerMissing,
    /// The approval id was used before.
    ApprovalTaken,
    /// The approver is the grantee (SoD-07).
    SelfApproval,
    /// The grantee is not a tenant admin.
    GranteeNotAdmin,
    /// The approval is unknown, used, or for another grant or grantee.
    ApprovalNotOpen,
    /// The approval lapsed (P-71 after it was given).
    ApprovalExpired,
    /// The instant lies outside the ledger's range.
    InvalidInstant,
    /// The value breaks the parameter's rule.
    InvalidSetting(TenantParam),
    /// The configuration id was recorded before.
    ConfigTaken,
    /// The models break the P-21 rule (NOTE 10).
    InvalidModels,
    /// The models are not those of the validated Inference step.
    NotDefaultModels,
    /// Onboarding was completed already.
    AlreadyCompleted,
    /// A step is not validated.
    StepsNotValidated,
    /// Fewer than two tenant admins exist (SoD-07).
    TooFewAdmins,
    /// The vault does not report every tenant admin as verified (Q2).
    AdminNotVerified,
    /// A tenant admin granted a signatory role to their own account. No
    /// tenant-wide SoD-07 approval exists yet, so a second tenant admin
    /// grants it instead (SoD-07, NOTE 5; interim, pending Daniel).
    SignatorySelfGrant,
    /// The account holds the signatory role already. A role is granted
    /// again only after its binding ends (M4 design section 15.0).
    SignatoryHeld,
    /// The account holds no binding of the signatory role.
    SignatoryNotHeld,
    /// The end would leave the role with no holder while the organisation
    /// is active (SoD-17).
    LastSignatory,
    /// No account holds Financial signatory (SoD-14).
    NoFinancialSignatory,
    /// No account holds Legal signatory (SoD-15).
    NoLegalSignatory,
    /// An activation request is open already (SoD-18).
    ActivationPending,
    /// The organisation is active already (SoD-18).
    AlreadyActive,
    /// No activation request is open, or the approval names another one
    /// (SoD-18).
    ActivationNotOpen,
    /// The approver requested the activation (SoD-18).
    SelfActivationApproval,
    /// The Guide's privacy statement address is not an `https:` address
    /// (R-GA-01).
    InvalidAddress,
    /// The brand tokens fail I-70: these pairs of the table miss WCAG 2.2
    /// AA contrast. The set names pairs only, never a colour.
    BrandingContrast(fstp_brand::PairSet),
    /// The terminology breaks the shape bounds (I-68, I-72).
    TerminologyInvalid,
    /// A record contradicts the state it folds into.
    Inconsistent,
}

impl TenantRefusal {
    /// A stable code for the refusal.
    pub const fn code(self) -> &'static str {
        match self {
            TenantRefusal::HighRiskViaMcp => "high_risk_via_mcp",
            TenantRefusal::WebOnlyViaMcp => "web_only_via_mcp",
            TenantRefusal::NotTenantAdmin => "not_tenant_admin",
            TenantRefusal::StaleRevision => "stale_revision",
            TenantRefusal::StepLocked => "step_locked",
            TenantRefusal::StepSkipped => "step_skipped",
            TenantRefusal::InvitationTaken => "invitation_taken",
            TenantRefusal::InvitationNotOpen => "invitation_not_open",
            TenantRefusal::InvitationMismatch => "invitation_mismatch",
            TenantRefusal::AlreadyAdmin => "already_admin",
            TenantRefusal::HoldsReceiving => "holds_receiving",
            TenantRefusal::AnswerMissing => "answer_missing",
            TenantRefusal::ApprovalTaken => "approval_taken",
            TenantRefusal::SelfApproval => "self_approval",
            TenantRefusal::GranteeNotAdmin => "grantee_not_admin",
            TenantRefusal::ApprovalNotOpen => "approval_not_open",
            TenantRefusal::ApprovalExpired => "approval_expired",
            TenantRefusal::InvalidInstant => "invalid_instant",
            TenantRefusal::InvalidSetting(_) => "invalid_setting",
            TenantRefusal::ConfigTaken => "config_taken",
            TenantRefusal::InvalidModels => "invalid_models",
            TenantRefusal::NotDefaultModels => "not_default_models",
            TenantRefusal::AlreadyCompleted => "already_completed",
            TenantRefusal::StepsNotValidated => "steps_not_validated",
            TenantRefusal::TooFewAdmins => "too_few_admins",
            TenantRefusal::AdminNotVerified => "admin_not_verified",
            TenantRefusal::SignatorySelfGrant => "signatory_self_grant",
            TenantRefusal::SignatoryHeld => "signatory_held",
            TenantRefusal::SignatoryNotHeld => "signatory_not_held",
            TenantRefusal::LastSignatory => "last_signatory",
            TenantRefusal::NoFinancialSignatory => "no_financial_signatory",
            TenantRefusal::NoLegalSignatory => "no_legal_signatory",
            TenantRefusal::ActivationPending => "activation_pending",
            TenantRefusal::AlreadyActive => "already_active",
            TenantRefusal::ActivationNotOpen => "activation_not_open",
            TenantRefusal::SelfActivationApproval => "self_activation_approval",
            TenantRefusal::InvalidAddress => "invalid_address",
            TenantRefusal::BrandingContrast(_) => "branding_contrast",
            TenantRefusal::TerminologyInvalid => "terminology_invalid",
            TenantRefusal::Inconsistent => "inconsistent",
        }
    }
}

impl fmt::Display for TenantRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TenantRefusal::InvalidSetting(p) => {
                write!(f, "refused: invalid_setting {}", p.param_id().spec_id())
            }
            other => write!(f, "refused: {}", other.code()),
        }
    }
}

impl std::error::Error for TenantRefusal {}

/// A record that does not fold into the state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FoldError(pub TenantRefusal);

impl fmt::Display for FoldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tenant record does not fold: {}", self.0.code())
    }
}

impl std::error::Error for FoldError {}

/// Why bytes did not decode. It holds a fixed message only, never input
/// content (R-NF-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DecodeError(pub(crate) &'static str);

impl DecodeError {
    /// The fixed message.
    pub const fn message(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tenant decode error: {}", self.0)
    }
}

impl std::error::Error for DecodeError {}

/// Why an operation of this crate failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TenantError {
    /// The named operation is not built in this milestone. No operation of
    /// this build returns it. It stays so that a later seam can refuse
    /// with a typed error.
    NotImplemented(&'static str),
    /// Bytes did not decode.
    Decode(DecodeError),
    /// A record did not fold.
    Fold(FoldError),
    /// A value has no canonical text, so it cannot be stored.
    Encode,
}

impl fmt::Display for TenantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TenantError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
            TenantError::Decode(e) => e.fmt(f),
            TenantError::Fold(e) => e.fmt(f),
            TenantError::Encode => f.write_str("tenant value has no canonical text"),
        }
    }
}

impl std::error::Error for TenantError {}

impl From<DecodeError> for TenantError {
    fn from(e: DecodeError) -> TenantError {
        TenantError::Decode(e)
    }
}

impl From<FoldError> for TenantError {
    fn from(e: FoldError) -> TenantError {
        TenantError::Fold(e)
    }
}
