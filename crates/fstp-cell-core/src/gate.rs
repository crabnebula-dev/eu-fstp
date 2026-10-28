//! The gate and `Admitted` (I-77, I-78, SoD-08, design sections 5.4 and
//! 8.4, ADR-008).
//!
//! `HighRiskAction` is the single high-risk table. [`HIGH_RISK_TABLE`]
//! lists every command or action it covers, each with the Action cell of
//! its row in `SPEC/03-architecture/authentication.md`, verbatim.
//! [`STRICT_ADDITIONS`] lists the entries that read a spec row strictly
//! beyond what `fstp_domain::CommandKind::high_risk()` marks, so no
//! addition is silent.
//!
//! W0 reviewed both lists row by row against the spec table and against
//! `CommandKind::high_risk()` at the M2 base commit `367b7be`
//! (`docs/handoff/m3-base.md`). That commit marks seven kinds:
//! `CreateProgramme`, `GrantRole`, `EndRole`, `ReinstateBinding`,
//! `ApprovePayment`, `ReleasePayment` and `PublishCall`. Each is an entry.
//! The test `i78_high_risk_table_matches_spec_and_domain` in
//! `fstp-celltest` reads the spec text at run time and checks both lists.
//!
//! Status: W0 stub for everything else. Lane W2c fills `admit`, which
//! refuses with [`Deny::NotImplemented`] until then.

use fstp_auth::SessionView;
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;

use crate::{CellCommand, CellState};

/// `authentication.md` row: granting or changing a management role.
pub const ROLE_ROW: &str =
    "Granting or changing a role in the Drafting, Judging or Operations groups, or tenant admin";
/// `authentication.md` row: exporting data.
pub const EXPORT_ROW: &str =
    "Tenant export, vault export, and any download containing identity attributes";
/// `authentication.md` row: linking a new device.
pub const DEVICE_ROW: &str = "Adding a passkey, linking a device, or signing in the desktop client";
/// `authentication.md` row: the account takeover path.
pub const LOGIN_ROW: &str = "Changing the account email address or login methods";
/// `authentication.md` row: payment diversion.
pub const BANK_ROW: &str = "Changing bank details";
/// `authentication.md` row: money movement.
pub const PAYMENT_ROW: &str = "Approving or releasing a payment";
/// `authentication.md` row: binding public commitments.
pub const PUBLIC_ROW: &str = "Activating a programme or publishing a call";
/// `authentication.md` row: data leaving the cell.
pub const TEMPLATE_ROW: &str = "Publishing a template to other tenants";
/// `authentication.md` row: operator access to content.
pub const BREAK_GLASS_ROW: &str = "Approving break-glass access";
/// `authentication.md` row: changing another account's login methods.
pub const RECOVERY_ROW: &str = "Approving an account recovery";

/// A high-risk action (I-78). Closed: each variant needs a fresh,
/// phishing-resistant step-up within P-71.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HighRiskAction {
    /// Granting or changing a Drafting, Judging, Operations or tenant
    /// admin role.
    ManagementRoleChange,
    /// A tenant export (M9).
    TenantExport,
    /// A vault export (M9).
    VaultExport,
    /// A download that contains identity attributes.
    IdentityDownload,
    /// Adding a passkey.
    AddPasskey,
    /// Linking a device.
    LinkDevice,
    /// Signing in the desktop client.
    DesktopSignIn,
    /// Changing the account email address.
    ChangeEmail,
    /// Changing login methods, including the tenant login policy.
    ChangeLoginMethods,
    /// Changing bank details (M5).
    ChangeBankDetails,
    /// Approving a payment.
    ApprovePayment,
    /// Releasing a payment.
    ReleasePayment,
    /// Activating a programme. Creating one counts as activating it.
    ActivateProgramme,
    /// Publishing a call.
    PublishCall,
    /// Publishing a template to other tenants (M4).
    PublishTemplate,
    /// Approving break-glass access.
    ApproveBreakGlass,
    /// Approving an account recovery.
    ApproveRecovery,
}

impl HighRiskAction {
    /// The high-risk class of `action`, or `None` for an action that needs
    /// no step-up (design section 5.4 step 3, I-78).
    ///
    /// Design section 5.4 gives an infallible classifier. The W0 stub
    /// returns a `Result` and refuses with [`Deny::NotImplemented`], so no
    /// caller treats an unclassified action as low risk. Lane W2c fills it
    /// from [`HIGH_RISK_TABLE`] and restores the designed signature.
    pub fn of(action: &Action) -> Result<Option<HighRiskAction>, Deny> {
        let _ = action;
        Err(Deny::NotImplemented(
            "fstp_cell_core::gate::HighRiskAction::of",
        ))
    }
}

/// One entry of the high-risk table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HighRiskEntry {
    /// The action.
    pub action: HighRiskAction,
    /// The variant name of the command or action the entry covers.
    pub command: &'static str,
    /// The Action cell of the `authentication.md` row, verbatim.
    pub spec_row: &'static str,
}

const fn entry(
    action: HighRiskAction,
    command: &'static str,
    spec_row: &'static str,
) -> HighRiskEntry {
    HighRiskEntry {
        action,
        command,
        spec_row,
    }
}

/// The high-risk table of design section 8.4 and ADR-008, reviewed row by
/// row in W0 (I-78).
///
/// `GrantTenantAdmin`, `EndTenantAdmin`, `ApproveSelfGrant` and
/// `SetLoginPolicy` are cell commands (design section 5.1). The export,
/// device, email, bank, template, break-glass and recovery entries name
/// actions of `fstp-auth`, of the cell or of later milestones.
pub const HIGH_RISK_TABLE: &[HighRiskEntry] = &[
    // Domain high-risk kinds at the M2 base, and the tenant admin commands.
    entry(HighRiskAction::ManagementRoleChange, "GrantRole", ROLE_ROW),
    entry(HighRiskAction::ManagementRoleChange, "EndRole", ROLE_ROW),
    entry(
        HighRiskAction::ManagementRoleChange,
        "ReinstateBinding",
        ROLE_ROW,
    ),
    entry(
        HighRiskAction::ManagementRoleChange,
        "GrantTenantAdmin",
        ROLE_ROW,
    ),
    entry(
        HighRiskAction::ManagementRoleChange,
        "EndTenantAdmin",
        ROLE_ROW,
    ),
    // Strict addition: SoD-07 approval changes who holds a management role.
    entry(
        HighRiskAction::ManagementRoleChange,
        "ApproveSelfGrant",
        ROLE_ROW,
    ),
    // Strict additions (G28, Q38): an assigned reviewer is a Judging role.
    entry(HighRiskAction::ManagementRoleChange, "Assign", ROLE_ROW),
    entry(HighRiskAction::ManagementRoleChange, "Unassign", ROLE_ROW),
    entry(HighRiskAction::TenantExport, "TenantExport", EXPORT_ROW),
    entry(HighRiskAction::VaultExport, "VaultExport", EXPORT_ROW),
    entry(
        HighRiskAction::IdentityDownload,
        "IdentityDownload",
        EXPORT_ROW,
    ),
    entry(HighRiskAction::AddPasskey, "AddPasskey", DEVICE_ROW),
    entry(HighRiskAction::LinkDevice, "LinkDevice", DEVICE_ROW),
    entry(HighRiskAction::DesktopSignIn, "DesktopSignIn", DEVICE_ROW),
    entry(HighRiskAction::ChangeEmail, "ChangeEmail", LOGIN_ROW),
    entry(
        HighRiskAction::ChangeLoginMethods,
        "ChangeLoginMethods",
        LOGIN_ROW,
    ),
    // Strict addition (G28, Q38): the tenant login policy is a login method
    // choice, read strictly.
    entry(
        HighRiskAction::ChangeLoginMethods,
        "SetLoginPolicy",
        LOGIN_ROW,
    ),
    entry(
        HighRiskAction::ChangeBankDetails,
        "ChangeBankDetails",
        BANK_ROW,
    ),
    entry(
        HighRiskAction::ApprovePayment,
        "ApprovePayment",
        PAYMENT_ROW,
    ),
    entry(
        HighRiskAction::ReleasePayment,
        "ReleasePayment",
        PAYMENT_ROW,
    ),
    // Creating a programme counts as activating it (confirmed 2026-10-25).
    entry(
        HighRiskAction::ActivateProgramme,
        "CreateProgramme",
        PUBLIC_ROW,
    ),
    entry(HighRiskAction::PublishCall, "PublishCall", PUBLIC_ROW),
    entry(
        HighRiskAction::PublishTemplate,
        "PublishTemplate",
        TEMPLATE_ROW,
    ),
    entry(
        HighRiskAction::ApproveBreakGlass,
        "ApproveBreakGlass",
        BREAK_GLASS_ROW,
    ),
    // Its own spec row since Q15 (decided 2026-10-28).
    entry(
        HighRiskAction::ApproveRecovery,
        "ApproveRecovery",
        RECOVERY_ROW,
    ),
];

/// An entry that reads a spec row strictly, beyond the domain's
/// `high_risk()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StrictAddition {
    /// The variant name of the command.
    pub command: &'static str,
    /// The `authentication.md` row it reads strictly, verbatim.
    pub source: &'static str,
}

/// The strict additions, interim pending Daniel (Q38, ADR-008 "High-risk
/// table"). `ApproveRecovery` is not among them, since the spec lists it
/// (Q15). Design section 8.4 still lists it here; SPEC and ADR-008 win.
pub const STRICT_ADDITIONS: &[StrictAddition] = &[
    StrictAddition {
        command: "Assign",
        source: ROLE_ROW,
    },
    StrictAddition {
        command: "Unassign",
        source: ROLE_ROW,
    },
    StrictAddition {
        command: "ApproveSelfGrant",
        source: ROLE_ROW,
    },
    StrictAddition {
        command: "SetLoginPolicy",
        source: LOGIN_ROW,
    },
];

/// A read action that the gate admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadAction {
    /// Read content.
    ReadContent,
    /// Read the audit log.
    ReadAudit,
    /// Read the erasure log.
    ReadErasureLog,
}

/// What a request asks the gate to admit.
#[allow(
    clippy::large_enum_variant,
    reason = "a command is the common case; boxing it would change the designed API"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// A command.
    Command(CellCommand),
    /// A read.
    Read(ReadAction),
}

/// Who acts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Principal {
    /// An account.
    Account(AccountId),
    /// A break-glass grant (SoD-08).
    BreakGlass([u8; 16]),
}

/// The use of a step-up by one command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepUpUse {
    /// The step-up id.
    pub id: [u8; 16],
    /// The action digest it authorised.
    pub action_digest: [u8; 32],
}

/// A step-up as the gate sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepUpView {
    /// The step-up id.
    pub id: [u8; 16],
    /// The session it belongs to.
    pub session: [u8; 16],
    /// The action digest.
    pub action_digest: [u8; 32],
    /// When the assertion was made.
    pub asserted_at: Timestamp,
    /// Whether the method was phishing resistant with user verification.
    pub strong: bool,
    /// Whether a command already consumed it.
    pub consumed: bool,
}

/// The tenant login policy (P-70 to P-72).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoginPolicy {
    /// P-71 in microseconds. It may only shorten the default.
    pub stepup_freshness_us: i64,
}

/// An admitted action. Only [`admit`] builds one, so a step-up proof
/// cannot be made outside the gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    action: Action,
    principal: Principal,
    stepup: Option<StepUpUse>,
    at: Timestamp,
}

impl Admitted {
    /// The admitted action.
    pub fn action(&self) -> &Action {
        &self.action
    }

    /// Who acts.
    pub fn principal(&self) -> Principal {
        self.principal
    }

    /// The step-up the action consumes, if any.
    pub fn stepup(&self) -> Option<StepUpUse> {
        self.stepup
    }

    /// When the action was admitted.
    pub fn at(&self) -> Timestamp {
        self.at
    }
}

/// Why the gate refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deny {
    /// No session.
    NoSession,
    /// The session ended.
    SessionEnded,
    /// A weak session of a management role holder (I-77).
    WeakSessionForRole,
    /// The action needs a step-up.
    StepUpRequired(HighRiskAction),
    /// The step-up is older than P-71.
    StepUpStale,
    /// The step-up was for another action or session.
    StepUpMismatch,
    /// The step-up used a method that is not phishing resistant.
    StepUpFromWeakMethod,
    /// A magic-link session asked for a high-risk action.
    MagicLinkSessionHighRisk,
    /// The account needs a passkey first.
    EnrolPasskeyFirst,
    /// The action is not permitted.
    NotPermitted,
    /// The gate is a W0 stub. It names the operation. This variant goes
    /// when lane W2c lands the gate.
    NotImplemented(&'static str),
}

/// Admits an action, or refuses it (design section 5.4).
pub fn admit(
    s: &CellState,
    session: &SessionView,
    action: Action,
    stepup: Option<&StepUpView>,
    now: Timestamp,
    policy: &LoginPolicy,
) -> Result<Admitted, Deny> {
    let _ = (s, session, action, stepup, now, policy);
    Err(Deny::NotImplemented("fstp_cell_core::gate::admit"))
}
