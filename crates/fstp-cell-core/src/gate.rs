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
//! [`admit`] runs the checks of design section 5.4 in order:
//!
//! 1. The session has not ended by a record, and no binding of its
//!    account ended after it started and at or before `now`, by any cause
//!    and including a scheduled end (section 8.2). Nor did it start at or
//!    before a completed recovery of its account (I-79, section 8.5).
//! 2. `fstp_auth::admit_session` checks the P-72 lifetimes and refuses a
//!    weak session of a management holder (I-77). Holdings come from the
//!    engine roster and the tenant fold at `now`.
//! 3. The audit log and the erasure log are read by tenant admins and
//!    Auditors only (ADR-007, G30). Other reads are admitted here, and the
//!    read path applies the M2 visibility rules.
//! 4. For a high-risk action: the session's method is phishing resistant,
//!    and the step-up exists, belongs to this session, matches the action
//!    digest, used a phishing-resistant method with UV, is no older than
//!    P-71 and is unused (I-78).
//!
//! The digest check needs the command id. [`admit`] takes none, as design
//! section 5.4 gives it, so a high-risk action with a step-up reaches the
//! digest check only through [`admit_command`].
//!
//! A session never admits a command that only a system task issues: key
//! records, relationship records, operator tickets and scheduled session
//! ends ([`crate::SystemTask`]). Nor does it admit the auth commands that
//! only a route issues once it verified what the record states:
//! `GrantStepUp`, `ProveRecoveryEmail`, `RequestRecovery` and
//! `CompleteRecovery`. [`admit_system`] admits a system task's own
//! commands, with no session.
//!
//! A step-up admits only when the ledger granted it (`StepUpGranted`),
//! and then only the digest and the session its record names. P-71 is
//! checked against the caller's assertion instant and against the entry
//! instant of the grant (design sections 5.4 and 8.4).
//!
//! The route admissions take what only a route holds (design sections
//! 8.3 to 8.5 and 8.7):
//!
//! - [`admit_add_passkey`]: `RegisterCredential` as `AddPasskey`. The gate
//!   verifies the registration itself, and the batch records that key.
//! - [`admit_recovery_request`]: the public `RequestRecovery`, with the
//!   deployment mode.
//! - [`Admitted::with_sessions`]: the live session rows of any admitted
//!   command, so `EndSession`, `RevokeCredential`,
//!   `EndSessionsAtBindingEnd` and the grant and end reactions of design
//!   section 5.1 name the sessions they end.
//! - [`admit_verified_stepup`]: `GrantStepUp` under the challenge id. The
//!   gate verifies the passkey assertion itself through
//!   `fstp_auth::stepup::verify_step_up` (lane int5).
//! - [`admit_invitation_enrolment`]: `EnrolByInvitation`, the first
//!   passkey of an invited account. The gate matches the proof to the
//!   invitation and verifies the registration (design section 8.3).
//! - [`admit_first_admin_invitation`]: `IssueFirstAdminInvitation` of
//!   provisioning, with the deployment mode (design section 9.2 step 10).
//!
//! These fail closed ([`ROUTE_ADMISSION_SEAM`]), since their route holds
//! no proof this crate can verify yet:
//!
//! - `GrantStepUp` from a `fstp_auth::stepup::StepUp` alone:
//!   [`admit_stepup_grant`] runs its ledger and session checks, then
//!   refuses. A `StepUp` has public fields, so a caller can write one with
//!   no assertion behind it. [`admit_verified_stepup`] takes the assertion
//!   instead.
//! - `CompleteRecovery`: [`admit_recovery_completion`] recomputes the path
//!   and verifies the new passkey, then refuses. Nothing binds the caller
//!   to the case: the enrolment token and the email proof have no
//!   lifetime under ADR-008 "Unset lifetimes".
//! - `ProveRecoveryEmail`: it has no admission, for the same reason.
//!
//! Steps 1 and 3 are this crate's. Step 2 calls `fstp_auth::admit_session`
//! and `fstp_auth::holds_management` (lanes W2b and W2c, integrated).

use fstp_auth::{
    AuthError, Method, RosterView, SessionDeny, SessionLifetimes, SessionView, TenantView,
};
use fstp_domain::id::AccountId;
use fstp_domain::roles::{Group, Role};
use fstp_domain::time::Timestamp;

use crate::inputs::{RouteInputs, SessionRows};
use crate::tenant::{P71_DEFAULT_US, TenantCommand};
use crate::{CellCommand, CellState, SystemTask};

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
    /// An M2 command is classified by the table entry of its kind. A kind
    /// that `high_risk()` marks and the table lacks is refused with
    /// [`Deny::NotPermitted`], so no caller treats an unclassified
    /// high-risk command as low risk. The cell commands are classified by
    /// their entries: `RegisterCredential` is `AddPasskey`, and
    /// `RevokeCredential` removes a device, which section 8.2 classes as
    /// `ChangeLoginMethods`.
    ///
    /// Design section 5.4 gives an infallible classifier. The `Result`
    /// stays because the W1 suites call it so.
    pub fn of(action: &Action) -> Result<Option<HighRiskAction>, Deny> {
        let Action::Command(c) = action else {
            return Ok(None);
        };
        match c {
            CellCommand::Engine(fstp_engine::Command::Core(core)) => {
                let kind = core.kind();
                let name = format!("{kind:?}");
                match (table_action(&name), kind.high_risk()) {
                    (Some(a), _) => Ok(Some(a)),
                    (None, true) => Err(Deny::NotPermitted),
                    (None, false) => Ok(None),
                }
            }
            CellCommand::Engine(fstp_engine::Command::Finding(_)) => Ok(None),
            other => Ok(cell_entry(other).and_then(table_action)),
        }
    }
}

/// The table action of the entry named `name`.
fn table_action(name: &str) -> Option<HighRiskAction> {
    HIGH_RISK_TABLE
        .iter()
        .find(|e| e.command == name)
        .map(|e| e.action)
}

/// The table entry name of a cell command, if a row names it.
fn cell_entry(c: &CellCommand) -> Option<&'static str> {
    match c {
        CellCommand::Auth(fstp_auth::AuthCommand::RegisterCredential { .. }) => Some("AddPasskey"),
        CellCommand::Auth(fstp_auth::AuthCommand::RevokeCredential { .. }) => {
            Some("ChangeLoginMethods")
        }
        CellCommand::Tenant(TenantCommand::GrantTenantAdmin { .. }) => Some("GrantTenantAdmin"),
        CellCommand::Tenant(TenantCommand::EndTenantAdmin { .. }) => Some("EndTenantAdmin"),
        CellCommand::Tenant(TenantCommand::ApproveSelfGrant { .. }) => Some("ApproveSelfGrant"),
        CellCommand::Tenant(TenantCommand::SetLoginPolicy { .. }) => Some("SetLoginPolicy"),
        CellCommand::Ops(crate::ops::OpsCommand::ApproveBreakGlass { .. }) => {
            Some("ApproveBreakGlass")
        }
        CellCommand::Auth(fstp_auth::AuthCommand::ApproveRecovery { .. }) => {
            Some("ApproveRecovery")
        }
        _ => None,
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
    // M4 addition (D2, m4-design Q10): the activation step is high risk in
    // the domain, so it needs its own step-up.
    entry(
        HighRiskAction::ActivateProgramme,
        "ActivateProgramme",
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
    /// A system task of the cell ([`admit_system`]).
    System(SystemTask),
    /// A public or ceremony step for the account it names, which holds no
    /// session: a recovery request or a recovery completion (design
    /// section 8.7). Only [`admit_recovery_request`] builds it, after its
    /// own checks. No admission builds it for a completion yet
    /// ([`ROUTE_ADMISSION_SEAM`]).
    Ceremony(AccountId),
}

/// The use of a step-up by one command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepUpUse {
    /// The step-up id.
    pub id: [u8; 16],
    /// The action digest it authorised.
    pub action_digest: [u8; 32],
    /// When the assertion was made.
    pub asserted_at: Timestamp,
    /// The effective P-71 the gate checked it under, in microseconds. The
    /// commit checks freshness again under the same value (design section
    /// 8.4, ADR-008).
    pub p71_us: i64,
}

impl StepUpUse {
    /// The last UTC microsecond at which a command may commit under this
    /// step-up: `asserted_at + P-71`. `None` on overflow, which no commit
    /// meets.
    pub fn fresh_until(&self) -> Option<i64> {
        self.asserted_at.micros().checked_add(self.p71_us)
    }
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

/// The login policy the gate is asked under (P-70 to P-72).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoginPolicy {
    /// P-71 in microseconds. It may only shorten the default: the gate
    /// uses the shortest of this value, the default and the tenant's.
    pub stepup_freshness_us: i64,
}

/// An admitted action. Only [`admit`] and [`admit_command`] build one, so
/// a step-up proof cannot be made outside the gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    action: Action,
    principal: Principal,
    stepup: Option<StepUpUse>,
    at: Timestamp,
    command: Option<[u8; 16]>,
    inputs: RouteInputs,
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

    /// The command id the gate checked the step-up digest under, when the
    /// caller gave one ([`admit_command`]).
    pub fn command_id(&self) -> Option<[u8; 16]> {
        self.command
    }

    /// The route or task inputs the command's batch is decided with
    /// ([`RouteInputs`]).
    pub fn inputs(&self) -> &RouteInputs {
        &self.inputs
    }

    /// The same admission with the live session rows `rows`, which its
    /// route or task read from `auth.session` (design section 4.2). The
    /// batch then names the sessions it ends: the reactions of design
    /// section 5.1, `EndSession`, `RevokeCredential` and
    /// `EndSessionsAtBindingEnd`.
    ///
    /// Rows are data, not proof (module [`crate::inputs`]). They change no
    /// check of the gate, and a row can only make a batch end a session.
    #[must_use]
    pub fn with_sessions(mut self, rows: SessionRows) -> Admitted {
        self.inputs = self.inputs.with_sessions(rows);
        self
    }

    /// The same admission with the message bodies of a timeline firing
    /// (M6 design section 4 step 2). Only the timeline task calls it. The
    /// decider refuses bodies that do not name exactly the fired messages.
    #[must_use]
    pub fn with_outbox(mut self, bodies: Vec<crate::timeline::MessageBody>) -> Admitted {
        self.inputs = self.inputs.with_outbox(bodies);
        self
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
    /// The step-up is older than P-71, or a command already consumed it.
    StepUpStale,
    /// The step-up was for another action or session.
    StepUpMismatch,
    /// The step-up used a method that is not phishing resistant.
    StepUpFromWeakMethod,
    /// A session of a method that is not phishing resistant asked for a
    /// high-risk action.
    MagicLinkSessionHighRisk,
    /// The account needs a passkey first.
    EnrolPasskeyFirst,
    /// The action is not permitted.
    NotPermitted,
    /// A check the gate needs is not available: the step-up digest check
    /// through [`admit`], which has no command id. The `fstp-auth` W0 stub
    /// refusals also map here, though no `fstp-auth` operation returns one
    /// since lane W2b. It names the operation.
    NotImplemented(&'static str),
}

/// Admits an action, or refuses it (design section 5.4).
///
/// It takes no command id, so a high-risk action that offers a step-up is
/// refused at the digest check with [`Deny::NotImplemented`]. Callers use
/// [`admit_command`] for commands.
pub fn admit(
    s: &CellState,
    session: &SessionView,
    action: Action,
    stepup: Option<&StepUpView>,
    now: Timestamp,
    policy: &LoginPolicy,
) -> Result<Admitted, Deny> {
    admit_inner(s, session, action, None, stepup, now, policy)
}

/// [`admit`] for an action whose command runs under `command_id`, so the
/// gate checks the step-up digest `SHA-256(canonical(command) ||
/// command_id)` (design section 8.4). The `Admitted` it gives carries the
/// id, and the driver runs the command under it.
pub fn admit_command(
    s: &CellState,
    session: &SessionView,
    action: Action,
    command_id: [u8; 16],
    stepup: Option<&StepUpView>,
    now: Timestamp,
    policy: &LoginPolicy,
) -> Result<Admitted, Deny> {
    admit_inner(s, session, action, Some(command_id), stepup, now, policy)
}

fn admit_inner(
    s: &CellState,
    session: &SessionView,
    action: Action,
    command: Option<[u8; 16]>,
    stepup: Option<&StepUpView>,
    now: Timestamp,
    policy: &LoginPolicy,
) -> Result<Admitted, Deny> {
    // System commands and the route-only auth commands never come
    // through a session (module documentation). This reads no session,
    // so it runs first.
    if let Action::Command(c) = &action
        && (system_only(c) || route_only(c))
    {
        return Err(Deny::NotPermitted);
    }
    admit_in_session(s, session, action, command, stepup, now, policy)
}

/// Steps 1 and 2 of design section 5.4: the session has not ended, by a
/// record or by a binding end after it started, and `fstp_auth` admits it
/// under P-72 and I-77.
fn session_checks(s: &CellState, session: &SessionView, now: Timestamp) -> Result<(), Deny> {
    // Step 1: a record, a binding end or a completed recovery of the
    // account ended the session (I-79: a completion ends every session
    // of the account, not only those its route read).
    if s.auth().session_ended(session.id)
        || s.binding_ended_between(session.account, session.started, now)
        || s.auth().ended_by_recovery(session.account, session.started)
    {
        return Err(Deny::SessionEnded);
    }
    // Step 2: P-72 and I-77, through fstp-auth.
    let holds = holds_management(s, session.account, now)?;
    let tenant = s.tenant().policy();
    let lifetimes = SessionLifetimes {
        idle_us: tenant.p72_idle_us(),
        absolute_us: tenant.p72_absolute_us(),
    };
    fstp_auth::admit_session(holds, session, now, &lifetimes).map_err(session_deny)
}

/// The checks of design section 5.4 after the route-only refusal: the
/// session, the log readers and the step-up. The route admissions call it
/// for their own command once their proof verified.
fn admit_in_session(
    s: &CellState,
    session: &SessionView,
    action: Action,
    command: Option<[u8; 16]>,
    stepup: Option<&StepUpView>,
    now: Timestamp,
    policy: &LoginPolicy,
) -> Result<Admitted, Deny> {
    session_checks(s, session, now)?;
    let tenant = s.tenant().policy();
    // The audit and erasure logs are read by tenant admins and Auditors
    // only (ADR-007 "Retention and erasure", G30, design section 8.7).
    if matches!(
        action,
        Action::Read(ReadAction::ReadAudit | ReadAction::ReadErasureLog)
    ) && !s.tenant().is_admin(session.account)
        && !holds_auditor(s, session.account, now)
    {
        return Err(Deny::NotPermitted);
    }
    // Step 3: I-78.
    let used = match HighRiskAction::of(&action)? {
        None => None,
        Some(high) => {
            let p71 = P71_DEFAULT_US
                .min(policy.stepup_freshness_us)
                .min(tenant.p71_us());
            Some(check_stepup(
                s, session, &action, command, stepup, high, now, p71,
            )?)
        }
    };
    Ok(Admitted {
        action,
        principal: Principal::Account(session.account),
        stepup: used,
        at: now,
        command,
        inputs: RouteInputs::none(),
    })
}

/// The step-up checks of design section 5.4 step 3, in order.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is one input of the designed check"
)]
fn check_stepup(
    s: &CellState,
    session: &SessionView,
    action: &Action,
    command: Option<[u8; 16]>,
    stepup: Option<&StepUpView>,
    high: HighRiskAction,
    now: Timestamp,
    p71_us: i64,
) -> Result<StepUpUse, Deny> {
    if !phishing_resistant(session.method) {
        return Err(Deny::MagicLinkSessionHighRisk);
    }
    let Some(u) = stepup else {
        return Err(Deny::StepUpRequired(high));
    };
    if u.session != session.id {
        return Err(Deny::StepUpMismatch);
    }
    let Action::Command(c) = action else {
        return Err(Deny::NotPermitted);
    };
    let Some(id) = command else {
        return Err(Deny::NotImplemented(
            "fstp_cell_core::gate::admit has no command id for the step-up digest: use gate::admit_command (design section 8.4)",
        ));
    };
    // A command whose canonical form does not name it alone has no digest,
    // so no step-up admits it (fail closed).
    let Some(want) = crate::try_action_digest(c, id) else {
        return Err(Deny::NotPermitted);
    };
    if !fstp_crypto::constant_time_eq(&u.action_digest, &want) {
        return Err(Deny::StepUpMismatch);
    }
    // The step-up must exist in the ledger: every step-up is logged with
    // the action it authorised (`StepUpGranted`, design sections 5.4 and
    // 8.4). It authorises its recorded digest in its recorded session
    // only. A step-up the ledger never granted is no step-up.
    let Some(grant) = s.auth().stepup_grant(u.id) else {
        return Err(Deny::StepUpMismatch);
    };
    if !fstp_crypto::constant_time_eq(&grant.action_digest, &u.action_digest)
        || grant.session != session.id
    {
        return Err(Deny::StepUpMismatch);
    }
    if !u.strong {
        return Err(Deny::StepUpFromWeakMethod);
    }
    // P-71 holds for the caller's assertion instant and for the logged
    // one, the entry instant of the grant. A view that claims a later
    // assertion than the ledger logged gains nothing.
    if !within(u.asserted_at, now, p71_us) || !within(grant.granted_at, now, p71_us) {
        return Err(Deny::StepUpStale);
    }
    if u.consumed || s.auth().consumed(u.id) {
        return Err(Deny::StepUpStale);
    }
    // The commit checks freshness again from the earlier of the two
    // instants, so it is never later than either check above allows.
    Ok(StepUpUse {
        id: u.id,
        action_digest: u.action_digest,
        asserted_at: u.asserted_at.min(grant.granted_at),
        p71_us,
    })
}

/// Whether only a system path issues `c`: key records, scheduled session
/// ends, relationship records and operator tickets
/// ([`crate::SystemTask`]).
fn system_only(c: &CellCommand) -> bool {
    use crate::ops::OpsCommand;
    use crate::release::ReleaseCommand;
    matches!(
        c,
        CellCommand::Key(_)
            | CellCommand::Release(ReleaseCommand::RecordRelationship { .. })
            | CellCommand::Ops(
                OpsCommand::ApplyOperatorTicket { .. } | OpsCommand::EndSessionsAtBindingEnd { .. }
            )
            | CellCommand::Tenant(TenantCommand::IssueFirstAdminInvitation { .. })
    )
}

/// The route-only steps that no admission admits, each for want of a
/// proof this crate can verify. A session never admits them. So
/// `CellEngine::execute(Admitted)` cannot run them, and they fail closed.
///
/// - `GrantStepUp` from a `StepUp` alone (design section 8.4, I-78): only
///   `fstp_auth::stepup::verify_step_up` may vouch for an assertion, and a
///   `StepUp` has public fields. [`admit_verified_stepup`] runs that
///   verification over the assertion itself, through the in-house
///   `fstp-webauthn` edge (lane int5).
/// - `CompleteRecovery` (design section 8.5, I-79): the one-time enrolment
///   token or the email ceremony binds the caller to the case. Without it
///   the approving admin, who sees the case id, could enrol their own key
///   on the holder's account.
/// - `ProveRecoveryEmail` (design section 8.5): its proof is the email
///   token.
///
/// ADR-008 "Unset lifetimes" gives the recovery tokens no lifetime, so no
/// route verifies them yet.
pub const ROUTE_ADMISSION_SEAM: &str = "fstp_cell_core::gate admits no GrantStepUp from a StepUp alone, and no CompleteRecovery or ProveRecoveryEmail (design sections 8.4 and 8.5, lane W3a). A step-up is admitted only with its assertion, which admit_verified_stepup verifies through fstp_auth::stepup::verify_step_up. The recovery steps need the enrolment or email token, which has no lifetime (ADR-008 \"Unset lifetimes\")";

/// Whether only an auth route issues `c`, after it verified what the
/// record states (design sections 8.4, 8.5 and 8.7): `GrantStepUp` after a
/// step-up assertion, `ProveRecoveryEmail` after the email proof, and the
/// public or ceremony steps `RequestRecovery` and `CompleteRecovery`,
/// whose account holds no session. A session never admits them. Only
/// `RequestRecovery` has a route admission that admits today
/// ([`ROUTE_ADMISSION_SEAM`]).
fn route_only(c: &CellCommand) -> bool {
    use fstp_auth::AuthCommand as A;
    matches!(
        c,
        CellCommand::Auth(
            A::GrantStepUp { .. }
                | A::RequestRecovery { .. }
                | A::ProveRecoveryEmail { .. }
                | A::CompleteRecovery { .. }
        ) | CellCommand::Tenant(TenantCommand::EnrolByInvitation { .. })
    )
}

// ---------------------------------------------------------------------------
// Route admissions (design sections 8.3 to 8.5 and 8.7).
//
// Each takes what its route holds. A new passkey is verified here,
// through `fstp_auth`, from the browser's registration, so the batch's
// key is always the output of the gate's own verification. The other
// inputs are route data that can only restrict (session rows) or that
// names the cell (the deployment mode). A route admission whose proof
// this crate cannot verify runs its own checks and then refuses with
// `Deny::NotImplemented(ROUTE_ADMISSION_SEAM)`, so a refusal still names
// its cause and nothing is admitted on route data alone.

/// Why a route admission refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteDeny {
    /// The gate refused the session or the action (design section 5.4).
    Gate(Deny),
    /// The step-up assertion did not verify
    /// (`fstp_auth::stepup::verify_step_up`).
    StepUp(fstp_auth::stepup::StepUpDeny),
    /// The new passkey did not pass its enrolment checks
    /// (`fstp_auth::ceremony`).
    Enrol(fstp_auth::ceremony::EnrolDeny),
    /// The recovery completion was refused (`fstp_auth::recovery`).
    Recovery(fstp_auth::recovery::RecoveryDeny),
    /// The assertion names no live credential of the cell.
    UnknownCredential,
    /// The recovery case is not open.
    UnknownCase,
    /// The recovery case id is taken already.
    CaseTaken,
}

/// `POST /auth/stepup` (design section 8.4, I-78): the checks of
/// `GrantStepUp` for the step-up `stepup`, in `session`. It admits
/// nothing ([`ROUTE_ADMISSION_SEAM`]): the route calls
/// [`admit_verified_stepup`] with the assertion instead.
///
/// `stepup` would be the `stepup` member of the `Granted` that
/// `fstp_auth::stepup::verify_step_up` returned for the route's challenge,
/// and `credential` the id of the credential that asserted. But
/// `fstp_auth::stepup::StepUp` has public fields, so a caller can write
/// one with `uv: true` and no assertion behind it. This crate cannot name
/// the assertion type to verify it itself. So the gate checks what it can
/// against the session and the ledger, and then refuses:
///
/// - the session passes steps 1 and 2 of design section 5.4, and its
///   method is phishing resistant;
/// - `credential` is a live credential of the ledger, owned by the
///   session's account, so a stolen cookie with the thief's own passkey
///   is refused;
/// - the step-up names this session, a passkey with user verification,
///   asserted at `now`, and not consumed;
/// - then [`Deny::NotImplemented`] with [`ROUTE_ADMISSION_SEAM`], since
///   nothing proves that an assertion verified.
///
/// [`admit_verified_stepup`] verifies the assertion itself and runs the
/// command under the challenge id as its command id ([`crate::stepup_id`]).
///
/// # Errors
///
/// Always: the first check that fails, or the seam refusal.
pub fn admit_stepup_grant(
    s: &CellState,
    session: &SessionView,
    stepup: &fstp_auth::stepup::StepUp,
    credential: &[u8],
    now: Timestamp,
) -> Result<Admitted, RouteDeny> {
    use fstp_auth::stepup::StepUpDeny;
    session_checks(s, session, now).map_err(RouteDeny::Gate)?;
    if !phishing_resistant(session.method) {
        return Err(RouteDeny::StepUp(StepUpDeny::MagicLinkSession));
    }
    let owner = s
        .auth()
        .credential(credential)
        .filter(|c| !c.revoked)
        .map(|c| c.account)
        .ok_or(RouteDeny::UnknownCredential)?;
    if owner != session.account {
        return Err(RouteDeny::StepUp(StepUpDeny::OtherAccount));
    }
    let u = stepup;
    if u.session != session.id {
        return Err(RouteDeny::StepUp(StepUpDeny::OtherSession));
    }
    if !u.method.phishing_resistant() {
        return Err(RouteDeny::StepUp(StepUpDeny::WeakMethod));
    }
    if !u.uv {
        return Err(RouteDeny::StepUp(StepUpDeny::NoUserVerification));
    }
    if u.asserted_at != now {
        return Err(RouteDeny::StepUp(StepUpDeny::Stale));
    }
    if u.consumed {
        return Err(RouteDeny::StepUp(StepUpDeny::Consumed));
    }
    // I-78: a `StepUp` is no proof that an assertion verified, so the
    // grant fails closed. [`admit_verified_stepup`] takes the assertion.
    Err(RouteDeny::Gate(Deny::NotImplemented(ROUTE_ADMISSION_SEAM)))
}

/// `POST /auth/stepup` (design section 8.4, I-78): admits `GrantStepUp`
/// for the passkey assertion `assertion` over the step-up challenge of
/// `req`, in `session`.
///
/// The gate verifies the assertion itself, through
/// `fstp_auth::stepup::verify_step_up`, so the grant never rests on a
/// `StepUp` that a caller wrote by hand ([`admit_stepup_grant`]). In
/// order:
///
/// - the session passes steps 1 and 2 of design section 5.4, and its
///   method is phishing resistant;
/// - the assertion names a live credential of the ledger, with the sign
///   count `sign_count` of its operational row;
/// - `verify_step_up` verifies the assertion with UV over the challenge
///   `SHA-256("fstp-stepup-v1" || cell || session || action_digest ||
///   nonce)`, and the credential belongs to the session's account.
///
/// The command runs under the challenge id `req.id` as its command id, so
/// the step-up id is that challenge id (`crate::stepup_id`), and a replay
/// of the same assertion is a duplicate of the first grant (ADR-007). The
/// `Granted` it returns carries the new sign count for the route to
/// store.
///
/// # Errors
///
/// The first check that fails.
pub fn admit_verified_stepup(
    s: &CellState,
    session: &SessionView,
    req: &fstp_auth::stepup::StepUpRequest,
    assertion: &fstp_webauthn::AssertionResponse,
    sign_count: u32,
    now: Timestamp,
) -> Result<(Admitted, fstp_auth::stepup::Granted), RouteDeny> {
    use fstp_auth::stepup::StepUpDeny;
    session_checks(s, session, now).map_err(RouteDeny::Gate)?;
    if !phishing_resistant(session.method) {
        return Err(RouteDeny::StepUp(StepUpDeny::MagicLinkSession));
    }
    let (owner, stored) = s
        .auth()
        .stored_credential(&assertion.credential_id, sign_count)
        .ok_or(RouteDeny::UnknownCredential)?;
    let granted = fstp_auth::stepup::verify_step_up(session, req, assertion, &stored, owner, now)
        .map_err(RouteDeny::StepUp)?;
    let command = CellCommand::Auth(fstp_auth::AuthCommand::GrantStepUp {
        session: session.id,
        action_digest: req.action_digest,
    });
    Ok((
        Admitted {
            action: Action::Command(command),
            principal: Principal::Account(session.account),
            stepup: None,
            at: now,
            command: Some(req.id),
            inputs: RouteInputs::none(),
        },
        granted,
    ))
}

/// `POST /auth/invitations/{token}/register` (ceremony, design section
/// 8.3, G10, Q35): admits `EnrolByInvitation` for the invitation that
/// `proof` matches, with the new passkey that `reg` registers.
///
/// - The invitation is the one whose stored digest is the digest of the
///   proof: `split_token_digest` of two halves, `token_digest` of one
///   token. No invitation holds it: the token does not match.
/// - `fstp_auth::ceremony::admit_invitation`: unused, at most 72 hours
///   old at `now`, the shape of the proof is the shape of the invitation,
///   the digest matches in constant time, and the invitee holds no
///   passkey.
/// - `fstp_auth::ceremony::verify_fresh_passkey`, with UV required for
///   the first admin's invitation and for a holder of a management role
///   (ADR-008 "User verification"), and a credential id new to the cell.
///
/// No session acts, so the principal is [`Principal::Ceremony`] for the
/// invited account. The verified credential goes into the batch's inputs,
/// so `decide` records the key that `fstp_webauthn` verified. The command
/// runs under `command_id`.
///
/// # Errors
///
/// The first check that fails.
pub fn admit_invitation_enrolment(
    s: &CellState,
    proof: &fstp_auth::ceremony::InvitationProof,
    reg: &fstp_auth::ceremony::Registration<'_>,
    command_id: [u8; 16],
    now: Timestamp,
) -> Result<Admitted, RouteDeny> {
    use fstp_auth::ceremony::{
        EnrolDeny, InvitationProof, admit_invitation, split_token_digest, token_digest,
        verify_fresh_passkey,
    };
    let digest = match proof {
        InvitationProof::Token(t) => token_digest(t),
        InvitationProof::Halves(a, b) => split_token_digest(a, b),
    };
    let (id, inv) = s
        .auth()
        .invitation_by_digest(&digest)
        .ok_or(RouteDeny::Enrol(EnrolDeny::InvitationToken))?;
    let view = inv.ceremony_view(id);
    admit_invitation(&view, proof, s.auth().has_any_credential(inv.account), now)
        .map_err(RouteDeny::Enrol)?;
    let holds = holds_management(s, inv.account, now).map_err(RouteDeny::Gate)?;
    let known = |c: &[u8]| s.auth().is_registered(c);
    let cred =
        verify_fresh_passkey(reg, holds || inv.first_admin, &known).map_err(RouteDeny::Enrol)?;
    let command = CellCommand::Tenant(TenantCommand::EnrolByInvitation {
        invitation: id,
        credential: cred.id.clone(),
    });
    Ok(Admitted {
        action: Action::Command(command),
        principal: Principal::Ceremony(inv.account),
        stepup: None,
        at: now,
        command: Some(command_id),
        inputs: RouteInputs::none().with_credential(cred),
    })
}

/// Provisioning (design sections 8.3 and 9.2 step 10, Q35): admits
/// `IssueFirstAdminInvitation` of `invitation` for the new account
/// `account`, with the token digest `token_digest`, as the system task
/// `SystemTask::Provisioning` under `command_id`. The cell's deployment
/// mode `mode` is the task's input, so a SaaS cell records a split token.
/// `decide` applies the provisioning rule of
/// `fstp_auth::ceremony::issue_invitation`.
///
/// # Errors
///
/// [`admit_system`]'s refusal.
pub fn admit_first_admin_invitation(
    s: &CellState,
    invitation: [u8; 16],
    account: AccountId,
    token_digest: [u8; 32],
    mode: fstp_auth::recovery::Deployment,
    command_id: [u8; 16],
    now: Timestamp,
) -> Result<Admitted, Deny> {
    let action = Action::Command(CellCommand::Tenant(
        TenantCommand::IssueFirstAdminInvitation {
            invitation,
            account,
            token_digest,
        },
    ));
    let mut admitted = admit_system(s, action, SystemTask::Provisioning, command_id, now)?;
    admitted.inputs = std::mem::take(&mut admitted.inputs).with_mode(mode);
    Ok(admitted)
}

/// `POST /auth/passkeys` (high risk `AddPasskey`, design sections 8.3 and
/// 8.7): admits `RegisterCredential` of the passkey that `reg` registers,
/// for the session's own account.
///
/// The registration is verified first, with user verification required
/// for a management holder (ADR-008), and its credential id must be new
/// to the cell. The command names that id. It then passes every check of
/// [`admit_command`] under `command_id`, the step-up of `AddPasskey`
/// included, and `fstp_auth::ceremony::admit_add_passkey`: the account
/// holds a passkey already and the session is phishing resistant. The
/// verified credential goes into the batch's inputs, so `decide` records
/// the key that `fstp_webauthn` verified.
#[allow(
    clippy::too_many_arguments,
    reason = "the session, the registration, the command id, the step-up, the instant and the policy"
)]
pub fn admit_add_passkey(
    s: &CellState,
    session: &SessionView,
    reg: &fstp_auth::ceremony::Registration<'_>,
    command_id: [u8; 16],
    stepup: Option<&StepUpView>,
    now: Timestamp,
    policy: &LoginPolicy,
) -> Result<Admitted, RouteDeny> {
    session_checks(s, session, now).map_err(RouteDeny::Gate)?;
    let holds = holds_management(s, session.account, now).map_err(RouteDeny::Gate)?;
    let known = |id: &[u8]| s.auth().is_registered(id);
    let cred =
        fstp_auth::ceremony::verify_fresh_passkey(reg, holds, &known).map_err(RouteDeny::Enrol)?;
    let cmd = CellCommand::Auth(fstp_auth::AuthCommand::RegisterCredential {
        account: session.account,
        credential: cred.id.clone(),
    });
    let mut admitted = admit_in_session(
        s,
        session,
        Action::Command(cmd),
        Some(command_id),
        stepup,
        now,
        policy,
    )
    .map_err(RouteDeny::Gate)?;
    // The step-up passed above, as the check of the high-risk action.
    fstp_auth::ceremony::admit_add_passkey(
        s.auth().has_any_credential(session.account),
        session,
        Ok(()),
    )
    .map_err(RouteDeny::Enrol)?;
    admitted.inputs = std::mem::take(&mut admitted.inputs).with_credential(cred);
    Ok(admitted)
}

/// `POST /auth/recovery` (public, design sections 8.5 and 8.7): admits
/// `RequestRecovery` of case `case` for `account`, with the cell's
/// deployment mode `mode` as its input. The route draws `case` at random
/// and answers the same whether or not the account exists.
///
/// No session acts, so the principal is [`Principal::Ceremony`] for the
/// account the request names. The batch only opens a case and records the
/// path at request time. Every later step needs its own proof.
pub fn admit_recovery_request(
    s: &CellState,
    case: [u8; 16],
    account: AccountId,
    mode: fstp_auth::recovery::Deployment,
    command_id: [u8; 16],
    now: Timestamp,
) -> Result<Admitted, RouteDeny> {
    if s.auth().recovery(case).is_some() {
        return Err(RouteDeny::CaseTaken);
    }
    Ok(Admitted {
        action: Action::Command(CellCommand::Auth(fstp_auth::AuthCommand::RequestRecovery {
            case,
            account,
        })),
        principal: Principal::Ceremony(account),
        stepup: None,
        at: now,
        command: Some(command_id),
        inputs: RouteInputs::none().with_mode(mode),
    })
}

/// `POST /auth/recovery/{case}/complete` (ceremony, I-79, design sections
/// 8.5 and 8.7): the checks of `CompleteRecovery` of case `case` with the
/// new passkey that `reg` registers. It admits nothing yet
/// ([`ROUTE_ADMISSION_SEAM`]).
///
/// The path is recomputed from the holdings at `now` and the deployment
/// mode `mode`, and the case's recorded evidence, with the verified
/// operator ticket `ticket` for `OperatorProcess`, must complete it
/// (`fstp_auth::recovery::decide`). A role granted during an open email
/// recovery therefore makes it fail. The new passkey is then verified with
/// the UV rule of that path and a fresh credential id
/// (`fstp_auth::recovery::new_passkey`).
///
/// Then it refuses with [`Deny::NotImplemented`] and
/// [`ROUTE_ADMISSION_SEAM`]. Design section 8.5 binds the new passkey to
/// the holder: "a new passkey in the same ceremony" as the email proof,
/// or one "from a one-time enrolment token". Nothing here proves that the
/// caller holds that token or ceremony. The case id alone is no proof,
/// since the approving admin sees it in `.../{case}/approve`, and a
/// completion revokes every passkey of the holder and enrols the caller's
/// key. ADR-008 "Unset lifetimes" gives those tokens no lifetime, so no
/// route verifies them yet.
///
/// Once that proof exists, the admission carries `_rows`, the live
/// session rows of the holder that the completion ends, and runs under
/// `_command_id`. No record holds a host console command either, so
/// `HostConsole` never completes here.
///
/// # Errors
///
/// Always: the first check that fails, or the seam refusal.
#[allow(
    clippy::too_many_arguments,
    reason = "the case, the registration, the session rows, the mode, the ticket, the command id and the instant"
)]
pub fn admit_recovery_completion(
    s: &CellState,
    case: [u8; 16],
    reg: &fstp_auth::ceremony::Registration<'_>,
    _rows: SessionRows,
    mode: fstp_auth::recovery::Deployment,
    ticket: Option<fstp_auth::recovery::VerifiedTicket>,
    _command_id: [u8; 16],
    now: Timestamp,
) -> Result<Admitted, RouteDeny> {
    let c = crate::decide::recovery_case(s, case, ticket).map_err(|_| RouteDeny::UnknownCase)?;
    let roster = RosterView::from_roster(s.engine().core.roster(), now);
    let tenant = TenantView {
        admins: s.tenant().admins(),
    };
    fstp_auth::recovery::decide(&c, &roster, &tenant, mode).map_err(RouteDeny::Recovery)?;
    let known = |id: &[u8]| s.auth().is_registered(id);
    fstp_auth::recovery::new_passkey(reg, &c, &roster, &tenant, mode, &known)
        .map_err(RouteDeny::Recovery)?;
    // I-79: nothing binds the caller to the case, so the completion fails
    // closed.
    Err(RouteDeny::Gate(Deny::NotImplemented(ROUTE_ADMISSION_SEAM)))
}

/// Admits a command of a system task, which holds no session (design
/// sections 3.5 and 5.1). The erasure runner is admitted for key records
/// only. The timeline is admitted for `EndSessionsAtBindingEnd` and for M2
/// core commands, which `decide` then checks against `fstp_domain::due`.
/// Every read and every other command is refused with
/// [`Deny::NotPermitted`]. The command runs under `command_id`.
///
/// Only the cell's own tasks call it, never a request handler: a route
/// reaches [`admit_command`] with a session (design section 5.4).
pub fn admit_system(
    s: &CellState,
    action: Action,
    task: SystemTask,
    command_id: [u8; 16],
    now: Timestamp,
) -> Result<Admitted, Deny> {
    let _ = s;
    let Action::Command(c) = &action else {
        return Err(Deny::NotPermitted);
    };
    let admitted = match (task, c) {
        (SystemTask::ErasureRunner, CellCommand::Key(_)) => true,
        (
            SystemTask::Timeline,
            CellCommand::Ops(crate::ops::OpsCommand::EndSessionsAtBindingEnd { .. }),
        ) => true,
        (SystemTask::Timeline, CellCommand::Engine(fstp_engine::Command::Core(core))) => {
            !matches!(core, fstp_domain::Command::VaultChanged { .. })
        }
        (SystemTask::Timeline, CellCommand::Timeline(_)) => true,
        (
            SystemTask::Provisioning,
            CellCommand::Tenant(TenantCommand::IssueFirstAdminInvitation { .. }),
        ) => true,
        _ => false,
    };
    if !admitted {
        return Err(Deny::NotPermitted);
    }
    Ok(Admitted {
        action,
        principal: Principal::System(task),
        stepup: None,
        at: now,
        command: Some(command_id),
        inputs: RouteInputs::none(),
    })
}

/// Whether `authentication.md` counts the method as phishing resistant.
const fn phishing_resistant(m: Method) -> bool {
    matches!(m, Method::Passkey | Method::EudiWallet)
}

/// Whether `now - from <= limit_us` with `from <= now`. An overflow is
/// false.
fn within(from: Timestamp, now: Timestamp, limit_us: i64) -> bool {
    match now.micros().checked_sub(from.micros()) {
        Some(age) => age >= 0 && age <= limit_us,
        None => false,
    }
}

/// The accounts that hold a Drafting, Judging or Operations binding at
/// `now`: active, scheduled and suspended bindings count, voided ones do
/// not, and a binding counts until its scheduled end instant (design
/// section 8.2). A binding counts from its grant, even when its start lies
/// later, which is the strictest reading for I-77.
pub fn management_holders(s: &CellState, now: Timestamp) -> Vec<AccountId> {
    let mut out: Vec<AccountId> = s
        .engine()
        .core
        .roster()
        .bindings()
        .filter(|(_, b)| {
            b.group() != Group::Receiving && !b.voided() && b.scheduled_end.is_none_or(|e| now < e)
        })
        .map(|(_, b)| b.account)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Whether `a` holds a management role at `now`, through
/// `fstp_auth::holds_management` over the engine roster and the tenant
/// fold.
fn holds_management(s: &CellState, a: AccountId, now: Timestamp) -> Result<bool, Deny> {
    let roster = RosterView {
        management: management_holders(s, now),
    };
    let tenant = TenantView {
        admins: s.tenant().admins(),
    };
    fstp_auth::holds_management(&roster, &tenant, a, now).map_err(auth_deny)
}

fn auth_deny(e: AuthError) -> Deny {
    match e {
        AuthError::NotImplemented(op) => Deny::NotImplemented(op),
    }
}

fn session_deny(e: SessionDeny) -> Deny {
    match e {
        SessionDeny::SessionEnded => Deny::SessionEnded,
        SessionDeny::WeakSessionForRole => Deny::WeakSessionForRole,
        SessionDeny::NotImplemented(op) => Deny::NotImplemented(op),
    }
}

/// Whether `a` holds an active Auditor binding at `now`, in any programme.
/// The programme filter of what an Auditor reads (Q42, interim) is not a
/// gate rule.
fn holds_auditor(s: &CellState, a: AccountId, now: Timestamp) -> bool {
    s.engine().core.roster().bindings().any(|(_, b)| {
        b.account == a
            && b.role == Role::Auditor
            && b.active_at(now)
            && b.scheduled_end.is_none_or(|e| now < e)
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod review_tests {
    use super::*;
    use crate::driver::{DriverCore, Event, ExecError, Need, Step, VaultFault};

    /// Design section 5.2, `fstp_engine::Engine::execute_finding`: the
    /// driver follows the M2 engine step for step, and M2 never reads the
    /// vault for a finding command without questions. Today `DriverCore`
    /// asks the vault epoch first for every command, so a vault fault
    /// refuses a finding that M2 would decide (and append).
    #[test]
    fn review_finding_without_questions_never_reads_the_vault() {
        let cmd = CellCommand::Engine(fstp_engine::Command::Finding(
            fstp_engine::FindingCommand::Regenerate {
                call: fstp_domain::id::CallId::from_raw(1),
                config: fstp_domain::id::LlmConfigId::from_raw(1),
                config_model: fstp_domain::policy::ModelRef("m".to_owned()),
                findings: Vec::new(),
            },
        ));
        let admitted = Admitted {
            action: Action::Command(cmd),
            principal: Principal::Account(AccountId::from_raw(101)),
            stepup: None,
            at: Timestamp::from_micros(1_000_000),
            command: Some([0x31; 16]),
            inputs: RouteInputs::none(),
        };
        let mut d = DriverCore::start(admitted);
        let mut s = CellState::genesis();
        let mut ev = None;
        for _ in 0..32 {
            match d.step(&mut s, ev.take()) {
                Step::Need(Need::ReadFrom(_)) => ev = Some(Event::Read(Vec::new())),
                Step::Need(Need::Epoch) => {
                    ev = Some(Event::Epoch(Err(VaultFault::Unavailable)));
                }
                Step::Need(Need::Append { .. }) => return,
                Step::Need(n) => panic!("a finding without questions needed {n:?}"),
                Step::Done(r) => {
                    assert_ne!(
                        r,
                        Err(ExecError::VaultFault),
                        "a finding without questions failed on the vault"
                    );
                    return;
                }
            }
        }
        panic!("the driver did not finish");
    }
}
