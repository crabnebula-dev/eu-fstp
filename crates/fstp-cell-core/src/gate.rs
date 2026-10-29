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
//!    and including a scheduled end (section 8.2).
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
//! ends ([`crate::SystemTask`]). Nor does it admit `GrantStepUp` through
//! the command path: design section 8.4 records `StepUpGranted` only after
//! `POST /auth/stepup` verified an assertion, and that route has no
//! admission of its own yet (fail closed). [`admit_system`] admits a
//! system task's own commands, with no session.
//!
//! Lane W2c. Steps 1 and 3 are this crate's. Step 2 calls `fstp-auth`,
//! which lane W2b builds in parallel. Until it lands, the stub refuses,
//! and the gate passes that on as [`Deny::NotImplemented`].

use fstp_auth::{
    AuthError, Method, RosterView, SessionDeny, SessionLifetimes, SessionView, TenantView,
};
use fstp_domain::id::AccountId;
use fstp_domain::roles::{Group, Role};
use fstp_domain::time::Timestamp;

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
    /// A check the gate needs is not available yet: an `fstp-auth`
    /// operation that is still a W0 stub (lane W2b), or the step-up digest
    /// check through [`admit`], which has no command id. It names the
    /// operation.
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
    // System commands and the step-up record never come through a
    // session (module documentation). This reads no session, so it runs
    // first.
    if let Action::Command(c) = &action
        && (system_only(c)
            || matches!(
                c,
                CellCommand::Auth(fstp_auth::AuthCommand::GrantStepUp { .. })
            ))
    {
        return Err(Deny::NotPermitted);
    }
    // Step 1: a record or a binding end ended the session.
    if s.auth().session_ended(session.id)
        || s.binding_ended_between(session.account, session.started, now)
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
    fstp_auth::admit_session(holds, session, now, &lifetimes).map_err(session_deny)?;
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
    if s.auth().stepup(u.id).is_some_and(|d| d != u.action_digest) {
        return Err(Deny::StepUpMismatch);
    }
    if !u.strong {
        return Err(Deny::StepUpFromWeakMethod);
    }
    if !within(u.asserted_at, now, p71_us) {
        return Err(Deny::StepUpStale);
    }
    if u.consumed || s.auth().consumed(u.id) {
        return Err(Deny::StepUpStale);
    }
    Ok(StepUpUse {
        id: u.id,
        action_digest: u.action_digest,
        asserted_at: u.asserted_at,
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
    )
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
