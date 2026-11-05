//! The reference login, session, step-up, SoD-07 self-grant approval,
//! recovery, first-passkey and break-glass rules (I-77, I-78, I-79,
//! R-LG-04, SoD-07, SoD-08). Lane W1b owns this file.
//!
//! The reference is written from `SPEC/03-architecture/authentication.md`,
//! ADR-008 and design section 8, not from `fstp-auth` or `fstp-cell-core`.
//! It names no production predicate. It uses M2 types only as data, and
//! it classifies roles by its own transcription of the roles table.
//!
//! Every function is pure and total. No function panics, and every time
//! comparison uses checked arithmetic, so an overflow refuses.
//!
//! Readings the sources leave open are marked "Reading" in the item that
//! takes them. Each one is reported to Daniel by lane W1b.
//!
//! The compile-fail twins of design section 14.4 sit in the doc-only
//! modules [`i78_route_without_risk_class_does_not_compile`] and
//! [`i78_stepup_proof_cannot_be_built_outside_the_gate`].

use fstp_domain::id::AccountId;
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;

// ---------------------------------------------------------------------------
// Constants (ADR-008 "Constants", `policy-parameters.md`).

/// One second in microseconds.
pub const SECOND_US: i64 = 1_000_000;
/// One minute in microseconds.
pub const MINUTE_US: i64 = 60 * SECOND_US;
/// One hour in microseconds.
pub const HOUR_US: i64 = 60 * MINUTE_US;

/// P-71, step-up freshness: 5 minutes (proposed). A tenant may only shorten it.
pub const P71_DEFAULT_US: i64 = 5 * MINUTE_US;
/// P-72, idle session lifetime: 30 minutes (proposed).
pub const P72_IDLE_US: i64 = 30 * MINUTE_US;
/// P-72, absolute session lifetime: 12 hours (proposed).
pub const P72_ABSOLUTE_US: i64 = 12 * HOUR_US;
/// The invitation lifetime: 72 hours (ADR-008 constant, Q37).
pub const INVITATION_US: i64 = 72 * HOUR_US;
/// The longest break-glass grant: 4 hours (ADR-008 constant, Q37).
pub const BREAK_GLASS_MAX_US: i64 = 4 * HOUR_US;

/// The domain separation prefix of a step-up challenge (design section 8.4).
pub const STEPUP_CHALLENGE_PREFIX: &[u8] = b"fstp-stepup-v1";

// ---------------------------------------------------------------------------
// Roles and holdings (design section 8.2, ADR-008 "Methods in M3").

/// A role group of `roles-and-sod.md`, transcribed here on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefGroup {
    /// Programme manager and call drafter.
    Drafting,
    /// FSTP coordinator, committee member and chair, IRC member.
    Judging,
    /// Applicant, applicant team member and guardian.
    Receiving,
    /// Tenant admin, finance approver, payment releaser, contract signatory, auditor.
    Operations,
}

/// The group of `role`, from the roles table. Written out role by role,
/// so it does not reuse `Role::group`.
pub const fn role_group(role: Role) -> RefGroup {
    match role {
        Role::ProgrammeManager | Role::CallDrafter => RefGroup::Drafting,
        Role::FstpCoordinator | Role::CommitteeMember | Role::CommitteeChair | Role::IrcMember => {
            RefGroup::Judging
        }
        Role::Applicant | Role::ApplicantTeamMember | Role::Guardian => RefGroup::Receiving,
        Role::TenantAdmin
        | Role::FinanceApprover
        | Role::PaymentReleaser
        | Role::ContractSignatory
        | Role::FinancialSignatory
        | Role::LegalSignatory
        | Role::Auditor => RefGroup::Operations,
    }
}

/// Whether a binding of `role` is a management holding for I-77 and I-79.
pub const fn is_management_role(role: Role) -> bool {
    !matches!(role_group(role), RefGroup::Receiving)
}

/// One role binding as the reference sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefBinding {
    /// The account.
    pub account: AccountId,
    /// The role.
    pub role: Role,
    /// The end instant, recorded or scheduled. The binding holds before it.
    pub end: Option<Timestamp>,
    /// Whether the binding is suspended. A suspended binding still holds.
    pub suspended: bool,
    /// Whether the binding is voided. A voided binding never holds.
    pub voided: bool,
}

/// A tenant admin grant as the reference sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefAdmin {
    /// The account.
    pub account: AccountId,
    /// The end instant, if the grant ended. It holds before it.
    pub end: Option<Timestamp>,
}

/// The roster and tenant admin facts of one cell.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefRoster {
    /// Every binding, in any order.
    pub bindings: Vec<RefBinding>,
    /// Every tenant admin grant, in any order.
    pub admins: Vec<RefAdmin>,
}

/// Whether an interval that ends at `end` still holds at `now`.
fn before_end(end: Option<Timestamp>, now: Timestamp) -> bool {
    end.is_none_or(|e| now.micros() < e.micros())
}

impl RefRoster {
    /// Whether `a` is a tenant admin at `now`.
    pub fn is_admin(&self, a: AccountId, now: Timestamp) -> bool {
        self.admins
            .iter()
            .any(|g| g.account == a && before_end(g.end, now))
    }

    /// The tenant admins at `now`, sorted and without duplicates.
    pub fn admins_at(&self, now: Timestamp) -> Vec<AccountId> {
        let mut out: Vec<AccountId> = self
            .admins
            .iter()
            .filter(|g| before_end(g.end, now))
            .map(|g| g.account)
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Whether `a` holds a binding outside Receiving at `now`.
    ///
    /// Active, scheduled and suspended bindings count. Voided bindings do
    /// not. A binding with an end counts until that instant, and not at it.
    ///
    /// Reading: a binding counts from its grant, even when its start lies
    /// later. This is the strictest reading of "holding" for I-77.
    pub fn holds_binding(&self, a: AccountId, now: Timestamp) -> bool {
        self.bindings.iter().any(|b| {
            b.account == a && !b.voided && is_management_role(b.role) && before_end(b.end, now)
        })
    }

    /// Whether `a` holds a Drafting, Judging, Operations or tenant admin
    /// role at `now` (I-77, design section 8.2).
    pub fn holds_management(&self, a: AccountId, now: Timestamp) -> bool {
        self.holds_binding(a, now) || self.is_admin(a, now)
    }

    /// The accounts that hold a management binding at `now`, sorted. Tenant
    /// admin grants are not listed, as `fstp_auth::RosterView` keeps them apart.
    pub fn binding_holders_at(&self, now: Timestamp) -> Vec<AccountId> {
        let mut out: Vec<AccountId> = self
            .bindings
            .iter()
            .map(|b| b.account)
            .filter(|a| self.holds_binding(*a, now))
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Whether any binding or admin grant of `a` ended at an instant after
    /// `after` and at or before `upto` (design section 5.4 step 2, Q16 A).
    ///
    /// Every group counts, Receiving too, since the rule names "any
    /// binding of the account". A voided binding counts by its end.
    ///
    /// Reading, reported to Daniel: a session that started at the end
    /// instant did not start "before the end instant" (design section
    /// 8.2), so this check leaves it live. A recorded end at that instant
    /// still ends it in its batch ([`ended_by_binding_end`]).
    pub fn binding_ended_between(&self, a: AccountId, after: Timestamp, upto: Timestamp) -> bool {
        let inside = |end: Option<Timestamp>| {
            end.is_some_and(|e| after.micros() < e.micros() && e.micros() <= upto.micros())
        };
        self.bindings
            .iter()
            .any(|b| b.account == a && inside(b.end))
            || self.admins.iter().any(|g| g.account == a && inside(g.end))
    }

    /// The recovery holdings class of `a` at `now` (I-79).
    pub fn holdings(&self, a: AccountId, now: Timestamp) -> RefHoldings {
        if self.is_admin(a, now) {
            RefHoldings::TenantAdmin
        } else if self.holds_binding(a, now) {
            RefHoldings::Management
        } else {
            RefHoldings::ReceivingOnly
        }
    }

    /// The number of tenant admins at `now` other than `a`.
    pub fn other_admins(&self, a: AccountId, now: Timestamp) -> usize {
        self.admins_at(now).iter().filter(|x| **x != a).count()
    }
}

// ---------------------------------------------------------------------------
// Login methods (I-77, P-70, ADR-008 "Methods in M3").

/// A login method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefMethod {
    /// A passkey.
    Passkey,
    /// The EUDI Wallet. Refused until M4.
    EudiWallet,
    /// An OPAQUE password. Refused until an ADR-001 addition.
    Opaque,
    /// An email magic link.
    MagicLink,
}

impl RefMethod {
    /// Every method.
    pub const ALL: [RefMethod; 4] = [
        RefMethod::Passkey,
        RefMethod::EudiWallet,
        RefMethod::Opaque,
        RefMethod::MagicLink,
    ];

    /// Whether `authentication.md` counts the method as phishing resistant.
    pub const fn phishing_resistant(self) -> bool {
        matches!(self, RefMethod::Passkey | RefMethod::EudiWallet)
    }

    /// Whether M3 builds the method at all (Q10 A).
    pub const fn built_in_m3(self) -> bool {
        matches!(self, RefMethod::Passkey | RefMethod::MagicLink)
    }
}

/// The methods a tenant enables (P-70). Passkeys are always enabled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefEnabled {
    /// Magic links.
    pub magic_link: bool,
    /// The EUDI Wallet.
    pub eudi_wallet: bool,
    /// OPAQUE.
    pub opaque: bool,
}

impl RefEnabled {
    /// Whether the tenant offers `m`. M3 refuses the deferred methods.
    pub const fn offers(self, m: RefMethod) -> bool {
        match m {
            RefMethod::Passkey => true,
            RefMethod::MagicLink => self.magic_link,
            RefMethod::EudiWallet | RefMethod::Opaque => false,
        }
    }
}

/// Why the reference refuses a login.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefLoginDeny {
    /// The method is not phishing resistant, and the account holds a management role.
    WeakMethodForRole,
    /// The tenant does not offer the method, or M3 does not build it.
    MethodDisabled,
    /// A management holder's passkey gave no user verification.
    NoUserVerification,
}

/// The login rule (I-77, ADR-008 "User verification").
///
/// `uv` says whether the authenticator gave user verification. It matters
/// only for a phishing-resistant method of a holder.
pub fn admit_login(
    holds: bool,
    m: RefMethod,
    uv: bool,
    enabled: RefEnabled,
) -> Result<(), RefLoginDeny> {
    if holds && !m.phishing_resistant() {
        return Err(RefLoginDeny::WeakMethodForRole);
    }
    if !m.built_in_m3() || !enabled.offers(m) {
        return Err(RefLoginDeny::MethodDisabled);
    }
    if holds && !uv {
        return Err(RefLoginDeny::NoUserVerification);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sessions (design section 8.2, P-72, R-LG-04).

/// The session lifetimes of P-72, in microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefLifetimes {
    /// The idle lifetime.
    pub idle_us: i64,
    /// The absolute lifetime.
    pub absolute_us: i64,
}

impl RefLifetimes {
    /// The proposed defaults of P-72.
    pub const DEFAULT: RefLifetimes = RefLifetimes {
        idle_us: P72_IDLE_US,
        absolute_us: P72_ABSOLUTE_US,
    };
}

/// Why a session ended by a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EndCause {
    /// The user ended it (R-LG-04).
    User,
    /// A grant of a management role ended a weak session (I-77).
    Grant,
    /// A binding of the account ended (Q16 A).
    BindingEnd,
    /// A recovery completed (Q15).
    Recovery,
    /// A device was removed. Reading: removing a device ends the sessions
    /// it logged in (R-LG-04).
    DeviceRemoved,
}

/// One session as the reference sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefSession {
    /// The session id.
    pub id: [u8; 16],
    /// The account.
    pub account: AccountId,
    /// The login method.
    pub method: RefMethod,
    /// The device, for a passkey session: an index into the account's devices.
    pub device: Option<u8>,
    /// When the session started.
    pub started: Timestamp,
    /// When the session was last used.
    pub last_used: Timestamp,
    /// When and why a record ended it.
    pub ended: Option<(Timestamp, EndCause)>,
}

/// Why the reference refuses a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefSessionDeny {
    /// A record ended the session.
    Ended,
    /// The idle or absolute lifetime ran out, or the clock is before the start.
    Expired,
    /// A binding of the account ended after the session started (Q16 A).
    BindingEnded,
    /// A weak session of a management holder (I-77).
    WeakSessionForRole,
}

/// Whether `now - from <= limit`, with `from <= now`. An overflow is false.
pub fn within(from: Timestamp, now: Timestamp, limit_us: i64) -> bool {
    match now.micros().checked_sub(from.micros()) {
        Some(age) => age >= 0 && age <= limit_us,
        None => false,
    }
}

/// The session rule at `now` (I-77, design sections 5.4 and 8.2).
///
/// `binding_ended` is [`RefRoster::binding_ended_between`] over the
/// session's start and `now`.
///
/// Reading: a session is live while its idle and absolute ages are at
/// most the P-72 limits, as P-71 freshness reads "no older than".
///
/// Reading: the rule does not look at user verification, as
/// [`ended_by_grant`] explains.
pub fn admit_session(
    holds: bool,
    s: &RefSession,
    binding_ended: bool,
    now: Timestamp,
    p72: RefLifetimes,
) -> Result<(), RefSessionDeny> {
    if s.ended.is_some_and(|(at, _)| at.micros() <= now.micros()) {
        return Err(RefSessionDeny::Ended);
    }
    if !within(s.started, now, p72.absolute_us) || !within(s.last_used, now, p72.idle_us) {
        return Err(RefSessionDeny::Expired);
    }
    if binding_ended {
        return Err(RefSessionDeny::BindingEnded);
    }
    if holds && !s.method.phishing_resistant() {
        return Err(RefSessionDeny::WeakSessionForRole);
    }
    Ok(())
}

/// The sessions that a grant of a management role to `account` ends in
/// its own batch: every live weak session of the account (ADR-008).
///
/// Reading, reported to Daniel: a passkey session whose login gave no user
/// verification is not weak, so a later grant leaves it live. A passkey
/// without UV is still phishing resistant, which is what I-77 asks. ADR-008
/// requires UV for every login of a management account, and this login
/// came before the grant. The stricter reading would end such sessions in
/// the grant batch. [`RefSession`] records no UV, so that reading needs a
/// session field first. Every M-AUTH login gives UV, so no model run
/// depends on this choice.
pub fn ended_by_grant(
    sessions: &[RefSession],
    account: AccountId,
    now: Timestamp,
) -> Vec<[u8; 16]> {
    sessions
        .iter()
        .filter(|s| s.account == account && !s.method.phishing_resistant())
        .filter(|s| s.ended.is_none_or(|(at, _)| at.micros() > now.micros()))
        .map(|s| s.id)
        .collect()
}

/// The sessions that the batch of a binding end of `account` recorded at
/// `at` ends: every live session of the account that started at or before
/// `at` (Q16 A).
///
/// Reading, reported to Daniel: design section 5.1 says the batch "ends
/// every session of the account", and section 8.2 says "started before the
/// end instant". A session that started at the same microsecond as a
/// recorded end or suspension ran before that batch, so this rule takes the
/// stricter section 5.1 reading and ends it too. The gate's check of a
/// scheduled end keeps the section 8.2 rule
/// ([`RefRoster::binding_ended_between`]), so a login after the batch at
/// the same instant stays live.
pub fn ended_by_binding_end(
    sessions: &[RefSession],
    account: AccountId,
    at: Timestamp,
) -> Vec<[u8; 16]> {
    sessions
        .iter()
        .filter(|s| s.account == account && s.started.micros() <= at.micros())
        .filter(|s| s.ended.is_none_or(|(e, _)| e.micros() > at.micros()))
        .map(|s| s.id)
        .collect()
}

/// The sessions that a conflict-of-interest suspension of a binding of
/// `account` at `at` ends: the same set as a binding end (design section
/// 5.1 "Reactions": "An ended, suspended or voided binding of those groups
/// ends every session of the account").
///
/// The suspended binding still holds (design section 8.2), so the account
/// may log in again by passkey only.
pub fn ended_by_suspension(
    sessions: &[RefSession],
    account: AccountId,
    at: Timestamp,
) -> Vec<[u8; 16]> {
    ended_by_binding_end(sessions, account, at)
}

/// The sessions that revoking `account`'s credential on `device` ends:
/// every live passkey session that device logged in.
///
/// Reading, reported to Daniel: revoking a credential is removing its
/// device (R-LG-04, [`EndCause::DeviceRemoved`]), so it ends the sessions
/// that device logged in, and no other session.
pub fn ended_by_credential_revocation(
    sessions: &[RefSession],
    account: AccountId,
    device: u8,
    at: Timestamp,
) -> Vec<[u8; 16]> {
    sessions
        .iter()
        .filter(|s| s.account == account && s.device == Some(device))
        .filter(|s| s.method.phishing_resistant())
        .filter(|s| s.ended.is_none_or(|(e, _)| e.micros() > at.micros()))
        .map(|s| s.id)
        .collect()
}

/// What a user may see and end (R-LG-04).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefAccountOp {
    /// `GET /auth/sessions`.
    ListSessions,
    /// `DELETE /auth/sessions/{id}`.
    EndSession([u8; 16]),
    /// `GET /auth/devices`.
    ListDevices,
    /// `DELETE /auth/devices/{id}`: the high-risk action `ChangeLoginMethods`.
    RemoveDevice(u8),
}

/// The sessions `account` sees in `GET /auth/sessions` under `roster`:
/// its own live sessions and no other account's (R-LG-04).
///
/// A session is listed only when the gate would admit it now
/// ([`admit_session`]). So a session refused for a binding end, or as a
/// weak session of a holder, is not listed as live.
pub fn listed_sessions(
    roster: &RefRoster,
    sessions: &[RefSession],
    account: AccountId,
    now: Timestamp,
    p72: RefLifetimes,
) -> Vec<[u8; 16]> {
    let holds = roster.holds_management(account, now);
    let mut out: Vec<[u8; 16]> = sessions
        .iter()
        .filter(|s| s.account == account)
        .filter(|s| {
            let ended = roster.binding_ended_between(account, s.started, now);
            admit_session(holds, s, ended, now, p72).is_ok()
        })
        .map(|s| s.id)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Whether `actor` may end session `id` through `DELETE /auth/sessions/{id}`.
/// Only the session's own account may, and only a live session.
pub fn may_end_session(sessions: &[RefSession], actor: AccountId, id: [u8; 16]) -> bool {
    sessions
        .iter()
        .any(|s| s.id == id && s.account == actor && s.ended.is_none())
}

// ---------------------------------------------------------------------------
// High-risk actions and step-up (I-78, design section 8.4).

/// A high-risk action, transcribed from design section 8.4 on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefHighRisk {
    /// Granting or changing a Drafting, Judging, Operations or tenant admin role.
    ManagementRoleChange,
    /// A tenant export.
    TenantExport,
    /// A vault export.
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
    /// Changing bank details.
    ChangeBankDetails,
    /// Approving a payment.
    ApprovePayment,
    /// Releasing a payment.
    ReleasePayment,
    /// Activating a programme; creating one counts.
    ActivateProgramme,
    /// Publishing a call.
    PublishCall,
    /// Publishing a template to other tenants.
    PublishTemplate,
    /// Approving break-glass access.
    ApproveBreakGlass,
    /// Approving an account recovery.
    ApproveRecovery,
}

/// The high-risk class of the command or action named `name`, from design
/// section 8.4 and ADR-008. `None` for every other name.
pub fn high_risk_of(name: &str) -> Option<RefHighRisk> {
    use RefHighRisk as H;
    let class = match name {
        "GrantRole" | "EndRole" | "ReinstateBinding" | "GrantTenantAdmin" | "EndTenantAdmin"
        | "ApproveSelfGrant" | "Assign" | "Unassign" => H::ManagementRoleChange,
        "TenantExport" => H::TenantExport,
        "VaultExport" => H::VaultExport,
        "IdentityDownload" => H::IdentityDownload,
        "AddPasskey" => H::AddPasskey,
        "LinkDevice" => H::LinkDevice,
        "DesktopSignIn" => H::DesktopSignIn,
        "ChangeEmail" => H::ChangeEmail,
        "ChangeLoginMethods" | "SetLoginPolicy" => H::ChangeLoginMethods,
        "ChangeBankDetails" => H::ChangeBankDetails,
        "ApprovePayment" => H::ApprovePayment,
        "ReleasePayment" => H::ReleasePayment,
        "CreateProgramme" => H::ActivateProgramme,
        "PublishCall" => H::PublishCall,
        "PublishTemplate" => H::PublishTemplate,
        "ApproveBreakGlass" => H::ApproveBreakGlass,
        "ApproveRecovery" => H::ApproveRecovery,
        _ => return None,
    };
    Some(class)
}

/// Every command or action name that [`high_risk_of`] classifies.
pub const HIGH_RISK_NAMES: [&str; 25] = [
    "GrantRole",
    "EndRole",
    "ReinstateBinding",
    "GrantTenantAdmin",
    "EndTenantAdmin",
    "ApproveSelfGrant",
    "Assign",
    "Unassign",
    "TenantExport",
    "VaultExport",
    "IdentityDownload",
    "AddPasskey",
    "LinkDevice",
    "DesktopSignIn",
    "ChangeEmail",
    "ChangeLoginMethods",
    "SetLoginPolicy",
    "ChangeBankDetails",
    "ApprovePayment",
    "ReleasePayment",
    "CreateProgramme",
    "PublishCall",
    "PublishTemplate",
    "ApproveBreakGlass",
    "ApproveRecovery",
];

/// `action_digest = SHA-256(canonical(command) || command_id)` (design section 8.4).
pub fn action_digest(canonical_command: &[u8], command_id: [u8; 16]) -> [u8; 32] {
    let mut input = Vec::with_capacity(canonical_command.len().saturating_add(16));
    input.extend_from_slice(canonical_command);
    input.extend_from_slice(&command_id);
    fstp_crypto::sha256(&input)
}

/// The step-up challenge
/// `SHA-256("fstp-stepup-v1" || cell || session || action_digest || nonce)`.
///
/// Reading: the design concatenates a cell id of any length with no
/// length prefix. This reference takes the cell id as given, so a
/// 16-byte cell id keeps the input unambiguous.
pub fn stepup_challenge(
    cell: &[u8],
    session: [u8; 16],
    digest: [u8; 32],
    nonce: &[u8],
) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(STEPUP_CHALLENGE_PREFIX);
    input.extend_from_slice(cell);
    input.extend_from_slice(&session);
    input.extend_from_slice(&digest);
    input.extend_from_slice(nonce);
    fstp_crypto::sha256(&input)
}

/// A step-up as the reference sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefStepUp {
    /// The step-up id.
    pub id: [u8; 16],
    /// The session it was made in.
    pub session: [u8; 16],
    /// The action digest it authorises.
    pub action_digest: [u8; 32],
    /// When the assertion was made.
    pub asserted_at: Timestamp,
    /// The method of the assertion.
    pub method: RefMethod,
    /// Whether the authenticator gave user verification.
    pub uv: bool,
    /// Whether a committed command consumed it.
    pub consumed: bool,
}

/// Why the reference refuses a high-risk action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefStepUpDeny {
    /// The session is a magic-link session, which never performs a high-risk action.
    MagicLinkSession,
    /// No step-up was named.
    Required,
    /// The step-up belongs to another session.
    OtherSession,
    /// The step-up authorises another command.
    OtherCommand,
    /// The step-up used a method that is not phishing resistant.
    WeakMethod,
    /// The step-up gave no user verification.
    NoUserVerification,
    /// The step-up is older than P-71, or dated after `now`.
    Stale,
    /// A committed command already consumed the step-up.
    Consumed,
}

/// The P-71 a tenant value gives: the default when unset, and never longer.
pub fn effective_p71(tenant_us: Option<i64>) -> i64 {
    match tenant_us {
        Some(v) if v > 0 && v <= P71_DEFAULT_US => v,
        Some(_) | None => P71_DEFAULT_US,
    }
}

/// Why the reference refuses a login policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefPolicyDeny {
    /// P-71 above the default: it may only shorten.
    P71Longer,
    /// P-71 of zero or less.
    P71NotPositive,
}

/// The rule for a tenant P-71 value in `SetLoginPolicy` (I-78, P-71).
pub fn validate_p71(tenant_us: i64) -> Result<(), RefPolicyDeny> {
    if tenant_us <= 0 {
        Err(RefPolicyDeny::P71NotPositive)
    } else if tenant_us > P71_DEFAULT_US {
        Err(RefPolicyDeny::P71Longer)
    } else {
        Ok(())
    }
}

/// The step-up rule for one high-risk command at `now` (I-78, ADR-008
/// "Step-up"). It holds at admission and again at commit.
pub fn admit_high_risk(
    session: &RefSession,
    digest: [u8; 32],
    stepup: Option<&RefStepUp>,
    now: Timestamp,
    p71_us: i64,
) -> Result<(), RefStepUpDeny> {
    if !session.method.phishing_resistant() {
        return Err(RefStepUpDeny::MagicLinkSession);
    }
    let Some(u) = stepup else {
        return Err(RefStepUpDeny::Required);
    };
    if u.session != session.id {
        return Err(RefStepUpDeny::OtherSession);
    }
    if u.action_digest != digest {
        return Err(RefStepUpDeny::OtherCommand);
    }
    if !u.method.phishing_resistant() {
        return Err(RefStepUpDeny::WeakMethod);
    }
    if !u.uv {
        return Err(RefStepUpDeny::NoUserVerification);
    }
    if !within(u.asserted_at, now, p71_us) {
        return Err(RefStepUpDeny::Stale);
    }
    if u.consumed {
        return Err(RefStepUpDeny::Consumed);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The SoD-07 self-grant approval (design section 5.1, TH-05, Q40).

/// `grant_digest = SHA-256(canonical(GrantRole without second_admin) || command_id)`
/// (design section 5.1). The caller passes the canonical grant with its
/// `second_admin` field already removed.
pub fn self_grant_digest(canonical_grant: &[u8], command_id: [u8; 16]) -> [u8; 32] {
    action_digest(canonical_grant, command_id)
}

/// One recorded `SelfGrantApproved`, as the reference sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefSelfGrantApproval {
    /// The approving tenant admin.
    pub approver: AccountId,
    /// The grant digest it approves.
    pub grant_digest: [u8; 32],
    /// When the approval's step-up was asserted. The approval lapses P-71
    /// after it (Q40).
    pub stepup_at: Timestamp,
    /// Whether a grant batch recorded `SelfGrantApprovalUsed` for it.
    pub used: bool,
}

/// Why the reference refuses a self-grant (SoD-07).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefSelfGrantDeny {
    /// No approval of any digest exists.
    NoApproval,
    /// Every approval approves another digest.
    OtherDigest,
    /// The only approvals of the digest are by the grantor.
    ApproverIsGrantor,
    /// The only approvals of the digest are by accounts that are not
    /// current tenant admins.
    ApproverNotAdmin,
    /// The only approvals of the digest are older than P-71.
    Expired,
    /// The only approvals of the digest were used by a grant already.
    Used,
}

/// The SoD-07 rule for a grant by `grantor` to `grantee` with digest
/// `digest` at `now` (design section 5.1). `Ok(None)` when the grant is
/// not a self-grant. `Ok(Some(i))` names the approval the grant uses, so
/// its batch records `SelfGrantApprovalUsed` for approval `i` only.
///
/// An approval admits the grant when it matches the digest, is unused, is
/// no older than P-71 from its step-up, and comes from a current tenant
/// admin other than the grantor. Each refusal names the first failed check
/// among the approvals of the digest.
///
/// Reading: "has not expired" reads as P-71 freshness does, "no older
/// than", so an approval exactly P-71 old still admits.
pub fn admit_self_grant(
    roster: &RefRoster,
    grantor: AccountId,
    grantee: AccountId,
    digest: [u8; 32],
    approvals: &[RefSelfGrantApproval],
    now: Timestamp,
    p71_us: i64,
) -> Result<Option<usize>, RefSelfGrantDeny> {
    if grantor != grantee {
        return Ok(None);
    }
    if approvals.is_empty() {
        return Err(RefSelfGrantDeny::NoApproval);
    }
    let check = |a: &RefSelfGrantApproval| -> Result<(), RefSelfGrantDeny> {
        if a.used {
            Err(RefSelfGrantDeny::Used)
        } else if a.approver == grantor {
            Err(RefSelfGrantDeny::ApproverIsGrantor)
        } else if !roster.is_admin(a.approver, now) {
            Err(RefSelfGrantDeny::ApproverNotAdmin)
        } else if !within(a.stepup_at, now, p71_us) {
            Err(RefSelfGrantDeny::Expired)
        } else {
            Ok(())
        }
    };
    let mut first = RefSelfGrantDeny::OtherDigest;
    let mut seen = false;
    for (i, a) in approvals.iter().enumerate() {
        if a.grant_digest != digest {
            continue;
        }
        match check(a) {
            Ok(()) => return Ok(Some(i)),
            Err(d) if !seen => {
                first = d;
                seen = true;
            }
            Err(_) => {}
        }
    }
    Err(first)
}

// ---------------------------------------------------------------------------
// Routes (design section 8.7).

/// The risk class of a cell route, transcribed from design section 8.7.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefRisk {
    /// No session.
    Public,
    /// A first-passkey ceremony (design section 8.3).
    Ceremony,
    /// A session, with no step-up.
    Session,
    /// A high-risk action.
    HighRisk(RefHighRisk),
    /// Classified per command through `HighRiskAction::of`.
    PerCommand,
    /// A session, with `IdentityDownload` for the download scope.
    SessionOrIdentityDownload,
    /// A session of an Auditor or tenant admin.
    AuditorOrAdmin,
    /// A session of a tenant admin with a verified identity (ADR-008).
    VerificationTicket,
    /// Loopback only.
    Loopback,
}

/// One route of design section 8.7.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefRoute {
    /// The HTTP method.
    pub method: &'static str,
    /// The path.
    pub path: &'static str,
    /// The risk class.
    pub risk: RefRisk,
}

const fn route(method: &'static str, path: &'static str, risk: RefRisk) -> RefRoute {
    RefRoute { method, path, risk }
}

/// The cell routes of M3 (design section 8.7).
pub const ROUTES: &[RefRoute] = &[
    route(
        "POST",
        "/auth/invitations/{token}/register/options",
        RefRisk::Ceremony,
    ),
    route(
        "POST",
        "/auth/invitations/{token}/register",
        RefRisk::Ceremony,
    ),
    route("POST", "/auth/signup/options", RefRisk::Ceremony),
    route("POST", "/auth/signup", RefRisk::Ceremony),
    route("POST", "/auth/passkey/login/options", RefRisk::Public),
    route("POST", "/auth/passkey/login", RefRisk::Public),
    route("POST", "/auth/magic/request", RefRisk::Public),
    route("GET", "/auth/magic", RefRisk::Public),
    route("POST", "/auth/magic/consume", RefRisk::Public),
    route("POST", "/auth/stepup/options", RefRisk::Session),
    route("POST", "/auth/stepup", RefRisk::Session),
    route(
        "POST",
        "/auth/passkeys/options",
        RefRisk::HighRisk(RefHighRisk::AddPasskey),
    ),
    route(
        "POST",
        "/auth/passkeys",
        RefRisk::HighRisk(RefHighRisk::AddPasskey),
    ),
    route("GET", "/auth/sessions", RefRisk::Session),
    route("DELETE", "/auth/sessions/{id}", RefRisk::Session),
    route("GET", "/auth/devices", RefRisk::Session),
    route(
        "DELETE",
        "/auth/devices/{id}",
        RefRisk::HighRisk(RefHighRisk::ChangeLoginMethods),
    ),
    route("POST", "/auth/recovery", RefRisk::Public),
    route("POST", "/auth/recovery/{case}/email", RefRisk::Public),
    route(
        "POST",
        "/auth/recovery/{case}/approve",
        RefRisk::HighRisk(RefHighRisk::ApproveRecovery),
    ),
    route("POST", "/auth/recovery/{case}/complete", RefRisk::Ceremony),
    route("POST", "/api/v1/commands", RefRisk::PerCommand),
    route(
        "POST",
        "/api/v1/vault-tickets",
        RefRisk::SessionOrIdentityDownload,
    ),
    route("POST", "/api/v1/verifications", RefRisk::VerificationTicket),
    route("GET", "/api/v1/audit/anchors", RefRisk::AuditorOrAdmin),
    route("GET", "/api/v1/erasures", RefRisk::AuditorOrAdmin),
    route("GET", "/healthz", RefRisk::Loopback),
];

// ---------------------------------------------------------------------------
// Recovery (I-79, design section 8.5, ADR-008 "Recovery").

/// The holdings class that decides a recovery path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefHoldings {
    /// Receiving roles only, or no role.
    ReceivingOnly,
    /// A role outside Receiving, and not tenant admin.
    Management,
    /// Tenant admin.
    TenantAdmin,
}

/// How the cell is deployed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefDeployment {
    /// Hosted by CrabNebula.
    Saas,
    /// Self-hosted.
    SelfHosted,
}

/// A recovery path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefPath {
    /// Email proof, then a new passkey.
    EmailThenPasskey,
    /// Email proof, approval by another current tenant admin with a step-up, then a new passkey.
    SecondAdmin,
    /// Email proof, an operator ticket with two staff approvals, then a new passkey.
    OperatorProcess,
    /// A host console command as root with custody access, then a new passkey.
    HostConsole,
}

/// The recovery path (design section 8.5).
///
/// Reading: an account outside Receiving with no other tenant admin takes
/// the operator path, as a sole tenant admin does. I-79 forbids email
/// alone, and no second admin exists to approve.
pub const fn recovery_path(h: RefHoldings, other_admins: usize, mode: RefDeployment) -> RefPath {
    match (h, other_admins, mode) {
        (RefHoldings::ReceivingOnly, _, _) => RefPath::EmailThenPasskey,
        (_, 0, RefDeployment::Saas) => RefPath::OperatorProcess,
        (_, 0, RefDeployment::SelfHosted) => RefPath::HostConsole,
        (_, _, _) => RefPath::SecondAdmin,
    }
}

/// An approval of a recovery by a tenant admin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefApproval {
    /// The approving account.
    pub approver: AccountId,
    /// Whether the approver was a current tenant admin at approval.
    pub approver_admin: bool,
    /// Whether the approval's step-up passed [`admit_high_risk`] for its digest.
    pub stepup_ok: bool,
    /// The vault's `SameIdentityAsAny` answer for approver and holder.
    /// `None` when the vault could not answer, which refuses the approval.
    pub same_identity: Option<bool>,
    /// Whether both approver and holder are verified, so the vault check
    /// applies. This is a vault fact too, so it means nothing when
    /// `same_identity` is `None`.
    pub both_verified: bool,
}

/// Why the reference refuses a recovery approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefApprovalDeny {
    /// The approver is the account holder.
    SelfApproval,
    /// The approver is not a current tenant admin.
    NotAdmin,
    /// The approval has no valid step-up.
    StepUp,
    /// Approver and holder share an identity.
    SameIdentity,
    /// The vault could not answer, so the approval fails closed.
    VaultDown,
}

/// The approval rule for the recovery of `holder` (I-79, ADR-008).
///
/// A vault outage refuses the approval whatever `both_verified` says.
/// Whether both accounts are verified is itself a vault fact, so the cell
/// cannot know it while the vault does not answer (fail closed).
pub fn approve_recovery(holder: AccountId, a: &RefApproval) -> Result<(), RefApprovalDeny> {
    if a.approver == holder {
        return Err(RefApprovalDeny::SelfApproval);
    }
    if !a.approver_admin {
        return Err(RefApprovalDeny::NotAdmin);
    }
    if !a.stepup_ok {
        return Err(RefApprovalDeny::StepUp);
    }
    match a.same_identity {
        None => Err(RefApprovalDeny::VaultDown),
        Some(true) if a.both_verified => Err(RefApprovalDeny::SameIdentity),
        Some(_) => Ok(()),
    }
}

/// An operator ticket for a recovery case (`OperatorProcess`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefTicket {
    /// The first staff approval.
    pub staff_1: u8,
    /// The second staff approval.
    pub staff_2: u8,
    /// Whether the ticket names this case's opaque reference.
    pub case_matches: bool,
    /// Whether the ticket's signature verified.
    pub signature_ok: bool,
}

/// What a recovery case gathered before completion.
///
/// The approval and the ticket are kept as the facts they were accepted
/// on, so a check after the fact can tell a valid one from one that a
/// defective check let in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefEvidence {
    /// The email proof.
    pub email: bool,
    /// The approval a backend accepted, if any.
    pub approval: Option<RefApproval>,
    /// The operator ticket a backend accepted, if any.
    pub ticket: Option<RefTicket>,
    /// A host console command run as root with custody access.
    pub host_console: bool,
}

/// Whether an operator ticket has two different staff approvals, names the
/// case and verifies.
pub const fn ticket_ok(t: &RefTicket) -> bool {
    t.staff_1 != t.staff_2 && t.case_matches && t.signature_ok
}

/// Whether a case with evidence `e` may take an approval or an operator
/// ticket. Design section 8.5 orders the steps of `SecondAdmin` and
/// `OperatorProcess`: email proof first, then the approval or the ticket.
pub const fn may_take_approval_or_ticket(e: &RefEvidence) -> bool {
    e.email
}

/// Whether `e` completes `path` (design section 8.5).
///
/// `admins_now` lists the current tenant admins at completion. Reading: an
/// approver must still be a tenant admin at completion, so a revoked admin's
/// approval does not complete a recovery. The approval and the ticket must
/// still pass [`approve_recovery`] and [`ticket_ok`].
pub fn evidence_completes(
    path: RefPath,
    e: &RefEvidence,
    holder: AccountId,
    admins_now: &[AccountId],
) -> bool {
    match path {
        RefPath::EmailThenPasskey => e.email,
        RefPath::SecondAdmin => {
            e.email
                && e.approval.is_some_and(|a| {
                    approve_recovery(holder, &a).is_ok() && admins_now.contains(&a.approver)
                })
        }
        RefPath::OperatorProcess => e.email && e.ticket.is_some_and(|t| ticket_ok(&t)),
        RefPath::HostConsole => e.host_console,
    }
}

/// Why the reference refuses a recovery completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefRecoveryDeny {
    /// The evidence does not complete the path recomputed at completion.
    PathNotSatisfied(RefPath),
}

/// The completion rule (I-79): the path is recomputed from the holdings at
/// completion, and the evidence must complete it.
pub fn complete_recovery(
    roster: &RefRoster,
    holder: AccountId,
    e: &RefEvidence,
    mode: RefDeployment,
    now: Timestamp,
) -> Result<RefPath, RefRecoveryDeny> {
    let path = recovery_path(
        roster.holdings(holder, now),
        roster.other_admins(holder, now),
        mode,
    );
    if evidence_completes(path, e, holder, &roster.admins_at(now)) {
        Ok(path)
    } else {
        Err(RefRecoveryDeny::PathNotSatisfied(path))
    }
}

/// Whether a completed recovery was shown as `authentication.md` requires:
/// the operator and host console paths are logged and shown to the tenant.
pub const fn completion_shown(path: RefPath, shown_to_tenant: bool) -> bool {
    match path {
        RefPath::OperatorProcess | RefPath::HostConsole => shown_to_tenant,
        RefPath::EmailThenPasskey | RefPath::SecondAdmin => true,
    }
}

/// What a completion did, as its records show it (Q15).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefCompletion {
    /// Whether every earlier credential of the account was revoked.
    pub credentials_revoked: bool,
    /// Whether every earlier session of the account ended.
    pub sessions_ended: bool,
    /// Whether the completion was logged where the tenant sees it.
    pub shown_to_tenant: bool,
}

impl RefCompletion {
    /// A completion that revoked nothing, ended nothing and showed nothing.
    pub const NOTHING: RefCompletion = RefCompletion {
        credentials_revoked: false,
        sessions_ended: false,
        shown_to_tenant: false,
    };
}

/// What a completion of `path` must do (design section 8.5, Q15): revoke
/// every credential and end every session, and show an operator or host
/// console completion to the tenant.
pub const fn completion_of(path: RefPath) -> RefCompletion {
    RefCompletion {
        credentials_revoked: true,
        sessions_ended: true,
        shown_to_tenant: matches!(path, RefPath::OperatorProcess | RefPath::HostConsole),
    }
}

/// Whether completion `c` of `path` did what Q15 and `authentication.md`
/// require.
pub const fn completion_ok(path: RefPath, c: &RefCompletion) -> bool {
    c.credentials_revoked && c.sessions_ended && completion_shown(path, c.shown_to_tenant)
}

// ---------------------------------------------------------------------------
// First-passkey ceremonies (design section 8.3, ADR-008).

/// The context in which a passkey is enrolled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefEnrolment {
    /// An invitation.
    Invitation {
        /// When it was issued.
        issued_at: Timestamp,
        /// Whether a token use already consumed it.
        consumed: bool,
        /// Whether a tenant admin issued it with a valid step-up, or provisioning did.
        issued_validly: bool,
        /// For a SaaS first admin: whether both token halves were given.
        /// `None` for every other invitation.
        both_halves: Option<bool>,
    },
    /// Self-registration of a new account.
    SelfRegistration {
        /// Whether the account is new in this ceremony.
        new_account: bool,
        /// Whether it holds Receiving roles only.
        receiving_only: bool,
        /// Whether the email was proven earlier in the same ceremony.
        email_proven: bool,
    },
    /// A recovery completion that passed [`complete_recovery`].
    RecoveryCompletion {
        /// Whether the completion passed.
        completed: bool,
    },
    /// The high-risk action `AddPasskey` in an ordinary session.
    AddPasskey {
        /// Whether [`admit_high_risk`] passed for the command.
        stepup_ok: bool,
        /// The session's method.
        session_method: RefMethod,
    },
}

/// Why the reference refuses an enrolment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefEnrolDeny {
    /// The invitation is used, expired, invalidly issued or incomplete.
    Invitation,
    /// The self-registration is not a new Receiving account with email proof.
    SelfRegistration,
    /// The recovery did not complete.
    Recovery,
    /// `AddPasskey` outside a strong session, or without a step-up, or as a first passkey.
    AddPasskey,
}

/// The enrolment rule (design section 8.3). `has_passkey` says whether the
/// account holds a passkey already.
pub fn admit_enrolment(
    has_passkey: bool,
    e: &RefEnrolment,
    now: Timestamp,
) -> Result<(), RefEnrolDeny> {
    match *e {
        RefEnrolment::Invitation {
            issued_at,
            consumed,
            issued_validly,
            both_halves,
        } => {
            let ok = !consumed
                && issued_validly
                && within(issued_at, now, INVITATION_US)
                && both_halves.is_none_or(|b| b);
            if ok {
                Ok(())
            } else {
                Err(RefEnrolDeny::Invitation)
            }
        }
        RefEnrolment::SelfRegistration {
            new_account,
            receiving_only,
            email_proven,
        } => {
            if new_account && receiving_only && email_proven {
                Ok(())
            } else {
                Err(RefEnrolDeny::SelfRegistration)
            }
        }
        RefEnrolment::RecoveryCompletion { completed } => {
            if completed {
                Ok(())
            } else {
                Err(RefEnrolDeny::Recovery)
            }
        }
        RefEnrolment::AddPasskey {
            stepup_ok,
            session_method,
        } => {
            if has_passkey && stepup_ok && session_method.phishing_resistant() {
                Ok(())
            } else {
                Err(RefEnrolDeny::AddPasskey)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Break-glass (SoD-08, TH-18, design section 8.6).

/// A read action a break-glass grant may cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefRead {
    /// Read content.
    Content,
    /// Read the audit log.
    Audit,
    /// Read the erasure log.
    ErasureLog,
}

/// A platform operator staff member, as the control plane's staff
/// assertion names them. Staff are not accounts of the cell (SoD-08).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefStaff(pub u16);

/// A break-glass grant: `BreakGlassApproved { grant, staff, scope, until }`
/// (design section 8.6).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefBreakGlass {
    /// The one staff member the request named.
    pub staff: RefStaff,
    /// The read actions it covers.
    pub scope: Vec<RefRead>,
    /// When a tenant admin approved it.
    pub approved_at: Timestamp,
    /// When it ends.
    pub until: Timestamp,
    /// When `EndBreakGlass` ended it early, if it did.
    pub ended: Option<Timestamp>,
}

/// Why the reference refuses a break-glass approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefBreakGlassDeny {
    /// The approver is not a current tenant admin.
    NotAdmin,
    /// The approval has no valid step-up.
    StepUp,
    /// The end lies before the approval or more than 4 hours after it.
    Window,
    /// The scope is empty.
    EmptyScope,
}

/// The break-glass approval rule (design section 8.6).
pub fn approve_break_glass(
    approver_admin: bool,
    stepup_ok: bool,
    g: &RefBreakGlass,
) -> Result<(), RefBreakGlassDeny> {
    if !approver_admin {
        return Err(RefBreakGlassDeny::NotAdmin);
    }
    if !stepup_ok {
        return Err(RefBreakGlassDeny::StepUp);
    }
    if g.until.micros() <= g.approved_at.micros()
        || !within(g.approved_at, g.until, BREAK_GLASS_MAX_US)
    {
        return Err(RefBreakGlassDeny::Window);
    }
    if g.scope.is_empty() {
        return Err(RefBreakGlassDeny::EmptyScope);
    }
    Ok(())
}

/// Whether a staff principal may perform `read` at `now` under `g`.
///
/// `asserted` is the staff member a staff assertion names, when the
/// assertion verified against the pinned key, and `None` otherwise. Only
/// the staff member the grant names is admitted.
///
/// Reading: the grant admits reads before `until` and not at it. A
/// self-hosted cell pins no staff key (`pinned_key` false), so it admits
/// no break-glass principal.
pub fn admit_break_glass_read(
    g: &RefBreakGlass,
    read: RefRead,
    pinned_key: bool,
    asserted: Option<RefStaff>,
    now: Timestamp,
) -> bool {
    pinned_key
        && asserted == Some(g.staff)
        && g.scope.contains(&read)
        && g.approved_at.micros() <= now.micros()
        && now.micros() < g.until.micros()
        && g.ended.is_none_or(|e| now.micros() < e.micros())
}

/// What a break-glass principal asks the gate for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefStaffRequest {
    /// A read action.
    Read(RefRead),
    /// Any command, including a high-risk one.
    Command,
}

/// The roles a break-glass principal holds in a cell: none (SoD-08,
/// "Platform operator staff hold no roles in SaaS cells").
pub const BREAK_GLASS_ROLES: &[Role] = &[];

/// Whether the gate admits `request` from a break-glass principal (SoD-08,
/// design section 5.4 step 4). The principal holds no binding, so no
/// command is admitted and only reads under the grant are.
pub fn admit_break_glass(
    g: &RefBreakGlass,
    request: RefStaffRequest,
    pinned_key: bool,
    asserted: Option<RefStaff>,
    now: Timestamp,
) -> bool {
    match request {
        RefStaffRequest::Read(read) => admit_break_glass_read(g, read, pinned_key, asserted, now),
        RefStaffRequest::Command => false,
    }
}

/// Whether `staff_accounts`, the cell accounts of platform operator staff,
/// hold no binding and no tenant admin grant at `now` (SoD-08).
///
/// Reading: SoD-08 forbids any role, so every group counts, Receiving too,
/// and a voided binding does not.
pub fn sod08_staff_hold_no_role(
    roster: &RefRoster,
    staff_accounts: &[AccountId],
    now: Timestamp,
) -> bool {
    staff_accounts.iter().all(|a| {
        !roster.is_admin(*a, now)
            && !roster
                .bindings
                .iter()
                .any(|b| b.account == *a && !b.voided && before_end(b.end, now))
    })
}

// ---------------------------------------------------------------------------
// Compile-fail twins (design section 14.4, I-78).

/// I-78: every route needs a risk class. `Route::new` has no default.
///
/// A route without a risk class does not compile:
///
/// ```compile_fail
/// use fstp_cell::routes::Route;
/// const R: Route = Route::new("GET", "/auth/sessions");
/// ```
///
/// The twin below differs only in that line and compiles:
///
/// ```no_run
/// use fstp_cell::routes::{RiskClass, Route};
/// const R: Route = Route::new("GET", "/auth/sessions", RiskClass::Normal);
/// ```
///
/// A route cannot be written as a struct literal either:
///
/// ```compile_fail
/// use fstp_cell::routes::Route;
/// fn forge(r: Route) -> Route {
///     Route { ..r }
/// }
/// ```
///
/// ```no_run
/// use fstp_cell::routes::Route;
/// fn forge(r: Route) -> Route {
///     r
/// }
/// ```
pub mod i78_route_without_risk_class_does_not_compile {}

/// I-78: only `gate::admit` builds an `Admitted`, so a step-up proof
/// cannot be made outside the gate.
///
/// ```compile_fail
/// use fstp_cell_core::gate::Admitted;
/// fn forge(a: Admitted) -> Admitted {
///     Admitted { ..a }
/// }
/// ```
///
/// The twin below differs only in the forbidden line:
///
/// ```no_run
/// use fstp_cell_core::gate::Admitted;
/// fn forge(a: Admitted) -> Admitted {
///     a
/// }
/// ```
///
/// No constructor other than the gate exists:
///
/// ```compile_fail
/// use fstp_cell_core::gate::{Action, Admitted, ReadAction};
/// fn forge() -> Admitted {
///     Admitted::new(Action::Read(ReadAction::ReadAudit))
/// }
/// ```
///
/// ```no_run
/// use fstp_cell_core::gate::{Action, Admitted, ReadAction};
/// fn forge(a: &Admitted) -> &Action {
///     let _ = Action::Read(ReadAction::ReadAudit);
///     a.action()
/// }
/// ```
pub mod i78_stepup_proof_cannot_be_built_outside_the_gate {}
