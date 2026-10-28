//! Login policy, sessions, step-up, recovery, magic links and enrolment
//! ceremonies (I-77, I-78, I-79, ADR-008, M3 design section 8). Pure.
//!
//! Status: W0 stub. Lane W2b fills the crate. Every operation refuses with
//! [`AuthError::NotImplemented`]. The designed `holds_management` and
//! `recovery_path` are infallible; they return a `Result` until the lane
//! lands them, so a stub never answers a policy question.

pub mod codec;
pub mod recovery;

use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;

/// A login method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    /// A passkey with user verification.
    Passkey,
    /// The EUDI Wallet (M4).
    EudiWallet,
    /// OPAQUE (later).
    Opaque,
    /// A magic link by email.
    MagicLink,
}

/// Why an auth operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// A command of the auth fold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthCommand {
    /// Register a credential.
    RegisterCredential {
        /// The account.
        account: AccountId,
        /// The credential id.
        credential: Vec<u8>,
    },
    /// Revoke a credential.
    RevokeCredential {
        /// The account.
        account: AccountId,
        /// The credential id.
        credential: Vec<u8>,
    },
    /// Grant a step-up for one action digest.
    GrantStepUp {
        /// The session.
        session: [u8; 16],
        /// The action digest.
        action_digest: [u8; 32],
    },
}

/// A record of the auth fold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthRecord {
    /// A credential was registered.
    CredentialRegistered {
        /// The account.
        account: AccountId,
        /// The credential id.
        credential: Vec<u8>,
    },
    /// A step-up was granted.
    StepUpGranted {
        /// The step-up id.
        id: [u8; 16],
        /// The action digest.
        action_digest: [u8; 32],
    },
    /// A session ended.
    SessionEnded {
        /// The session.
        session: [u8; 16],
    },
}

/// The roster facts that login needs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RosterView {
    /// Accounts with a binding in the Drafting, Judging or Operations groups.
    pub management: Vec<AccountId>,
}

/// The tenant fold facts that login needs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TenantView {
    /// Current tenant admins.
    pub admins: Vec<AccountId>,
}

/// The methods a tenant enables (P-70).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnabledMethods {
    /// The enabled methods.
    pub methods: Vec<Method>,
}

/// A session as the gate sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionView {
    /// The session id.
    pub id: [u8; 16],
    /// The account.
    pub account: AccountId,
    /// The login method.
    pub method: Method,
    /// When the session started.
    pub started: Timestamp,
    /// When the session was last used.
    pub last_used: Timestamp,
}

/// The session lifetimes (P-72).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionLifetimes {
    /// Idle lifetime in microseconds.
    pub idle_us: i64,
    /// Absolute lifetime in microseconds.
    pub absolute_us: i64,
}

/// Why a login was refused (I-77).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginDeny {
    /// The method is not phishing resistant, and the account holds a
    /// management role.
    WeakMethodForRole,
    /// The tenant does not enable the method.
    MethodDisabled,
    /// The check is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// Why a session was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionDeny {
    /// The session ended or expired.
    SessionEnded,
    /// A weak session of a management role holder.
    WeakSessionForRole,
    /// The check is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// Whether `a` holds a management role at `now`.
pub fn holds_management(
    roster: &RosterView,
    tenant: &TenantView,
    a: AccountId,
    now: Timestamp,
) -> Result<bool, AuthError> {
    let _ = (roster, tenant, a, now);
    Err(AuthError::NotImplemented("fstp_auth::holds_management"))
}

/// I-77 at login.
pub fn admit_method(holdings: bool, m: Method, enabled: &EnabledMethods) -> Result<(), LoginDeny> {
    let _ = (holdings, m, enabled);
    Err(LoginDeny::NotImplemented("fstp_auth::admit_method"))
}

/// I-77 for an existing session.
pub fn admit_session(
    holdings: bool,
    s: &SessionView,
    now: Timestamp,
    p72: &SessionLifetimes,
) -> Result<(), SessionDeny> {
    let _ = (holdings, s, now, p72);
    Err(SessionDeny::NotImplemented("fstp_auth::admit_session"))
}
