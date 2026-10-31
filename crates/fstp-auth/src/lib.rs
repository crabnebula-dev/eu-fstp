//! Login policy, sessions, step-up, recovery, magic links, enrolment
//! ceremonies and break-glass (I-77, I-78, I-79, SoD-08, ADR-008, M3
//! design section 8). Pure: no I/O, no clock and no randomness. The shell
//! passes every instant and every random value in.
//!
//! - [`admit_method`] and [`session::admit_login`] apply I-77 at login.
//!   [`admit_session`] and [`session::admit_session_at`] apply it on every
//!   request.
//! - [`holds_management`] reads a [`RosterView`] and a [`TenantView`].
//!   [`RosterView::at`] and [`RosterView::from_roster`] build the view by
//!   the holdings rule of design section 8.2. That rule counts every
//!   suspended binding, so it does not reuse the M2 roster's `held`.
//! - [`stepup`] holds the action digest, the challenge, P-71 and the
//!   step-up rule (I-78).
//! - [`recovery`] holds the recovery paths, the approval and operator
//!   ticket checks and the completion (I-79).
//! - [`ceremony`] holds the first-passkey ceremonies and magic links.
//! - [`breakglass`] holds the break-glass approval and read rules.
//! - [`codec`] holds the record, command, cookie, token and ticket codecs.
//!
//! Every time comparison uses checked arithmetic. An overflow refuses.

pub mod breakglass;
pub mod ceremony;
pub mod codec;
mod holdings;
pub mod recovery;
pub mod session;
pub mod stepup;

/// The credential types that [`AuthRecord`] carries, so a fold of auth
/// records names them without its own `fstp-webauthn` edge.
pub use fstp_webauthn::{CoseKey, NewCredential, StoredCredential};
pub use holdings::{AdminGrant, BindingFact, is_management_role};
pub use recovery::RecoveryPath;

use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;

/// One second in microseconds.
pub const SECOND_US: i64 = 1_000_000;
/// One minute in microseconds.
pub const MINUTE_US: i64 = 60 * SECOND_US;
/// One hour in microseconds.
pub const HOUR_US: i64 = 60 * MINUTE_US;

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

impl Method {
    /// Every method.
    pub const ALL: [Method; 4] = [
        Method::Passkey,
        Method::EudiWallet,
        Method::Opaque,
        Method::MagicLink,
    ];

    /// Whether `authentication.md` counts the method as phishing
    /// resistant: passkeys and the EUDI Wallet. OPAQUE and magic links
    /// are not.
    pub const fn phishing_resistant(self) -> bool {
        matches!(self, Method::Passkey | Method::EudiWallet)
    }

    /// Whether M3 builds the method at all: passkeys and magic links
    /// (Q10 A, ADR-008 "Methods in M3").
    pub const fn built_in_m3(self) -> bool {
        matches!(self, Method::Passkey | Method::MagicLink)
    }
}

/// The error type of the W0 API that callers still match on.
///
/// No operation of this crate returns it any more. [`holds_management`]
/// and [`recovery::recovery_path`] are infallible by design. They keep the
/// W0 `Result` so that callers written against the stub still compile.
/// The other operations return their own typed refusals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// Kept from the W0 stub. No operation returns it.
    NotImplemented(&'static str),
}

/// A command of the auth fold (design section 5.1).
///
/// The actor of a command comes from the gate's admitted principal, never
/// from a command field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthCommand {
    /// Register a credential, inside a ceremony or as `AddPasskey`.
    ///
    /// The command names the credential id only, since W1 builds it with
    /// these two members. Its batch records
    /// [`AuthRecord::CredentialRegistered`] from the verified credential
    /// that [`ceremony::verify_new_passkey`] returns for the same id
    /// ([`AuthRecord::registration`]). A command without that verified
    /// credential records nothing.
    RegisterCredential {
        /// The account.
        account: AccountId,
        /// The credential id.
        credential: Vec<u8>,
    },
    /// Revoke a credential (`DELETE /auth/devices/{id}`,
    /// `ChangeLoginMethods`).
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
    /// End a session (`DELETE /auth/sessions/{id}`, R-LG-04).
    EndSession {
        /// The session.
        session: [u8; 16],
    },
    /// Open a recovery case (`POST /auth/recovery`).
    RequestRecovery {
        /// The opaque case reference, drawn by the shell.
        case: [u8; 16],
        /// The account to recover.
        account: AccountId,
    },
    /// Record the email proof of a case.
    ProveRecoveryEmail {
        /// The case.
        case: [u8; 16],
    },
    /// Approve a case as a second tenant admin (`ApproveRecovery`, high
    /// risk).
    ApproveRecovery {
        /// The case.
        case: [u8; 16],
    },
    /// Complete a case with a new passkey.
    CompleteRecovery {
        /// The case.
        case: [u8; 16],
        /// The new credential id.
        credential: Vec<u8>,
    },
}

/// A record of the auth fold (design section 5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthRecord {
    /// A credential was registered, as `fstp_webauthn::verify_registration`
    /// verified it. Credential public keys are ledger records (design
    /// section 4.2), so a replay rebuilds the stored credential from this
    /// record ([`AuthRecord::stored_credential`]). The sign count is an
    /// operational row (`auth.sign_count`), so the record does not carry
    /// it.
    CredentialRegistered {
        /// The account.
        account: AccountId,
        /// The credential id.
        credential: Vec<u8>,
        /// The credential's public key.
        key: CoseKey,
        /// Whether the registration gave user verification. The cell
        /// records it for applicant passkeys (ADR-008 "User verification").
        user_verified: bool,
    },
    /// A step-up was granted. Its entry's instant is the assertion time.
    StepUpGranted {
        /// The step-up id.
        id: [u8; 16],
        /// The action digest.
        action_digest: [u8; 32],
        /// The session it was made in.
        session: [u8; 16],
    },
    /// A session ended.
    ///
    /// Open point for lane W2e and the lead: the record names no end
    /// cause, although `auth_log.session_end.cause` is NOT NULL (design
    /// section 4.2). W1 code matches this variant by its one member, so
    /// this lane does not widen it.
    SessionEnded {
        /// The session.
        session: [u8; 16],
    },
    /// A credential was revoked.
    CredentialRevoked {
        /// The account.
        account: AccountId,
        /// The credential id.
        credential: Vec<u8>,
    },
    /// A credential's sign count went down (ADR-008 "Sign counts").
    CredentialSuspect {
        /// The account.
        account: AccountId,
        /// The credential id.
        credential: Vec<u8>,
    },
    /// A high-risk command consumed a step-up.
    StepUpConsumed {
        /// The step-up id.
        id: [u8; 16],
    },
    /// A recovery case was opened.
    RecoveryRequested {
        /// The case.
        case: [u8; 16],
        /// The account.
        account: AccountId,
        /// The path at request time.
        path: RecoveryPath,
    },
    /// The email proof of a case was given.
    RecoveryEmailProven {
        /// The case.
        case: [u8; 16],
    },
    /// A second tenant admin approved a case.
    RecoveryApproved {
        /// The case.
        case: [u8; 16],
        /// The approver.
        approver: AccountId,
    },
    /// A case completed.
    RecoveryCompleted {
        /// The case.
        case: [u8; 16],
        /// The account.
        account: AccountId,
        /// The path recomputed at completion.
        path: RecoveryPath,
        /// Whether the tenant's audit view shows the completion. It always
        /// equals `path.shown_to_tenant()`: true for the operator and host
        /// console paths. The decoder refuses a record where it differs.
        shown_to_tenant: bool,
    },
    /// An invitation was issued. Only the token digest is stored.
    InvitationIssued {
        /// The invitation id.
        invitation: [u8; 16],
        /// The invited account.
        account: AccountId,
        /// The SHA-256 digest of the token.
        token_digest: [u8; 32],
        /// Whether it is the first tenant admin's invitation. Its
        /// enrolment records [`AuthRecord::FirstAdminEnrolled`].
        first_admin: bool,
        /// Whether the token is drawn as two halves (Q35). True exactly
        /// for the first admin's invitation of a SaaS cell.
        split: bool,
    },
    /// An invitation was used to enrol a first passkey.
    InvitationConsumed {
        /// The invitation id.
        invitation: [u8; 16],
    },
    /// The first tenant admin enrolled. Every later tenant admin sees it.
    FirstAdminEnrolled {
        /// The account.
        account: AccountId,
    },
}

impl AuthRecord {
    /// The registration record of `credential` for `account`.
    ///
    /// `credential` is what `fstp_webauthn::verify_registration` returned.
    /// [`ceremony::verify_new_passkey`] runs it with the user verification
    /// rule of ADR-008.
    pub fn registration(
        account: AccountId,
        credential: &fstp_webauthn::NewCredential,
    ) -> AuthRecord {
        AuthRecord::CredentialRegistered {
            account,
            credential: credential.id.clone(),
            key: credential.key.clone(),
            user_verified: credential.user_verified,
        }
    }

    /// The owner and the stored credential of a registration record, with
    /// the sign count `sign_count` from the operational row. `None` for
    /// every other record.
    ///
    /// The caller passes the credential to [`session::verify_passkey_login`]
    /// or [`stepup::verify_step_up`] together with its owner.
    pub fn stored_credential(&self, sign_count: u32) -> Option<(AccountId, StoredCredential)> {
        match self {
            AuthRecord::CredentialRegistered {
                account,
                credential,
                key,
                ..
            } => Some((
                *account,
                StoredCredential {
                    id: credential.clone(),
                    key: key.clone(),
                    sign_count,
                },
            )),
            _ => None,
        }
    }
}

/// The accounts that hold a management binding at one instant.
///
/// Build it with [`RosterView::at`] or [`RosterView::from_roster`], which
/// apply the holdings rule of design section 8.2.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RosterView {
    /// Accounts with a binding in the Drafting, Judging or Operations
    /// groups.
    pub management: Vec<AccountId>,
}

/// The tenant admins at one instant. Build it with [`TenantView::at`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TenantView {
    /// Current tenant admins.
    pub admins: Vec<AccountId>,
}

/// The methods a tenant enables (P-70). Passkeys are always enabled,
/// whatever the list holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnabledMethods {
    /// The enabled methods.
    pub methods: Vec<Method>,
}

impl EnabledMethods {
    /// Whether the tenant offers `m` in M3. A passkey always; a magic link
    /// when listed; the deferred methods never (Q10 A).
    pub fn offers(&self, m: Method) -> bool {
        match m {
            Method::Passkey => true,
            Method::MagicLink => self.methods.contains(&m),
            Method::EudiWallet | Method::Opaque => false,
        }
    }
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

impl SessionLifetimes {
    /// The proposed P-72 defaults: 30 minutes idle and 12 hours absolute
    /// (ADR-008 "Constants", interim pending Daniel, Q37).
    pub const DEFAULT: SessionLifetimes = SessionLifetimes {
        idle_us: 30 * MINUTE_US,
        absolute_us: 12 * HOUR_US,
    };
}

/// Why a login was refused (I-77).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginDeny {
    /// The method is not phishing resistant, and the account holds a
    /// management role.
    WeakMethodForRole,
    /// The tenant does not enable the method, or M3 does not build it.
    MethodDisabled,
    /// Kept from the W0 stub so that callers written against it still
    /// compile. No operation returns it.
    NotImplemented(&'static str),
}

/// Why a session was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionDeny {
    /// The session ended or expired, or a binding of the account ended
    /// after it started.
    SessionEnded,
    /// A weak session of a management role holder.
    WeakSessionForRole,
    /// Kept from the W0 stub so that callers written against it still
    /// compile. No operation returns it.
    NotImplemented(&'static str),
}

/// Whether `now - from` lies in `0..=limit_us`. An overflow is false, so
/// the caller refuses (fail closed). P-71 and P-72 read "no older than",
/// so both bounds are inclusive.
pub(crate) fn within(from: Timestamp, now: Timestamp, limit_us: i64) -> bool {
    match now.micros().checked_sub(from.micros()) {
        Some(age) => age >= 0 && age <= limit_us,
        None => false,
    }
}

/// Whether `a` holds a management role at the instant of the views
/// (design section 8.2): a Drafting, Judging or Operations binding, or a
/// tenant admin grant.
///
/// The views are taken at one instant, so `now` names it and changes
/// nothing. The designed signature is infallible. The `Result` is kept
/// from the W0 API and is always `Ok`.
pub fn holds_management(
    roster: &RosterView,
    tenant: &TenantView,
    a: AccountId,
    now: Timestamp,
) -> Result<bool, AuthError> {
    let _ = now;
    Ok(roster.management.contains(&a) || tenant.admins.contains(&a))
}

/// I-77 and P-70 at login.
///
/// A holder never logs in with a weak method, so that refusal comes
/// first. Then M3 refuses every method it does not build and every method
/// the tenant does not enable. User verification is checked by
/// [`session::admit_login`].
pub fn admit_method(holdings: bool, m: Method, enabled: &EnabledMethods) -> Result<(), LoginDeny> {
    if holdings && !m.phishing_resistant() {
        return Err(LoginDeny::WeakMethodForRole);
    }
    if !m.built_in_m3() || !enabled.offers(m) {
        return Err(LoginDeny::MethodDisabled);
    }
    Ok(())
}

/// I-77 and P-72 for an existing session at `now`.
///
/// A session is live while its absolute and idle ages are at most the
/// P-72 limits. A clock before the start or the last use refuses, and so
/// does an overflow. A weak session of a holder is refused.
pub fn admit_session(
    holdings: bool,
    s: &SessionView,
    now: Timestamp,
    p72: &SessionLifetimes,
) -> Result<(), SessionDeny> {
    if !within(s.started, now, p72.absolute_us) || !within(s.last_used, now, p72.idle_us) {
        return Err(SessionDeny::SessionEnded);
    }
    if holdings && !s.method.phishing_resistant() {
        return Err(SessionDeny::WeakSessionForRole);
    }
    Ok(())
}
