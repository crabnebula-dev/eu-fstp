//! The caller of one operation (M4 design section 3.6, I-84).
//!
//! [`Principal`] has private fields. Only the checked constructors below
//! build one, and only `fstp-api-core` calls them, since layering rules A1,
//! A2 and A2b keep this crate away from every adapter. Roles come from the
//! engine state at the call's instant and the tenant admin flag from the
//! attested admin set, so no request field can raise either.
//!
//! The session, agent client and login method types live here, below
//! `fstp-api-core`, so the principal can name them without a cycle.
//! Interim, pending the lead: `fstp-api-core/src/port.rs` declares its own
//! copies of these three types, and the lead reconciles the two at merge.

use std::collections::BTreeSet;

use fstp_domain::Via;
use fstp_domain::id::AccountId;
use fstp_domain::roles::{Group, Role};
use fstp_domain::time::Timestamp;
use fstp_engine::EngineState;

use crate::registry::{RoleOrApplicant, Scope};

/// Why a principal could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessError {
    /// The token's consent came from a session that was not
    /// phishing-resistant. Consenting to an agent links a device, which is
    /// high-risk (I-78), so such a grant cannot exist.
    WeakConsent,
}

impl std::fmt::Display for AccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessError::WeakConsent => {
                write!(f, "the agent grant comes from a weak session (I-78)")
            }
        }
    }
}

impl std::error::Error for AccessError {}

macro_rules! access_id {
    ($($(#[$doc:meta])* $n:ident),* $(,)?) => { $(
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $n(u128);

        impl $n {
            /// The id with raw value `r`, as the shell draws it.
            pub const fn from_raw(r: u128) -> Self {
                Self(r)
            }

            /// The raw value.
            pub const fn raw(self) -> u128 {
                self.0
            }
        }
    )* };
}

access_id!(
    /// An M3 session.
    SessionId,
    /// An OAuth client of an agent.
    AgentClientId,
);

/// A login method (`authentication.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoginMethod {
    /// A passkey.
    Passkey,
    /// A magic link.
    MagicLink,
    /// OPAQUE.
    Opaque,
    /// The EUDI Wallet.
    EudiWallet,
}

impl LoginMethod {
    /// Whether the method is phishing-resistant (I-77): a passkey or the
    /// EUDI Wallet.
    pub const fn phishing_resistant(self) -> bool {
        matches!(self, LoginMethod::Passkey | LoginMethod::EudiWallet)
    }
}

/// The OAuth scopes of one token (design section 3.8). A scope never adds
/// a right that the roles lack.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ScopeSet(BTreeSet<Scope>);

impl ScopeSet {
    /// No scope.
    pub fn empty() -> ScopeSet {
        ScopeSet(BTreeSet::new())
    }

    /// Whether the set holds `s`.
    pub fn contains(&self, s: Scope) -> bool {
        self.0.contains(&s)
    }

    /// Every scope, in order.
    pub fn iter(&self) -> impl Iterator<Item = Scope> + '_ {
        self.0.iter().copied()
    }
}

impl FromIterator<Scope> for ScopeSet {
    fn from_iter<I: IntoIterator<Item = Scope>>(iter: I) -> ScopeSet {
        ScopeSet(iter.into_iter().collect())
    }
}

/// The kinds of role an account holds now, plus
/// [`RoleOrApplicant::Applicant`] for an account acting with no binding
/// and no admin role yet (design section 3.6).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RoleSet(BTreeSet<RoleOrApplicant>);

impl RoleSet {
    /// Whether the set holds `r`.
    pub fn contains(&self, r: RoleOrApplicant) -> bool {
        self.0.contains(&r)
    }

    /// Every entry, in order.
    pub fn iter(&self) -> impl Iterator<Item = RoleOrApplicant> + '_ {
        self.0.iter().copied()
    }

    /// Whether the set is empty, as it is for an anonymous caller only.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// What an M3 session attests about its caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionFacts {
    /// The account.
    pub account: AccountId,
    /// The session.
    pub session: SessionId,
    /// How the session logged in.
    pub method: LoginMethod,
}

/// What a validated MCP token attests about its caller. The token store
/// of `fstp-oauth` fills it once ADR-013 is accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantFacts {
    /// The account that consented.
    pub account: AccountId,
    /// The agent client.
    pub agent: AgentClientId,
    /// The scopes of the grant.
    pub scopes: ScopeSet,
    /// How the session that consented logged in. The token inherits its
    /// strength (design section 3.7, step 2).
    pub consent_method: LoginMethod,
}

/// The caller of one operation. Fields are private. Only the constructors
/// below build a `Principal`, and only `fstp-api-core` calls them (I-84).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    account: Option<AccountId>,
    tenant_admin: bool,
    method: Option<LoginMethod>,
    phishing_resistant: bool,
    session: Option<SessionId>,
    via: Via,
    agent: Option<AgentClientId>,
    scopes: ScopeSet,
    roles: RoleSet,
    management: bool,
}

impl Principal {
    /// The caller with no credential, on the web channel.
    pub fn anonymous() -> Principal {
        Principal {
            account: None,
            tenant_admin: false,
            method: None,
            phishing_resistant: false,
            session: None,
            via: Via::Web,
            agent: None,
            scopes: ScopeSet::empty(),
            roles: RoleSet::default(),
            management: false,
        }
    }

    /// The caller with no credential on the public MCP endpoint
    /// (`/mcp/public`, R-MC-04). It holds no scope and no role, so it
    /// reaches the public tools only.
    pub fn anonymous_mcp() -> Principal {
        Principal {
            via: Via::Mcp,
            ..Principal::anonymous()
        }
    }

    /// The caller of an M3 session. The tenant admin flag comes from the
    /// attested admin set `admins`, and the roles from the bindings of
    /// `state` that are active at `now`.
    pub fn web(
        s: &SessionFacts,
        admins: &BTreeSet<AccountId>,
        state: &EngineState,
        now: Timestamp,
    ) -> Principal {
        let tenant_admin = admins.contains(&s.account);
        Principal {
            account: Some(s.account),
            tenant_admin,
            method: Some(s.method),
            phishing_resistant: s.method.phishing_resistant(),
            session: Some(s.session),
            via: Via::Web,
            agent: None,
            scopes: ScopeSet::empty(),
            roles: roles_at(state, s.account, tenant_admin, now),
            management: holds_management(state, s.account, tenant_admin),
        }
    }

    /// The caller of a validated MCP token. The strength is the consenting
    /// session's, the scopes are the grant's, and the roles are evaluated
    /// again at `now`, so no token outlives a role. A grant whose consent
    /// came from a weak session is refused (I-78).
    pub fn mcp(
        g: &GrantFacts,
        admins: &BTreeSet<AccountId>,
        state: &EngineState,
        now: Timestamp,
    ) -> Result<Principal, AccessError> {
        if !g.consent_method.phishing_resistant() {
            return Err(AccessError::WeakConsent);
        }
        let tenant_admin = admins.contains(&g.account);
        Ok(Principal {
            account: Some(g.account),
            tenant_admin,
            method: Some(g.consent_method),
            phishing_resistant: true,
            session: None,
            via: Via::Mcp,
            agent: Some(g.agent),
            scopes: g.scopes.clone(),
            roles: roles_at(state, g.account, tenant_admin, now),
            management: holds_management(state, g.account, tenant_admin),
        })
    }

    /// The account, if the caller has one.
    pub fn account(&self) -> Option<AccountId> {
        self.account
    }

    /// Whether the attested tenant admin set holds the account.
    pub fn tenant_admin(&self) -> bool {
        self.tenant_admin
    }

    /// The login method, if the caller has a session or a token.
    pub fn method(&self) -> Option<LoginMethod> {
        self.method
    }

    /// Whether the session, or the session behind the token, is
    /// phishing-resistant (I-77).
    pub fn phishing_resistant(&self) -> bool {
        self.phishing_resistant
    }

    /// The M3 session of a web caller.
    pub fn session(&self) -> Option<SessionId> {
        self.session
    }

    /// The channel.
    pub fn via(&self) -> Via {
        self.via
    }

    /// The agent client of an MCP caller.
    pub fn agent(&self) -> Option<AgentClientId> {
        self.agent
    }

    /// The token's scopes. Empty on the web.
    pub fn scopes(&self) -> &ScopeSet {
        &self.scopes
    }

    /// The roles the account holds now.
    pub fn roles(&self) -> &RoleSet {
        &self.roles
    }

    /// Whether I-77 covers the account: it holds a Drafting, Judging or
    /// Operations binding, a suspended one included, or is a tenant admin.
    pub fn holds_management_role(&self) -> bool {
        self.management
    }
}

/// The roles `account` acts under at `now`: the role of each binding that
/// is active then, in any programme, plus tenant admin from the attested
/// set. With neither, the account acts as an applicant with no binding.
fn roles_at(
    state: &EngineState,
    account: AccountId,
    tenant_admin: bool,
    now: Timestamp,
) -> RoleSet {
    let mut set: BTreeSet<RoleOrApplicant> = state
        .core
        .roster()
        .bindings()
        .filter(|(_, b)| b.account == account && b.active_at(now))
        .map(|(_, b)| RoleOrApplicant::Role(b.role))
        .collect();
    if tenant_admin {
        set.insert(RoleOrApplicant::Role(Role::TenantAdmin));
    }
    if set.is_empty() {
        set.insert(RoleOrApplicant::Applicant);
    }
    RoleSet(set)
}

/// Whether `account` holds a binding outside the Receiving group, active,
/// suspended or not yet started, or is a tenant admin (I-77). A voided or
/// conflict-of-interest binding is not held, and an ended one has left
/// the roster.
fn holds_management(state: &EngineState, account: AccountId, tenant_admin: bool) -> bool {
    tenant_admin
        || state
            .core
            .roster()
            .bindings()
            .any(|(_, b)| b.account == account && b.held() && b.group() != Group::Receiving)
}
