//! Access, channels and the operation registry (I-84, I-85, M4 design
//! section 3.6).
//!
//! The crate holds [`Principal`], with private fields and checked
//! constructors, the `OPS` registry with every `ToolDef` (the only tool
//! table), the read rules, scopes, classifications and [`channel_policy`],
//! the one pure function where the web and MCP channels differ.
//!
//! The crate holds no parser, so it has no fuzz project (design section
//! 9). It names `fstp-import` for operation kinds only (rule A3).
//!
//! Status: W0 stub. Lane W3a (L-ACCESS) owns this crate. The registry is
//! empty, so dispatch stays closed until W3a fills it.
//!
//! Declarations added by lane W3b (M4 wave 7a), so `fstp-api-core`
//! compiles while lane W3a writes this crate in parallel. Each one copies
//! the name and signature of W3a's API as it stood on 2026-10-30. Every
//! body fails closed: the registry is empty, the channel denies, no
//! session is strong enough, every read is refused and no token becomes a
//! principal. At merge the lead takes W3a's file for this one.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeSet;

use fstp_domain::CommandKind;
use fstp_domain::Via;
use fstp_domain::id::{AccountId, AssignmentId, CallId, ProgrammeId, ProposalId};
use fstp_domain::policy::McpBindingActions;
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_engine::EngineState;

/// Why an access operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessError {
    /// The W0 stub of the named operation refuses.
    NotImplemented(&'static str),
    /// The token's consent came from a session that was not
    /// phishing-resistant (I-78).
    WeakConsent,
}

impl std::fmt::Display for AccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
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
    /// Whether the method is phishing-resistant (I-77).
    pub const fn phishing_resistant(self) -> bool {
        matches!(self, LoginMethod::Passkey | LoginMethod::EudiWallet)
    }
}

/// An OAuth scope issued in M4 (design section 3.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// `calls:read`.
    CallsRead,
    /// `proposals:read`.
    ProposalsRead,
    /// `proposals:draft`.
    ProposalsDraft,
    /// `proposals:binding`.
    ProposalsBinding,
    /// `stage2:draft`.
    Stage2Draft,
    /// `review:read`.
    ReviewRead,
    /// `review:draft`.
    ReviewDraft,
    /// `ranking:read`.
    RankingRead,
    /// `findings:read`.
    FindingsRead,
    /// `creator:draft`.
    CreatorDraft,
    /// `calls:draft`.
    CallsDraft,
    /// `audit:read`.
    AuditRead,
}

/// The OAuth scopes of one token.
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
}

impl FromIterator<Scope> for ScopeSet {
    fn from_iter<I: IntoIterator<Item = Scope>>(iter: I) -> ScopeSet {
        ScopeSet(iter.into_iter().collect())
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

/// What a validated MCP token attests about its caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantFacts {
    /// The account that consented.
    pub account: AccountId,
    /// The agent client.
    pub agent: AgentClientId,
    /// The scopes of the grant.
    pub scopes: ScopeSet,
    /// How the session that consented logged in.
    pub consent_method: LoginMethod,
}

/// The caller of one operation. Fields are private. Only the constructors
/// below build a `Principal`, and only `fstp-api-core` calls them (I-84).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    account: Option<AccountId>,
    tenant_admin: bool,
    via: Via,
}

impl Principal {
    /// The caller with no credential, on the web channel.
    pub fn anonymous() -> Principal {
        Principal {
            account: None,
            tenant_admin: false,
            via: Via::Web,
        }
    }

    /// The caller with no credential on the public MCP endpoint.
    pub fn anonymous_mcp() -> Principal {
        Principal {
            via: Via::Mcp,
            ..Principal::anonymous()
        }
    }

    /// The caller of an M3 session. The stub holds no role, and the empty
    /// registry exposes no operation to it.
    pub fn web(
        s: &SessionFacts,
        admins: &BTreeSet<AccountId>,
        state: &EngineState,
        now: Timestamp,
    ) -> Principal {
        let _ = (state, now);
        Principal {
            account: Some(s.account),
            tenant_admin: admins.contains(&s.account),
            via: Via::Web,
        }
    }

    /// The caller of a validated MCP token. The stub refuses.
    pub fn mcp(
        g: &GrantFacts,
        admins: &BTreeSet<AccountId>,
        state: &EngineState,
        now: Timestamp,
    ) -> Result<Principal, AccessError> {
        let _ = (g, admins, state, now);
        Err(AccessError::NotImplemented("fstp_access::Principal::mcp"))
    }

    /// The account, if the caller has one.
    pub fn account(&self) -> Option<AccountId> {
        self.account
    }

    /// Whether the attested tenant admin set holds the account.
    pub fn tenant_admin(&self) -> bool {
        self.tenant_admin
    }

    /// The channel.
    pub fn via(&self) -> Via {
        self.via
    }
}

/// How an MCP response classifies its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Classification {
    /// Public data.
    Public,
    /// Confidential data.
    Confidential,
    /// Personal data.
    Personal,
}

/// An HTTP method of a web route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `DELETE`.
    Delete,
}

/// The session strength an operation needs (I-77).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SessionNeed {
    /// Any session.
    Any,
    /// A passkey or EUDI Wallet session only.
    PhishingResistant,
}

/// A role through which an operation can be performed (P-74).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RoleOrApplicant {
    /// A role of `Role::ALL`.
    Role(Role),
    /// An account acting with no binding yet.
    Applicant,
}

/// A creator operation kind (design section 3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(
    missing_docs,
    reason = "W0 stub declarations, named as lane W3a names them"
)]
pub enum CreatorKind {
    OpenDraft,
    ApplyStart,
    SaveFields,
    AcceptNarrative,
    Invite,
    WithdrawInvitation,
    AcknowledgeWarning,
    RequestActivation,
    ApproveActivation,
    SaveAsTenantTemplate,
}

/// An engine bridge operation kind (design section 3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BridgeKind {
    /// `BridgeCommand::ResolveImport` (I-65).
    ResolveImport,
}

/// A tenant-level parameter that M4 can set (design section 3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(
    missing_docs,
    reason = "W0 stub declarations, named as lane W3a names them"
)]
pub enum TenantParam {
    P20,
    P69,
    P70,
    P71,
    P72,
    P74,
}

/// A tenant operation kind (design section 3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(
    missing_docs,
    reason = "W0 stub declarations, named as lane W3a names them"
)]
pub enum TenantKind {
    SaveStep,
    Complete,
    InviteAdmin,
    ApproveSelfGrant,
    SetSetting(TenantParam),
    RecordInferenceConfig,
}

/// A finding operation kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(
    missing_docs,
    reason = "W0 stub declarations, named as lane W3a names them"
)]
pub enum FindingKind {
    Record,
    Mark,
    Regenerate,
}

/// An import operation kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(
    missing_docs,
    reason = "W0 stub declarations, named as lane W3a names them"
)]
pub enum ImportKind {
    RegisterDocument,
    RecordProposals,
}

/// An agent operation kind (R-MC-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AgentKind {
    /// The OAuth consent, which links a device.
    Consent,
    /// Revoking an agent client.
    Revoke,
}

/// A pending action operation kind (I-85).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PendingKind {
    /// Confirming a pending action in the platform.
    Confirm,
    /// Discarding a pending action.
    Discard,
}

/// A public page, feed or public tool kind (I-87).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(
    missing_docs,
    reason = "W0 stub declarations, named as lane W3a names them"
)]
pub enum PublicKind {
    Programme,
    ListOpenCalls,
    Call,
    Guide,
    Deadlines,
    Eligibility,
    Funded,
    Finished,
    Feed,
}

/// An operation served by an M3 port (design section 6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(
    missing_docs,
    reason = "W0 stub declarations, named as lane W3a names them"
)]
pub enum PortKind {
    BeginVerification,
    AcceptInvitation,
    BeginInvitationVerification,
    BeginGuardianConsent,
    StateCountry,
    DeclareAffiliations,
    SaveWorkspace,
    RequestCopy,
    AcknowledgeNegotiationNotice,
    EndSession,
    AddPasskey,
    ApproveRecovery,
    ApproveBreakGlass,
}

/// A read (design section 3.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(
    missing_docs,
    reason = "W0 stub declarations, named as lane W3a names them"
)]
pub enum ReadKind {
    ListOpenCalls,
    GetPublicCall,
    GetGuide,
    ListOwnProposals,
    GetOwnProposal,
    GetOwnWorkspace,
    GetOwnStage2Thread,
    GetOwnNotices,
    GetNegotiationLanding,
    ListMyAssignments,
    GetDeclarationView,
    GetContent,
    GetScoreSheet,
    GetStage2Thread,
    GetFindings,
    GetRankingView,
    GetCutOffRound,
    ListMyIrcCases,
    GetIrcCase,
    GetIntakeQueue,
    GetCallBoard,
    GetDraft,
    GetReport,
    GetPreview,
    GetImpact,
    ListImportProposals,
    ListInvitations,
    ListBindings,
    GetAuditLog,
    GetVaultOutcomes,
    ListMyAgents,
    ListMyAgentActivity,
    ListMyPendingActions,
    ListMySessions,
    ListNotifiableConflicts,
    ListApprovals,
    GetTenantSettings,
    GetOnboarding,
}

/// The kind of an operation (design section 3.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OpKind {
    /// A core domain command.
    Command(CommandKind),
    /// A creator command.
    Creator(CreatorKind),
    /// An engine bridge command.
    Bridge(BridgeKind),
    /// A tenant command.
    Tenant(TenantKind),
    /// A finding command.
    Finding(FindingKind),
    /// An import command.
    Import(ImportKind),
    /// A read.
    Read(ReadKind),
    /// An agent operation.
    Agent(AgentKind),
    /// A pending action operation.
    Pending(PendingKind),
    /// A public page, feed or tool.
    Public(PublicKind),
    /// An operation served by an M3 port.
    M3Port(PortKind),
}

/// The input schema of a tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schema {
    /// The path parameters, in route order.
    pub params: &'static [&'static str],
    /// Whether the call carries a request object.
    pub body: bool,
}

/// An MCP tool definition: fixed name, description and input schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToolDef {
    /// The tool name.
    pub name: &'static str,
    /// The fixed description. It never holds tenant text (TH-63).
    pub description: &'static str,
    /// The input schema.
    pub input: &'static Schema,
    /// The scope the tool needs.
    pub scope: Scope,
    /// Whether the tool only prepares a pending action (I-85).
    pub prepare_only: bool,
}

/// One operation of the registry (design section 3.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpSpec {
    /// The operation name, such as `call.publish`.
    pub name: &'static str,
    /// The kind.
    pub kind: OpKind,
    /// The web route.
    pub route: Option<(Method, &'static str)>,
    /// The MCP tool, if the operation has one.
    pub tool: Option<ToolDef>,
    /// Whether the operation is high-risk (I-78).
    pub high_risk: bool,
    /// Whether the operation is binding under P-77 (R-MC-05).
    pub binding: bool,
    /// The session strength it needs (I-77).
    pub session: SessionNeed,
    /// The OAuth scope it needs through MCP.
    pub scope: Option<Scope>,
    /// The roles through which it can be performed (P-74).
    pub acting: &'static [RoleOrApplicant],
    /// How MCP responses classify its data.
    pub classification: Classification,
}

/// Every operation of M4. Empty in W0, so no operation is exposed.
pub const OPS: &[OpSpec] = &[];

/// The operation named `name`.
pub fn op(name: &str) -> Option<&'static OpSpec> {
    OPS.iter().find(|o| o.name == name)
}

/// The path parameters of a route, in order: each `{name}` segment.
pub fn route_params(path: &str) -> impl Iterator<Item = &str> {
    path.split('/')
        .filter_map(|s| s.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
}

/// The tenant's MCP settings, the P-74 value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct McpSettings {
    enabled: bool,
}

impl McpSettings {
    /// Enabled for all roles.
    pub fn all_roles() -> McpSettings {
        McpSettings { enabled: true }
    }

    /// Disabled.
    pub fn disabled() -> McpSettings {
        McpSettings { enabled: false }
    }

    /// Whether the MCP server is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }
}

/// Why the MCP channel refuses a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChannelDenial {
    /// The operation has no tool.
    NotExposed,
    /// The token lacks the tool's scope.
    Scope,
    /// The tenant disabled MCP, or limits its roles (P-74).
    P74,
}

impl ChannelDenial {
    /// The rule text a refusal names.
    pub const fn spec_id(self) -> &'static str {
        match self {
            ChannelDenial::NotExposed => "I-84",
            ChannelDenial::Scope => "scope",
            ChannelDenial::P74 => "P-74",
        }
    }
}

/// What the channel allows for one call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChannelVerdict {
    /// Execute the call.
    Execute,
    /// Store a pending action for a web confirmation (I-85).
    Prepare,
    /// Refuse the call.
    Deny(ChannelDenial),
}

/// The only channel-specific function. The stub denies every call, so it
/// never answers a channel question with a made-up verdict.
pub fn channel_policy(
    op: &OpSpec,
    p: &Principal,
    governing_p77: McpBindingActions,
    tenant: &McpSettings,
) -> ChannelVerdict {
    let _ = (op, p, governing_p77, tenant);
    ChannelVerdict::Deny(ChannelDenial::NotExposed)
}

/// Whether the caller's session is strong enough for the operation
/// (I-77). The stub admits none.
pub fn session_admits(op: &OpSpec, p: &Principal) -> bool {
    let _ = (op, p);
    false
}

/// What a read is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReadTarget {
    /// The caller's own objects or the tenant.
    None,
    /// A programme.
    Programme(ProgrammeId),
    /// A call.
    Call(CallId),
    /// A proposal.
    Proposal(ProposalId),
    /// A reviewer or IRC assignment.
    Assignment(AssignmentId),
}

/// One read to judge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReadOp {
    /// The read.
    pub kind: ReadKind,
    /// What it reads.
    pub target: ReadTarget,
}

/// The rule text a refused read names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DenyRule {
    /// The caller has no account.
    Actor,
    /// R-AC-01: the read is not open to the caller here.
    Rac01,
    /// I-21: drafts are the team's alone.
    I21,
    /// R-CF-02: the caller must declare first.
    Rcf02,
    /// I-03: the caller has a conflict on the proposal.
    I03,
    /// P-75: a reviewer's agent may not read full content.
    P75,
    /// The target does not exist.
    Input,
}

impl DenyRule {
    /// The rule as `ApiError` carries it.
    pub const fn spec_id(self) -> &'static str {
        match self {
            DenyRule::Actor => "actor",
            DenyRule::Rac01 => "R-AC-01",
            DenyRule::I21 => "I-21",
            DenyRule::Rcf02 => "R-CF-02",
            DenyRule::I03 => "I-03",
            DenyRule::P75 => "P-75",
            DenyRule::Input => "Input",
        }
    }
}

/// A refused read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Denied {
    rule: DenyRule,
}

impl Denied {
    /// The rule that refused.
    pub const fn rule(&self) -> DenyRule {
        self.rule
    }
}

/// A cleared read. The stub builds none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReadClearance {
    op: ReadOp,
}

impl ReadClearance {
    /// The read it clears.
    pub const fn op(&self) -> ReadOp {
        self.op
    }
}

/// Judges one read. The stub refuses every read with R-AC-01.
pub fn authorize_read(
    op: &ReadOp,
    p: &Principal,
    state: &EngineState,
    now: Timestamp,
) -> Result<ReadClearance, Denied> {
    let _ = (op, p, state, now);
    Err(Denied {
        rule: DenyRule::Rac01,
    })
}
