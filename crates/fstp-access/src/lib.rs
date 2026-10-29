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
//! empty and every operation refuses with [`AccessError::NotImplemented`].
//! An empty registry exposes no operation, so dispatch stays closed until
//! W3a fills it.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

use fstp_domain::Via;
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_engine::EngineState;

/// Why an access operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessError {
    /// The W0 stub of the named operation refuses.
    NotImplemented(&'static str),
}

impl std::fmt::Display for AccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for AccessError {}

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

    /// The caller of an M3 session. The stub refuses, so no session
    /// principal exists until lane W3a writes the checked constructor.
    pub fn web(
        account: AccountId,
        state: &EngineState,
        now: Timestamp,
    ) -> Result<Principal, AccessError> {
        let _ = (account, state, now);
        Err(AccessError::NotImplemented("fstp_access::Principal::web"))
    }

    /// The caller of a validated MCP token. The stub refuses.
    pub fn mcp(
        account: AccountId,
        state: &EngineState,
        now: Timestamp,
    ) -> Result<Principal, AccessError> {
        let _ = (account, state, now);
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

/// An MCP tool definition: fixed name, description and input schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToolDef {
    /// The tool name.
    pub name: &'static str,
    /// The fixed description. It never holds tenant text (TH-63).
    pub description: &'static str,
    /// The scope the tool needs.
    pub scope: Scope,
    /// Whether the tool only prepares a pending action (I-85).
    pub prepare_only: bool,
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

/// One operation of the registry.
///
/// W0 placeholder with the tool field only. Lane W3a writes the designed
/// fields of section 3.6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpSpec {
    /// The MCP tool, if the operation has one.
    pub tool: Option<ToolDef>,
}

/// Every operation of M4. Empty in W0, so no operation is exposed.
pub const OPS: &[OpSpec] = &[];

/// What the channel allows for one call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelVerdict {
    /// Execute the call.
    Execute,
    /// Store a pending action for a web confirmation (I-85).
    Prepare,
    /// Refuse the call.
    Deny,
}

/// The only channel-specific function. The design makes it total and pure.
/// The stub returns a `Result`, so it never answers a channel question
/// with a made-up verdict.
pub fn channel_policy(op: &OpSpec, p: &Principal) -> Result<ChannelVerdict, AccessError> {
    let _ = (op, p);
    Err(AccessError::NotImplemented("fstp_access::channel_policy"))
}
