//! Access, channels and the operation registry (I-84, I-85, M4 design
//! section 3.6).
//!
//! The crate holds [`Principal`], with private fields and checked
//! constructors, the [`OPS`] registry with every [`ToolDef`] (the only
//! tool table), the read rules and [`authorize_read`], scopes,
//! classifications, the session rule [`session_admits`] and
//! [`channel_policy`], the one pure function where the web and MCP
//! channels differ.
//!
//! The crate holds no parser, so it has no fuzz project (design section
//! 9). It names `fstp-import` for operation kinds only (rule A3), and no
//! adapter may depend on it (rule A1).
//!
//! Every recommendation of the M4 design is built here as an interim
//! reading, pending Daniel (design section 15.0). Each module names the
//! readings it builds.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

mod channel;
mod principal;
mod reads;
mod registry;

// I-84 compile-fail twins. Doc comments only, owned by the test author.
#[cfg(doctest)]
mod twins;

pub use channel::{ChannelDenial, ChannelVerdict, McpSettings, channel_policy, session_admits};
pub use principal::{
    AccessError, AgentClientId, GrantFacts, LoginMethod, Principal, RoleSet, ScopeSet,
    SessionFacts, SessionId,
};
pub use reads::{
    Denied, DenyRule, READ_RULES, ReadClearance, ReadKind, ReadOp, ReadRule, ReadTarget,
    authorize_read, read_rule,
};
pub use registry::{
    AgentKind, BridgeKind, COMPOSED_ONLY, Classification, CreatorKind, FindingKind, ImportKind,
    LATER, Method, Milestone, OPS, OpKind, OpSpec, PendingKind, PortKind, PublicKind,
    RoleOrApplicant, STRICT_EXTRA_HIGH_RISK, SYSTEM_ONLY, SYSTEM_ONLY_OTHER, Schema, Scope,
    SessionNeed, TenantKind, TenantParam, ToolDef, op, route_params,
};

#[cfg(test)]
mod tests;
