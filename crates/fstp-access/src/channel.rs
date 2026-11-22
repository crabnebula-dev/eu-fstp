//! The channel rules (M4 design sections 3.6 and 3.7, I-77, I-84, I-85).
//!
//! [`channel_policy`] is the only function where the web and MCP channels
//! differ by operation. It reads nothing but its arguments. For a decoded
//! creator command, [`creator_channel_policy`] refines its verdict by the
//! request: through MCP, a call that sets P-75 or P-77 is prepared
//! (ADR-013, Daniel, 2026-11-20). [`session_admits`] is the
//! session strength rule that dispatch applies before it, on both
//! channels.

use std::collections::BTreeSet;

use fstp_creator::{CreatorCommand, StartingPoint};
use fstp_domain::Via;
use fstp_domain::policy::McpBindingActions;
use fstp_programme::FieldId;

use crate::principal::Principal;
use crate::registry::{OpKind, OpSpec, RoleOrApplicant, SessionNeed};

/// The tenant's MCP settings, the P-74 value: whether the MCP server is
/// enabled and which roles may act through it. The public research tools
/// stay open whenever the server is enabled.
///
/// Interim, pending the lead: `fstp-tenant` owns the P-74 setting record.
/// Its W0 stub has no settings type yet, so the value the channel reads
/// is declared here.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct McpSettings {
    enabled: bool,
    roles: Option<BTreeSet<RoleOrApplicant>>,
}

impl McpSettings {
    /// Enabled for all roles, plus the public research tools: the P-74
    /// default and the SuperSAFE value.
    pub fn all_roles() -> McpSettings {
        McpSettings {
            enabled: true,
            roles: None,
        }
    }

    /// Disabled. Public tools are refused too.
    pub fn disabled() -> McpSettings {
        McpSettings {
            enabled: false,
            roles: None,
        }
    }

    /// Enabled for `roles` only, plus the public research tools.
    pub fn limited_to(roles: impl IntoIterator<Item = RoleOrApplicant>) -> McpSettings {
        McpSettings {
            enabled: true,
            roles: Some(roles.into_iter().collect()),
        }
    }

    /// Whether the MCP server is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Whether an enabled server lets `r` act through MCP.
    pub fn allows(&self, r: RoleOrApplicant) -> bool {
        self.enabled && self.roles.as_ref().is_none_or(|set| set.contains(&r))
    }
}

/// Why the MCP channel refuses a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChannelDenial {
    /// The operation has no tool.
    NotExposed,
    /// The token lacks the tool's scope.
    Scope,
    /// The tenant disabled MCP, or limits it to roles other than one the
    /// call can act under (P-74, Q42).
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

/// The only channel-specific function. Total and pure.
///
/// - `Via::Web`: `Execute`.
/// - `Via::Mcp`: `Deny(NotExposed)` without a tool, `Deny(Scope)` without
///   the tool's scope, and `Deny(P74)` when the tenant disabled MCP or
///   when a role in `p.roles() ∩ op.acting` is outside the roles P-74
///   allows (Q42 interim). Public tools need no scope and no role.
///   Otherwise `Prepare` when the operation is high-risk or its tool is
///   prepare-only (I-85), or when it is binding and the governing P-77 is
///   "draft only" (R-MC-05). Otherwise `Execute`.
///
/// For an operation outside any programme, the caller passes `DraftOnly`,
/// the strict P-77 value.
pub fn channel_policy(
    op: &OpSpec,
    p: &Principal,
    governing_p77: McpBindingActions,
    tenant: &McpSettings,
) -> ChannelVerdict {
    if p.via() == Via::Web {
        return ChannelVerdict::Execute;
    }
    let Some(tool) = op.tool else {
        return ChannelVerdict::Deny(ChannelDenial::NotExposed);
    };
    let public = matches!(op.kind, OpKind::Public(_));
    if !public && !p.scopes().contains(tool.scope) {
        return ChannelVerdict::Deny(ChannelDenial::Scope);
    }
    if !tenant.enabled() {
        return ChannelVerdict::Deny(ChannelDenial::P74);
    }
    if !public
        && p.roles()
            .iter()
            .any(|r| op.acting.contains(&r) && !tenant.allows(r))
    {
        return ChannelVerdict::Deny(ChannelDenial::P74);
    }
    if tool.prepare_only
        || op.high_risk
        || (op.binding && governing_p77 == McpBindingActions::DraftOnly)
    {
        return ChannelVerdict::Prepare;
    }
    ChannelVerdict::Execute
}

/// Whether a creator command sets P-21, P-75 or P-77 (ADR-013, Daniel's
/// decision of 2026-11-20 for P-75 and P-77; ADR-033 adds P-21, whose
/// provider can open the coordinator's client path). A save or a clear
/// that names one of them sets it, alone or mixed with other fields. So
/// does a start from a template or a clone, which applies the source's
/// values of all three. An accepted or edited narrative names one of them
/// only in a request the creator refuses, and it counts too. A blank start
/// and a start from an import apply no value of any.
pub fn sets_agent_policy(cmd: &CreatorCommand) -> bool {
    // ADR-033: P-21 too, since its provider can open the client path,
    // where the coordinator's agent reads proposal content.
    let named = |f: &FieldId| matches!(f, FieldId::P21 | FieldId::P75 | FieldId::P77);
    match cmd {
        CreatorCommand::SaveFields { fields, clear, .. } => {
            fields.iter().any(|e| named(&e.field)) || clear.iter().any(named)
        }
        CreatorCommand::ApplyStart { start, .. } => matches!(
            start,
            StartingPoint::Template { .. } | StartingPoint::Clone { .. }
        ),
        CreatorCommand::AcceptNarrative { field, .. } => named(field),
        CreatorCommand::EditNarrative { edit, .. } => named(&edit.field),
        _ => false,
    }
}

/// The verdict for a decoded creator command, from the verdict
/// [`channel_policy`] gave its operation (ADR-013, Daniel's decision of
/// 2026-11-20). Through MCP, `Execute` becomes `Prepare` when the command
/// sets P-75 or P-77 ([`sets_agent_policy`]), so the whole call waits for
/// a confirmation in the platform (I-85). Every other verdict, and every
/// web call, is returned unchanged. Total and pure.
pub fn creator_channel_policy(
    verdict: ChannelVerdict,
    p: &Principal,
    cmd: &CreatorCommand,
) -> ChannelVerdict {
    if verdict == ChannelVerdict::Execute && p.via() == Via::Mcp && sets_agent_policy(cmd) {
        return ChannelVerdict::Prepare;
    }
    verdict
}

/// Whether the caller's session is strong enough for the operation
/// (I-77, I-78). A session that is not phishing-resistant is refused for
/// a high-risk operation, and for every operation of an account that
/// holds a Drafting, Judging, Operations or tenant admin role. Public
/// operations have no session rule. A caller with no session passes
/// here, and the actor rules refuse it where an account is needed.
pub fn session_admits(op: &OpSpec, p: &Principal) -> bool {
    if matches!(op.kind, OpKind::Public(_)) || p.account().is_none() {
        return true;
    }
    if p.phishing_resistant() {
        return true;
    }
    op.session == SessionNeed::Any && !op.high_risk && !p.holds_management_role()
}
