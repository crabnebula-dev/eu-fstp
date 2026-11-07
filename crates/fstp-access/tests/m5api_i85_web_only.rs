//! I-85, I-84, M5 design reading 9 and 12.1 (lane L-API): every M5
//! command is web only, so MCP refuses it as not exposed whatever the
//! token's scopes, P-77 and P-74 say. The only M5 tools are the read-only
//! contract status, payment status and payment queue tools, and the web
//! channel executes every M5 operation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_access::{
    AgentClientId, ChannelDenial, ChannelVerdict, GrantFacts, LoginMethod, McpSettings, OPS,
    OpKind, Principal, Scope, SessionFacts, SessionId, channel_policy, op,
};
use fstp_domain::id::AccountId;
use fstp_domain::policy::McpBindingActions;
use fstp_domain::time::Timestamp;
use fstp_engine::EngineState;

/// Every M5 command and non-read operation of M5 design section 5.
const M5_COMMANDS: [&str; 33] = [
    "grant.determine_amount",
    "grant.accept",
    "grant.approve",
    "grant.terminate",
    "milestone.close",
    "contract.draft",
    "contract.propose_change",
    "contract.decide_change",
    "contract.send",
    "contract.sign",
    "contract.approve_advanced",
    "contract.decline",
    "payment.submit",
    "payment.resubmit",
    "payment.withdraw",
    "payment.review_line",
    "payment.request_changes",
    "payment.approve",
    "payment.release",
    "payment.confirm_paid",
    "payment.close",
    "amendment.propose",
    "amendment.route",
    "vault.bank.set",
    "vault.bank.verify",
    "vault.bank.dispute",
    "vault.bank.view_for_release",
    "vault.hardship.submit",
    "vault.hardship.verify",
    "report.generate",
    "report.approve",
    // The two reads with no tool are web only too.
    "grant.overview",
    "report.list",
];

/// The read-only tools of 12.1.
const M5_TOOLS: [(&str, &str); 3] = [
    ("contract.view", "fstp_get_contract_status"),
    ("payment.status", "fstp_get_payment_status"),
    ("payment.queue", "fstp_get_payment_queue"),
];

const T0: Timestamp = Timestamp::from_micros(1_000_000);

fn mcp(scopes: &[Scope]) -> Principal {
    let grant = GrantFacts {
        account: AccountId::from_raw(301),
        agent: AgentClientId::from_raw(9),
        scopes: scopes.iter().copied().collect(),
        consent_method: LoginMethod::Passkey,
    };
    Principal::mcp(&grant, &BTreeSet::new(), &EngineState::genesis(), T0)
        .unwrap_or_else(|e| panic!("{e}"))
}

/// I-85: no M5 command is reachable through MCP, under every P-77 value
/// and every P-74 setting that enables the server.
#[test]
fn i85_every_m5_command_is_not_exposed_through_mcp() {
    let p = mcp(&Scope::ALL);
    for name in M5_COMMANDS {
        let spec = op(name).unwrap_or_else(|| panic!("{name} is not in the registry"));
        assert!(spec.tool.is_none(), "{name} has a tool");
        for p77 in [McpBindingActions::DraftOnly, McpBindingActions::Allowed] {
            assert_eq!(
                channel_policy(spec, &p, p77, &McpSettings::all_roles()),
                ChannelVerdict::Deny(ChannelDenial::NotExposed),
                "I-85: {name} through MCP"
            );
        }
    }
}

/// I-84, 12.1: the three read-only tools sit on reads, with no
/// prepare-only flag, and execute through MCP with their scope.
#[test]
fn i84_m5_status_tools_are_read_only() {
    let p = mcp(&Scope::ALL);
    for (name, tool) in M5_TOOLS {
        let spec = op(name).unwrap_or_else(|| panic!("{name} is not in the registry"));
        let t = spec.tool.unwrap_or_else(|| panic!("{name} has no tool"));
        assert_eq!(t.name, tool);
        assert!(matches!(spec.kind, OpKind::Read(_)), "{name} is a read");
        assert!(
            !t.prepare_only && !spec.high_risk && !spec.binding,
            "{name}"
        );
        assert_eq!(
            channel_policy(
                spec,
                &p,
                McpBindingActions::DraftOnly,
                &McpSettings::all_roles()
            ),
            ChannelVerdict::Execute,
            "{name} through MCP"
        );
    }
    let none = mcp(&[]);
    for (name, _) in M5_TOOLS {
        let spec = op(name).unwrap();
        assert_eq!(
            channel_policy(
                spec,
                &none,
                McpBindingActions::Allowed,
                &McpSettings::all_roles()
            ),
            ChannelVerdict::Deny(ChannelDenial::Scope),
            "{name} without its scope"
        );
    }
}

/// I-84: the web channel executes every M5 operation; its own rules
/// judge it after the channel.
#[test]
fn i84_web_executes_every_m5_operation() {
    let s = EngineState::genesis();
    let facts = SessionFacts {
        account: AccountId::from_raw(301),
        session: SessionId::from_raw(1),
        method: LoginMethod::Passkey,
    };
    let p = Principal::web(&facts, &BTreeSet::new(), &s, T0);
    let names: BTreeSet<&str> = M5_COMMANDS
        .iter()
        .chain(M5_TOOLS.iter().map(|(n, _)| n))
        .copied()
        .collect();
    let mut seen = 0usize;
    for o in OPS.iter().filter(|o| names.contains(o.name)) {
        assert_eq!(
            channel_policy(
                o,
                &p,
                McpBindingActions::DraftOnly,
                &McpSettings::disabled()
            ),
            ChannelVerdict::Execute,
            "{}",
            o.name
        );
        seen += 1;
    }
    assert_eq!(seen, names.len());
}
