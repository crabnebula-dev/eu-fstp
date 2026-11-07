//! I-85 through the MCP server (M4 design sections 3.8 and 8.4, ADR-013
//! "High-risk operations"): high-risk actions never complete through MCP.
//!
//! The dispatch-level tests of `i85_pending_actions.rs` send decoded
//! operations to `ApiCore::dispatch`. These tests send real `tools/list`
//! and `tools/call` requests through `fstp_mcp::McpServer`, so the MCP
//! adapter itself is under test:
//!
//! - every high-risk operation of `OPS` either has no tool, so no tool
//!   name reaches it and it is `Deny(NotExposed)`, or has a prepare-only
//!   tool; no listed tool of any caller completes a high-risk operation;
//! - `fstp_prepare_call_publication` gives a pending action, publishes
//!   nothing, and the call is published only when the owner confirms it
//!   in the platform with a fresh step-up bound to the stored digest.
//!
//! Status: red until `fstp_mcp::McpServer` exists, except the registry
//! check, which is green.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod mcp_support;

use fstp_access::OPS;
use fstp_api_core::meta::{Scope, tools};
use fstp_api_core::{Credential, OpResult};
use fstp_api_testkit::fake::cell::{Class, class};
use fstp_api_testkit::fake::fixture::{ADMIN, ADMIN_2, AGENT, CALL_PUBLISH, LEAD, OTHER, OWNER};
use fstp_api_testkit::fake::requests;
use fstp_api_testkit::matrix::Observed;
use fstp_domain::Via;
use fstp_domain::command::CommandKind;
use fstp_engine::Command;
use fstp_mcp::Surface;
use mcp_support::{McpCell, call, list, listed_names, obj, observed, op_of_tool, structured};

/// Every scope M4 issues (design section 3.8).
const EVERY_SCOPE: [Scope; 12] = [
    Scope::CallsRead,
    Scope::ProposalsRead,
    Scope::ProposalsDraft,
    Scope::ProposalsBinding,
    Scope::Stage2Draft,
    Scope::ReviewRead,
    Scope::ReviewDraft,
    Scope::RankingRead,
    Scope::FindingsRead,
    Scope::CreatorDraft,
    Scope::CallsDraft,
    Scope::AuditRead,
];

/// How many commands of `kind` the engine appended.
fn appended(c: &McpCell, kind: CommandKind) -> usize {
    c.ports
        .engine
        .appended()
        .iter()
        .filter(|e| matches!(&e.cmd, Command::Core(x) if x.kind() == kind))
        .count()
}

/// How many high-risk commands the engine appended through MCP.
fn high_risk_through_mcp(c: &McpCell) -> usize {
    c.ports
        .engine
        .appended()
        .iter()
        .filter(|e| e.meta.via == Via::Mcp)
        .filter(|e| match &e.cmd {
            Command::Core(x) => x.kind().high_risk(),
            _ => fstp_access::op(e.meta.op.0).is_some_and(|o| o.high_risk),
        })
        .count()
}

/// I-85, ADR-013: in the registry, every high-risk operation has no tool
/// or a prepare-only one. Green now, and it must stay green.
#[test]
fn i85_mcp_registry_high_risk_ops_have_no_tool_or_a_prepare_only_one() {
    for op in OPS.iter().filter(|o| o.high_risk) {
        if let Some(t) = op.tool {
            assert!(
                t.prepare_only,
                "{} has the executing tool {}",
                op.name, t.name
            );
        }
    }
    let prepare: Vec<&str> = tools().filter(|t| t.prepare_only).map(|t| t.name).collect();
    assert_eq!(prepare, ["fstp_prepare_call_publication"]);
}

/// I-85, I-84: through the MCP server, for every world account with
/// every scope, the only listed tool of a high-risk operation is
/// prepare-only, and calling every listed tool of a high-risk operation
/// gives a pending action or a refusal, never a completion. No high-risk
/// command is appended through MCP, and no step-up is taken.
#[test]
fn i85_mcp_every_high_risk_op_is_not_exposed_or_prepare_only() {
    let c = McpCell::new();
    let s = c.server();
    for account in [OWNER, OTHER, ADMIN, ADMIN_2, LEAD] {
        let token = c.token(account, AGENT, EVERY_SCOPE);
        let listed = list(&s, Surface::Mcp, Credential::Bearer(token.clone()))
            .unwrap_or_else(|e| panic!("{account:?}: {e:?}"));
        for name in listed_names(&listed) {
            let op = op_of_tool(&name).unwrap_or_else(|| panic!("{name} is outside OPS"));
            if !op.high_risk {
                continue;
            }
            assert!(
                op.tool.is_some_and(|t| t.prepare_only),
                "{account:?} sees {name}, which executes {}",
                op.name
            );
            let args = obj(vec![("call", mcp_support::dec(CALL_PUBLISH.raw()))]);
            let r = call(
                &s,
                Surface::Mcp,
                Credential::Bearer(token.clone()),
                &name,
                &args,
            );
            let got = observed(&r).unwrap_or_else(|e| panic!("{account:?} {name}: {e:?}"));
            assert!(
                matches!(
                    got,
                    Observed::Pending
                        | Observed::Refused(_)
                        | Observed::NotFound(_)
                        | Observed::ChannelDenied(_)
                ),
                "{account:?} {name} gave {got:?}"
            );
        }
    }
    assert_eq!(high_risk_through_mcp(&c), 0);
    assert_eq!(appended(&c, CommandKind::PublishCall), 0);
    assert!(
        c.ports.step_up.taken().is_empty(),
        "a step-up was taken through MCP"
    );
}

/// I-85, I-78 (design section 3.8, Q32): the owner's agent prepares the
/// publication of call 1 through `fstp_prepare_call_publication`. The
/// result is a pending action whose data is the receipt, and nothing is
/// published. The owner sees it in the platform. A confirmation without a
/// step-up asks for one bound to the stored digest and publishes nothing.
/// With a fresh step-up for that digest it publishes the call once,
/// through the web. No tool confirms a pending action.
#[test]
fn i85_mcp_prepared_publication_needs_platform_step_up() {
    let c = McpCell::new();
    let s = c.server();
    let token = c.token(OWNER, AGENT, [Scope::CallsDraft, Scope::CallsRead]);
    let args = obj(vec![("call", mcp_support::dec(CALL_PUBLISH.raw()))]);
    let r = call(
        &s,
        Surface::Mcp,
        Credential::Bearer(token.clone()),
        "fstp_prepare_call_publication",
        &args,
    );
    assert_eq!(observed(&r), Ok(Observed::Pending), "{r:?}");
    let sc = structured(r.as_ref().unwrap()).unwrap();
    let data = sc.get("data").and_then(|d| d.as_object()).unwrap();
    assert!(
        mcp_support::text(data, "confirm_path").is_some_and(|p| p.starts_with("/app/")),
        "the receipt names the platform page that confirms it: {data:?}"
    );
    assert_eq!(appended(&c, CommandKind::PublishCall), 0);

    for name in [
        "fstp_confirm_pending",
        "fstp_pending_confirm",
        "fstp_publish_call",
    ] {
        let r = call(
            &s,
            Surface::Mcp,
            Credential::Bearer(token.clone()),
            name,
            &args,
        );
        assert!(r.is_err(), "{name} is a tool: {r:?}");
    }

    let owner = c.login(OWNER);
    let list = match c.web(&owner, requests::pending_list()) {
        Ok(OpResult::Done {
            body: fstp_api_core::ReadModel::PendingActions(l),
            ..
        }) => l,
        other => panic!("pending.list gave {other:?}"),
    };
    assert_eq!(list.len(), 1, "{list:?}");
    let view = &list[0];
    let first = c.web(&owner, requests::pending_confirm(view.id, &view.digest));
    match &first {
        Ok(OpResult::StepUpRequired(ch)) => assert_eq!(ch.action, view.digest),
        other => panic!("a confirmation without a step-up gave {other:?}"),
    }
    assert_eq!(appended(&c, CommandKind::PublishCall), 0);
    c.ports
        .step_up
        .approve(owner.session, view.digest)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let done = c.web(&owner, requests::pending_confirm(view.id, &view.digest));
    assert_eq!(class(&done), Class::Done, "{done:?}");
    assert_eq!(appended(&c, CommandKind::PublishCall), 1);
    let e = c
        .ports
        .engine
        .appended()
        .into_iter()
        .find(|e| matches!(&e.cmd, Command::Core(x) if x.kind() == CommandKind::PublishCall))
        .unwrap();
    assert_eq!(e.meta.via, Via::Web);
    assert_eq!(e.meta.pending, Some(view.id));
    assert!(e.meta.step_up.is_some());
}
