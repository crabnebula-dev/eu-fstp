//! I-12 at the MCP path (R-MC-05, design 2.4 point 3).
//!
//! A binding action through MCP that a published call governs reads that
//! call's frozen P-77. A later edit of the head never changes it. A command
//! that no published call governs reads the head P-77. The engine routes
//! both through `policy::mcp_binding_allowed`, which delegates to the two
//! public reads used here. Two examples send commands through
//! `Via::Mcp`, so the engine routing and each lane scope are checked too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::{Command, Via};
use fstp_domain::id::CallId;
use fstp_domain::policy::McpBindingActions;
use fstp_domain::refusal::{RefusalReason, RuleRef};
use fstp_domain::rules::ParamId;
use fstp_domain_testkit::r#gen::policy::{
    ADMIN, DRAFTER_1, P1, P2, PM_A, PM_B, PM_C, PolicyWorld, base_version,
};
use fstp_domain_testkit::mc::policy_model::reads;
use fstp_engine::ExecError;
use fstp_ledger::Seq;

fn call_allows(w: &PolicyWorld, call: u128) -> Result<bool, String> {
    reads::call_allows_mcp_binding(w.state(), CallId::from_raw(call))
}

/// I-12: a call published under P-77 "draft only" keeps refusing MCP
/// binding actions after the head allows them. A call published after the
/// edit allows them, and an unpublished call has no governing P-77.
#[test]
fn i12_mcp_binding_actions_read_the_frozen_p77() {
    let mut w = PolicyWorld::new(false).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(w.head(P1).unwrap().frozen.p77, McpBindingActions::DraftOnly);
    for call in [1, 2, 3] {
        assert!(w.draft(DRAFTER_1, call, P1).unwrap().is_ok());
        assert!(w.approve(PM_B, call).is_ok());
    }
    assert!(w.publish(PM_A, 1).unwrap().is_ok());
    assert_eq!(call_allows(&w, 1), Ok(false));
    let r = w
        .edit(PM_C, P1, |v| v.frozen.p77 = McpBindingActions::Allowed)
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(reads::programme_allows_mcp_binding(w.state(), P1), Ok(true));
    assert_eq!(call_allows(&w, 1), Ok(false));
    assert!(w.publish(PM_A, 2).unwrap().is_ok());
    assert_eq!(call_allows(&w, 2), Ok(true));
    assert!(call_allows(&w, 3).is_err());
}

/// Whether `r` is the refusal of a binding action under P-77 "draft only".
fn refused_by_p77(r: &Result<Seq, ExecError>) -> bool {
    matches!(r, Err(ExecError::Refused(x))
        if x.rule == RuleRef::Param(ParamId::P77) && x.reason == RefusalReason::NotThroughMcp)
}

/// Whether `r` is the I-85 refusal of a high-risk command through MCP.
fn refused_by_i85(r: &Result<Seq, ExecError>) -> bool {
    matches!(r, Err(ExecError::Refused(x))
        if x.rule == RuleRef::I85 && x.reason == RefusalReason::NotThroughMcp)
}

/// R-MC-05 with I-12 through the engine: a call command through MCP that
/// no published call governs reads the head P-77 of the call's programme.
/// Under "draft only" `EditCall`, `ApproveCallPublication` and `EditPolicy`
/// are refused. An edit through MCP cannot unlock itself. Once the head
/// allows binding actions, `EditCall` and `ApproveCallPublication` through
/// MCP are accepted.
#[test]
fn i12_r_mc_05_call_commands_through_mcp_read_the_head_p77() {
    let mut w = PolicyWorld::new(false).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(w.head(P1).unwrap().frozen.p77, McpBindingActions::DraftOnly);
    assert!(w.draft(DRAFTER_1, 1, P1).unwrap().is_ok());
    w.setup.via = Via::Mcp;
    let r = w.edit_call(DRAFTER_1, 1).unwrap();
    assert!(refused_by_p77(&r), "EditCall: {r:?}");
    let r = w.approve(PM_B, 1);
    assert!(refused_by_p77(&r), "ApproveCallPublication: {r:?}");
    let r = w
        .edit(PM_C, P1, |v| v.frozen.p77 = McpBindingActions::Allowed)
        .unwrap();
    assert!(refused_by_p77(&r), "EditPolicy: {r:?}");
    w.setup.via = Via::Web;
    let r = w
        .edit(PM_C, P1, |v| v.frozen.p77 = McpBindingActions::Allowed)
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    w.setup.via = Via::Mcp;
    let r = w.edit_call(DRAFTER_1, 1).unwrap();
    assert!(r.is_ok(), "EditCall: {r:?}");
    let r = w.approve(PM_B, 1);
    assert!(r.is_ok(), "ApproveCallPublication: {r:?}");
}

/// I-85 through the engine: `PublishCall` and `CreateProgramme` are high
/// risk and never complete through MCP, even when the head P-77 allows
/// binding actions.
#[test]
fn i85_publication_and_programme_creation_never_complete_through_mcp() {
    let mut w = PolicyWorld::new(false).unwrap_or_else(|e| panic!("{e}"));
    let r = w
        .edit(PM_C, P1, |v| v.frozen.p77 = McpBindingActions::Allowed)
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    assert!(w.draft(DRAFTER_1, 1, P1).unwrap().is_ok());
    assert!(w.approve(PM_B, 1).is_ok());
    w.setup.via = Via::Mcp;
    let r = w.publish(PM_A, 1).unwrap();
    assert!(refused_by_i85(&r), "PublishCall: {r:?}");
    let policy = Box::new(base_version(w.fresh_version(), P2, None).unwrap());
    let r = w
        .setup
        .run(ADMIN, true, Command::CreateProgramme { policy });
    assert!(refused_by_i85(&r), "CreateProgramme: {r:?}");
    w.setup.via = Via::Web;
    assert!(w.publish(PM_A, 1).unwrap().is_ok());
}
