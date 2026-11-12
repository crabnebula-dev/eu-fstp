//! R-PB-02, R-PB-03, I-41, I-43, I-85, I-86 (M9 lane P1): the grantee
//! lead's public choice operations in the registry.
//!
//! - `grant.publicity.view` is the lead's read (`ReadRule::ChoiceMaker`),
//!   open in GRANTED, IN_EXECUTION and COMPLETED only (I-41).
//! - `grant.publicity.set` and `grant.publicity.withdraw` carry the core
//!   commands `SetPublicChoice` and `WithdrawPublicChoice`, acting as the
//!   lead.
//! - All three are web only (I-85). The view's reply names no account,
//!   amount or proposal text (I-86, R-PB-03).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_access::{OpKind, ReadKind, ReadRule, RoleOrApplicant, op, read_rule, reply};
use fstp_domain::roles::Role;
use fstp_domain::{CommandKind, StateTag};

/// I-41: the view is the choice maker's, open from GRANTED on and closed
/// in every state before it and in TERMINATED.
#[test]
fn i41_publicity_view_is_the_leads_from_granted_on() {
    let (rule, open) = read_rule(ReadKind::GetPublicity).expect("a rule");
    assert_eq!(rule, ReadRule::ChoiceMaker);
    assert_eq!(
        open,
        &[
            StateTag::Granted,
            StateTag::InExecution,
            StateTag::Completed
        ]
    );
    let spec = op("grant.publicity.view").expect("in the registry");
    assert_eq!(spec.kind, OpKind::Read(ReadKind::GetPublicity));
    assert_eq!(
        spec.route.map(|(_, p)| p),
        Some("/grants/{proposal}/publicity")
    );
    assert_eq!(spec.acting, &[RoleOrApplicant::Role(Role::Applicant)]);
}

/// R-PB-02, I-43, I-85: the two choice operations carry the core
/// commands, act as the lead, and have no MCP tool.
#[test]
fn r_pb_02_choice_ops_carry_the_core_commands_web_only() {
    for (name, kind, path) in [
        (
            "grant.publicity.set",
            CommandKind::SetPublicChoice,
            "/grants/{proposal}/publicity",
        ),
        (
            "grant.publicity.withdraw",
            CommandKind::WithdrawPublicChoice,
            "/grants/{proposal}/publicity/withdrawal",
        ),
    ] {
        let spec = op(name).unwrap_or_else(|| panic!("{name} is not in the registry"));
        assert_eq!(spec.kind, OpKind::Command(kind), "{name}");
        assert_eq!(spec.route.map(|(_, p)| p), Some(path), "{name}");
        assert_eq!(spec.acting, &[RoleOrApplicant::Role(Role::Applicant)]);
        assert!(spec.tool.is_none(), "I-85: {name} has a tool");
    }
    assert!(op("grant.publicity.view").expect("view").tool.is_none());
}

/// I-86, R-PB-03: the view's reply carries the levels, the lead's own
/// public texts and the accepted deliverables, and nothing that names an
/// account, an amount or a bank detail.
#[test]
fn i86_publicity_view_reply_names_no_account_or_amount() {
    let text = format!("{:?}", reply("grant.publicity.view").expect("a shape"));
    for member in [
        "\"max_funded\"",
        "\"max_finished\"",
        "\"minor\"",
        "\"effective\"",
        "\"summary\"",
        "\"deliverables\"",
    ] {
        assert!(text.contains(member), "lacks {member}: {text}");
    }
    for leak in ["account", "amount", "bank", "email", "\"content\""] {
        assert!(!text.contains(leak), "the view names {leak}: {text}");
    }
}
