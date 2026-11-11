//! M7 design sections 4 and 7: the pre-check ops and the findings
//! status read in the registry (I-21, TH-02, T-LLM-ORACLE, I-10).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_access::{
    AgentClientId, ChannelDenial, ChannelVerdict, GrantFacts, LoginMethod, McpSettings, Member,
    OpKind, Principal, REPLIES, ReadKind, ReadRule, Scope, Shape, channel_policy, op, read_rule,
};
use fstp_domain::StateTag;
use fstp_domain::id::AccountId;
use fstp_domain::policy::McpBindingActions;
use fstp_domain::time::Timestamp;
use fstp_engine::EngineState;

/// Member names from which a score or band would be derivable.
const SCORE_NAMES: [&str; 8] = [
    "score",
    "band",
    "weight",
    "confidence",
    "rank",
    "decision",
    "points",
    "grade",
];

fn names(shape: &Shape, out: &mut Vec<&'static str>) {
    match shape {
        Shape::Array(s) | Shape::Nullable(s) => names(s, out),
        Shape::Object(ms) => {
            for Member { name, shape, .. } in ms.iter() {
                out.push(name);
                names(shape, out);
            }
        }
        _ => {}
    }
}

fn reply_names(op: &str) -> Vec<&'static str> {
    let (_, shape) = REPLIES
        .iter()
        .find(|(n, _)| *n == op)
        .unwrap_or_else(|| panic!("{op} has no reply shape"));
    let mut out = Vec::new();
    names(shape, &mut out);
    out
}

/// TH-02, T-LLM-ORACLE, R-LA-06: neither pre-check reply has a member
/// from which a score, band or confidence is derivable.
#[test]
fn th02_precheck_reply_has_no_score_member() {
    for op in ["proposal.precheck", "proposal.precheck_runs"] {
        let names = reply_names(op);
        assert!(names.contains(&"statement"), "{op} shows findings");
        for n in &names {
            assert!(
                !SCORE_NAMES.iter().any(|s| n.contains(s)),
                "TH-02: {op} has member {n}"
            );
        }
    }
}

/// I-10, M7 design section 7: the coordinator's findings status shows
/// counts only, never a statement, kind or severity.
#[test]
fn i10_findings_status_shows_counts_only() {
    let names = reply_names("assess.findings_status");
    assert_eq!(names, vec!["proposal", "status", "findings"]);
}

fn mcp() -> Principal {
    let grant = GrantFacts {
        account: AccountId::from_raw(301),
        agent: AgentClientId::from_raw(9),
        scopes: Scope::ALL.iter().copied().collect(),
        consent_method: LoginMethod::Passkey,
    };
    Principal::mcp(
        &grant,
        &BTreeSet::new(),
        &EngineState::genesis(),
        Timestamp::from_micros(1_000_000),
    )
    .unwrap()
}

/// I-21, M7 design section 4: the pre-check is web only. MCP answers
/// not exposed whatever the scopes, P-77 and P-74 say.
#[test]
fn i21_precheck_ops_are_not_exposed_through_mcp() {
    let p = mcp();
    for name in [
        "proposal.precheck",
        "proposal.precheck_runs",
        "assess.findings_status",
    ] {
        let spec = op(name).unwrap_or_else(|| panic!("{name} is not in the registry"));
        assert!(spec.tool.is_none(), "{name} has a tool");
        for p77 in [McpBindingActions::DraftOnly, McpBindingActions::Allowed] {
            assert_eq!(
                channel_policy(spec, &p, p77, &McpSettings::all_roles()),
                ChannelVerdict::Deny(ChannelDenial::NotExposed),
                "I-21: {name} through MCP"
            );
        }
    }
}

/// I-21: the runs read admits the team alone and only on a draft, so no
/// Operator or Judging role reads a run in any state.
#[test]
fn i21_precheck_runs_read_is_the_drafting_team_only() {
    let (rule, open) = read_rule(ReadKind::GetPrecheckRuns).unwrap();
    assert_eq!(rule, ReadRule::Team);
    assert_eq!(open, &[StateTag::Draft]);
    let spec = op("proposal.precheck").unwrap();
    assert!(matches!(spec.kind, OpKind::M3Port(_)));
    assert_eq!(spec.acting, op("proposal.save_workspace").unwrap().acting);
}
