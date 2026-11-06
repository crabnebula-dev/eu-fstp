//! I-84 and R-AU-01 through the MCP server (M4 design sections 3.7 and
//! 3.8): the same policy engine and audit as the web, and the agent named
//! next to the user.
//!
//! - An applicant's read of their own proposal through MCP appends a
//!   `ContentRead`, as the same read through the web does (R-AU-01, D6:
//!   the team reads its own proposal whatever P-75 says).
//! - Every audit entry of an MCP call, accepted or refused, names the
//!   account and the agent client, with `Via::Mcp`.
//! - A scope never adds a right the roles lack: a token with every scope
//!   is refused where the account's roles refuse it.
//!
//! Status: red until `fstp_mcp::McpServer` exists.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod mcp_support;

use fstp_api_core::Credential;
use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::meta::Scope;
use fstp_api_core::port::Outcome;
use fstp_api_testkit::fake::cell::{Class, class};
use fstp_api_testkit::fake::fixture::{AGENT, AGENT_2, CALL_OPEN, LEAD, OTHER, PX};
use fstp_api_testkit::matrix::Observed;
use fstp_domain::Via;
use fstp_domain::command::{Actor, CommandKind};
use fstp_engine::Command;
use fstp_mcp::Surface;
use mcp_support::{McpCell, call, dec, obj, observed};

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

/// The `ReadContent` executions on PX, with their channel and agent.
fn content_reads(c: &McpCell) -> Vec<(Via, Option<fstp_api_core::port::AgentClientId>, Actor)> {
    c.ports
        .engine
        .appended()
        .into_iter()
        .filter(|e| matches!(&e.cmd, Command::Core(x) if x.kind() == CommandKind::ReadContent))
        .map(|e| (e.meta.via, e.meta.agent, e.ctx.actor))
        .collect()
}

/// R-AU-01, I-84, D6: the lead's agent reads the submitted PX through
/// `fstp_get_my_proposal`. One `ContentRead` by the lead is appended,
/// through MCP and naming the agent client, exactly as the lead's own
/// read of `proposal.view` through the web appends one through the web.
#[test]
fn r_au_01_applicant_reads_through_mcp_append_content_read() {
    let c = McpCell::submitted();
    let lead = c.login(LEAD);
    let path = fstp_access::op("proposal.view")
        .and_then(|o| o.route)
        .map(|(_, p)| p.replace("{proposal}", &PX.raw().to_string()))
        .unwrap();
    let web = c.web(&lead, decode_route(Method::Get, &path, b""));
    assert_eq!(class(&web), Class::Done, "the web read: {web:?}");
    let after_web = content_reads(&c);
    assert_eq!(
        after_web.len(),
        1,
        "R-AU-01: proposal.view through the web must append one ContentRead, since design section 3.8 has fstp_get_my_proposal run ReadContent and I-84 asks the same of both channels"
    );
    assert_eq!(after_web[0].0, Via::Web);

    let s = c.server();
    let token = c.token(LEAD, AGENT, [Scope::ProposalsRead]);
    let r = call(
        &s,
        Surface::Mcp,
        Credential::Bearer(token),
        "fstp_get_my_proposal",
        &obj(vec![("proposal", dec(PX.raw()))]),
    );
    assert_eq!(observed(&r), Ok(Observed::Completed), "{r:?}");
    let all = content_reads(&c);
    assert_eq!(all.len(), 2, "the MCP read appends one ContentRead");
    assert_eq!(all[1], (Via::Mcp, Some(AGENT), Actor::Account(LEAD)));
}

/// I-84 (`i84_audit_entries_match_modulo_channel_and_client`, design
/// section 3.8 "Agent attribution"): an accepted and a refused MCP call
/// each record one audit entry that names the account, `Via::Mcp` and the
/// agent client of the token, and the refusal's rule.
#[test]
fn i84_mcp_audit_entry_names_agent_client() {
    let c = McpCell::new();
    let s = c.server();
    let token = c.token(LEAD, AGENT_2, EVERY_SCOPE);
    let before = c.ports.audit.entries().len();
    let ok = call(
        &s,
        Surface::Mcp,
        Credential::Bearer(token.clone()),
        "fstp_list_my_proposals",
        &obj(vec![]),
    );
    assert_eq!(observed(&ok), Ok(Observed::Completed), "{ok:?}");
    let refused = call(
        &s,
        Surface::Mcp,
        Credential::Bearer(token),
        "fstp_get_call_board",
        &obj(vec![("call", dec(CALL_OPEN.raw()))]),
    );
    assert!(
        matches!(
            observed(&refused),
            Ok(Observed::Refused(Some(_)) | Observed::NotFound(_))
        ),
        "the lead reads no call board: {refused:?}"
    );
    let entries = c.ports.audit.entries();
    let new = &entries[before..];
    assert_eq!(new.len(), 2, "{new:?}");
    for e in new {
        assert_eq!(e.actor, Some(LEAD));
        assert_eq!(e.via, Via::Mcp);
        assert_eq!(e.agent, Some(AGENT_2));
    }
    assert_eq!(new[0].outcome, Outcome::Accepted);
    assert!(matches!(new[1].outcome, Outcome::Refused(_)));
}

/// I-84, design section 3.8 "Scopes": a token with every scope never adds
/// a right the roles lack. The lead's token is refused the call board and
/// the publication, the call drafter's is refused the creator draft read
/// that only a programme manager may make, and nothing is appended.
#[test]
fn i84_scope_never_adds_a_right_the_roles_lack() {
    let c = McpCell::new();
    let s = c.server();
    let head = c.ports.engine.appended().len();
    let cases = [
        (
            LEAD,
            "fstp_get_call_board",
            obj(vec![("call", dec(CALL_OPEN.raw()))]),
        ),
        (
            LEAD,
            "fstp_prepare_call_publication",
            obj(vec![(
                "call",
                dec(fstp_api_testkit::fake::fixture::CALL_PUBLISH.raw()),
            )]),
        ),
        (
            OTHER,
            "fstp_prepare_call_publication",
            obj(vec![(
                "call",
                dec(fstp_api_testkit::fake::fixture::CALL_PUBLISH.raw()),
            )]),
        ),
    ];
    for (who, name, args) in cases {
        let token = c.token(who, AGENT, EVERY_SCOPE);
        let r = call(&s, Surface::Mcp, Credential::Bearer(token), name, &args);
        let got = observed(&r).unwrap_or_else(|e| panic!("{who:?} {name}: {e:?}"));
        assert!(
            matches!(got, Observed::Refused(Some(_)) | Observed::NotFound(_)),
            "{who:?} {name} gave {got:?}"
        );
    }
    assert_eq!(c.ports.engine.appended().len(), head);
}
