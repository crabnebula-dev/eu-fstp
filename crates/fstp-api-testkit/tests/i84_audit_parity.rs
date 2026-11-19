//! I-84 audit parity over random sequences on both channels (M4 design
//! sections 3.7 step 9, 3.8 "Agent attribution" and 8.4:
//! `i84_audit_entries_match_modulo_channel_and_client` and
//! `i84_mcp_audit_records_refusals_too`).
//!
//! Each case draws a random sequence of calls from a fixed menu over the
//! I-85 world of `fake::fixture`: reads, refused reads and call edits by
//! the lead, the programme manager and the call drafter. The sequence runs
//! once through the web, in a passkey session per call, on one cell, and
//! once through the `tools/call` handler of the MCP server, with a token
//! of every scope, on a second cell over the same world.
//!
//! The menu holds direct exposures only (design section 8.5, M-PARITY):
//! no high-risk operation and no binding one under P-77 "draft only". So
//! channel policy changes no outcome, and the two cells walk the same
//! states. The edits are of call 4, in P2 under P-77 "allowed".
//!
//! Properties, per call:
//!
//! - each channel records exactly one audit entry, accepted or refused;
//! - with `via` and `agent` removed, the two entries are equal: actor,
//!   operation, outcome, request digest and step-up;
//! - the web entry says `Via::Web` with no agent, and the MCP entry says
//!   `Via::Mcp` with the agent client of the token.
//!
//! Every account and text is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod mcp_support;

use fstp_api_core::Credential;
use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::meta::Scope;
use fstp_api_core::port::{AgentClientId, AuditEntry, Outcome};
use fstp_api_testkit::fake::WebLogin;
use fstp_api_testkit::fake::fixture::{
    AGENT, AGENT_2, CALL_ALLOWED, CALL_OPEN, LEAD, OTHER, OWNER, P2, PX,
};
use fstp_domain::Via;
use fstp_domain::id::AccountId;
use fstp_json::Value;
use fstp_mcp::Surface;
use fstp_prop::{Config, Gen, check_with};
use mcp_support::{McpCell, call, dec, obj, op_of_tool};

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

/// The accounts of the menu.
const WHO: [AccountId; 3] = [LEAD, OWNER, OTHER];

/// The tools of the menu that take no request object. Each names its
/// path parameters with the I-85 world's targets.
const READS: [(&str, &[(&str, u128)]); 7] = [
    ("fstp_list_my_proposals", &[]),
    ("fstp_get_my_proposal", &[("proposal", PX.raw())]),
    ("fstp_get_call_board", &[("call", CALL_OPEN.raw())]),
    ("fstp_get_call_board", &[("call", CALL_ALLOWED.raw())]),
    ("fstp_list_open_calls", &[]),
    ("fstp_list_notices", &[]),
    ("fstp_creator_get_draft", &[("programme", P2.raw())]),
];

/// One call of a sequence.
#[derive(Clone, Debug)]
enum Step {
    /// A read of [`READS`] by an account of [`WHO`].
    Read { who: AccountId, tool: usize },
    /// An edit of call 4 by an account of [`WHO`], with text number `n`.
    Edit { who: AccountId, n: u8 },
}

fn step(g: &mut Gen) -> Step {
    let who = *g.pick(&WHO);
    if g.weighted(&[3, 1]) == 0 {
        Step::Read {
            who,
            tool: g.usize_in(0..=READS.len() - 1),
        }
    } else {
        Step::Edit {
            who,
            n: g.u8_in(0..=3),
        }
    }
}

/// The web method of the registry's method.
fn method(m: fstp_access::Method) -> Method {
    match m {
        fstp_access::Method::Get => Method::Get,
        fstp_access::Method::Post => Method::Post,
        fstp_access::Method::Put => Method::Put,
        fstp_access::Method::Delete => Method::Delete,
    }
}

/// The members of a request object.
type Members = Vec<(&'static str, Value)>;

/// The tool name, its path parameters and its request members.
fn parts(s: &Step) -> (&'static str, Vec<(&'static str, u128)>, Option<Members>) {
    match s {
        Step::Read { tool, .. } => {
            let (name, params) = READS[*tool];
            (name, params.to_vec(), None)
        }
        Step::Edit { n, .. } => {
            let members = vec![
                (
                    "opens",
                    Value::String(
                        fstp_domain_testkit::r#gen::roster::CALL_OPENS
                            .micros()
                            .to_string(),
                    ),
                ),
                (
                    "deadline",
                    Value::String(
                        fstp_domain_testkit::r#gen::roster::CALL_DEADLINE
                            .micros()
                            .to_string(),
                    ),
                ),
                ("deadline_zone", Value::String("Europe/Brussels".to_owned())),
                ("currency", Value::String("EUR".to_owned())),
                ("budget", Value::String(format!("90000{n}.00"))),
                (
                    "text",
                    Value::String(format!("SYNTHETIC CALL TEXT, AUDIT PARITY EDIT {n}")),
                ),
            ];
            (
                "fstp_edit_call",
                vec![("call", CALL_ALLOWED.raw())],
                Some(members),
            )
        }
    }
}

fn who(s: &Step) -> AccountId {
    match s {
        Step::Read { who, .. } | Step::Edit { who, .. } => *who,
    }
}

/// Runs `s` through the web on `c`, in `login`'s session.
fn web(c: &McpCell, login: &WebLogin, s: &Step) -> Result<(), String> {
    let (name, params, members) = parts(s);
    let spec = op_of_tool(name).ok_or_else(|| format!("no op has the tool {name}"))?;
    let (m, template) = spec
        .route
        .ok_or_else(|| format!("{} has no web route", spec.name))?;
    let mut path = template.to_owned();
    for (k, v) in &params {
        path = path.replace(&format!("{{{k}}}"), &v.to_string());
    }
    let body = match members {
        Some(ms) => obj(ms).to_compact().into_bytes(),
        None if m == fstp_access::Method::Get => Vec::new(),
        None => b"{}".to_vec(),
    };
    // The answer is judged by the audit entries, so only a decode error
    // is a harness failure here.
    let op = decode_route(method(m), &path, &body).map_err(|e| format!("{path}: {e:?}"))?;
    let _ = c.web(login, Ok(op));
    Ok(())
}

/// Runs `s` through MCP on `server` with `token`.
fn mcp(server: &fstp_mcp::McpServer, token: &[u8], s: &Step) -> Result<(), String> {
    let (name, params, members) = parts(s);
    let mut all: Vec<(&str, Value)> = params.iter().map(|(k, v)| (*k, dec(*v))).collect();
    all.extend(members.unwrap_or_default());
    let r = call(
        server,
        Surface::Mcp,
        Credential::Bearer(token.to_vec()),
        name,
        &obj(all),
    );
    match r {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("{name}: JSON-RPC error {}: {}", e.code, e.message)),
    }
}

/// The audit entries of one cell after `audit` sink entries and `appended`
/// executions. An accepted command writes its entry in the transaction of
/// its ledger batch (design section 6.1, `AsyncEngine::execute`), so the
/// fake engine port holds it as the execution's `ExecMeta`. Every other
/// call writes it through the `AuditSink`.
fn entries(c: &McpCell, audit: usize, appended: usize) -> Vec<AuditEntry> {
    let mut out: Vec<AuditEntry> = c.ports.audit.entries().split_off(audit);
    for x in c.ports.engine.appended().split_off(appended) {
        let actor = match x.ctx.actor {
            fstp_domain::command::Actor::Account(a) => Some(a),
            fstp_domain::command::Actor::System(_) => None,
        };
        out.push(AuditEntry {
            actor,
            via: x.meta.via,
            agent: x.meta.agent,
            op: x.meta.op,
            outcome: Outcome::Accepted,
            request: x.meta.request,
            step_up: x.meta.step_up,
        });
    }
    out
}

/// The entry with the channel and the agent client removed.
fn modulo_channel(e: &AuditEntry) -> String {
    format!(
        "actor {:?} op {:?} outcome {:?} request {:?} step-up {:?}",
        e.actor, e.op, e.outcome, e.request, e.step_up
    )
}

/// The agent client each account's token names.
fn agent_of(who: AccountId) -> AgentClientId {
    if who == LEAD { AGENT_2 } else { AGENT }
}

/// How many MCP entries of a run were refusals, accepted reads and
/// accepted commands.
#[derive(Clone, Copy, Debug, Default)]
struct Tally {
    refused: usize,
    reads: usize,
    commands: usize,
}

/// Runs `steps` on both channels and checks every pair of entries.
fn run(steps: &[Step]) -> Result<Tally, String> {
    let web_cell = McpCell::new();
    let mcp_cell = McpCell::new();
    let server = mcp_cell.server();
    let tokens: Vec<(AccountId, Vec<u8>)> = WHO
        .iter()
        .map(|w| (*w, mcp_cell.token(*w, agent_of(*w), EVERY_SCOPE)))
        .collect();
    let mut tally = Tally::default();
    for (i, s) in steps.iter().enumerate() {
        let a = who(s);
        let token = &tokens.iter().find(|(w, _)| *w == a).unwrap().1;
        let login = web_cell.login(a);
        let wb = (
            web_cell.ports.audit.entries().len(),
            web_cell.ports.engine.appended().len(),
        );
        let mb = (
            mcp_cell.ports.audit.entries().len(),
            mcp_cell.ports.engine.appended().len(),
        );
        web(&web_cell, &login, s)?;
        mcp(&server, token, s)?;
        let w = entries(&web_cell, wb.0, wb.1);
        let m = entries(&mcp_cell, mb.0, mb.1);
        let (w, m) = (w.as_slice(), m.as_slice());
        let [we] = w else {
            return Err(format!(
                "step {i} {s:?}: {} web audit entries: {w:?}",
                w.len()
            ));
        };
        let [me] = m else {
            return Err(format!(
                "step {i} {s:?}: {} MCP audit entries: {m:?}",
                m.len()
            ));
        };
        if (we.via, we.agent) != (Via::Web, None) {
            return Err(format!("step {i} {s:?}: the web entry {we:?}"));
        }
        if (me.via, me.agent) != (Via::Mcp, Some(agent_of(a))) {
            return Err(format!("step {i} {s:?}: the MCP entry {me:?}"));
        }
        if me.actor != Some(a) {
            return Err(format!(
                "step {i} {s:?}: the MCP entry names {:?}",
                me.actor
            ));
        }
        if modulo_channel(we) != modulo_channel(me) {
            return Err(format!(
                "step {i} {s:?}: the entries differ beyond the channel:\n web {we:?}\n mcp {me:?}"
            ));
        }
        match (me.outcome, s) {
            (Outcome::Refused(_), _) => tally.refused += 1,
            (Outcome::Accepted, Step::Read { .. }) => tally.reads += 1,
            (Outcome::Accepted, Step::Edit { .. }) => tally.commands += 1,
        }
    }
    Ok(tally)
}

/// I-84, R-AU-01, design section 8.4: random sequences of direct
/// exposures, run once through the web and once through MCP, give equal
/// audit entries once `via` and `agent` are removed. Each MCP entry names
/// the account and the agent client of the token.
#[test]
fn i84_audit_entries_match_modulo_channel_and_client() {
    check_with(
        "i84_audit_entries_match_modulo_channel_and_client",
        Config::default().with_cases(48),
        |g| {
            let steps = g.vec(1..=8, step);
            g.note("steps", &steps);
            run(&steps).map(|_| ())
        },
    );
}

/// I-84, design section 3.7 step 9: every MCP call records one audit
/// entry, refused calls too. The sequences always hold a refused call
/// (the lead's read of a call board), so the property is not vacuous.
#[test]
fn i84_mcp_audit_records_refusals_too() {
    check_with(
        "i84_mcp_audit_records_refusals_too",
        Config::default().with_cases(32),
        |g| {
            let mut steps = g.vec(0..=6, step);
            let at = g.usize_in(0..=steps.len());
            steps.insert(at, Step::Read { who: LEAD, tool: 2 });
            g.note("steps", &steps);
            let tally = run(&steps)?;
            if tally.refused == 0 {
                return Err("no MCP refusal was recorded".to_owned());
            }
            Ok(())
        },
    );
}

/// I-84: the menu reaches every kind of entry. On one fixed sequence the
/// programme manager's and the call drafter's edits of call 4 append, the
/// lead's own reads complete, and the lead's call board read and edit are
/// refused, with equal entries on both channels.
#[test]
fn i84_audit_parity_covers_accepted_commands_reads_and_refusals() {
    let steps = [
        Step::Edit { who: OWNER, n: 1 },
        Step::Read { who: LEAD, tool: 0 },
        Step::Read { who: LEAD, tool: 1 },
        Step::Read { who: LEAD, tool: 2 },
        Step::Edit { who: OTHER, n: 2 },
        Step::Edit { who: LEAD, n: 3 },
        Step::Read {
            who: OWNER,
            tool: 3,
        },
    ];
    let tally = run(&steps).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(tally.commands, 2, "{tally:?}");
    assert_eq!(tally.refused, 2, "{tally:?}");
    assert_eq!(tally.reads, 3, "{tally:?}");
}
