//! I-86: no identity attribute, bank detail or vault value in any MCP
//! result (M4 design sections 3.8 and 8.4, TH-61, R-NF-02).
//!
//! Two crawls live here. Both call every tool of
//! `fstp_api_core::meta::tools()` through `fstp_mcp::McpServer` and
//! refuse any canary in any result, error or tool list.
//!
//! - `i86_canary_crawl_over_every_tool_and_principal`: the I-85 world,
//!   every world account with every scope on both surfaces, with PX in
//!   DRAFT and with PX submitted.
//! - `i86_canary_crawl_over_every_tool_role_and_state` (lane m4/i86): the
//!   matrix worlds of `harness::canary_crawl`, every matrix principal in
//!   every state profile, NEGOTIATION included, with the arguments the
//!   matrix sends. The canary vault of `fstp_api_testkit::canary` gives
//!   the whole cast canary identity numbers and canary login emails.
//!   `i86_no_canary_in_logs_or_metrics` scans the logs of that run, and
//!   `i86_teeth_identity_field_leak_is_caught` plants a mutant read model.
//!
//! The canaries, all synthetic:
//!
//! - every account's vault identity is a distinctive number, searched as
//!   decimal and as hexadecimal text;
//! - every account of the matrix cast has a canary login email under
//!   `canary.invalid` in the accounts port;
//! - bank details have no M4 port, so the crawl also refuses any string
//!   of IBAN shape: two capital letters, two digits, then 11 to 30
//!   capitals or digits.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod mcp_support;

use fstp_api_core::Credential;
use fstp_api_core::meta::{Scope, tools};
use fstp_api_testkit::fake::fixture::{ADMIN, ADMIN_2, AGENT, LEAD, OTHER, OWNER};
use fstp_domain::id::AccountId;
use fstp_domain_testkit::vault::IdentityTag;
use fstp_json::Object;
use fstp_mcp::Surface;
use mcp_support::{McpCell, args_for, call, list, world};

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

/// The world accounts the crawl calls as.
const ACCOUNTS: [AccountId; 5] = [OWNER, OTHER, ADMIN, ADMIN_2, LEAD];

/// The first canary identity tag.
const TAG_BASE: u64 = 0x0CA4_A41D_0086_0000;

/// The canary strings of the cell.
fn canaries() -> Vec<String> {
    let mut out = Vec::new();
    for i in 0..ACCOUNTS.len() as u64 {
        let n = TAG_BASE + i;
        out.push(n.to_string());
        out.push(format!("{n:x}"));
        out.push(format!("{n:X}"));
    }
    out
}

/// Whether `s` has IBAN shape somewhere in it.
fn iban_shaped(s: &str) -> bool {
    let b = s.as_bytes();
    (0..b.len()).any(|i| {
        let head = b.get(i..i + 4).is_some_and(|h| {
            h[0].is_ascii_uppercase()
                && h[1].is_ascii_uppercase()
                && h[2].is_ascii_digit()
                && h[3].is_ascii_digit()
        });
        let tail = b
            .iter()
            .skip(i + 4)
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            .count();
        head && (11..=30).contains(&tail)
    })
}

/// The cell with the canaries planted.
fn canary_cell(submit: bool) -> McpCell {
    let mut w = world(submit);
    for (i, a) in ACCOUNTS.iter().enumerate() {
        w.truth
            .set_identity(*a, IdentityTag::new(TAG_BASE + i as u64));
    }
    McpCell::over(&w)
}

/// The texts one crawl step yields: the result or the error, as text.
fn crawl_texts(c: &McpCell) -> Vec<(String, String)> {
    let s = c.server();
    let mut out = Vec::new();
    let empty = Object::new();
    for surface in [Surface::Public, Surface::Mcp] {
        let creds: Vec<(String, Credential)> = match surface {
            Surface::Public => vec![("anonymous".to_owned(), Credential::None)],
            Surface::Mcp => ACCOUNTS
                .iter()
                .map(|a| {
                    (
                        format!("{a:?}"),
                        Credential::Bearer(c.token(*a, AGENT, EVERY_SCOPE)),
                    )
                })
                .collect(),
        };
        for (who, cred) in creds {
            let l = list(&s, surface, cred.clone());
            out.push((format!("{who} tools/list"), format!("{l:?}")));
            for t in tools() {
                let r = call(&s, surface, cred.clone(), t.name, &args_for(t.name, &empty));
                let shown = match &r {
                    Ok(v) => v.to_compact(),
                    Err(e) => format!("{}: {}", e.code, e.message),
                };
                out.push((format!("{who} {surface:?} {}", t.name), shown));
            }
        }
    }
    out
}

/// I-86, TH-61: every tool, for every world account with every scope and
/// anonymously on `/mcp/public`, in DRAFT and after submission, returns no
/// canary identity tag and nothing of IBAN shape, in its
/// result or its error, and no tool list holds one.
#[test]
fn i86_canary_crawl_over_every_tool_and_principal() {
    let canaries = canaries();
    let mut leaks = Vec::new();
    let mut answered = 0usize;
    for submit in [false, true] {
        let c = canary_cell(submit);
        for (at, text) in crawl_texts(&c) {
            if !text.contains("is not implemented yet") {
                answered += 1;
            }
            for k in &canaries {
                if text.contains(k.as_str()) {
                    leaks.push(format!("{at}: canary {k}"));
                }
            }
            if iban_shaped(&text) {
                leaks.push(format!("{at}: an IBAN-shaped string"));
            }
        }
    }
    assert!(leaks.is_empty(), "I-86 leaks:\n{}", leaks.join("\n"));
    assert!(answered > 0, "no tool answered: the crawl judged nothing");
}

/// I-86: the crawl's own predicates catch what they look for. Green now.
#[test]
fn i86_canary_predicates_self_test() {
    assert!(iban_shaped("x DE89370400440532013000 y"));
    assert!(!iban_shaped("Proposal 11 in call 3"));
    assert!(!iban_shaped("deadbeef0123456789abcdef"));
    let k = canaries();
    assert!(k.iter().any(|c| c == &TAG_BASE.to_string()));
    assert_eq!(k.len(), 3 * ACCOUNTS.len());
}

// ---------------------------------------------------------------------------
// Lane m4/i86: the crawl over every state of the matrix worlds.
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

use fstp_api_testkit::canary::CanaryVault;
use fstp_api_testkit::harness::canary_crawl::{CrawlAnswer, CrawlWorld, cast_vault};
use fstp_api_testkit::reference::authz::StateProfile;
use fstp_domain::StateTag;

/// What the crawl of one state left: the answers and the captured logs.
struct StateCrawl {
    state: StateProfile,
    answers: Vec<CrawlAnswer>,
    logs: Vec<(String, String)>,
}

/// The crawl over every state profile of the matrix, run once per test
/// binary: the crawl test and the log test judge the same run.
fn full_crawl() -> &'static (CanaryVault, Vec<StateCrawl>) {
    static CRAWL: OnceLock<(CanaryVault, Vec<StateCrawl>)> = OnceLock::new();
    CRAWL.get_or_init(|| {
        let vault = cast_vault();
        let crawls = StateProfile::all()
            .into_iter()
            .map(|state| {
                let mut w = CrawlWorld::new(state, &vault)
                    .unwrap_or_else(|e| panic!("the world of {state:?}: {e}"));
                let answers = w.crawl().unwrap_or_else(|e| panic!("crawl {state:?}: {e}"));
                StateCrawl {
                    state,
                    answers,
                    logs: w.logs(),
                }
            })
            .collect();
        (vault, crawls)
    })
}

/// The leaks of `texts` under `vault`, one line each.
fn leaks_of<'a>(
    vault: &CanaryVault,
    state: StateProfile,
    texts: impl Iterator<Item = (&'a str, &'a str)>,
) -> Vec<String> {
    texts
        .flat_map(|(at, text)| {
            vault
                .leaks_in(text)
                .into_iter()
                .map(move |l| format!("{state:?} {at}: {l}"))
        })
        .collect()
}

/// I-86, TH-61, R-NG-01: the canary vault gives every account of the
/// matrix cast a canary identity number and a canary login email, and the
/// scan refuses bank-shaped canaries and any IBAN shape. Every tool is
/// called for every matrix principal in every state profile of the
/// matrix: onboarding, programme and call states, and the 16 proposal
/// states with NEGOTIATION included. No canary appears in any MCP result,
/// error or tool list. Every state has completed calls, so the crawl
/// judged real answers.
#[test]
fn i86_canary_crawl_over_every_tool_role_and_state() {
    let (vault, crawls) = full_crawl();
    let mut leaks = Vec::new();
    let mut completed = Vec::new();
    for c in crawls {
        leaks.extend(leaks_of(
            vault,
            c.state,
            c.answers.iter().map(|a| (a.at.as_str(), a.text.as_str())),
        ));
        completed.push((c.state, c.answers.iter().filter(|a| a.completed).count()));
    }
    assert!(leaks.is_empty(), "I-86 leaks:\n{}", leaks.join("\n"));
    assert_eq!(completed.len(), StateProfile::all().len());
    assert!(
        completed
            .iter()
            .any(|(s, n)| *s == StateProfile::Proposal(StateTag::Negotiation) && *n > 0),
        "no tool completed in NEGOTIATION: {completed:?}"
    );
    assert!(
        completed.iter().all(|(_, n)| *n > 0),
        "a state where no tool completed: {completed:?}"
    );
}

/// I-86, R-NF-02: the same scan over the logs the cell wrote during the
/// crawl of every state: every audit entry, which records each MCP call
/// and refusal, and every ledger record the calls appended. No canary
/// appears in any of them.
///
/// Seam: neither `fstp-mcp` nor `fstp-api-core` writes an `fstp_obs` log
/// event or metric, so the audit log and the ledger are the logs of this
/// path. `fstp_obs` events take no free text by construction (R-NF-02).
#[test]
fn i86_no_canary_in_logs_or_metrics() {
    let (vault, crawls) = full_crawl();
    let mut leaks = Vec::new();
    let mut lines = 0usize;
    for c in crawls {
        lines += c.logs.len();
        leaks.extend(leaks_of(
            vault,
            c.state,
            c.logs.iter().map(|(at, t)| (at.as_str(), t.as_str())),
        ));
    }
    assert!(leaks.is_empty(), "R-NF-02 leaks:\n{}", leaks.join("\n"));
    assert!(
        lines > 0,
        "the crawl wrote no log line: the scan judged nothing"
    );
}

/// I-86 teeth: a mutant read model adds a vault field. The mutant is
/// planted in test code only: in NEGOTIATION, every completed MCP read
/// gains the member `identity` with the caller's vault identity number.
/// The crawl must report it.
#[test]
fn i86_teeth_identity_field_leak_is_caught() {
    let vault = cast_vault();
    let state = StateProfile::Proposal(StateTag::Negotiation);
    let mut w =
        CrawlWorld::new(state, &vault).unwrap_or_else(|e| panic!("the world of {state:?}: {e}"));
    w.plant_identity_field_mutant();
    let answers = w.crawl().unwrap_or_else(|e| panic!("crawl {state:?}: {e}"));
    let caught = leaks_of(
        &vault,
        state,
        answers.iter().map(|a| (a.at.as_str(), a.text.as_str())),
    );
    assert!(
        caught.iter().any(|l| l.contains("identity of")),
        "I-86 teeth: the crawl missed a read model that carries a vault identity"
    );
}
