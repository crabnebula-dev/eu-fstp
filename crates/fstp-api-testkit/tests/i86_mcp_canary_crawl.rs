//! I-86: no identity attribute, bank detail or vault value in any MCP
//! result (M4 design sections 3.8 and 8.4, TH-61).
//!
//! The canary crawl plants canaries where the cell keeps identity data,
//! then calls every tool of `fstp_api_core::meta::tools()` through
//! `fstp_mcp::McpServer` for every world account, with every scope, on
//! both surfaces, in the I-85 world with PX in DRAFT and with PX
//! submitted. No canary may appear in any result, error or tool list.
//!
//! The canaries, all synthetic:
//!
//! - every account's vault identity tag is set to a distinctive number,
//!   searched as decimal and as hexadecimal text;
//! - no fake port holds an email or a name: an invitation email goes to
//!   M3 only once a port takes it (`dispatch/tenant.rs`), so emails join
//!   the canaries with that port;
//! - bank details have no M4 port, so the crawl also refuses any string
//!   of IBAN shape: two capital letters, two digits, then 11 to 30
//!   capitals or digits.
//!
//! Seam: the design asks for the crawl in every proposal state,
//! NEGOTIATION included. Those states exist only in the matrix harness's
//! worlds, which have no MCP transport yet (`matrix::mcp_channel`). This
//! file covers the states the I-85 world reaches.
//!
//! Status: red until `fstp_mcp::McpServer` exists.

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
