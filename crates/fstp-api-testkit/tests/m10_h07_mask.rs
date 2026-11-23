//! M10 H-07, finding F-005 (I-86, I-17, TH-07): the vault name mask is no
//! oracle for the applicant side.
//!
//! A team member who writes candidate values into the shared draft and
//! reads the draft back through MCP must never get the vault's answer.
//! Daniel's decision (2026-11-23): the MCP content read of a draft is
//! refused for the applicant side, which reads its drafts in the web app.
//! No read by the applicant side, on any channel and in any state, sends
//! a mask request to the vault. Every account and text is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod mcp_support;

use fstp_api_core::Credential;
use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::meta::Scope;
use fstp_api_testkit::fake::fixture::{AGENT, LEAD, PX};
use fstp_api_testkit::matrix::{Denial, Observed};
use fstp_json::Value;
use fstp_mcp::Surface;
use mcp_support::{McpCell, call, dec, obj, observed, structured, text};

/// A draft narrative that holds every ISO date of 1990: the probe of
/// F-005. Synthetic.
fn candidates() -> String {
    let mut out = String::from("Synthetic plan. Dates:\n");
    for m in 1..=12u8 {
        for d in 1..=31u8 {
            out.push_str(&format!("1990-{m:02}-{d:02}\n"));
        }
    }
    out
}

/// The lead saves `narrative` into PX's workspace through the web.
fn save(c: &McpCell, narrative: &str) {
    let lead = c.login(LEAD);
    let body = obj(vec![
        ("narrative", Value::from(narrative)),
        ("summary", Value::from("Synthetic summary.")),
        ("title", Value::from("Synthetic title")),
    ]);
    let path = format!("/proposals/{}/workspace", PX.raw());
    let r = c.web(
        &lead,
        decode_route(Method::Put, &path, body.to_compact().as_bytes()),
    );
    assert!(r.is_ok(), "the save: {r:?}");
}

/// The lead's agent reads PX's content through `fstp_get_proposal_content`.
fn mcp_read(c: &McpCell) -> Result<Value, fstp_mcp::RpcError> {
    let token = c.token(LEAD, AGENT, [Scope::ReviewRead]);
    call(
        &c.server(),
        Surface::Mcp,
        Credential::Bearer(token),
        "fstp_get_proposal_content",
        &obj(vec![("proposal", dec(PX.raw()))]),
    )
}

/// M10 F-005, I-86, I-17, TH-07: the lead holds a verified date of birth,
/// and the draft holds every date of that year. Through MCP the draft
/// read is refused as not exposed (I-86), the vault is never asked to
/// mask, and no `[BIRTHDATE-n]` comes back. The web read of the same
/// draft still completes, with no mask request either. Once PX is
/// submitted, the team's MCP read of its own content completes and still
/// asks the vault nothing.
#[test]
fn m10_h07_i86_team_content_read_through_mcp_never_asks_the_vault_mask() {
    let c = McpCell::new();
    c.ports
        .vault
        .set_legal_name(LEAD, "Velquorra", "Isrenne", Some("1990-04-07"));
    save(&c, &candidates());
    let before = c.ports.vault.mask_requests();

    let r = mcp_read(&c);
    assert_eq!(
        observed(&r),
        Ok(Observed::ChannelDenied(Denial::NotExposed)),
        "the team's MCP read of a draft is refused: {r:?}"
    );
    let v = r.unwrap();
    let rule = structured(&v).and_then(|o| text(o, "rule")).unwrap_or("");
    assert_eq!(rule, "I-86", "{}", v.to_compact());
    assert!(!v.to_compact().contains("BIRTHDATE"), "{}", v.to_compact());
    assert_eq!(
        c.ports.vault.mask_requests(),
        before,
        "the draft read through MCP asked the vault to mask"
    );

    let lead = c.login(LEAD);
    let path = format!("/proposals/{}/content", PX.raw());
    let web = c.web(&lead, decode_route(Method::Get, &path, b""));
    assert!(web.is_ok(), "the team reads its draft in the web: {web:?}");
    assert_eq!(c.ports.vault.mask_requests(), before, "the web read");

    let submission = obj(vec![
        ("ethics", Value::from("none")),
        ("notice_version", Value::from("1")),
    ]);
    let r = c.web(
        &lead,
        decode_route(
            Method::Post,
            &format!("/proposals/{}/submission", PX.raw()),
            submission.to_compact().as_bytes(),
        ),
    );
    assert!(r.is_ok(), "the submission: {r:?}");
    let r = mcp_read(&c);
    assert_eq!(observed(&r), Ok(Observed::Completed), "{r:?}");
    let v = r.unwrap().to_compact();
    assert!(!v.contains("BIRTHDATE"), "{v}");
    assert!(v.contains("1990-04-07"), "the team reads its own text: {v}");
    assert_eq!(
        c.ports.vault.mask_requests(),
        before,
        "the team's MCP read of its submitted content asked the vault to mask"
    );
}
