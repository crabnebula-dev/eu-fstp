//! Review reproducers for lane W3b (M4 design section 3.7, I-84, I-24).
//!
//! Each test drives `ApiCore::dispatch` on the fake cell. They need the
//! dispatch seams of `port.rs`, so in a tree where `Core<P>` still
//! refuses every call they fail for that reason as well.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::decode::{Method, decode_route, decode_tool};
use fstp_api_core::meta::Scope;
use fstp_api_core::port::{LoginMethod, OpName, Outcome};
use fstp_api_core::{ApiError, ErrorCode, OpResult};
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::fixture::{AGENT, OWNER};
use fstp_domain::Via;

/// An assignment id that no assignment of the I-85 world holds.
const NO_SUCH_ASSIGNMENT: u128 = 987_654_321;

fn ranking_summary_members() -> Vec<(&'static str, &'static str)> {
    vec![
        ("title", "SYNTHETIC TITLE"),
        ("neutral_summary", "SYNTHETIC SUMMARY"),
        ("rationale", "SYNTHETIC RATIONALE"),
    ]
}

fn object(members: Vec<(&str, &str)>) -> Vec<u8> {
    let mut o = fstp_json::Object::new();
    for (k, v) in members {
        let _ = o.insert(k, fstp_json::Value::from(v));
    }
    fstp_json::Value::Object(o).to_compact().into_bytes()
}

fn refused_entries(c: &FakeCell, via: Via) -> usize {
    c.ports
        .audit
        .entries()
        .iter()
        .filter(|e| {
            e.via == via
                && e.op == OpName("review.ranking_summary")
                && matches!(e.outcome, Outcome::Refused(_))
        })
        .count()
}

/// I-84, design section 3.7 step 9: every MCP call passes the same audit
/// logging as the web. A binding tool call whose request names an
/// assignment that does not exist is refused on both channels. The web
/// refusal is audited. Through MCP the refusal comes from the P-77
/// resolution (`governing_p77`), which returns its build error with `?`
/// and records no audit entry.
#[test]
fn review_mcp_refusal_during_p77_resolution_is_audited() {
    let c = FakeCell::new().unwrap_or_else(|e| panic!("the fake cell: {e}"));
    let login = c.login(OWNER, LoginMethod::Passkey);
    let path = format!("/assignments/{NO_SUCH_ASSIGNMENT}/ranking-summary");
    let web = c.web(
        &login,
        decode_route(Method::Post, &path, &object(ranking_summary_members())),
    );
    assert!(
        matches!(web, Err(ApiError::Refused { .. })),
        "the web call: {web:?}"
    );
    assert_eq!(
        refused_entries(&c, Via::Web),
        1,
        "the web refusal is audited"
    );

    let token = c.token(OWNER, AGENT, [Scope::ReviewDraft], LoginMethod::Passkey);
    let id = NO_SUCH_ASSIGNMENT.to_string();
    let mut args = vec![("assignment", id.as_str())];
    args.extend(ranking_summary_members());
    let mcp = c.mcp(
        &token,
        decode_tool("fstp_record_ranking_summary", &object(args)),
    );
    assert!(
        matches!(
            mcp,
            Err(ApiError::Refused {
                code: ErrorCode::NotFound | ErrorCode::Refused,
                ..
            })
        ),
        "the MCP call: {mcp:?}"
    );
    assert!(!matches!(mcp, Ok(OpResult::Done { .. })));
    assert_eq!(
        refused_entries(&c, Via::Mcp),
        1,
        "I-84: the MCP refusal has no audit entry: {:?}",
        c.ports.audit.entries()
    );
}
