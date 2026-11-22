//! The claim of an anonymous draft (`proposal.claim_draft`, ADR-032,
//! Daniel 2026-11-22).
//!
//! A signed-in lead creates a draft in the open call with
//! `proposal.create`, then claims the anonymous draft into it. The text
//! lands in the draft's workspace and the anonymous draft is deleted, so
//! its resume link stops working. Every other case is refused with the
//! one guard rule `Input`, after the actor check. Agents cannot claim:
//! the operation has no tool (R-MC-04).
//!
//! Every account and text is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::anon::{AnonymousDrafts, Draft, Row, Token};
use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::model::ReadModel;
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, OpResult};
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::fixture::{CALL_EDIT, CALL_OPEN, LEAD, OTHER, START};
use fstp_domain::time::Timestamp;
use fstp_json::{ToJson, Value};

fn cell() -> FakeCell {
    FakeCell::new().unwrap_or_else(|e| panic!("the fake cell: {e}"))
}

fn block<T>(f: impl std::future::Future<Output = T>) -> T {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    let mut f = std::pin::pin!(f);
    match f.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(v) => v,
        std::task::Poll::Pending => panic!("the memory store never waits"),
    }
}

fn synthetic() -> Draft {
    Draft {
        title: "Synthetic open hardware sensor".to_owned(),
        summary: "A synthetic summary.".to_owned(),
        narrative: "Line one of a synthetic narrative.\nLine two.".to_owned(),
    }
}

/// Stores an anonymous draft for `call` and answers its token.
fn anonymous(c: &FakeCell, call: fstp_domain::id::CallId) -> Token {
    let t = Token::fresh().unwrap();
    let row = Row {
        call,
        draft: synthetic(),
        started: START,
        expires: Timestamp::from_micros(i64::MAX),
    };
    block(c.ports.anon.start(t.digest(), row)).unwrap();
    t
}

/// A new draft of `who` in the open call, through the page.
fn new_draft(c: &FakeCell, who: fstp_domain::id::AccountId) -> u128 {
    let login = c.login(who, LoginMethod::Passkey);
    let r = c.web(
        &login,
        decode_route(
            Method::Post,
            &format!("/calls/{}/proposals", CALL_OPEN.raw()),
            b"{}",
        ),
    );
    match r {
        Ok(OpResult::Done {
            body: ReadModel::Created(ids),
            ..
        }) => ids.iter().find(|(n, _)| *n == "proposal").unwrap().1,
        other => panic!("proposal.create gave {other:?}"),
    }
}

fn claim(
    c: &FakeCell,
    who: fstp_domain::id::AccountId,
    p: u128,
    token: &str,
) -> Result<OpResult, ApiError> {
    let login = c.login(who, LoginMethod::Passkey);
    let body = format!("{{\"token\":\"{token}\"}}");
    c.web(
        &login,
        decode_route(
            Method::Post,
            &format!("/proposals/{p}/claim"),
            body.as_bytes(),
        ),
    )
}

fn rule(r: &Result<OpResult, ApiError>) -> Option<&'static str> {
    match r {
        Err(ApiError::Refused { rule, .. }) => Some(rule),
        _ => None,
    }
}

fn workspace(c: &FakeCell, p: u128) -> Value {
    let login = c.login(LEAD, LoginMethod::Passkey);
    match c.web(
        &login,
        decode_route(Method::Get, &format!("/proposals/{p}/workspace"), b""),
    ) {
        Ok(OpResult::Done { body, .. }) => body.to_json(),
        other => panic!("proposal.get_workspace gave {other:?}"),
    }
}

/// ADR-032, Daniel 2026-11-22: the lead's claim copies the anonymous
/// draft into its own draft's workspace and deletes the anonymous draft,
/// so the same link claims nothing again.
#[test]
fn adr032_claim_moves_the_draft_into_the_account() {
    let c = cell();
    let t = anonymous(&c, CALL_OPEN);
    let p = new_draft(&c, LEAD);
    let r = claim(&c, LEAD, p, &t.hex());
    assert!(matches!(r, Ok(OpResult::Done { .. })), "claim: {r:?}");
    let w = workspace(&c, p);
    let o = w.as_object().unwrap();
    assert_eq!(
        o.get("title").and_then(Value::as_str),
        Some("Synthetic open hardware sensor")
    );
    assert_eq!(
        o.get("narrative").and_then(Value::as_str),
        Some("Line one of a synthetic narrative.\nLine two.")
    );
    assert!(c.ports.anon.is_empty(), "the anonymous draft is gone");
    let again = claim(&c, LEAD, p, &t.hex());
    assert_eq!(rule(&again), Some("Input"), "{again:?}");
}

/// ADR-032: a token no store holds, and a draft for another call, are
/// refused with `Input`, and the other call's draft stays where it is.
#[test]
fn adr032_unknown_or_foreign_draft_is_refused() {
    let c = cell();
    let p = new_draft(&c, LEAD);
    let unknown = claim(&c, LEAD, p, &"5a".repeat(32));
    assert_eq!(rule(&unknown), Some("Input"), "{unknown:?}");
    let other_call = anonymous(&c, CALL_EDIT);
    let foreign = claim(&c, LEAD, p, &other_call.hex());
    assert_eq!(rule(&foreign), Some("Input"), "{foreign:?}");
    assert_eq!(c.ports.anon.len(), 1, "the foreign draft is kept");
}

/// ADR-032, T-AUTHZ-MATRIX: an account that is not the lead is refused
/// as no actor before the token is looked at, and the draft stays.
#[test]
fn adr032_only_the_lead_claims() {
    let c = cell();
    let t = anonymous(&c, CALL_OPEN);
    let p = new_draft(&c, LEAD);
    let r = claim(&c, OTHER, p, &t.hex());
    assert_eq!(rule(&r), Some("actor"), "{r:?}");
    assert_eq!(c.ports.anon.len(), 1);
}

/// ADR-032, R-NF-02: a token in any other spelling is a malformed
/// request, and the draft stays.
#[test]
fn adr032_malformed_token_is_a_bad_request() {
    let c = cell();
    let t = anonymous(&c, CALL_OPEN);
    let p = new_draft(&c, LEAD);
    let r = claim(&c, LEAD, p, &t.hex().to_uppercase());
    assert!(matches!(r, Err(ApiError::Refused { .. })), "{r:?}");
    assert_ne!(rule(&r), Some("Input"));
    assert_eq!(c.ports.anon.len(), 1);
}

/// ADR-032, R-MC-04, I-84: the claim is web only. It has no tool and no
/// scope, so no agent claims a draft or drafts anonymously.
#[test]
fn adr032_r_mc_04_claim_has_no_tool() {
    let op = fstp_access::op("proposal.claim_draft").expect("the registry names the claim");
    assert!(op.tool.is_none());
    assert!(op.scope.is_none());
}
