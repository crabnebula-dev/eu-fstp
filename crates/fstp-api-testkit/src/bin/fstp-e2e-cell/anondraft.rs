//! The anonymous draft routes of the cell (ADR-032, Daniel 2026-11-22),
//! emulated over the fake ports, so the demo reaches the draft page by
//! clicking from a public call page.
//!
//! The routes and bodies are those of `fstp_cell::routes::drafts`:
//! `POST /auth/drafts {call}`, `/auth/drafts/open {token}`,
//! `/auth/drafts/save {narrative, summary, title, token}` and
//! `/auth/drafts/discard {token}`. The store is the fake cell's own
//! (`FakePorts::anon`), which the API core's `proposal.claim_draft` reads,
//! so a claim in the demo moves the draft as the production cell does.
//! The demo cell lifts the rate limits, as its other emulated routes do.

use fstp_api_core::anon::{self, Draft, Row, Token};
use fstp_api_core::port::AsyncEngine as _;
use fstp_domain::id::CallId;
use fstp_domain::time::Timestamp;
use fstp_http::{Request, Response, StatusCode};

use crate::Inner;
use crate::wire::{self, obj};

/// The deadline of `call` when it is open now in an active programme.
fn open_call(inner: &Inner, call: CallId, now: Timestamp) -> Option<Timestamp> {
    let state = inner.ports.engine.snapshot();
    let view = fstp_domain::programme::call(&state.core, call)?;
    let active = fstp_domain::programme::programme_status(&state.core, view.programme())
        == Some(fstp_domain::programme::ProgrammeStatus::Active);
    (active && view.is_open_at(now)).then(|| view.deadline())
}

fn gone() -> Response {
    wire::refuse(StatusCode::NOT_FOUND, "draft")
}

fn token_of(o: &fstp_json::Object) -> Option<Token> {
    wire::str_member(o, "token").and_then(Token::parse)
}

fn block<T>(f: impl std::future::Future<Output = T>) -> T {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    let mut f = std::pin::pin!(f);
    match f.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(v) => v,
        // The memory store answers at once.
        std::task::Poll::Pending => unreachable!("the memory store never waits"),
    }
}

/// Answers one draft route: `op` is `None` for the start, else the last
/// path segment.
pub(crate) fn handle(inner: &Inner, op: Option<&str>, req: &Request) -> Response {
    use fstp_api_core::anon::AnonymousDrafts as _;
    let Some(body) = wire::body(req) else {
        return wire::bad("body");
    };
    let store = inner.ports.anon.as_ref();
    let now = inner.ports.clock.read();
    match op {
        None => {
            let Some(call) = wire::dec_member(&body, "call")
                .and_then(|c| u128::try_from(c).ok())
                .map(CallId::from_raw)
            else {
                return wire::bad("call");
            };
            let Some(deadline) = open_call(inner, call, now) else {
                return wire::refuse(StatusCode::CONFLICT, "call");
            };
            let Some(token) = Token::fresh() else {
                return wire::refuse(StatusCode::SERVICE_UNAVAILABLE, "random");
            };
            let expires = anon::expires_at(now, deadline);
            let row = Row {
                call,
                draft: Draft::default(),
                started: now,
                expires,
            };
            if block(store.start(token.digest(), row)).is_err() {
                return wire::refuse(StatusCode::SERVICE_UNAVAILABLE, "store");
            }
            wire::json(
                StatusCode::CREATED,
                &obj(vec![
                    ("expires", wire::dec(expires.micros())),
                    ("token", token.hex().into()),
                ]),
            )
        }
        Some(kind) => {
            let Some(token) = token_of(&body) else {
                return wire::bad("token");
            };
            let digest = token.digest();
            if kind == "discard" {
                return match block(store.remove(digest)) {
                    Ok(true) => wire::json(StatusCode::OK, &obj(vec![("status", "saved".into())])),
                    _ => gone(),
                };
            }
            let Ok(Some(row)) = block(store.open(digest, now)) else {
                return gone();
            };
            if open_call(inner, row.call, now).is_none() {
                return gone();
            }
            match kind {
                "open" => wire::json(
                    StatusCode::OK,
                    &obj(vec![
                        ("call", wire::dec(row.call.raw())),
                        ("expires", wire::dec(row.expires.micros())),
                        ("narrative", row.draft.narrative.as_str().into()),
                        ("summary", row.draft.summary.as_str().into()),
                        ("title", row.draft.title.as_str().into()),
                    ]),
                ),
                "save" => {
                    let text = |k: &str| wire::str_member(&body, k).map(str::to_owned);
                    let (Some(title), Some(summary), Some(narrative)) =
                        (text("title"), text("summary"), text("narrative"))
                    else {
                        return wire::bad("draft");
                    };
                    let draft = Draft {
                        title,
                        summary,
                        narrative,
                    };
                    if !draft.fits() {
                        return wire::bad("draft");
                    }
                    match block(store.save(digest, draft, now)) {
                        Ok(true) => {
                            wire::json(StatusCode::OK, &obj(vec![("status", "saved".into())]))
                        }
                        _ => gone(),
                    }
                }
                _ => wire::not_found(),
            }
        }
    }
}
