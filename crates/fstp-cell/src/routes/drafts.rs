//! The anonymous draft routes (ADR-032, Daniel 2026-11-22).
//!
//! A person may start a draft for an open call without an account. The
//! draft is kept under a secret resume link: `/auth/draft#<token>`. The
//! fragment never reaches the server, and the token travels only in a
//! JSON body, so no route log, path or query holds it (R-NF-02). The
//! store keeps the token's SHA-256 digest only, and seals the text
//! (R-NF-08).
//!
//! Four routes, each a `POST` of canonical JSON with no session, through
//! the shared checks of every route (`Origin`, `Content-Type`, the body
//! limit):
//!
//! - `/auth/drafts` `{call}` starts a draft for a published call that is
//!   open now, in an active programme. It answers 201 `{token, expires}`.
//!   Its limits: [`crate::routes::limits`] per peer and per cell, and at
//!   most [`MAX_LIVE`] live drafts in the cell.
//! - `/auth/drafts/open` `{token}` answers `{call, title, summary,
//!   narrative, expires}`.
//! - `/auth/drafts/save` `{narrative, summary, title, token}` replaces the
//!   text.
//! - `/auth/drafts/discard` `{token}` deletes the draft.
//!
//! An unknown, expired, claimed or discarded token gets 404 with one body
//! for every cause, and so does a draft whose call has closed. The draft
//! is not a proposal and writes no ledger record: the proposal and its
//! Receiving binding start at the claim (`proposal.claim_draft`).
//!
//! No AI pre-check runs on an anonymous draft (ADR-032, interim, pending
//! Daniel). No MCP tool reaches these routes (R-MC-04).

use fstp_api_core::anon::{self, Draft, Row, Token};
use fstp_domain::id::CallId;
use fstp_domain::time::Timestamp;
use fstp_http::{Request, StatusCode};
use fstp_json::{Object, Value};

use crate::http::body::{self, BodyRefusal};
use crate::routes::handle::{Ctx, Reply, Rule, bad_body, unavailable};
use crate::routes::{Backend, BackendFault};

/// The most live anonymous drafts one cell holds (ADR-032). Interim,
/// pending Daniel.
pub const MAX_LIVE: u64 = 20_000;

/// The body limit of the save route: the three sections at their limits,
/// each byte escaped at most to two in canonical JSON, and the token.
pub const DRAFT_BODY_LIMIT: usize = 160 * 1024;

/// The body limit of the start, open and discard routes.
pub const SMALL_BODY_LIMIT: usize = 1024;

/// The decimal spelling of an id: canonical, as the API spells it.
fn canonical_id(s: &str) -> Option<u128> {
    let b = s.as_bytes();
    let canonical = !b.is_empty()
        && b.len() <= 39
        && b.iter().all(u8::is_ascii_digit)
        && (b.len() == 1 || b.first() != Some(&b'0'));
    if !canonical {
        return None;
    }
    s.parse::<u128>().ok()
}

/// Decodes the body of `POST /auth/drafts`: `{"call":"<decimal id>"}`.
/// Fuzzed (`anon_draft_body_decode`).
///
/// # Errors
///
/// The first [`BodyRefusal`] that applies.
pub fn decode_start(bytes: &[u8]) -> Result<CallId, BodyRefusal> {
    let o = body::object(bytes, SMALL_BODY_LIMIT)?;
    body::members(&o, &["call"], &[])?;
    canonical_id(body::string(&o, "call")?)
        .map(CallId::from_raw)
        .ok_or(BodyRefusal::Member("call"))
}

fn token_of(o: &Object) -> Result<Token, BodyRefusal> {
    Token::parse(body::string(o, "token")?).ok_or(BodyRefusal::Member("token"))
}

/// Decodes the body of the open and discard routes: `{"token":"<64
/// lowercase hex>"}`. Fuzzed (`anon_draft_body_decode`).
///
/// # Errors
///
/// The first [`BodyRefusal`] that applies.
pub fn decode_token(bytes: &[u8]) -> Result<Token, BodyRefusal> {
    let o = body::object(bytes, SMALL_BODY_LIMIT)?;
    body::members(&o, &["token"], &[])?;
    token_of(&o)
}

/// Decodes the body of `POST /auth/drafts/save`: the token and the three
/// sections, each within its limit and clean (`anon::Draft::fits`).
/// Fuzzed (`anon_draft_body_decode`).
///
/// # Errors
///
/// The first [`BodyRefusal`] that applies.
pub fn decode_save(bytes: &[u8]) -> Result<(Token, Draft), BodyRefusal> {
    let o = body::object(bytes, DRAFT_BODY_LIMIT)?;
    body::members(&o, &["narrative", "summary", "title", "token"], &[])?;
    let token = token_of(&o)?;
    let draft = Draft {
        title: body::string(&o, "title")?.to_owned(),
        summary: body::string(&o, "summary")?.to_owned(),
        narrative: body::string(&o, "narrative")?.to_owned(),
    };
    if !draft.fits() {
        return Err(BodyRefusal::Member("narrative"));
    }
    Ok((token, draft))
}

/// The one reply for an unknown, expired, claimed or discarded draft, and
/// for a draft whose call has closed.
fn gone() -> Reply {
    Reply::refuse(StatusCode::NOT_FOUND, Some(Rule::Spec("ADR-032")), "draft")
}

/// The reply when a start is refused for its call.
fn call_closed() -> Reply {
    Reply::refuse(StatusCode::CONFLICT, Some(Rule::Spec("ADR-032")), "call")
}

/// The reply when the cell holds its most live drafts.
fn full() -> Reply {
    Reply::refuse(StatusCode::TOO_MANY_REQUESTS, Some(Rule::Adr024), "rate")
}

/// The store, or 503.
fn store<B: Backend>(ctx: &Ctx<B>) -> Result<std::sync::Arc<dyn anon::AnonymousDrafts>, Reply> {
    ctx.backend
        .anonymous_drafts()
        .ok_or_else(|| unavailable(BackendFault::Unavailable))
}

/// The deadline of `call` when it is published, open at `now` and in an
/// active programme, as `CreateDraft` asks.
async fn open_call<B: Backend>(
    ctx: &Ctx<B>,
    call: CallId,
    now: Timestamp,
) -> Result<Option<Timestamp>, Reply> {
    let s = ctx.backend.state().await.map_err(unavailable)?;
    let core = &s.engine().core;
    let Some(view) = fstp_domain::programme::call(core, call) else {
        return Ok(None);
    };
    let active = fstp_domain::programme::programme_status(core, view.programme())
        == Some(fstp_domain::programme::ProgrammeStatus::Active);
    Ok((active && view.is_open_at(now)).then(|| view.deadline()))
}

fn time_value(t: Timestamp) -> Value {
    Value::String(t.micros().to_string())
}

/// `POST /auth/drafts`: starts an anonymous draft for an open call.
pub(crate) async fn start<B: Backend>(ctx: &Ctx<B>, req: &Request) -> Reply {
    let call = match decode_start(&req.body) {
        Ok(c) => c,
        Err(r) => return bad_body(r),
    };
    let store = match store(ctx) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let now = ctx.backend.now();
    let deadline = match open_call(ctx, call, now).await {
        Ok(Some(d)) => d,
        Ok(None) => return call_closed(),
        Err(r) => return r,
    };
    match store.live(now).await {
        Ok(n) if n >= MAX_LIVE => return full(),
        Ok(_) => {}
        Err(_) => return unavailable(BackendFault::Unavailable),
    }
    let Some(token) = Token::fresh() else {
        return unavailable(BackendFault::Unavailable);
    };
    let expires = anon::expires_at(now, deadline);
    let row = Row {
        call,
        draft: Draft::default(),
        started: now,
        expires,
    };
    if store.start(token.digest(), row).await.is_err() {
        return unavailable(BackendFault::Unavailable);
    }
    let mut o = Object::with_capacity(2);
    o.insert("expires", time_value(expires));
    o.insert("token", Value::String(token.hex()));
    Reply::json(StatusCode::CREATED, &Value::Object(o))
}

/// The live draft of `token` whose call is still open, or the reply.
async fn live<B: Backend>(
    ctx: &Ctx<B>,
    store: &dyn anon::AnonymousDrafts,
    token: &Token,
    now: Timestamp,
) -> Result<Row, Reply> {
    let row = store
        .open(token.digest(), now)
        .await
        .map_err(|_| unavailable(BackendFault::Unavailable))?
        .ok_or_else(gone)?;
    match open_call(ctx, row.call, now).await? {
        Some(_) => Ok(row),
        None => Err(gone()),
    }
}

/// `POST /auth/drafts/open`: the draft of the token.
pub(crate) async fn open<B: Backend>(ctx: &Ctx<B>, req: &Request) -> Reply {
    let token = match decode_token(&req.body) {
        Ok(t) => t,
        Err(r) => return bad_body(r),
    };
    let store = match store(ctx) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let row = match live(ctx, store.as_ref(), &token, ctx.backend.now()).await {
        Ok(r) => r,
        Err(reply) => return reply,
    };
    let mut o = Object::with_capacity(5);
    o.insert("call", Value::String(row.call.raw().to_string()));
    o.insert("expires", time_value(row.expires));
    o.insert("narrative", Value::String(row.draft.narrative));
    o.insert("summary", Value::String(row.draft.summary));
    o.insert("title", Value::String(row.draft.title));
    Reply::json(StatusCode::OK, &Value::Object(o))
}

/// `POST /auth/drafts/save`: replaces the text of the draft.
pub(crate) async fn save<B: Backend>(ctx: &Ctx<B>, req: &Request) -> Reply {
    let (token, draft) = match decode_save(&req.body) {
        Ok(v) => v,
        Err(r) => return bad_body(r),
    };
    let store = match store(ctx) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let now = ctx.backend.now();
    if let Err(reply) = live(ctx, store.as_ref(), &token, now).await {
        return reply;
    }
    match store.save(token.digest(), draft, now).await {
        Ok(true) => saved(),
        Ok(false) => gone(),
        Err(_) => unavailable(BackendFault::Unavailable),
    }
}

/// `POST /auth/drafts/discard`: deletes the draft.
pub(crate) async fn discard<B: Backend>(ctx: &Ctx<B>, req: &Request) -> Reply {
    let token = match decode_token(&req.body) {
        Ok(t) => t,
        Err(r) => return bad_body(r),
    };
    let store = match store(ctx) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match store.remove(token.digest()).await {
        Ok(true) => saved(),
        Ok(false) => gone(),
        Err(_) => unavailable(BackendFault::Unavailable),
    }
}

fn saved() -> Reply {
    let mut o = Object::with_capacity(1);
    o.insert("status", Value::String("saved".to_owned()));
    Reply::json(StatusCode::OK, &Value::Object(o))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-032, TH-26: each body has one spelling. The start takes a
    /// canonical decimal call, the token is 64 lowercase hex characters,
    /// and the save takes exactly the four members.
    #[test]
    fn adr032_th26_draft_bodies_decode_strictly() {
        assert_eq!(decode_start(br#"{"call":"42"}"#), Ok(CallId::from_raw(42)));
        for bad in [
            &br#"{"call":"042"}"#[..],
            br#"{"call":42}"#,
            br#"{"call":"42","x":"1"}"#,
            br#"{ "call":"42"}"#,
            br#"{"call":""}"#,
        ] {
            assert!(
                decode_start(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        let t = "ab".repeat(32);
        assert!(decode_token(format!(r#"{{"token":"{t}"}}"#).as_bytes()).is_ok());
        assert!(decode_token(format!(r#"{{"token":"{}"}}"#, t.to_uppercase()).as_bytes()).is_err());
        let save = format!(r#"{{"narrative":"N\nx","summary":"S","title":"T","token":"{t}"}}"#);
        let (_, d) = decode_save(save.as_bytes()).unwrap();
        assert_eq!(d.narrative, "N\nx");
        let minor = format!(r#"{{"minor":true,"token":"{t}"}}"#);
        assert_eq!(
            decode_token(minor.as_bytes()),
            Err(BodyRefusal::MinorMember)
        );
        let ctl = format!(r#"{{"narrative":"\u0007","summary":"S","title":"T","token":"{t}"}}"#);
        assert!(decode_save(ctl.as_bytes()).is_err());
        let long = format!(
            r#"{{"narrative":"","summary":"","title":"{}","token":"{t}"}}"#,
            "x".repeat(anon::MAX_TITLE + 1)
        );
        assert!(decode_save(long.as_bytes()).is_err());
    }

    /// ADR-032: the save limit holds a draft at every section limit, with
    /// every byte escaped to two.
    #[test]
    fn adr032_save_limit_holds_a_full_draft() {
        let need = 2 * (anon::MAX_TITLE + anon::MAX_SUMMARY + anon::MAX_NARRATIVE) + 200;
        assert!(DRAFT_BODY_LIMIT >= need);
        const { assert!(DRAFT_BODY_LIMIT <= 1 << 20) };
    }
}
