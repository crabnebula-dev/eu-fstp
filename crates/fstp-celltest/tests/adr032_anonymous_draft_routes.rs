//! The anonymous draft routes of the cell front (ADR-032, Daniel
//! 2026-11-22; R-NF-02, R-SB-01, I-21, ADR-024).
//!
//! Each test starts the production front over the in-memory backend
//! (`fstp_cell::routes::memory::LocalCell`) on a ledger that production
//! `decide` built through the M2 domain: PR1 of L1 in DRAFT, in call 1,
//! which is published and open from T0 until its deadline. The front
//! serves the anonymous routes with no session. Every text is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_api_core::anon::{AnonymousDrafts, LIFETIME_US};
use fstp_cell::routes::memory::LocalCell;
use fstp_cell_core::CellRecord;
use fstp_celltest::mc::auth_model::ProdCell;
use fstp_celltest::mc::driver_model::paths;
use fstp_domain::rules::StateTag;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{ADMIN, CALL_DEADLINE, T0, call};
use fstp_http::{Method, Request, RequestTarget, Response};
use fstp_ledger::Entry;

const CELL: [u8; 16] = [0xAD; 16];
const HOST: &str = "tenant-d.fstp.test";

fn ledger() -> Vec<Entry<CellRecord>> {
    let path = paths::to(StateTag::Draft).unwrap();
    let mut cell = ProdCell::genesis(paths::truth(true)).unwrap();
    cell.exec_tenant_admin_grant(ADMIN, ADMIN, T0).unwrap();
    for p in &path {
        cell.exec_step(&p.step, p.at).unwrap();
    }
    cell.entries()
}

fn cell_at(now: Timestamp) -> LocalCell {
    let c = LocalCell::start_after(CELL, HOST, &ledger()).unwrap();
    c.backend().set_now(now);
    c
}

fn post(path: &str, body: &str) -> Request {
    let mut req = Request::new(Method::POST, RequestTarget::origin(path).unwrap())
        .try_with_header("host", HOST)
        .unwrap()
        .try_with_header("origin", format!("https://{HOST}"))
        .unwrap()
        .try_with_header("content-type", "application/json")
        .unwrap();
    req.body = body.as_bytes().to_vec();
    req
}

fn text(r: &Response) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn member(r: &Response, key: &str) -> String {
    let t = text(r);
    let (_, rest) = t
        .split_once(&format!("\"{key}\":\""))
        .unwrap_or_else(|| panic!("no {key} in {t}"));
    rest.split_once('"').unwrap().0.to_owned()
}

fn start(c: &LocalCell) -> Response {
    c.serve(post(
        "/auth/drafts",
        &format!("{{\"call\":\"{}\"}}", call(1).raw()),
    ))
}

fn save_body(token: &str, title: &str, narrative: &str) -> String {
    format!(
        "{{\"narrative\":\"{narrative}\",\"summary\":\"A synthetic summary.\",\"title\":\"{title}\",\"token\":\"{token}\"}}"
    )
}

fn token_body(token: &str) -> String {
    format!("{{\"token\":\"{token}\"}}")
}

/// ADR-032, Daniel 2026-11-22: a person with no account starts a draft
/// for an open call, saves it, and opens it again by the token alone. The
/// draft expires 30 days after its start.
#[test]
fn adr032_start_save_and_resume_without_an_account() {
    let c = cell_at(T0);
    let r = start(&c);
    assert_eq!(r.status.as_u16(), 201, "{}", text(&r));
    let token = member(&r, "token");
    assert_eq!(token.len(), 64);
    assert_eq!(
        member(&r, "expires"),
        (T0.micros() + LIFETIME_US).to_string()
    );
    let s = c.serve(post(
        "/auth/drafts/save",
        &save_body(&token, "Synthetic sensor", "Line one.\\nLine two."),
    ));
    assert_eq!(s.status.as_u16(), 200, "{}", text(&s));
    let o = c.serve(post("/auth/drafts/open", &token_body(&token)));
    assert_eq!(o.status.as_u16(), 200, "{}", text(&o));
    assert_eq!(member(&o, "title"), "Synthetic sensor");
    assert_eq!(member(&o, "narrative"), "Line one.\\nLine two.");
    assert_eq!(member(&o, "call"), call(1).raw().to_string());
}

/// ADR-032, R-NF-02: the store keeps the token's digest only, and no log
/// event of the front holds the token.
#[test]
fn adr032_r_nf_02_token_is_kept_as_its_digest_and_never_logged() {
    let c = cell_at(T0);
    let token = member(&start(&c), "token");
    let raw = fstp_api_core::anon::Token::parse(&token).unwrap();
    let store = c.backend().anon_store();
    let at = Timestamp::from_micros(T0.micros() + 1);
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    let mut f = store.open(raw.digest(), at);
    let got = match f.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(v) => v.unwrap(),
        std::task::Poll::Pending => panic!("memory store waits"),
    };
    assert!(got.is_some(), "the draft is kept under the token's digest");
    let _ = c.serve(post("/auth/drafts/open", &token_body(&token)));
    for e in c.logs() {
        let shown = format!("{e:?}");
        assert!(!shown.contains(&token), "a log event holds the token");
        assert!(!shown.contains(&token[..16]));
    }
}

/// ADR-032: an unknown token, a discarded draft and an expired draft all
/// answer 404 with the same body, so the answer tells nothing more.
#[test]
fn adr032_unknown_discarded_and_expired_drafts_answer_alike() {
    let c = cell_at(T0);
    let unknown = c.serve(post("/auth/drafts/open", &token_body(&"5a".repeat(32))));
    assert_eq!(unknown.status.as_u16(), 404);
    let token = member(&start(&c), "token");
    let d = c.serve(post("/auth/drafts/discard", &token_body(&token)));
    assert_eq!(d.status.as_u16(), 200, "{}", text(&d));
    let gone = c.serve(post("/auth/drafts/open", &token_body(&token)));
    assert_eq!(gone.status.as_u16(), 404);
    assert_eq!(text(&gone), text(&unknown));
    let token = member(&start(&c), "token");
    c.backend()
        .set_now(Timestamp::from_micros(T0.micros() + LIFETIME_US));
    let expired = c.serve(post("/auth/drafts/open", &token_body(&token)));
    assert_eq!(expired.status.as_u16(), 404);
    assert_eq!(text(&expired), text(&unknown));
    let save = c.serve(post("/auth/drafts/save", &save_body(&token, "T", "N")));
    assert_eq!(save.status.as_u16(), 404);
}

/// ADR-032 open point 3, `pre-check.md`: a draft started close to the
/// call's deadline ends at the deadline, and no draft starts for a call
/// that is closed or unknown.
#[test]
fn adr032_draft_ends_at_the_call_deadline() {
    let late = Timestamp::from_micros(CALL_DEADLINE.micros() - 1_000_000);
    let c = cell_at(late);
    let r = start(&c);
    assert_eq!(r.status.as_u16(), 201, "{}", text(&r));
    assert_eq!(member(&r, "expires"), CALL_DEADLINE.micros().to_string());
    let token = member(&r, "token");
    c.backend().set_now(CALL_DEADLINE);
    let o = c.serve(post("/auth/drafts/open", &token_body(&token)));
    assert_eq!(o.status.as_u16(), 404);
    let closed = start(&c);
    assert_eq!(closed.status.as_u16(), 409, "{}", text(&closed));
    let unknown = c.serve(post("/auth/drafts", "{\"call\":\"987654321\"}"));
    assert_eq!(unknown.status.as_u16(), 409);
}

/// ADR-032, R-SB-01, TH-26: a body with any other member, such as an
/// email or a name, is refused, as is a `minor` member (I-18) and a text
/// over its limit. Nothing is stored.
#[test]
fn adr032_r_sb_01_no_identity_member_is_taken() {
    let c = cell_at(T0);
    let token = member(&start(&c), "token");
    for body in [
        format!(
            "{{\"email\":\"a@example.test\",\"narrative\":\"\",\"summary\":\"\",\"title\":\"\",\"token\":\"{token}\"}}"
        ),
        format!("{{\"minor\":true,\"token\":\"{token}\"}}"),
        save_body(&token, &"x".repeat(301), ""),
    ] {
        let r = c.serve(post("/auth/drafts/save", &body));
        assert_eq!(r.status.as_u16(), 400, "{body}: {}", text(&r));
    }
    let r = c.serve(post(
        "/auth/drafts",
        &format!("{{\"call\":\"{}\",\"name\":\"x\"}}", call(1).raw()),
    ));
    assert_eq!(r.status.as_u16(), 400);
}

/// ADR-032, ADR-024: one peer starts at most 10 drafts an hour. The
/// eleventh start is refused with 429 and stores nothing. The routes
/// check `Origin` as every POST route does.
#[test]
fn adr032_adr024_starts_are_rate_limited_per_peer() {
    let c = cell_at(T0);
    for i in 0..10 {
        assert_eq!(start(&c).status.as_u16(), 201, "start {i}");
    }
    let r = start(&c);
    assert_eq!(r.status.as_u16(), 429, "{}", text(&r));
    assert_eq!(c.backend().anon_store().len(), 10);
    let mut foreign = Request::new(Method::POST, RequestTarget::origin("/auth/drafts").unwrap())
        .try_with_header("host", HOST)
        .unwrap()
        .try_with_header("origin", "https://elsewhere.test")
        .unwrap()
        .try_with_header("content-type", "application/json")
        .unwrap();
    foreign.body = format!("{{\"call\":\"{}\"}}", call(1).raw()).into_bytes();
    assert_eq!(c.serve(foreign).status.as_u16(), 403);
}
