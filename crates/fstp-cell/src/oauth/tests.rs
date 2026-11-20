//! Tests of the cell's authorisation server over rows in memory (lane
//! L2). The rows follow the rules of `0010_mcp.sql`, so a restart is a new
//! [`AuthServer`] over the same rows. The PostgreSQL tests of the same
//! properties are in `fstp-celltest` (`tests/l2_oauth_pg.rs`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use fstp_api_core::port::{AgentClientId, ConsentApproval, LoginMethod, PortError, StepUpRef};
use fstp_cell_core::CellState;
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_http::{Method, Request, RequestTarget, Response, StatusCode};
use fstp_json::Value;
use fstp_rt::future::block_on;

use super::store::{McpStore, MemoryMcpStore};
use super::tokens::CellTokens;
use super::{AuthServer, Mount, OauthRoutes, config_for};

const HOST: &str = "cell-a.fstp.test";
const ORIGIN: &str = "https://cell-a.fstp.test";
const REDIRECT: &str = "http://127.0.0.1:8765/callback";
const VERIFIER: &str = "cell-verifier-0123456789abcdefghijklmnopqrstuvwxyz";
/// An account id above `u64::MAX`, as the production cell draws them.
const ACCOUNT: AccountId = AccountId::from_raw(0x0123_4567_89ab_cdef_fedc_ba98_7654_3210);

/// One cell's authorisation server over shared rows, with a clock the
/// test moves.
struct Cell {
    rows: Arc<MemoryMcpStore>,
    clock: Arc<AtomicI64>,
    server: Arc<AuthServer>,
    routes: OauthRoutes,
}

impl Cell {
    fn new() -> Cell {
        Cell::over(
            Arc::new(MemoryMcpStore::default()),
            Arc::new(AtomicI64::new(1_000)),
        )
    }

    fn over(rows: Arc<MemoryMcpStore>, clock: Arc<AtomicI64>) -> Cell {
        let c = Arc::clone(&clock);
        let server = block_on(AuthServer::start(
            config_for(HOST).unwrap(),
            Arc::clone(&rows) as Arc<dyn McpStore>,
            Arc::new(|| Arc::new(CellState::genesis())),
            Arc::new(move || c.load(Ordering::SeqCst)),
        ))
        .unwrap();
        let routes = OauthRoutes::new(Arc::clone(&server), HOST);
        Cell {
            rows,
            clock,
            server,
            routes,
        }
    }

    /// A process restart: a new server over the same rows.
    fn restart(&self) -> Cell {
        Cell::over(Arc::clone(&self.rows), Arc::clone(&self.clock))
    }

    fn tick(&self, us: i64) {
        self.clock.fetch_add(us, Ordering::SeqCst);
    }

    fn now(&self) -> Timestamp {
        Timestamp::from_micros(self.clock.load(Ordering::SeqCst))
    }

    fn send(&self, req: Request) -> Response {
        block_on(self.routes.serve(req))
    }

    fn post(&self, path: &str, body: &[u8]) -> Response {
        let mut r = Request::new(Method::POST, RequestTarget::origin(path).unwrap());
        r.body = body.to_vec();
        self.send(r)
    }

    fn tokens(&self) -> CellTokens {
        CellTokens::new(Arc::clone(&self.server))
    }
}

fn member(r: &Response, key: &str) -> String {
    fstp_json::parse(&r.body)
        .ok()
        .and_then(|v| v.get(key).and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_default()
}

fn form(pairs: &[(&str, &str)]) -> Vec<u8> {
    fstp_oauth::encode_form_urlencoded(pairs).into_bytes()
}

fn register(cell: &Cell) -> String {
    let r = cell.post(
        "/oauth/register",
        format!(r#"{{"client_name":"Unit agent","redirect_uris":["{REDIRECT}"]}}"#).as_bytes(),
    );
    assert_eq!(r.status, StatusCode::CREATED);
    member(&r, "client_id")
}

/// `GET /oauth/authorize`: the consent handle the 303 names.
fn authorize(cell: &Cell, client: &str) -> String {
    let challenge = fstp_oauth::encode_base64url(&fstp_crypto::sha256(VERIFIER.as_bytes()));
    let q = fstp_oauth::encode_form_urlencoded(&[
        ("response_type", "code"),
        ("client_id", client),
        ("redirect_uri", REDIRECT),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("scope", "calls:read creator:draft"),
        ("state", "s1"),
        ("resource", &format!("{ORIGIN}/mcp")),
    ]);
    let r = cell.send(Request::new(
        Method::GET,
        RequestTarget::origin(&format!("/oauth/authorize?{q}")).unwrap(),
    ));
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let to = r
        .headers
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    to.strip_prefix("/app/connect#").unwrap().to_owned()
}

/// The approval of `handle` as `agents.consent` makes it, after its
/// step-up: the redirect with the code.
fn approve(cell: &Cell, handle: &str) -> Result<String, PortError> {
    block_on(cell.tokens().approve(&ConsentApproval {
        account: ACCOUNT,
        handle: handle.to_owned(),
        method: LoginMethod::Passkey,
        step_up: StepUpRef(1),
        at: cell.now(),
    }))
}

fn code_of(redirect: &str) -> String {
    redirect
        .split(['?', '&'])
        .find_map(|p| p.strip_prefix("code="))
        .unwrap()
        .to_owned()
}

fn redeem(cell: &Cell, client: &str, code: &str) -> Response {
    cell.post(
        "/oauth/token",
        &form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
            ("resource", &format!("{ORIGIN}/mcp")),
        ]),
    )
}

fn refresh(cell: &Cell, client: &str, token: &str) -> Response {
    cell.post(
        "/oauth/token",
        &form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", token),
            ("client_id", client),
        ]),
    )
}

/// A connected agent: client id, access token, refresh token.
fn connected(cell: &Cell) -> (String, String, String) {
    let client = register(cell);
    let handle = authorize(cell, &client);
    let to = approve(cell, &handle).unwrap();
    assert!(to.starts_with(REDIRECT));
    assert!(to.contains("state=s1"));
    let r = redeem(cell, &client, &code_of(&to));
    assert_eq!(r.status, StatusCode::OK);
    (
        client,
        member(&r, "access_token"),
        member(&r, "refresh_token"),
    )
}

fn grant(cell: &Cell, token: &str) -> Result<fstp_access::GrantFacts, PortError> {
    block_on(cell.tokens().grant_facts(token.as_bytes(), cell.now()))
}

/// R-MC-01 over rows in memory: a restart keeps the client and the
/// family. The refresh token rotates after it, and the new access token
/// names the account and the client. The old access token is gone.
#[test]
fn r_mc_01_oauth_records_survive_restart_over_memory_rows() {
    let cell = Cell::new();
    let (client, access, refresh_token) = connected(&cell);
    let g = grant(&cell, &access).unwrap();
    assert_eq!(g.account, ACCOUNT);
    let cell = cell.restart();
    cell.tick(1);
    assert_eq!(grant(&cell, &access), Err(PortError::Refused));
    let r = refresh(&cell, &client, &refresh_token);
    assert_eq!(r.status, StatusCode::OK, "refresh after restart");
    let g = grant(&cell, &member(&r, "access_token")).unwrap();
    assert_eq!(g.account, ACCOUNT);
    let agents = block_on(cell.tokens().agents_of(ACCOUNT, cell.now())).unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].name.as_deref(), Some("Unit agent"));
}

/// R-MC-01: a code minted before a restart is burned by it.
#[test]
fn r_mc_01_code_minted_before_restart_is_burned_over_memory_rows() {
    let cell = Cell::new();
    let client = register(&cell);
    let handle = authorize(&cell, &client);
    let to = approve(&cell, &handle).unwrap();
    let cell = cell.restart();
    let r = redeem(&cell, &client, &code_of(&to));
    assert_eq!(member(&r, "error"), "invalid_grant");
}

/// TH-61: a retired refresh token presented after a restart revokes the
/// family, durably.
#[test]
fn th61_refresh_reuse_after_restart_revokes_family_over_memory_rows() {
    let cell = Cell::new();
    let (client, _, first) = connected(&cell);
    let second = member(&refresh(&cell, &client, &first), "refresh_token");
    let cell = cell.restart();
    assert_eq!(
        member(&refresh(&cell, &client, &first), "error"),
        "invalid_grant"
    );
    let cell = cell.restart();
    assert_eq!(
        member(&refresh(&cell, &client, &second), "error"),
        "invalid_grant"
    );
}

/// R-MC-03: `/oauth/revoke` and `agents.revoke` take effect at once, and
/// durably.
#[test]
fn r_mc_03_revocation_takes_effect_at_once_over_memory_rows() {
    let cell = Cell::new();
    let (client, access, refresh_token) = connected(&cell);
    let r = cell.post(
        "/oauth/revoke",
        &form(&[
            ("token", refresh_token.as_str()),
            ("client_id", client.as_str()),
        ]),
    );
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(grant(&cell, &access), Err(PortError::Refused));
    let cell = cell.restart();
    assert_eq!(
        member(&refresh(&cell, &client, &refresh_token), "error"),
        "invalid_grant"
    );

    let (client, access, refresh_token) = connected(&cell);
    let number = AgentClientId::from_raw(u128::from(
        block_on(cell.server.read(|s, _, _| s.client_number(&client)))
            .unwrap()
            .unwrap()
            .raw(),
    ));
    block_on(cell.tokens().revoke_agent(ACCOUNT, number)).unwrap();
    assert_eq!(grant(&cell, &access), Err(PortError::Refused));
    let cell = cell.restart();
    assert_eq!(
        member(&refresh(&cell, &client, &refresh_token), "error"),
        "invalid_grant"
    );
    assert_eq!(
        block_on(cell.tokens().revoke_agent(ACCOUNT, number)),
        Err(PortError::Refused),
        "nothing left to revoke"
    );
}

/// A failed write answers 503 and sends no token. The server reloads from
/// the rows before the next call, so the rotation that failed to commit
/// never happened: the refresh token in the rows still works.
#[test]
fn r_mc_01_failed_write_answers_503_and_reloads() {
    let cell = Cell::new();
    let (client, _, refresh_token) = connected(&cell);
    cell.rows.set_failing(true);
    let r = refresh(&cell, &client, &refresh_token);
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(member(&r, "access_token").is_empty());
    cell.rows.set_failing(false);
    let r = refresh(&cell, &client, &refresh_token);
    assert_eq!(
        r.status,
        StatusCode::OK,
        "the uncommitted rotation is forgotten"
    );
}

/// TH-61, R-NF-02: no stored row holds a token, a code or a handle.
#[test]
fn th61_mcp_rows_hold_hashes_only_over_memory_rows() {
    let cell = Cell::new();
    let client = register(&cell);
    let handle = authorize(&cell, &client);
    let to = approve(&cell, &handle).unwrap();
    let code = code_of(&to);
    let r = redeem(&cell, &client, &code);
    let secrets = [
        handle,
        code,
        member(&r, "access_token"),
        member(&r, "refresh_token"),
    ];
    let rec = cell.rows.records();
    let mut stored: Vec<Vec<u8>> = Vec::new();
    for c in &rec.clients {
        stored.push(c.metadata.clone());
        stored.push(c.client_id.as_bytes().to_vec());
    }
    for f in &rec.families {
        stored.push(f.current.to_vec());
    }
    for h in &rec.refresh {
        stored.push(h.hash.to_vec());
    }
    for s in &secrets {
        let raw = fstp_oauth::decode_base64url(s.as_bytes()).unwrap();
        for b in &stored {
            assert!(!b.windows(s.len()).any(|w| w == s.as_bytes()));
            assert!(!b.windows(32).any(|w| w == raw.as_bytes()));
        }
    }
}

/// TW-4: a refused authorisation request gets a page with its OAuth
/// error and no redirect.
#[test]
fn tw4_refused_authorize_never_redirects() {
    let cell = Cell::new();
    let r = cell.send(Request::new(
        Method::GET,
        RequestTarget::origin("/oauth/authorize?client_id=nobody&response_type=code").unwrap(),
    ));
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.headers.get("location").is_none());
    assert!(String::from_utf8_lossy(&r.body).contains("invalid_client"));
}

/// The denial of the consent page: only a script of the cell origin may
/// send it. It answers the client's redirect URI with `access_denied`,
/// `state` and `iss`, and the handle then is gone.
#[test]
fn rfc6749_deny_answers_access_denied_to_the_client() {
    let cell = Cell::new();
    let client = register(&cell);
    let handle = authorize(&cell, &client);
    let body = format!(r#"{{"consent":"{handle}"}}"#);
    let deny = |origin: Option<&str>, mark: bool| {
        let mut r = Request::new(Method::POST, RequestTarget::origin("/oauth/deny").unwrap());
        if let Some(o) = origin {
            let _ = r.headers.try_append("origin", o);
        }
        if mark {
            let _ = r.headers.try_append("x-fstp-request", "1");
        }
        r.body = body.as_bytes().to_vec();
        cell.send(r)
    };
    assert_eq!(deny(None, true).status, StatusCode::FORBIDDEN);
    assert_eq!(
        deny(Some("https://evil.example"), true).status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(deny(Some(ORIGIN), false).status, StatusCode::FORBIDDEN);
    let r = deny(Some(ORIGIN), true);
    assert_eq!(r.status, StatusCode::OK);
    let to = member(&r, "redirect");
    assert!(to.starts_with(REDIRECT));
    assert!(to.contains("error=access_denied"));
    assert!(to.contains("state=s1"));
    assert!(to.contains("iss="));
    assert_eq!(deny(Some(ORIGIN), true).status, StatusCode::BAD_REQUEST);
    assert_eq!(approve(&cell, &handle), Err(PortError::Refused));
}

/// The four endpoints and the denial answer 405 to another method, and
/// every other path below `/oauth` is not found.
#[test]
fn oauth_routes_refuse_other_methods_and_paths() {
    let cell = Cell::new();
    for p in [
        "/oauth/register",
        "/oauth/token",
        "/oauth/revoke",
        "/oauth/deny",
    ] {
        let r = cell.send(Request::new(Method::GET, RequestTarget::origin(p).unwrap()));
        assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED, "{p}");
    }
    let r = cell.send(Request::new(
        Method::POST,
        RequestTarget::origin("/oauth/consent").unwrap(),
    ));
    assert_eq!(r.status, StatusCode::NOT_FOUND, "no demo consent route");
    let r = cell.send(Request::new(
        Method::POST,
        RequestTarget::origin("/oauth/consent/confirm").unwrap(),
    ));
    assert_eq!(r.status, StatusCode::NOT_FOUND, "no demo step-up route");
}
