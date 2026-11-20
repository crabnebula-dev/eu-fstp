//! Lane L2 (`docs/handoff/production-mcp-design.md` section 3.4, ADR-013
//! amendment of 2026-11-20): the production authorisation server of a
//! cell over PostgreSQL, in a one-cell world.
//!
//! The OAuth endpoints are reached over the cell's tunnel listener, as an
//! agent reaches them. The approval of `agents.consent` and the `Tokens`
//! port are the API core's, which lane L1 mounts in the production cell.
//! Until then these tests call the same server through
//! `fstp_cell::oauth::tokens::CellTokens`, as the API core will.
//!
//! A restart is a real stop and start of the cell process over the same
//! databases (`CellHandle::restart`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_api_core::port::{AgentClientId, ConsentApproval, LoginMethod, PortError, StepUpRef};
use fstp_cell::oauth::tokens::CellTokens;
use fstp_celltest::mc::auth_model::http::{AuthClient, one_cell_world};
use fstp_celltest::scan::{Needle, scan_bytes};
use fstp_celltest::world::{CellHandle, HttpReply, HttpRequest};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::B;
use fstp_json::Value;

const REDIRECT: &str = "http://127.0.0.1:8765/callback";
const VERIFIER: &str = "pg-verifier-0123456789abcdefghijklmnopqrstuvwxyz";

fn member(r: &HttpReply, key: &str) -> String {
    fstp_json::parse(&r.body)
        .ok()
        .and_then(|v| v.get(key).and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_default()
}

fn origin(cell: &CellHandle) -> String {
    format!("https://{}", cell.host())
}

fn send(cell: &CellHandle, req: HttpRequest) -> HttpReply {
    cell.request(&req.header("host", cell.host()))
        .unwrap_or_else(|e| panic!("{e}"))
}

fn post_form(cell: &CellHandle, path: &str, pairs: &[(&str, &str)]) -> HttpReply {
    send(
        cell,
        HttpRequest::new("POST", path)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(fstp_oauth::encode_form_urlencoded(pairs).into_bytes()),
    )
}

fn register(cell: &CellHandle) -> String {
    let r = send(
        cell,
        HttpRequest::new("POST", "/oauth/register")
            .header("content-type", "application/json")
            .body(
                format!(r#"{{"client_name":"PG agent","redirect_uris":["{REDIRECT}"]}}"#)
                    .into_bytes(),
            ),
    );
    assert_eq!(
        r.status,
        201,
        "registration: {}",
        String::from_utf8_lossy(&r.body)
    );
    member(&r, "client_id")
}

/// `GET /oauth/authorize`: the handle of the 303 to the consent page.
fn authorize(cell: &CellHandle, client: &str) -> String {
    let challenge = fstp_oauth::encode_base64url(&fstp_crypto::sha256(VERIFIER.as_bytes()));
    let resource = format!("{}/mcp", origin(cell));
    let q = fstp_oauth::encode_form_urlencoded(&[
        ("response_type", "code"),
        ("client_id", client),
        ("redirect_uri", REDIRECT),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("scope", "calls:read creator:draft"),
        ("resource", resource.as_str()),
    ]);
    let r = send(
        cell,
        HttpRequest::new("GET", &format!("/oauth/authorize?{q}")),
    );
    assert_eq!(r.status, 303);
    let to = String::from_utf8(r.header("location").unwrap().to_vec()).unwrap();
    to.strip_prefix("/app/connect#").unwrap().to_owned()
}

fn tokens(cell: &CellHandle) -> CellTokens {
    CellTokens::new(cell.oauth().unwrap_or_else(|e| panic!("{e}")))
}

fn now(cell: &CellHandle) -> Timestamp {
    Timestamp::from_micros(cell.clock().now())
}

/// `agents.consent` after its step-up, as the API core calls the port.
fn approve(cell: &CellHandle, account: AccountId, handle: &str) -> Result<String, PortError> {
    let t = tokens(cell);
    let c = ConsentApproval {
        account,
        handle: handle.to_owned(),
        method: LoginMethod::Passkey,
        step_up: StepUpRef(1),
        at: now(cell),
    };
    cell.block_on(t.approve(&c)).unwrap()
}

fn code_of(redirect: &str) -> String {
    redirect
        .split(['?', '&'])
        .find_map(|p| p.strip_prefix("code="))
        .unwrap()
        .to_owned()
}

fn redeem(cell: &CellHandle, client: &str, code: &str) -> HttpReply {
    let resource = format!("{}/mcp", origin(cell));
    post_form(
        cell,
        "/oauth/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
            ("resource", resource.as_str()),
        ],
    )
}

fn refresh(cell: &CellHandle, client: &str, token: &str) -> HttpReply {
    post_form(
        cell,
        "/oauth/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", token),
            ("client_id", client),
        ],
    )
}

/// A connected agent of `account`: client id, access and refresh token.
fn connect(cell: &CellHandle, account: AccountId) -> (String, String, String) {
    let client = register(cell);
    let handle = authorize(cell, &client);
    let to = approve(cell, account, &handle).unwrap();
    let r = redeem(cell, &client, &code_of(&to));
    assert_eq!(r.status, 200, "redemption");
    (
        client,
        member(&r, "access_token"),
        member(&r, "refresh_token"),
    )
}

fn grant(cell: &CellHandle, token: &str) -> Result<fstp_access::GrantFacts, PortError> {
    let t = tokens(cell);
    cell.block_on(t.grant_facts(token.as_bytes(), now(cell)))
        .unwrap()
}

/// An enrolled synthetic account of the world's cell.
fn enrolled(client: &AuthClient<'_>) -> AccountId {
    assert!(client.enrol(B).unwrap(), "b could not enrol");
    client.cell_account(B).unwrap()
}

/// R-MC-01: a cell restart keeps every grant. The refresh token rotates
/// after it, and the new access token names the account. An access token
/// issued before it is gone, and a code minted before it is burned.
#[test]
fn r_mc_01_oauth_records_survive_restart() {
    let world = one_cell_world().unwrap_or_else(|e| panic!("{e}"));
    let cell = world.cell(0).unwrap();
    let client = AuthClient::new(cell);
    let account = enrolled(&client);
    let (agent, access, refresh_token) = connect(cell, account);
    assert_eq!(grant(cell, &access).unwrap().account, account);
    let handle = authorize(cell, &agent);
    let pending_code = code_of(&approve(cell, account, &handle).unwrap());

    cell.restart().unwrap_or_else(|e| panic!("{e}"));
    cell.clock().advance(1);

    assert_eq!(grant(cell, &access), Err(PortError::Refused));
    let r = refresh(cell, &agent, &refresh_token);
    assert_eq!(
        r.status,
        200,
        "refresh after restart: {}",
        String::from_utf8_lossy(&r.body)
    );
    assert_eq!(
        grant(cell, &member(&r, "access_token")).unwrap().account,
        account
    );
    assert_eq!(
        member(&redeem(cell, &agent, &pending_code), "error"),
        "invalid_grant",
        "a code minted before the restart is burned"
    );
    let agents = {
        let t = tokens(cell);
        cell.block_on(t.agents_of(account, now(cell)))
            .unwrap()
            .unwrap()
    };
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].name.as_deref(), Some("PG agent"));
}

/// TH-61: a retired refresh token presented after a restart revokes its
/// family, and the revocation outlives the next restart.
#[test]
fn th61_refresh_reuse_after_restart_revokes_family() {
    let world = one_cell_world().unwrap_or_else(|e| panic!("{e}"));
    let cell = world.cell(0).unwrap();
    let account = enrolled(&AuthClient::new(cell));
    let (agent, _, first) = connect(cell, account);
    let second = member(&refresh(cell, &agent, &first), "refresh_token");
    assert!(!second.is_empty());
    cell.restart().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        member(&refresh(cell, &agent, &first), "error"),
        "invalid_grant"
    );
    cell.restart().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        member(&refresh(cell, &agent, &second), "error"),
        "invalid_grant",
        "the family is revoked for good"
    );
}

/// R-MC-03: a revocation through `/oauth/revoke` and through the
/// `agents.revoke` port takes effect at once, and outlives a restart.
#[test]
fn r_mc_03_revocation_takes_effect_at_once_on_pg() {
    let world = one_cell_world().unwrap_or_else(|e| panic!("{e}"));
    let cell = world.cell(0).unwrap();
    let account = enrolled(&AuthClient::new(cell));

    let (agent, access, refresh_token) = connect(cell, account);
    let r = post_form(
        cell,
        "/oauth/revoke",
        &[
            ("token", refresh_token.as_str()),
            ("client_id", agent.as_str()),
        ],
    );
    assert_eq!(r.status, 200);
    assert_eq!(grant(cell, &access), Err(PortError::Refused));

    let (agent2, access2, refresh2) = connect(cell, account);
    let number = {
        let s = cell.oauth().unwrap();
        cell.block_on(s.read(|s, _, _| s.client_number(&agent2)))
            .unwrap()
            .unwrap()
            .unwrap()
    };
    let t = tokens(cell);
    cell.block_on(t.revoke_agent(account, AgentClientId::from_raw(u128::from(number.raw()))))
        .unwrap()
        .unwrap();
    assert_eq!(grant(cell, &access2), Err(PortError::Refused));

    cell.restart().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        member(&refresh(cell, &agent, &refresh_token), "error"),
        "invalid_grant"
    );
    assert_eq!(
        member(&refresh(cell, &agent2, &refresh2), "error"),
        "invalid_grant"
    );
}

/// H-21, issue 6 M5, I-79, TH-57: a completed account recovery ends every
/// agent grant of the account. The old access token is refused, the old
/// refresh token gets `invalid_grant`, after a restart too, and a new
/// consent after the recovery works.
#[test]
fn h21_recovery_completion_revokes_agent_tokens_pg() {
    let world = one_cell_world().unwrap_or_else(|e| panic!("{e}"));
    let cell = world.cell(0).unwrap();
    let client = AuthClient::new(cell);
    let account = enrolled(&client);
    let (agent, access, refresh_token) = connect(cell, account);
    cell.clock().advance(1);
    let case = client
        .recovery(B)
        .unwrap()
        .unwrap_or_else(|| panic!("no case"));
    assert!(client.recovery_email(&case).unwrap());
    let fresh = client.recovery_complete(&case).unwrap();
    assert!(fresh.is_some(), "the recovery did not complete");
    cell.clock().advance(1);

    assert_eq!(grant(cell, &access), Err(PortError::Refused));
    assert_eq!(
        member(&refresh(cell, &agent, &refresh_token), "error"),
        "invalid_grant"
    );
    let agents = {
        let t = tokens(cell);
        cell.block_on(t.agents_of(account, now(cell)))
            .unwrap()
            .unwrap()
    };
    assert!(agents.is_empty(), "an agent survived the recovery");

    let (_, access2, _) = connect(cell, account);
    assert_eq!(grant(cell, &access2).unwrap().account, account);

    cell.restart().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        member(&refresh(cell, &agent, &refresh_token), "error"),
        "invalid_grant"
    );
}

/// I-79: a token family that started at or before the account's last
/// completed recovery is refused on every call, after a restart too,
/// even when its revocation never reached the rows: the row is put back
/// as a process that died between the completion's commit and the
/// revocation would leave it. The start sweeps it, and the token check
/// refuses it on every call.
#[test]
fn i79_token_family_older_than_recovery_is_refused() {
    let world = one_cell_world().unwrap_or_else(|e| panic!("{e}"));
    let cell = world.cell(0).unwrap();
    let client = AuthClient::new(cell);
    let account = enrolled(&client);
    let (agent, _, refresh_token) = connect(cell, account);
    let case = client
        .recovery(B)
        .unwrap()
        .unwrap_or_else(|| panic!("no case"));
    assert!(client.recovery_email(&case).unwrap());
    assert!(client.recovery_complete(&case).unwrap().is_some());
    cell.clock().advance(1);
    let out = world
        .app_superuser_sql(
            0,
            "UPDATE mcp.family SET revoked = false, version = version + 1000000 RETURNING id",
        )
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        out.lines().filter(|l| !l.trim().is_empty()).count(),
        1,
        "{out}"
    );
    cell.restart().unwrap_or_else(|e| panic!("{e}"));
    cell.clock().advance(1);
    assert_eq!(
        member(&refresh(cell, &agent, &refresh_token), "error"),
        "invalid_grant"
    );
    let revoked = world
        .app_superuser_sql(0, "SELECT count(*) FROM mcp.family WHERE revoked")
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        revoked.lines().any(|l| l.trim() == "1"),
        "the start sweep left the row: {revoked}"
    );
}

/// TH-61, R-NF-02: no store of the world holds a token, a code or a
/// consent handle the cell issued: every database, as files and as a
/// dump, and every log, in every encoding the scanner reads.
#[test]
fn th61_mcp_tables_hold_hashes_only() {
    let world = one_cell_world().unwrap_or_else(|e| panic!("{e}"));
    let cell = world.cell(0).unwrap();
    let account = enrolled(&AuthClient::new(cell));
    let agent = register(cell);
    let handle = authorize(cell, &agent);
    let code = code_of(&approve(cell, account, &handle).unwrap());
    let r = redeem(cell, &agent, &code);
    let refreshed = refresh(cell, &agent, &member(&r, "refresh_token"));
    let mut needles = Vec::new();
    for (label, text) in [
        ("consent handle", handle),
        ("code", code),
        ("access token", member(&r, "access_token")),
        ("refresh token", member(&r, "refresh_token")),
        ("rotated access token", member(&refreshed, "access_token")),
        ("rotated refresh token", member(&refreshed, "refresh_token")),
    ] {
        assert_eq!(text.len(), 43, "{label}");
        let raw = fstp_oauth::decode_base64url(text.as_bytes()).unwrap();
        needles.push(Needle {
            label: format!("{label} as text"),
            bytes: text.into_bytes(),
        });
        needles.push(Needle {
            label: format!("{label} as bytes"),
            bytes: raw.as_bytes().to_vec(),
        });
    }
    let report = scan_bytes(&world.stores().unwrap(), &needles).unwrap();
    assert!(report.is_clean(), "{report:?}");
}
