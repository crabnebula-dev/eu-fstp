//! The production cell's MCP path over PostgreSQL, wave 1 integrated
//! (lanes L1, L2 and L3, `docs/handoff/production-mcp-design.md` section
//! 4.1, ADR-026, ADR-013 amendment of 2026-11-20).
//!
//! A one-cell world mounts the web adapter over the cell's own `ApiCore`
//! with lane L2's token store. An agent registers, the first admin
//! consents through `agents.consent` with a passkey step-up, the agent
//! redeems its code, lists its tools and prepares a programme draft. The
//! draft waits until the admin confirms it in the platform with a second
//! step-up, and it executes once. Every request goes through the cell's
//! tunnel listener, as a browser or an agent sends it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::mc::auth_model::http::{AuthClient, Cookie, FIRST_ADMIN};
use fstp_celltest::world::{
    CellHandle, DbMode, HttpReply, HttpRequest, VaultLayout, World, WorldSpec,
};
use fstp_json::Value;

const REDIRECT: &str = "http://127.0.0.1:8765/callback";
const VERIFIER: &str = "l1-verifier-0123456789abcdefghijklmnopqrstuvwxyz";
const MODERN: &str = "2026-07-28";

fn world() -> World {
    World::start_with_api(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("{e}"))
}

fn json(r: &HttpReply) -> Value {
    fstp_json::parse(&r.body).unwrap_or(Value::Null)
}

fn text(r: &HttpReply) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn send(cell: &CellHandle, req: HttpRequest) -> HttpReply {
    cell.request(&req.header("host", cell.host()))
        .unwrap_or_else(|e| panic!("{e}"))
}

/// A call of the web API in the session `cookie`, as `web/src/core/api.ts`
/// sends it.
fn web(cell: &CellHandle, method: &str, path: &str, cookie: &Cookie, body: &str) -> HttpReply {
    let mut r = HttpRequest::new(method, path)
        .header("cookie", cookie.0.clone())
        .header("accept", "application/json");
    if method != "GET" {
        r = r
            .header("origin", format!("https://{}", cell.host()))
            .header("x-fstp-request", "1")
            .header("content-type", "application/json")
            .body(body.as_bytes().to_vec());
    }
    send(cell, r)
}

/// `web`, and on `step_up_required` the passkey ceremony of the
/// challenge, then the same request once more (`withStepUp`).
fn web_with_step_up(
    client: &AuthClient<'_>,
    method: &str,
    path: &str,
    cookie: &Cookie,
    body: &str,
) -> HttpReply {
    let cell = client.cell();
    let first = web(cell, method, path, cookie, body);
    let v = json(&first);
    if v.get("code").and_then(Value::as_str) != Some("step_up_required") {
        return first;
    }
    let ch = v.get("challenge").unwrap();
    let id = ch.get("challenge_id").and_then(Value::as_str).unwrap();
    let bytes = ch
        .get("public_key")
        .and_then(|p| p.get("challenge"))
        .and_then(Value::as_str)
        .unwrap();
    let challenge: [u8; 32] = fstp_oauth::decode_base64url(bytes.as_bytes())
        .unwrap()
        .as_bytes()
        .try_into()
        .unwrap();
    assert!(
        client.prove_api_step_up(cookie, id, challenge).unwrap(),
        "I-78: the passkey step-up was refused"
    );
    web(cell, method, path, cookie, body)
}

fn register(cell: &CellHandle) -> String {
    let r = send(
        cell,
        HttpRequest::new("POST", "/oauth/register")
            .header("content-type", "application/json")
            .body(
                format!(r#"{{"client_name":"Synthetic agent","redirect_uris":["{REDIRECT}"]}}"#)
                    .into_bytes(),
            ),
    );
    assert_eq!(r.status, 201, "registration: {}", text(&r));
    json(&r)
        .get("client_id")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned()
}

fn authorize(cell: &CellHandle, client: &str) -> String {
    let challenge = fstp_oauth::encode_base64url(&fstp_crypto::sha256(VERIFIER.as_bytes()));
    let resource = format!("https://{}/mcp", cell.host());
    let q = fstp_oauth::encode_form_urlencoded(&[
        ("response_type", "code"),
        ("client_id", client),
        ("redirect_uri", REDIRECT),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("scope", "calls:read creator:draft"),
        ("state", "synthetic-state"),
        ("resource", resource.as_str()),
    ]);
    let r = send(
        cell,
        HttpRequest::new("GET", &format!("/oauth/authorize?{q}")),
    );
    assert_eq!(r.status, 303, "authorize: {}", text(&r));
    let to = String::from_utf8(r.header("location").unwrap().to_vec()).unwrap();
    to.strip_prefix("/app/connect#").unwrap().to_owned()
}

fn redeem(cell: &CellHandle, client: &str, code: &str) -> String {
    let resource = format!("https://{}/mcp", cell.host());
    let body = fstp_oauth::encode_form_urlencoded(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", client),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("resource", resource.as_str()),
    ]);
    let r = send(
        cell,
        HttpRequest::new("POST", "/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body.into_bytes()),
    );
    assert_eq!(r.status, 200, "token: {}", text(&r));
    json(&r)
        .get("access_token")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned()
}

/// A modern MCP request of `method` with `params`, under `bearer`.
fn mcp(
    cell: &CellHandle,
    bearer: &str,
    method: &str,
    name: Option<&str>,
    params: &str,
) -> HttpReply {
    let sep = if params.is_empty() { "" } else { "," };
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{{{params}{sep}"_meta":{{"io.modelcontextprotocol/protocolVersion":"{MODERN}","io.modelcontextprotocol/clientInfo":{{"name":"synthetic-agent","version":"0.0.1"}},"io.modelcontextprotocol/clientCapabilities":{{}}}}}}}}"#
    );
    let mut r = HttpRequest::new("POST", "/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", MODERN)
        .header("mcp-method", method)
        .body(body.into_bytes());
    if !bearer.is_empty() {
        r = r.header("authorization", format!("Bearer {bearer}"));
    }
    if let Some(n) = name {
        r = r.header("mcp-name", n);
    }
    send(cell, r)
}

/// The connected agent of the first admin: the admin's session, its
/// access token, and the client.
fn connected<'w>(client: &AuthClient<'w>) -> (Cookie, String) {
    let cell = client.cell();
    assert!(client.enrol(FIRST_ADMIN).unwrap(), "the first admin enrols");
    let admin = client.admin_session().expect("the admin session");
    let agent = register(cell);
    let handle = authorize(cell, &agent);
    // The consent page's read names the client as unverified text and
    // no identity (I-86).
    let seen = web(
        cell,
        "GET",
        &format!("/api/v1/oauth/consents/{handle}"),
        &admin,
        "",
    );
    assert_eq!(
        seen.status,
        200,
        "the consent request read: {}",
        text(&seen)
    );
    assert!(text(&seen).contains("Synthetic agent"), "{}", text(&seen));
    // I-78: approving needs a passkey step-up bound to this request.
    let asked = web(
        cell,
        "POST",
        "/api/v1/oauth/consent",
        &admin,
        &format!(r#"{{"consent":"{handle}"}}"#),
    );
    assert_eq!(
        json(&asked).get("code").and_then(Value::as_str),
        Some("step_up_required"),
        "I-78: a consent without a step-up: {}",
        text(&asked)
    );
    let done = web_with_step_up(
        client,
        "POST",
        "/api/v1/oauth/consent",
        &admin,
        &format!(r#"{{"consent":"{handle}"}}"#),
    );
    assert_eq!(done.status, 200, "the consent: {}", text(&done));
    let to = text(&done);
    let code = to
        .split(['?', '&', '"'])
        .find_map(|p| p.strip_prefix("code="))
        .unwrap()
        .to_owned();
    assert!(to.contains("state=synthetic-state"), "{to}");
    (admin, redeem(cell, &agent, &code))
}

/// The agent prepares a programme draft: its pending id.
fn prepare(cell: &CellHandle, token: &str) -> String {
    let r = mcp(
        cell,
        token,
        "tools/call",
        Some("fstp_prepare_programme_draft"),
        r#""name":"fstp_prepare_programme_draft","arguments":{"name":"Synthetic programme"}"#,
    );
    assert_eq!(r.status, 200, "prepare: {}", text(&r));
    let path = text(&r)
        .split('"')
        .find(|s| s.starts_with("/app/pending/"))
        .unwrap_or_else(|| panic!("no confirm path: {}", text(&r)))
        .to_owned();
    path.trim_start_matches("/app/pending/").to_owned()
}

/// The admin's pending actions, as `pending.list` shows them.
fn pending(cell: &CellHandle, admin: &Cookie) -> Vec<Value> {
    let r = web(cell, "GET", "/api/v1/me/pending-actions", admin, "");
    assert_eq!(r.status, 200, "pending list: {}", text(&r));
    match json(&r) {
        Value::Array(a) => a.into_iter().collect(),
        other => other
            .get("actions")
            .and_then(Value::as_array)
            .map(|a| a.iter().cloned().collect())
            .unwrap_or_default(),
    }
}

fn programmes(cell: &CellHandle) -> usize {
    cell.cell_engine()
        .unwrap()
        .state()
        .engine()
        .creator
        .drafts()
        .count()
}

/// Production design section 4.1 steps 2 to 5 (R-MC-01, I-78, I-77, I-84,
/// I-85, I-24): connect, consent with a passkey step-up, list the tools,
/// prepare a draft that stays pending, and confirm it in the platform
/// with a fresh step-up. It executes once.
#[test]
fn prod_mcp_slice_connect_prepare_confirm_on_pg() {
    let world = world();
    let cell = world.cell(0).unwrap();
    let client = AuthClient::new(cell);
    // R-MC-01: no token names the resource metadata.
    let r = mcp(cell, "", "tools/list", None, "");
    assert_eq!(r.status, 401, "{}", text(&r));
    let (admin, token) = connected(&client);
    let listed = mcp(cell, &token, "tools/list", None, "");
    assert_eq!(listed.status, 200, "{}", text(&listed));
    assert!(
        text(&listed).contains("fstp_prepare_programme_draft"),
        "TH-63: {}",
        text(&listed)
    );
    let before = programmes(cell);
    let id = prepare(cell, &token);
    // I-85: nothing executed. The action waits for the admin.
    assert_eq!(programmes(cell), before, "I-85: the draft was opened");
    let open = pending(cell, &admin);
    let action = open
        .iter()
        .find(|a| a.get("id").and_then(Value::as_str) == Some(id.as_str()))
        .unwrap_or_else(|| panic!("the action is not listed: {open:?}"));
    assert_eq!(action.get("status").and_then(Value::as_str), Some("open"));
    let digest = action
        .get("digest")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    // I-78: the confirmation needs its own step-up for the stored digest.
    let path = format!("/api/v1/pending-actions/{id}/confirmation");
    let body = format!(r#"{{"shown":"{digest}"}}"#);
    let done = web_with_step_up(&client, "POST", &path, &admin, &body);
    assert_eq!(done.status, 200, "the confirmation: {}", text(&done));
    assert_eq!(programmes(cell), before + 1, "I-85: the draft opened once");
    // A second confirmation is refused and appends nothing.
    let again = web_with_step_up(&client, "POST", &path, &admin, &body);
    assert_ne!(again.status, 200, "I-85: {}", text(&again));
    assert_eq!(programmes(cell), before + 1, "I-85: the draft opened twice");
}

/// I-23, I-21, ADR-026: a pending action an agent prepared survives a
/// restart of the cell process: it is listed open afterwards, and its
/// stored request still executes once on confirmation. A sealed workspace
/// value in `workspace.drafts` opens to the same bytes after the restart.
#[test]
fn i23_restart_replays_pending_and_workspace() {
    let world = world();
    let cell = world.cell(0).unwrap();
    let client = AuthClient::new(cell);
    let (admin, token) = connected(&client);
    let id = prepare(cell, &token);
    let before = programmes(cell);
    let proposal = [0x9A; 16];
    let value = b"synthetic workspace value".to_vec();
    cell.with_running(async |c| {
        // F-017: the erasure task seals it under the proposal's own key.
        let sealed = c
            .erasure()
            .seal_workspace(proposal, value.clone())
            .await
            .unwrap();
        c.api_store()
            .unwrap()
            .put_workspace(proposal, "draft", &sealed, 1)
            .await
            .unwrap();
    })
    .unwrap();
    cell.restart().unwrap_or_else(|e| panic!("{e}"));
    cell.clock().advance(1);
    let reopened = cell
        .with_running(async |c| {
            let sealed = c
                .api_store()
                .unwrap()
                .workspace(proposal, "draft")
                .await
                .unwrap()
                .expect("I-23: the workspace row is lost");
            c.erasure()
                .open_workspace(proposal, sealed)
                .await
                .map(|t| t.to_vec())
                .unwrap_or_else(|_| panic!("I-23: the workspace value does not open"))
        })
        .unwrap();
    assert_eq!(reopened, value, "I-23: the workspace value");
    // The session survives the restart (`auth.session`).
    let open = pending(cell, &admin);
    let action = open
        .iter()
        .find(|a| a.get("id").and_then(Value::as_str) == Some(id.as_str()))
        .unwrap_or_else(|| panic!("I-23: the action is lost: {open:?}"));
    assert_eq!(action.get("status").and_then(Value::as_str), Some("open"));
    let digest = action
        .get("digest")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    let done = web_with_step_up(
        &client,
        "POST",
        &format!("/api/v1/pending-actions/{id}/confirmation"),
        &admin,
        &format!(r#"{{"shown":"{digest}"}}"#),
    );
    assert_eq!(done.status, 200, "I-23: {}", text(&done));
    assert_eq!(programmes(cell), before + 1);
}
