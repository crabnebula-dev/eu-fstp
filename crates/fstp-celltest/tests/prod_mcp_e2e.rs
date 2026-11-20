//! The definition of done of the production MCP design, section 4.1
//! (`docs/handoff/production-mcp-design.md`, lane L4, ADR-026).
//!
//! The production `fstp-cell` binary runs from its configuration file over
//! a local PostgreSQL cluster. The witness, the vault, the edge and two
//! `fstp-custody-sim --serve` processes come from the world
//! (`World::start_external`): one serves the cell's App chain, the other
//! the dedicated root of the cell key file. Proof mail goes through the
//! platform relay to the test SMTP sink. Every request goes through the
//! edge to the binary's tunnel listener, as a browser or an agent sends
//! it. An MCP client in Rust speaks the 2026-07-28 era, as Claude Code
//! 2.1.328 does (ADR-013 "Record of lane mcp-demo").
//!
//! The binary must be built first: `cargo build -p fstp-cell --bin
//! fstp-cell`. The CI part that runs this test builds it.
//!
//! Readings of lane L4, pending Daniel (ADR-026 "Configuration"):
//!
//! - Step 1: onboarding and activation through `/app` cannot run on a
//!   pilot cell. Its ledger holds no tenant part, since no control plane
//!   records `TenantProvisioned` (D1). The file sets
//!   `organisation_active`, so the ADR-021 port answers "active".
//! - Step 3: magic links are off on a production cell unless a tenant
//!   admin turns them on, so no magic-link session exists here. I-77 is
//!   covered on the PostgreSQL cell by lanes L1 and L2.
//! - Step 5: the binary's ledger keys stay in its own process, so this
//!   test does not read the App chain. I-24 per call is covered by
//!   `i24_every_api_call_leaves_one_chain_event` of lane L1.
//! - Step 7: `fstp-cell first-admin` names no login email, so the first
//!   admin cannot recover by email. A second tenant admin connects the
//!   agent, and the first admin approves its recovery.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::external_cell::ExternalSpec;
use fstp_celltest::mc::auth_model::RosterChange;
use fstp_celltest::mc::auth_model::http::{AuthClient, Cookie, FIRST_ADMIN};
use fstp_celltest::reference::auth::RefMethod;
use fstp_celltest::world::{
    CellHandle, DbMode, HttpReply, HttpRequest, VaultLayout, World, WorldSpec,
};
use fstp_celltest::world_host::{SimProcess, bin_path};
use fstp_domain_testkit::r#gen::roster::ADMIN_2;
use fstp_json::Value;

const REDIRECT: &str = "http://127.0.0.1:8765/callback";
const VERIFIER: &str = "l4-verifier-0123456789abcdefghijklmnopqrstuvwxyz";
const MODERN: &str = "2026-07-28";
const DRAFT: &str = "Synthetic production programme";

/// The processes of the run. The world drops first, so the cell drains
/// before its custody goes.
struct Stack {
    world: World,
    _custody: SimProcess,
    _key_file_custody: SimProcess,
    dir: std::path::PathBuf,
}

impl Drop for Stack {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn stack() -> Stack {
    let binary = bin_path("fstp-cell").unwrap_or_else(|e| {
        panic!("{e}: run `cargo build -p fstp-cell --bin fstp-cell` before this test")
    });
    let tag = fstp_crypto::random_array::<6>().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "fstp-l4-{}",
        tag.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let custody = SimProcess::spawn(0, &dir).unwrap_or_else(|e| panic!("{e}"));
    let key_file_custody = SimProcess::spawn(1, &dir).unwrap_or_else(|e| panic!("{e}"));
    let spec = ExternalSpec {
        binary,
        dir: dir.clone(),
        key_file_custody: key_file_custody.socket().to_path_buf(),
        assets_dir: None,
    };
    let world = World::start_external(
        WorldSpec {
            cells: 1,
            mode: DbMode::Shared,
            vault_layout: VaultLayout::SeparateCluster,
            self_hosted: false,
            process_mode: false,
        },
        custody.socket().to_path_buf(),
        &spec,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    Stack {
        world,
        _custody: custody,
        _key_file_custody: key_file_custody,
        dir,
    }
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
/// challenge with the software authenticator, then the same request once
/// more (`withStepUp`, I-78).
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
    assert_eq!(r.status, 201, "R-MC-01: registration: {}", text(&r));
    json(&r)
        .get("client_id")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned()
}

/// `/oauth/authorize` with PKCE `S256` and `resource`: the consent handle
/// of the 303 to the consent page.
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
    assert_eq!(r.status, 303, "R-MC-01: authorize: {}", text(&r));
    let to = String::from_utf8(r.header("location").unwrap().to_vec()).unwrap();
    to.strip_prefix("/app/connect#").unwrap().to_owned()
}

/// The access and refresh tokens of a token call with `form`.
fn token_call(cell: &CellHandle, form: &[(&str, &str)]) -> HttpReply {
    send(
        cell,
        HttpRequest::new("POST", "/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(fstp_oauth::encode_form_urlencoded(form).into_bytes()),
    )
}

fn tokens(r: &HttpReply) -> (String, String) {
    assert_eq!(r.status, 200, "token: {}", text(r));
    let v = json(r);
    let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap().to_owned();
    (s("access_token"), s("refresh_token"))
}

/// Steps 2 and 3 for the session `admin`: register, authorize, consent
/// with a passkey step-up, and redeem the code. The client id and the
/// access and refresh tokens.
fn connect(client: &AuthClient<'_>, admin: &Cookie) -> (String, String, String) {
    let cell = client.cell();
    let agent = register(cell);
    let handle = authorize(cell, &agent);
    let seen = web(
        cell,
        "GET",
        &format!("/api/v1/oauth/consents/{handle}"),
        admin,
        "",
    );
    assert_eq!(seen.status, 200, "the consent read: {}", text(&seen));
    // I-78: approving without a step-up is refused.
    let body = format!(r#"{{"consent":"{handle}"}}"#);
    let asked = web(cell, "POST", "/api/v1/oauth/consent", admin, &body);
    assert_eq!(
        json(&asked).get("code").and_then(Value::as_str),
        Some("step_up_required"),
        "I-78: a consent without a step-up: {}",
        text(&asked)
    );
    let done = web_with_step_up(client, "POST", "/api/v1/oauth/consent", admin, &body);
    assert_eq!(done.status, 200, "the consent: {}", text(&done));
    let to = text(&done);
    let code = to
        .split(['?', '&', '"'])
        .find_map(|p| p.strip_prefix("code="))
        .unwrap()
        .to_owned();
    assert!(to.contains("state=synthetic-state"), "{to}");
    assert!(to.contains("iss="), "RFC 9207: no iss: {to}");
    let resource = format!("https://{}/mcp", cell.host());
    let (access, refresh) = tokens(&token_call(
        cell,
        &[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("client_id", agent.as_str()),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
            ("resource", resource.as_str()),
        ],
    ));
    (agent, access, refresh)
}

fn refresh(cell: &CellHandle, agent: &str, refresh: &str) -> HttpReply {
    let resource = format!("https://{}/mcp", cell.host());
    token_call(
        cell,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", agent),
            ("resource", resource.as_str()),
        ],
    )
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

fn list_programmes(cell: &CellHandle, token: &str) -> String {
    let r = mcp(
        cell,
        token,
        "tools/call",
        Some("fstp_creator_list_programmes"),
        r#""name":"fstp_creator_list_programmes","arguments":{}"#,
    );
    assert_eq!(r.status, 200, "list programmes: {}", text(&r));
    text(&r)
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

fn action(cell: &CellHandle, admin: &Cookie, id: &str) -> Value {
    let open = pending(cell, admin);
    open.into_iter()
        .find(|a| a.get("id").and_then(Value::as_str) == Some(id))
        .unwrap_or_else(|| panic!("the action {id} is not listed"))
}

/// Production MCP design section 4.1, steps 1 to 7, over the `fstp-cell`
/// binary started from its configuration file (G1, G8, G10, G11).
///
/// 1. Start (ADR-026, D4): the binary reaches `ready` from the file, after
///    `fstp-cell first-admin` wrote the token halves. The first admin
///    enrols a passkey through the invitation, and invites a second tenant
///    admin.
/// 2. Connect (R-MC-01): `/mcp` without a token is 401 naming the
///    resource metadata. Both metadata documents read. Registration and
///    `/oauth/authorize` with PKCE `S256` answer.
/// 3. Consent with a passkey (I-78): a consent without a step-up is
///    refused, one with a step-up redirects with `code`, `state` and
///    `iss`, and the code redeems.
/// 4. Prepare (I-85, I-84): `tools/list` lists the prepare tool, and its
///    call answers a pending action. No programme exists yet.
/// 5. Confirm (I-85, I-78): the same account confirms with a fresh step-up
///    bound to the stored digest. The draft exists. A second confirmation
///    is refused.
/// 6. Restart (I-23): SIGTERM drains the binary, which starts again from
///    the same file with a new ledger key generation (ADR-004 record of
///    L4). The refresh token rotates, which needs the client's sealed
///    metadata text from before the restart to open (ADR-013 L2 reading
///    "Client metadata"). The draft is listed, and the pending action is
///    no longer open.
/// 7. Recovery revokes the agent (I-79, H-21): the account recovers on
///    the second-admin path, with the email proofs through the platform
///    relay (D3). The old access token gets 401, the old refresh token
///    `invalid_grant`, and a new consent with the new passkey works.
#[test]
fn prod_mcp_e2e_binary_from_config_file() {
    let stack = stack();
    let cell = stack.world.cell(0).unwrap();
    let ext = cell.external().expect("an external cell");
    assert_eq!(ext.starts(), 1);
    let client = AuthClient::new(cell);

    // Step 1.
    assert!(client.enrol(FIRST_ADMIN).unwrap(), "the first admin enrols");
    assert!(client.enrol(ADMIN_2).unwrap(), "the second admin enrols");
    let admin1 = client.admin_session().expect("the first admin's session");
    assert!(
        client
            .roster(&admin1, RosterChange::GrantAdmin { account: ADMIN_2 })
            .unwrap(),
        "the tenant admin grant to the second admin"
    );
    let admin2 = client
        .login(ADMIN_2, RefMethod::Passkey)
        .unwrap()
        .expect("the second admin's session");

    // Step 2.
    let r = mcp(cell, "", "tools/list", None, "");
    assert_eq!(r.status, 401, "R-MC-01: {}", text(&r));
    let challenge = String::from_utf8_lossy(r.header("www-authenticate").unwrap()).into_owned();
    assert!(challenge.contains("resource_metadata"), "{challenge}");
    for doc in [
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-authorization-server",
    ] {
        let r = send(cell, HttpRequest::new("GET", doc));
        assert_eq!(r.status, 200, "R-MC-01: {doc}: {}", text(&r));
    }

    // Step 3.
    let (agent, access, refresh_token) = connect(&client, &admin2);

    // Step 4.
    let listed = mcp(cell, &access, "tools/list", None, "");
    assert_eq!(listed.status, 200, "{}", text(&listed));
    assert!(
        text(&listed).contains("fstp_prepare_programme_draft"),
        "TH-63: {}",
        text(&listed)
    );
    let prepared = mcp(
        cell,
        &access,
        "tools/call",
        Some("fstp_prepare_programme_draft"),
        &format!(r#""name":"fstp_prepare_programme_draft","arguments":{{"name":"{DRAFT}"}}"#),
    );
    assert_eq!(prepared.status, 200, "prepare: {}", text(&prepared));
    let id = text(&prepared)
        .split('"')
        .find(|s| s.starts_with("/app/pending/"))
        .unwrap_or_else(|| panic!("no confirm path: {}", text(&prepared)))
        .trim_start_matches("/app/pending/")
        .to_owned();
    let before = list_programmes(cell, &access);
    assert!(
        before.contains(r#""programmes":[]"#),
        "I-85: a draft opened before a confirmation: {before}"
    );

    // Step 5.
    let open = action(cell, &admin2, &id);
    assert_eq!(open.get("status").and_then(Value::as_str), Some("open"));
    let digest = open
        .get("digest")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    let path = format!("/api/v1/pending-actions/{id}/confirmation");
    let body = format!(r#"{{"shown":"{digest}"}}"#);
    let done = web_with_step_up(&client, "POST", &path, &admin2, &body);
    assert_eq!(done.status, 200, "I-85: the confirmation: {}", text(&done));
    let programme = json(&done)
        .get("programme")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no programme: {}", text(&done)))
        .to_owned();
    let listed = list_programmes(cell, &access);
    assert!(
        listed.contains(&programme),
        "I-85: the confirmed draft is not listed: {listed}"
    );
    let again = web_with_step_up(&client, "POST", &path, &admin2, &body);
    assert_ne!(again.status, 200, "I-85: confirmed twice: {}", text(&again));

    // Step 6.
    ext.stop()
        .unwrap_or_else(|e| panic!("I-23: the drain: {e}"));
    ext.start()
        .unwrap_or_else(|e| panic!("I-23: the second start: {e}"));
    assert_eq!(ext.starts(), 2);
    let (access, refresh_token) = tokens(&refresh(cell, &agent, &refresh_token));
    let listed = list_programmes(cell, &access);
    assert!(
        listed.contains(&programme),
        "I-23: the draft is lost after the restart: {listed}"
    );
    let after = action(cell, &admin2, &id);
    assert_ne!(
        after.get("status").and_then(Value::as_str),
        Some("open"),
        "I-23: the confirmed action shows open again"
    );

    // Step 7.
    let case = client
        .recovery(ADMIN_2)
        .unwrap()
        .expect("I-79: no recovery proof reached the relay");
    assert!(client.recovery_email(&case).unwrap(), "the email proof");
    let admin1 = client
        .login(FIRST_ADMIN, RefMethod::Passkey)
        .unwrap()
        .expect("the first admin's session");
    assert!(
        client.recovery_approve(&case, &admin1, true).unwrap(),
        "I-79: the second-admin approval with a step-up"
    );
    let fresh = client
        .recovery_complete(&case)
        .unwrap()
        .expect("I-79: the approved recovery did not complete");
    let r = mcp(cell, &access, "tools/list", None, "");
    assert_eq!(
        r.status,
        401,
        "H-21: the old access token works: {}",
        text(&r)
    );
    let r = refresh(cell, &agent, &refresh_token);
    assert_eq!(
        r.status,
        400,
        "H-21: the old refresh token works: {}",
        text(&r)
    );
    assert!(text(&r).contains("invalid_grant"), "{}", text(&r));
    let (_, access, _) = connect(&client, &fresh);
    let r = mcp(cell, &access, "tools/list", None, "");
    assert_eq!(r.status, 200, "a new consent after recovery: {}", text(&r));
}
