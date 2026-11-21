//! I-84 audit parity on the production cell over PostgreSQL (ADR-010
//! amendment of 2026-11-20, ADR-026, production design section 3.3, lane
//! L7). The property of `fstp-api-testkit`'s `i84_audit_parity.rs`, run
//! through the cell's own HTTP listener and read back from the App chain.
//!
//! Every account and text is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::cycle::Cycle;
use fstp_celltest::mc::auth_model::http::{AuthClient, Cookie};
use fstp_celltest::world::{
    CellHandle, DbMode, HttpReply, HttpRequest, VaultLayout, World, WorldSpec,
};
use fstp_json::{Object, Value};

const REDIRECT: &str = "http://127.0.0.1:8765/callback";
const VERIFIER: &str = "l7-verifier-0123456789abcdefghijklmnopqrstuvwxyz";
const MODERN: &str = "2026-07-28";

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

/// `web`, with the step-up it asks proved.
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
    assert!(client.prove_api_step_up(cookie, id, challenge).unwrap());
    web(cell, method, path, cookie, body)
}

/// A modern MCP `tools/call` of `name` with `arguments`, under `bearer`.
fn mcp_call(cell: &CellHandle, bearer: &str, name: &str, arguments: &str) -> HttpReply {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{name}","arguments":{arguments},"_meta":{{"io.modelcontextprotocol/protocolVersion":"{MODERN}","io.modelcontextprotocol/clientInfo":{{"name":"synthetic-agent","version":"0.0.1"}},"io.modelcontextprotocol/clientCapabilities":{{}}}}}}}}"#
    );
    send(
        cell,
        HttpRequest::new("POST", "/mcp")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", MODERN)
            .header("mcp-method", "tools/call")
            .header("mcp-name", name)
            .header("authorization", format!("Bearer {bearer}"))
            .body(body.into_bytes()),
    )
}

/// The first admin's agent: registered, consented in a passkey session
/// with a step-up, its code redeemed. The access token.
fn agent_token(client: &AuthClient<'_>, admin: &Cookie) -> String {
    let cell = client.cell();
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
    let agent = json(&r)
        .get("client_id")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    let challenge = fstp_oauth::encode_base64url(&fstp_crypto::sha256(VERIFIER.as_bytes()));
    let resource = format!("https://{}/mcp", cell.host());
    let scopes: Vec<&str> = fstp_access::Scope::ALL.iter().map(|s| s.as_str()).collect();
    let scopes = scopes.join(" ");
    let q = fstp_oauth::encode_form_urlencoded(&[
        ("response_type", "code"),
        ("client_id", agent.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("scope", scopes.as_str()),
        ("state", "synthetic-state"),
        ("resource", resource.as_str()),
    ]);
    let r = send(
        cell,
        HttpRequest::new("GET", &format!("/oauth/authorize?{q}")),
    );
    assert_eq!(r.status, 303, "authorize: {}", text(&r));
    let to = String::from_utf8(r.header("location").unwrap().to_vec()).unwrap();
    let handle = to.strip_prefix("/app/connect#").unwrap().to_owned();
    let done = web_with_step_up(
        client,
        "POST",
        "/api/v1/oauth/consent",
        admin,
        &format!(r#"{{"consent":"{handle}"}}"#),
    );
    assert_eq!(done.status, 200, "the consent: {}", text(&done));
    let to = text(&done);
    let code = to
        .split(['?', '&', '"'])
        .find_map(|p| p.strip_prefix("code="))
        .unwrap()
        .to_owned();
    let form = fstp_oauth::encode_form_urlencoded(&[
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("client_id", agent.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("resource", resource.as_str()),
    ]);
    let r = send(
        cell,
        HttpRequest::new("POST", "/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form.into_bytes()),
    );
    assert_eq!(r.status, 200, "token: {}", text(&r));
    json(&r)
        .get("access_token")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned()
}

/// The opened bodies of the App chain's kind 2 events, in row order.
fn events(cell: &CellHandle) -> Vec<Object> {
    let id = cell.id();
    cell.with_running(async |c| {
        let rows = c.chain_rows().await.unwrap();
        rows.rows
            .iter()
            .filter_map(|r| match &r.row.kind {
                fstp_audit::RowKind::Event { body } => {
                    let plain = fstp_pgstore::open_event_body(c.ledger_keys(), &id, r.row.n, body)
                        .unwrap_or_else(|e| panic!("the event of row {}: {e:?}", r.row.n));
                    match fstp_json::parse(&plain).unwrap() {
                        Value::Object(o) => Some(o),
                        other => panic!("an event body that is no object: {other:?}"),
                    }
                }
                fstp_audit::RowKind::Ledger { .. } => None,
            })
            .collect()
    })
    .unwrap()
}

/// The one API call event appended by `call` (I-24).
fn one_event(
    cell: &CellHandle,
    what: &str,
    call: impl FnOnce() -> HttpReply,
) -> (Object, HttpReply) {
    let before = events(cell).len();
    let reply = call();
    let after = events(cell);
    let new: Vec<&Object> = after
        .iter()
        .skip(before)
        .filter(|o| o.get("kind").and_then(Value::as_str) == Some("api_call"))
        .collect();
    assert_eq!(
        new.len(),
        1,
        "I-24: {what} left {} API call events: {new:?}",
        new.len()
    );
    (new[0].clone(), reply)
}

/// An event without the members that name the channel.
fn modulo_channel(e: &Object) -> Object {
    let mut o = e.clone();
    let _ = o.remove("via");
    let _ = o.remove("agent");
    o
}

/// I-84, I-24, R-AU-01, ADR-010 amendment of 2026-11-20: the same
/// operation through the web and through MCP leaves equivalent audit
/// events on the App chain of the production cell.
///
/// The first admin of a cell with the cycle's programme P calls each
/// operation of a fixed menu once in a passkey session and once through
/// its own agent's token, with the same arguments. The menu holds reads
/// that are accepted and calls that are refused, none of them high-risk
/// and none binding, so channel policy changes no outcome. Each call
/// appends exactly one API call event, read back from the chain and
/// opened with the cell's ledger keys. With `via` and `agent` removed the
/// two events are equal: actor, operation, outcome, rule, request digest
/// and step-up. The web event says `web` and names no agent. The MCP
/// event says `mcp` and names the agent client that `agents.list` shows
/// for the admin.
#[test]
fn i84_audit_parity_on_pg() {
    let world = World::start_with_api(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("{e}"));
    let cell = world.cell(0).unwrap();
    let mut cycle = Cycle::new(cell);
    for step in ["login", "create-programme"] {
        cycle
            .step(step)
            .unwrap_or_else(|e| panic!("the cycle step {step}: {e}"));
    }
    let client = cycle.into_client();
    let admin = client.admin_session().expect("the admin session");
    let token = agent_token(&client, &admin);
    // The admin's agent client, as `agents.list` shows it.
    let listed = web(cell, "GET", "/api/v1/me/agents", &admin, "");
    assert_eq!(listed.status, 200, "agents.list: {}", text(&listed));
    let listed = text(&listed);
    let p = fstp_domain_testkit::r#gen::roster::P1.raw();
    // (operation, web path, tool, arguments, accepted)
    let menu: [(&str, String, &str, String, bool); 4] = [
        (
            "calls.list_open",
            "/api/v1/calls".to_owned(),
            "fstp_list_open_calls",
            "{}".to_owned(),
            true,
        ),
        (
            "creator.get_draft",
            format!("/api/v1/programmes/{p}/draft"),
            "fstp_creator_get_draft",
            format!(r#"{{"programme":"{p}"}}"#),
            true,
        ),
        (
            "proposal.view",
            "/api/v1/proposals/987654321".to_owned(),
            "fstp_get_my_proposal",
            r#"{"proposal":"987654321"}"#.to_owned(),
            false,
        ),
        (
            "creator.get_draft",
            "/api/v1/programmes/987654321/draft".to_owned(),
            "fstp_creator_get_draft",
            r#"{"programme":"987654321"}"#.to_owned(),
            false,
        ),
    ];
    let mut agents = std::collections::BTreeSet::new();
    for (op, path, tool, args, accepted) in &menu {
        let (w, wr) = one_event(cell, &format!("the web {op}"), || {
            web(cell, "GET", path, &admin, "")
        });
        let (m, mr) = one_event(cell, &format!("the MCP {op}"), || {
            mcp_call(cell, &token, tool, args)
        });
        assert_eq!(mr.status, 200, "the MCP {op}: {}", text(&mr));
        let outcome = w.get("outcome").and_then(Value::as_str);
        assert_eq!(
            outcome,
            Some(if *accepted { "accepted" } else { "refused" }),
            "the web {op}: {} {} {w:?}",
            wr.status,
            text(&wr)
        );
        assert_eq!(w.get("op").and_then(Value::as_str), Some(*op));
        assert_eq!(
            modulo_channel(&w),
            modulo_channel(&m),
            "I-84: the audit events of {op} differ beyond the channel"
        );
        assert_eq!(w.get("via").and_then(Value::as_str), Some("web"), "{w:?}");
        assert_eq!(w.get("agent"), Some(&Value::Null), "I-84: {w:?}");
        assert_eq!(m.get("via").and_then(Value::as_str), Some("mcp"), "{m:?}");
        let agent = m
            .get("agent")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("I-84: the MCP event names no agent: {m:?}"))
            .to_owned();
        assert!(
            listed.contains(&format!(r#""client":"{agent}""#)),
            "I-84: the MCP event names {agent}, which agents.list does not show: {listed}"
        );
        agents.insert(agent);
    }
    assert_eq!(agents.len(), 1, "I-84: one agent named {agents:?}");
}
