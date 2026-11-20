//! The MCP connector demo end to end, over HTTP against the running test
//! cell (lane mcp-demo, ADR-013, R-MC-03, I-78, I-84, I-85, I-86).
//!
//! Each test starts the cell's listeners on loopback, as the binary does,
//! and drives them as an MCP client and a browser would: discovery
//! through the 401 challenge and the two metadata documents, dynamic
//! registration, `/oauth/authorize` with PKCE `S256`, the consent page,
//! the demo sign-in and the demo step-up, the token endpoint, then
//! `/mcp`. Every account and text is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use fstp_domain_testkit::r#gen::roster::STAFF_PM;
use fstp_json::Value;

use super::*;

/// The redirect URI of the synthetic agent: a loopback callback, as a
/// native client registers it (RFC 8252).
const REDIRECT: &str = "http://localhost:49152/callback";

/// The PKCE verifier of the synthetic agent.
const VERIFIER: &str = "mcp-demo-verifier-0123456789abcdefghijklmnopqrstuvwxyz";

/// The pinned MCP revision.
const MODERN: &str = "2026-07-28";

/// One HTTP reply: status, header block and body.
struct Reply {
    status: u16,
    head: String,
    body: String,
}

impl Reply {
    /// The value of header `name`, case-insensitively.
    fn header(&self, name: &str) -> Option<String> {
        let want = format!("{}:", name.to_ascii_lowercase());
        self.head.split("\r\n").find_map(|l| {
            l.to_ascii_lowercase()
                .starts_with(&want)
                .then(|| l[want.len()..].trim().to_owned())
        })
    }

    /// The body as JSON.
    fn json(&self) -> Value {
        fstp_json::parse_str(self.body.trim())
            .unwrap_or_else(|e| panic!("{e:?}: {} {}", self.status, self.body))
    }
}

/// The client of one cell origin listener.
struct Client {
    addr: String,
    host: String,
    origin: String,
}

impl Client {
    fn of(running: &Running, i: usize) -> Client {
        let site = &running.sites[i];

        Client {
            addr: running.cell_addrs[i].to_string(),
            host: site.info.host.clone(),
            origin: site.info.origin.clone(),
        }
    }

    /// `method path` with `fields` and `body`.
    fn send(&self, method: &str, path: &str, fields: &[(&str, &str)], body: &str) -> Reply {
        let mut s = TcpStream::connect(&self.addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\n", self.host);
        for (k, v) in fields {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ));
        s.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let status = head
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        Reply {
            status,
            head: head.to_owned(),
            body: body.to_owned(),
        }
    }

    /// A form post of the cell's own pages, with the session `cookie`.
    fn form(&self, path: &str, cookie: &str, pairs: &[(&str, &str)]) -> Reply {
        let body = fstp_oauth::encode_form_urlencoded(pairs);
        let mut fields = vec![
            ("Origin", self.origin.as_str()),
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Sec-Fetch-Site", "same-origin"),
        ];
        if !cookie.is_empty() {
            fields.push(("Cookie", cookie));
        }
        self.send("POST", path, &fields, &body)
    }

    /// A modern MCP request of `method` with `params` and `bearer`.
    fn mcp(&self, bearer: &str, method: &str, name: Option<&str>, params: &str) -> Reply {
        let sep = if params.is_empty() { "" } else { "," };
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{{{params}{sep}"_meta":{{"io.modelcontextprotocol/protocolVersion":"{MODERN}","io.modelcontextprotocol/clientInfo":{{"name":"synthetic-agent","version":"0.0.1"}},"io.modelcontextprotocol/clientCapabilities":{{}}}}}}}}"#
        );
        let auth = format!("Bearer {bearer}");
        let mut fields = vec![
            ("Content-Type", "application/json"),
            ("Accept", "application/json, text/event-stream"),
            ("MCP-Protocol-Version", MODERN),
            ("Mcp-Method", method),
        ];
        if !bearer.is_empty() {
            fields.push(("Authorization", auth.as_str()));
        }
        if let Some(n) = name {
            fields.push(("Mcp-Name", n));
        }
        self.send("POST", "/mcp", &fields, &body)
    }

    /// A modern `tools/call` of `tool` with `arguments`: its result.
    fn call(&self, bearer: &str, tool: &str, arguments: &str) -> Value {
        let r = self.mcp(
            bearer,
            "tools/call",
            Some(tool),
            &format!(r#""name":"{tool}","arguments":{arguments}"#),
        );
        assert_eq!(r.status, 200, "{tool}: {}", r.body);
        r.json()
            .get("result")
            .cloned()
            .unwrap_or_else(|| panic!("{tool}: no result: {}", r.body))
    }
}

/// The value of the hidden input `name` of an HTML form.
fn hidden(html: &str, name: &str) -> String {
    let at = format!("name=\"{name}\" value=\"");
    let start = html
        .find(&at)
        .unwrap_or_else(|| panic!("no {name}: {html}"))
        .saturating_add(at.len());
    let len = html[start..].find('"').unwrap();
    html[start..].get(..len).unwrap().to_owned()
}

/// The query parameter `k` of URL `url`.
fn param(url: &str, k: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    let f = fstp_oauth::decode_form_urlencoded(q.as_bytes()).ok()?;
    f.get(k).map(str::to_owned)
}

/// Seeds `scene` at the control base of `site`: its JSON reply.
fn seed(site: &Site, path: &str, body: &str) -> Value {
    let control = site.info.control.trim_start_matches("http://").to_owned();
    let c = Client {
        addr: control.clone(),
        host: control,
        origin: String::new(),
    };
    let r = c.send("POST", path, &[("Content-Type", "application/json")], body);
    assert_eq!(r.status, 200, "{path}: {}", r.body);
    r.json()
}

/// The demo sign-in of `account`: the session cookie the cell sets, as
/// the "Sign in as" link of the demo page and its page script give it.
fn demo_sign_in(site: &Site, c: &Client, account: fstp_domain::id::AccountId) -> String {
    let link = demo_signin::link(&site.info, &site.inner(), account).unwrap();
    let token = link.split_once('#').unwrap().1.to_owned();
    let r = c.send(
        "POST",
        "/auth/demo-signin",
        &[
            ("Origin", c.origin.as_str()),
            ("X-FSTP-Request", "1"),
            ("Content-Type", "application/json"),
        ],
        &format!(r#"{{"token":"{token}"}}"#),
    );
    assert_eq!(r.status, 200, "demo sign-in: {}", r.body);
    let set = r.header("set-cookie").unwrap();
    set.split(';').next().unwrap().to_owned()
}

/// What the synthetic agent holds after discovery and registration.
struct Agent {
    client_id: String,
    authorize: String,
    token: String,
    resource: String,
}

/// R-MC-03, ADR-013 "Metadata", RFC 9728, RFC 8414, RFC 7591: the agent
/// finds the cell's authorisation server from the 401 challenge of
/// `/mcp`, reads both metadata documents, and registers.
fn discover_and_register(c: &Client) -> Agent {
    let first = c.mcp("", "server/discover", None, "");
    assert_eq!(first.status, 401, "{}", first.body);
    let challenge = first.header("www-authenticate").unwrap();
    let prm_url = format!("{}/.well-known/oauth-protected-resource", c.origin);
    assert!(
        challenge.contains(&format!("resource_metadata=\"{prm_url}\"")),
        "{challenge}"
    );
    let prm = c
        .send("GET", "/.well-known/oauth-protected-resource", &[], "")
        .json();
    // RFC 9728 section 3.1: the path form, where a client looks first
    // when no challenge named the document, answers the same.
    let pathed = c.send("GET", "/.well-known/oauth-protected-resource/mcp", &[], "");
    assert_eq!(pathed.json().to_compact(), prm.to_compact());
    let resource = prm
        .get("resource")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    assert_eq!(resource, format!("{}/mcp", c.origin));
    let issuer = prm
        .get("authorization_servers")
        .and_then(Value::as_array)
        .and_then(|a| a.iter().next())
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    assert_eq!(issuer, c.origin);
    let asm = c
        .send("GET", "/.well-known/oauth-authorization-server", &[], "")
        .json();
    let url = |k: &str| asm.get(k).and_then(Value::as_str).unwrap().to_owned();
    assert_eq!(url("issuer"), c.origin);
    let path = |u: String| u.strip_prefix(&c.origin).unwrap().to_owned();
    let register = path(url("registration_endpoint"));
    let reg = c.send(
        "POST",
        &register,
        &[("Content-Type", "application/json")],
        &format!(
            r#"{{"client_name":"Synthetic agent","redirect_uris":["{REDIRECT}"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}}"#
        ),
    );
    assert_eq!(reg.status, 201, "{}", reg.body);
    Agent {
        client_id: reg
            .json()
            .get("client_id")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned(),
        authorize: path(url("authorization_endpoint")),
        token: path(url("token_endpoint")),
        resource,
    }
}

/// `GET /oauth/authorize` of `agent` with PKCE `S256` and `scope`.
fn authorize(c: &Client, agent: &Agent, scope: &str) -> Reply {
    let challenge = fstp_oauth::encode_base64url(&fstp_crypto::sha256(VERIFIER.as_bytes()));
    let q = fstp_oauth::encode_form_urlencoded(&[
        ("response_type", "code"),
        ("client_id", agent.client_id.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("scope", scope),
        ("state", "synthetic-state"),
        ("resource", agent.resource.as_str()),
    ]);
    c.send("GET", &format!("{}?{q}", agent.authorize), &[], "")
}

/// The consent of `agent` approved by the demo session `cookie` with the
/// demo step-up: the redirect to the agent, with the code.
fn consent_with_demo_step_up(c: &Client, agent: &Agent, cookie: &str, scope: &str) -> String {
    let page = authorize(c, agent, scope);
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("Synthetic agent"), "{}", page.body);
    assert!(page.body.contains("unverified"), "{}", page.body);
    assert!(page.body.contains("localhost"), "the redirect host");
    assert!(
        !page.body.contains("<script"),
        "the consent page runs no script"
    );
    let handle = hidden(&page.body, "consent");
    // I-78: approving asks for a step-up; a demo session confirms it with
    // a plain button.
    let asked = c.form(
        oauth::CONSENT_ROUTE,
        cookie,
        &[("consent", &handle), ("decision", "approve")],
    );
    assert_eq!(asked.status, 200, "{}", asked.body);
    assert!(
        asked.body.contains("data-oauth=\"confirm\""),
        "{}",
        asked.body
    );
    let challenge = hidden(&asked.body, "challenge");
    let done = c.form(
        oauth::CONFIRM_ROUTE,
        cookie,
        &[("consent", &handle), ("challenge", &challenge)],
    );
    assert_eq!(done.status, 303, "{}", done.body);
    let to = done.header("location").unwrap();
    assert!(to.starts_with(REDIRECT), "{to}");
    assert_eq!(param(&to, "state").as_deref(), Some("synthetic-state"));
    assert_eq!(param(&to, "iss").as_deref(), Some(c.origin.as_str()));
    to
}

/// The access token for the code that `to` carries.
fn redeem(c: &Client, agent: &Agent, to: &str) -> String {
    let code = param(to, "code").unwrap();
    let body = fstp_oauth::encode_form_urlencoded(&[
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("client_id", agent.client_id.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("resource", agent.resource.as_str()),
    ]);
    let r = c.send(
        "POST",
        &agent.token,
        &[("Content-Type", "application/x-www-form-urlencoded")],
        &body,
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let v = r.json();
    assert!(v.get("refresh_token").is_some());
    v.get("access_token")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned()
}

/// The tool names of a `tools/list` reply.
fn tool_names(r: &Reply) -> Vec<String> {
    r.json()
        .get("result")
        .and_then(|v| v.get("tools"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|t| t.get("name").and_then(Value::as_str).map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The `structuredContent` of a tool result.
fn structured(v: &Value) -> Value {
    v.get("structuredContent")
        .cloned()
        .unwrap_or_else(|| panic!("no structuredContent: {}", v.to_compact()))
}

/// The whole flow on a cell of `cfg`, whose cell `a` origin the agent
/// uses as it is served.
fn connector_flow(cfg: &Config) {
    let running = start(cfg).unwrap_or_else(|e| panic!("{e}"));
    let site = &running.sites[0];
    let c = Client::of(&running, 0);
    // An active programme whose second call is approved and not yet
    // published, with programme manager M1.
    let _ = seed(site, "/test/scenario/applicant", r#"{"at":"OPEN_CALL"}"#);
    let agent = discover_and_register(&c);
    let cookie = demo_sign_in(site, &c, STAFF_PM);
    let to = consent_with_demo_step_up(&c, &agent, &cookie, "calls:read calls:draft creator:draft");
    let token = redeem(&c, &agent, &to);

    // ADR-013 record of lane mcp-demo: the modern probe now succeeds.
    let found = c.mcp(&token, "server/discover", None, "");
    assert_eq!(found.status, 200, "{}", found.body);

    // TH-63, I-84: the tools of M1's roles and the token's scopes.
    let listed = c.mcp(&token, "tools/list", None, "");
    assert_eq!(listed.status, 200, "{}", listed.body);
    let names = tool_names(&listed);
    for t in [
        "fstp_creator_get_draft",
        "fstp_creator_save_fields",
        "fstp_draft_call",
        "fstp_edit_call",
        "fstp_prepare_call_publication",
    ] {
        assert!(names.iter().any(|n| n == t), "{t} not in {names:?}");
    }

    // A creator read goes through the API core and answers a tool result.
    let draft = c.call(&token, "fstp_creator_get_draft", r#"{"programme":"1"}"#);
    let _ = structured(&draft);

    // I-85: the publication is prepared, not completed. It waits in the
    // platform for M1's confirmation with a step-up.
    let prepared = c.call(&token, "fstp_prepare_call_publication", r#"{"call":"2"}"#);
    let data = structured(&prepared)
        .get("data")
        .cloned()
        .unwrap_or_else(|| panic!("{}", prepared.to_compact()));
    assert_eq!(
        data.get("status").and_then(Value::as_str),
        Some("awaiting_confirmation"),
        "{}",
        prepared.to_compact()
    );
    // The web UI's page for the pending action, where M1 confirms it.
    assert!(
        data.get("confirm_path")
            .and_then(Value::as_str)
            .is_some_and(|p| p.starts_with("/app/pending/")),
        "{}",
        prepared.to_compact()
    );
    let pending = c.send(
        "GET",
        "/api/v1/me/pending-actions",
        &[("Cookie", cookie.as_str()), ("Accept", "application/json")],
        "",
    );
    assert_eq!(pending.status, 200, "{}", pending.body);
    assert!(
        pending.body.contains("\"op\":\"call.publish\"")
            && pending.body.contains("\"status\":\"open\""),
        "the prepared publication waits: {}",
        pending.body
    );
    let open = c.send(
        "GET",
        "/api/v1/calls",
        &[("Accept", "application/json")],
        "",
    );
    assert!(
        !open.body.contains("SuperSAFE open call 2027"),
        "I-85: call 2 is not published: {}",
        open.body
    );

    // I-86: no MCP answer names the demo person's identity.
    for r in [&found.body, &listed.body] {
        assert!(!r.contains("@e2e.invalid"), "{r}");
    }

    // R-MC-03: a new scene ends every grant, and keeps the registration.
    let _ = seed(site, "/test/scenario/setup", "{}");
    let after = c.mcp(&token, "tools/list", None, "");
    assert_eq!(after.status, 401, "{}", after.body);
    let again = authorize(&c, &agent, "creator:draft");
    assert_eq!(
        again.status, 200,
        "the client stays registered: {}",
        again.body
    );
}

/// R-MC-03, I-78, I-84, I-85, ADR-013 (lane mcp-demo): the connector flow
/// end to end on the cell's own loopback origin.
#[test]
fn r_mc_03_i85_connector_flow_end_to_end() {
    connector_flow(&Config {
        demo_signin: true,
        ..Config::loopback()
    });
}

/// R-MC-03, ADR-013 (lane mcp-demo): with `--public-origin`, as behind
/// an HTTPS tunnel, the challenge, both metadata documents, the issuer,
/// the resource and the `Origin` rule name the public origin, and the
/// whole flow works through it.
#[test]
fn r_mc_03_connector_flow_behind_a_public_origin() {
    connector_flow(&Config {
        demo_signin: true,
        public_origin: Some(public_origin("https://demo-tunnel.example").unwrap()),
        ..Config::loopback()
    });
    // Only https, or http on loopback, is admitted as a public origin.
    assert!(public_origin("http://demo-tunnel.example").is_err());
    assert!(public_origin("https://demo-tunnel.example/path").is_err());
    assert!(public_origin("http://127.0.0.1:8640").is_ok());
    assert!(public_origin("http://localhost:8640").is_ok());
}

/// R-MC-03, ADR-013 (lane mcp-demo): Claude Code 2.1.328 sends no
/// credential to a plain `http` token endpoint unless its host is
/// `localhost`, `127.0.0.1` or `::1`, so the local demo runs on
/// `--public-origin http://localhost:<port>`. The whole flow works there.
#[test]
fn r_mc_03_connector_flow_on_plain_localhost() {
    connector_flow(&Config {
        demo_signin: true,
        public_origin: Some(public_origin("http://localhost").unwrap()),
        ..Config::loopback()
    });
}

/// Layering rule A9, I-78 (lane mcp-demo): without `--demo-signin` the
/// demo step-up of a consent does not exist. The confirm route answers
/// 404, the consent page offers no demo text, and the demo sign-in route
/// answers 404 too. The OAuth endpoints themselves stay.
#[test]
fn a9_i78_no_demo_step_up_without_the_flag() {
    let running = start(&Config::loopback()).unwrap_or_else(|e| panic!("{e}"));
    let c = Client::of(&running, 0);
    let agent = discover_and_register(&c);
    let page = authorize(&c, &agent, "calls:read");
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(!page.body.contains("Demo"), "{}", page.body);
    let handle = hidden(&page.body, "consent");
    let confirm = c.form(
        oauth::CONFIRM_ROUTE,
        "",
        &[
            ("consent", &handle),
            ("challenge", "00000000000000000000000000000000"),
        ],
    );
    assert_eq!(confirm.status, 404, "{}", confirm.body);
    let signin = c.send(
        "POST",
        "/auth/demo-signin",
        &[
            ("Origin", c.origin.as_str()),
            ("X-FSTP-Request", "1"),
            ("Content-Type", "application/json"),
        ],
        r#"{"token":"0123456789abcdef0123456789abcdef"}"#,
    );
    assert_eq!(signin.status, 404, "{}", signin.body);
    // With no session, approving asks the person to sign in first, and
    // no code is issued.
    let approve = c.form(
        oauth::CONSENT_ROUTE,
        "",
        &[("consent", &handle), ("decision", "approve")],
    );
    assert_eq!(approve.status, 401, "{}", approve.body);
    assert!(approve.header("location").is_none());
}

/// TW-4, ADR-013 (lane mcp-demo): a consent form posted from another
/// origin is refused, and a denial sends the agent `access_denied` with
/// the `iss` parameter.
#[test]
fn adr013_consent_form_needs_the_cell_origin_and_deny_redirects() {
    let running = start(&Config::loopback()).unwrap_or_else(|e| panic!("{e}"));
    let c = Client::of(&running, 0);
    let agent = discover_and_register(&c);
    let page = authorize(&c, &agent, "calls:read");
    let handle = hidden(&page.body, "consent");
    let body = fstp_oauth::encode_form_urlencoded(&[("consent", &handle), ("decision", "deny")]);
    let foreign = c.send(
        "POST",
        oauth::CONSENT_ROUTE,
        &[
            ("Origin", "https://attacker.example"),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ],
        &body,
    );
    assert_eq!(foreign.status, 403);
    let denied = c.form(
        oauth::CONSENT_ROUTE,
        "",
        &[("consent", &handle), ("decision", "deny")],
    );
    assert_eq!(denied.status, 303, "{}", denied.body);
    let to = denied.header("location").unwrap();
    assert_eq!(param(&to, "error").as_deref(), Some("access_denied"));
    assert_eq!(param(&to, "iss").as_deref(), Some(c.origin.as_str()));
    // TW-4: a request the server refuses is shown, never redirected.
    let bad = c.send(
        "GET",
        &format!(
            "{}?client_id=unknown&redirect_uri={REDIRECT}",
            agent.authorize
        ),
        &[],
        "",
    );
    assert_eq!(bad.status, 400);
    assert!(bad.header("location").is_none());
}
