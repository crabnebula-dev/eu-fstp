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
//! - Step 1 (ADR-026 record of lane L18): the world runs `fstp-cell
//!   provision-tenant` before `first-admin`, so the ledger holds a tenant
//!   part and no organisation is active. Onboarding runs through
//!   `/api/v1` as the onboarding pages send it: the first admin invites
//!   the second by mail, the second enrols from the mailed link, both
//!   are verified, the signatories are granted, every step validates with
//!   the real probes, and the activation is requested and approved.
//! - The vault runs as the `fstp-vault` binary (lane L8). Both admins are
//!   verified with `fstp-vault verify-first-admin` (lane L13b), with the
//!   vault stopped, as the technical admin does on a pilot host.
//! - The sending domain probe asks a fake resolver on loopback, which
//!   serves SPF, DKIM and DMARC records of a synthetic domain. The channel
//!   probe greets the test SMTP sink, the platform relay.
//! - Step 3: magic links are off on a production cell unless a tenant
//!   admin turns them on, so no magic-link session exists here. I-77 is
//!   covered on the PostgreSQL cell by lanes L1 and L2.
//! - Step 5: the binary's ledger keys stay in its own process, so this
//!   test does not read the App chain. I-24 per call is covered by
//!   `i24_every_api_call_leaves_one_chain_event` of lane L1.
//! - Step 7: `fstp-cell first-admin --email` records the first admin's
//!   login email (ADR-026 "First admin email"). A second tenant admin
//!   connects the agent, and the first admin approves its recovery.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_api_testkit::smtp_sink::{SINK_SERVER_NAME, SinkConfig, SmtpSink};
use fstp_celltest::external_cell::{ExternalRelay, ExternalShell, ExternalSpec};
use fstp_celltest::external_vault::{ExternalVault, ExternalVaultSpec, start_world};
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

/// The synthetic sending domain of the Domains and email step.
const DOMAIN: &str = "mail.fstp-l18.invalid";
/// The DKIM selector the cell's `shell` member names.
const DKIM_SELECTOR: &str = "l18";

/// The TXT records the fake resolver serves: SPF, DMARC and DKIM of
/// [`DOMAIN`] (ADR-027). Every other name has none.
fn txt_records(name: &str) -> Vec<&'static str> {
    match name {
        n if n == DOMAIN => vec!["v=spf1 -all"],
        n if n == format!("_dmarc.{DOMAIN}") => vec!["v=DMARC1; p=reject"],
        n if n == format!("{DKIM_SELECTOR}._domainkey.{DOMAIN}") => {
            vec!["v=DKIM1; k=ed25519; p=c3ludGhldGljLWtleQ"]
        }
        _ => Vec::new(),
    }
}

/// Answers one DNS question over TCP (RFC 7766) on `s` with the TXT
/// records of [`txt_records`]: the question copied, one answer per
/// record, each name a pointer to the question's.
fn answer_one(s: &mut std::net::TcpStream) -> std::io::Result<()> {
    use std::io::{Read as _, Write as _};
    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len)?;
    let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
    s.read_exact(&mut q)?;
    let mut at = 12;
    let mut labels = Vec::new();
    while let Some(&n) = q.get(at) {
        at += 1;
        if n == 0 {
            break;
        }
        let end = at + usize::from(n);
        labels.push(String::from_utf8_lossy(q.get(at..end).unwrap_or(&[])).to_lowercase());
        at = end;
    }
    let question = q.get(12..at + 4).unwrap_or(&[]).to_vec();
    let records = txt_records(&labels.join("."));
    let mut m = Vec::new();
    m.extend_from_slice(q.get(..2).unwrap_or(&[0, 0]));
    m.extend_from_slice(&0x8180u16.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
    m.extend_from_slice(&[0, 0, 0, 0]);
    m.extend_from_slice(&question);
    for r in records {
        m.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60]);
        let n = u8::try_from(r.len()).unwrap();
        m.extend_from_slice(&u16::from(n + 1).to_be_bytes());
        m.push(n);
        m.extend_from_slice(r.as_bytes());
    }
    let mut out = u16::try_from(m.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(&m);
    s.write_all(&out)
}

/// A fake resolver on loopback (ADR-026 record of lane L18, "Loopback
/// resolver"), one question per connection, until the test ends.
fn dns_server() -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let _ = answer_one(&mut s);
        }
    });
    addr
}

/// The fstp-tls test CA, which issued the sink's `localhost` certificate.
const SINK_CA: &[u8] = include_bytes!("../../fstp-tls/testdata/ca.pem");

/// The processes of the run. The world drops first, so the cell drains
/// before its custody goes.
struct Stack {
    world: World,
    /// The vault, run by the `fstp-vault` binary (lane L8), so the first
    /// admins are verified with `fstp-vault verify-first-admin` (lane L13b).
    vault: ExternalVault,
    sink: SmtpSink,
    _rt: fstp_rt::tokio::TokioRuntime,
    _custody: SimProcess,
    _key_file_custody: SimProcess,
    _vault_custody: SimProcess,
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
    let vault_custody = SimProcess::spawn(2, &dir).unwrap_or_else(|e| panic!("{e}"));
    let vault_binary = bin_path("fstp-vault").unwrap_or_else(|e| {
        panic!("{e}: run `cargo build -p fstp-vault --bin fstp-vault` before this test")
    });
    // The platform relay (D3): the test SMTP sink, on the world's runtime
    // kind. It must outlive the cell, so the stack holds it.
    let rt = fstp_rt::tokio::TokioRuntime::new_multi_thread(1).unwrap();
    let cfg = SinkConfig::default();
    let sink = rt.block_on(SmtpSink::start(&rt, cfg.clone())).unwrap();
    let handle = sink.handle().clone();
    let relay = ExternalRelay {
        address: sink.addr(),
        relay: SINK_SERVER_NAME.to_owned(),
        username: cfg.username,
        password: cfg.password,
        ca_pem: SINK_CA.to_vec(),
        messages: std::sync::Arc::new(move || {
            handle
                .messages()
                .into_iter()
                .filter_map(|m| Some((m.to.first()?.clone(), m.data)))
                .collect()
        }),
    };
    let spec = ExternalSpec {
        binary,
        dir: dir.clone(),
        key_file_custody: key_file_custody.socket().to_path_buf(),
        assets_dir: None,
        relay: Some(relay),
        shell: Some(ExternalShell {
            resolver: dns_server(),
            dkim_selector: DKIM_SELECTOR.to_owned(),
        }),
    };
    let (world, vault) = start_world(
        WorldSpec {
            cells: 1,
            mode: DbMode::Shared,
            vault_layout: VaultLayout::SeparateCluster,
            self_hosted: false,
            process_mode: false,
        },
        custody.socket().to_path_buf(),
        &spec,
        ExternalVaultSpec {
            binary: vault_binary,
            dir: dir.clone(),
            keyd_socket: vault_custody.socket().to_path_buf(),
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    Stack {
        world,
        vault,
        sink,
        _rt: rt,
        _custody: custody,
        _key_file_custody: key_file_custody,
        _vault_custody: vault_custody,
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

/// How many messages to `to` the platform relay accepted.
fn relayed(stack: &Stack, to: &str) -> usize {
    stack
        .sink
        .messages()
        .iter()
        .filter(|m| m.to.iter().any(|t| t == to))
        .count()
}

/// A synthetic identity file of `fstp-vault verify-first-admin` (ADR-004
/// record of lane L13b), with no document number.
fn identity_file(family: &str) -> String {
    format!(
        r#"{{"method":"manual","document_type":"passport","checks":["document_authentic","photo_match"],"identity":{{"family_names":"{family}","given_names":"Synthetic","birth_date":"1990-02-28","issuing_state":"DEU"}}}}"#
    )
}

/// The link token of the newest admin invitation mail to `to`, read from
/// its text part's `/auth/invite#<token>` link as the invitee reads it.
fn admin_invitation_token(stack: &Stack, to: &str) -> Option<Vec<u8>> {
    let begun = std::time::Instant::now();
    while relayed(stack, to) == 0 && begun.elapsed() < std::time::Duration::from_secs(20) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let messages = stack.sink.messages();
    let m = messages
        .iter()
        .rev()
        .find(|m| m.to.iter().any(|t| t == to))?;
    let parsed = fstp_mail::parse(&m.data).ok()?;
    let text = parsed
        .parts
        .iter()
        .find(|p| p.content_type == "text/plain")
        .map(|p| String::from_utf8_lossy(&p.decoded).into_owned())?;
    let at = text.find("/auth/invite#")? + "/auth/invite#".len();
    let hex = text.get(at..at + 64)?;
    (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

/// A tenant call that must succeed, with a step-up where the cell asks
/// for one: its JSON reply.
fn admin_call(
    client: &AuthClient<'_>,
    method: &str,
    path: &str,
    who: &Cookie,
    body: &str,
) -> Value {
    let r = web_with_step_up(client, method, path, who, body);
    assert_eq!(r.status, 200, "{method} {path}: {}", text(&r));
    json(&r)
}

/// Step 1 of ADR-026 record of lane L18, the onboarding of a provisioned
/// cell: the second admin's invitation by mail and enrolment (SoD-07),
/// both admins verified, the signatories (SoD-14, SoD-15, SoD-16), every
/// step with the real probes (Q5, ADR-027), completion and the activation
/// by the other admin (SoD-18). The sessions of both admins.
fn onboard(stack: &Stack, client: &AuthClient<'_>) -> (Cookie, Cookie) {
    let cell = client.cell();
    assert!(client.enrol(FIRST_ADMIN).unwrap(), "the first admin enrols");
    let admin1 = client.admin_session().expect("the first admin's session");
    // ADR-021: nothing outside onboarding runs before the activation.
    let early = web(cell, "POST", "/api/v1/programmes", &admin1, "{}");
    assert!(
        early.status != 200 && text(&early).contains("ADR-021"),
        "ADR-021: a draft before the activation: {}",
        text(&early)
    );
    // SoD-07, J0: the second admin by mail, to the address the world
    // names as their login email, so recovery reaches it later.
    let email = cell.login_email(ADMIN_2);
    let _ = admin_call(
        client,
        "POST",
        "/api/v1/admin/admins",
        &admin1,
        &format!(r#"{{"email":"{email}"}}"#),
    );
    let token = admin_invitation_token(stack, &email).expect("SoD-07: no admin invitation mail");
    assert_eq!(relayed(stack, &email), 1, "I-26: the invitation mail once");
    let a2 = client
        .enrol_by_link(ADMIN_2, &token)
        .unwrap()
        .expect("SoD-07: the second admin enrols from the mailed link");
    let admin2 = client
        .login(ADMIN_2, RefMethod::Passkey)
        .unwrap()
        .expect("the second admin's session");
    let a1 = client
        .cell_account(FIRST_ADMIN)
        .expect("the first admin's account");
    let admins = admin_call(client, "GET", "/api/v1/admin/admins", &admin2, "");
    let listed = admins.to_compact();
    for a in [a1, a2] {
        assert!(
            listed.contains(&a.raw().to_string()),
            "SoD-07: the admin {a:?} is not listed: {listed}"
        );
    }
    // ADR-008 (lane L13b): the technical admin verifies both admins on
    // the host with `fstp-vault verify-first-admin`, the vault stopped.
    stack.vault.stop().unwrap_or_else(|e| panic!("{e}"));
    for (a, family) in [(a1, "Alpha"), (a2, "Bravo")] {
        stack
            .vault
            .verify_first_admin(a.raw(), &identity_file(family))
            .unwrap_or_else(|e| panic!("ADR-008: verify-first-admin: {e}"));
    }
    stack.vault.start().unwrap_or_else(|e| panic!("{e}"));
    // SoD-14, SoD-15, SoD-16: the first admin grants both signatory roles
    // to the second (SoD-07 bars a grant to oneself).
    for role in ["financial_signatory", "legal_signatory"] {
        let _ = admin_call(
            client,
            "POST",
            "/api/v1/admin/signatories",
            &admin1,
            &format!(r#"{{"account":"{}","role":"{role}"}}"#, a2.raw()),
        );
    }
    // The Administrators step takes the admin set in ascending order.
    let mut admins = [a1, a2];
    admins.sort();

    for name in fstp_api_testkit::harness::ONBOARDING_STEP_NAMES {
        if name == "payments" {
            let _ = admin_call(
                client,
                "PUT",
                "/api/v1/admin/settings/payment-mode",
                &admin1,
                r#"{"value":"record_only"}"#,
            );
        }
        let path = format!("/api/v1/admin/onboarding/{name}");
        let view = admin_call(client, "GET", &path, &admin1, "");
        let base = view
            .get("revision")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("no revision: {}", view.to_compact()))
            .to_owned();
        let values = if name == "domains_and_email" {
            format!(r#"{{"sending_domain":"{DOMAIN}"}}"#)
        } else {
            fstp_api_testkit::harness::onboarding_step_values(name, a2, &admins).to_compact()
        };
        let saved = admin_call(
            client,
            "PUT",
            &path,
            &admin1,
            &format!(r#"{{"base":"{base}","values":{values}}}"#),
        );
        assert_eq!(
            saved.get("outcome").and_then(Value::as_str),
            Some("validated"),
            "Q5, R-TN-01: the step {name}: {}",
            saved.to_compact()
        );
    }
    let _ = admin_call(
        client,
        "POST",
        "/api/v1/admin/onboarding/complete",
        &admin1,
        "{}",
    );
    let _ = admin_call(client, "POST", "/api/v1/admin/activation", &admin1, "{}");
    let view = admin_call(client, "GET", "/api/v1/admin/activation", &admin1, "");
    let request = view
        .get("request")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no request: {}", view.to_compact()))
        .to_owned();
    // SoD-18: the requester cannot approve.
    let own = web_with_step_up(
        client,
        "POST",
        "/api/v1/admin/activation/approval",
        &admin1,
        &format!(r#"{{"request":"{request}"}}"#),
    );
    assert_ne!(own.status, 200, "SoD-18: self-approved: {}", text(&own));
    let _ = admin_call(
        client,
        "POST",
        "/api/v1/admin/activation/approval",
        &admin2,
        &format!(r#"{{"request":"{request}"}}"#),
    );
    let view = admin_call(client, "GET", "/api/v1/admin/activation", &admin1, "");
    assert_eq!(
        view.get("state").and_then(Value::as_str),
        Some("active"),
        "SoD-18: {}",
        view.to_compact()
    );
    (admin1, admin2)
}

/// Production MCP design section 4.1, steps 1 to 7, over the `fstp-cell`
/// binary started from its configuration file (G1, G8, G10, G11).
///
/// 1. Start (ADR-026, D4): the binary reaches `ready` from the file, after
///    `fstp-cell provision-tenant` recorded the tenant part and
///    `fstp-cell first-admin --email` wrote the token halves and recorded
///    the first admin's login email. Onboarding then runs as on a pilot
///    (ADR-026 record of lane L18, [`onboard`]): the second admin joins by
///    mail, the probes pass, and the other admin approves the activation.
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
///    is refused. Then (step 5b, D3, I-26, wave 2 merge) the agent
///    prepares a role invitation, the person confirms it, and its mail
///    reaches the relay once.
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

    // Step 1 (ADR-026 record of lane L18).
    let (_admin1, admin2) = onboard(&stack, &client);
    // ADR-026 "First admin email" (decided by Daniel on 2026-11-21): the
    // address `first-admin --email` recorded serves recovery from day one.
    // The proof reaches the platform relay. The case stays open.
    assert!(
        client.recovery(FIRST_ADMIN).unwrap().is_some(),
        "I-79: recovery by email did not reach the first admin's address"
    );

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

    // Step 5b (wave 2 merge, D3, I-85, I-26): the agent prepares a role
    // invitation, the person confirms it in the platform, and its mail
    // reaches the platform relay once.
    let invitee = "invitee-l4@fstp-l4.invalid";
    let r = mcp(
        cell,
        &access,
        "tools/call",
        Some("fstp_prepare_invitation"),
        &format!(
            r#""name":"fstp_prepare_invitation","arguments":{{"programme":"{programme}","email":"{invitee}","role":"programme_manager"}}"#
        ),
    );
    assert_eq!(r.status, 200, "prepare invitation: {}", text(&r));
    assert!(!text(&r).contains(invitee), "I-86: {}", text(&r));
    let invitation = text(&r)
        .split('"')
        .find(|s| s.starts_with("/app/pending/"))
        .unwrap_or_else(|| panic!("no confirm path: {}", text(&r)))
        .trim_start_matches("/app/pending/")
        .to_owned();
    assert_eq!(relayed(&stack, invitee), 0, "I-85: preparing sent mail");
    let open = action(cell, &admin2, &invitation);
    let digest = open
        .get("digest")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    let done = web_with_step_up(
        &client,
        "POST",
        &format!("/api/v1/pending-actions/{invitation}/confirmation"),
        &admin2,
        &format!(r#"{{"shown":"{digest}"}}"#),
    );
    assert_eq!(done.status, 200, "the invitation: {}", text(&done));
    let begun = std::time::Instant::now();
    while relayed(&stack, invitee) == 0 && begun.elapsed() < std::time::Duration::from_secs(20) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(relayed(&stack, invitee), 1, "I-26: the invitation mail");

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
