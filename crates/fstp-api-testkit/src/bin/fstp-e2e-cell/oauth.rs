//! The OAuth 2.1 endpoints of the test cell, so an MCP client such as
//! Claude Code connects to the cell's `/mcp` (lane mcp-demo, ADR-013).
//! Test only: this module lives in `fstp-e2e-cell` (layering rule A9).
//!
//! `fstp-web` serves the two metadata documents and `/mcp`, and answers
//! `/oauth/**` with the typed ADR-013 refusal, since no production port
//! reaches an authorisation server yet. The test cell's token port holds a
//! real `fstp-oauth` server (`FakeTokens`), so this module mounts its
//! endpoints in front of `fstp-web`:
//!
//! - `POST /oauth/register`: open dynamic registration (RFC 7591), rate
//!   limited per peer.
//! - `GET /oauth/authorize`: the request is judged by `fstp-oauth`. A
//!   refused one gets a page naming its OAuth error and never redirects
//!   (TW-4). A valid one gets the consent page: the client name as
//!   unverified text, the redirect host, and every scope in plain words.
//! - `POST /oauth/consent`: the page's form. "Deny" sends the client
//!   `access_denied`. "Approve" calls `agents.consent` through the cell's
//!   own `/api/v1/oauth/consent`, with the browser's session cookie, so
//!   every guard of the API core runs: a magic-link session is refused
//!   (I-77), the call is web only (I-85), and it needs a step-up bound to
//!   the request (I-78).
//! - `POST /oauth/token` and `POST /oauth/revoke`: the token endpoint and
//!   RFC 7009 revocation.
//!
//! The step-up of a consent: a passkey step-up needs the WebAuthn
//! ceremony, which this server-rendered page does not run. On a cell
//! started with `--demo-signin`, a session that a demo sign-in opened
//! confirms the step-up with a plain button instead
//! (`POST /oauth/consent/confirm`), as the demo's `/app/` pages do
//! (`crate::demo_signin`). Without the flag that route answers 404, and
//! no consent completes on this page.
//!
//! The form posts carry no `X-FSTP-Request` mark, which a plain HTML form
//! cannot send. Each is admitted only when its `Origin` is the cell
//! origin and its `Sec-Fetch-Site`, when sent, is `same-origin`. The
//! session cookie is `SameSite=Strict` too.

use fstp_api_core::port::SessionId;
use fstp_http::{Method, Request, RequestTarget, Response, StatusCode};
use fstp_json::Value;
use fstp_oauth::{AuthorizeOutcome, ConsentRequest, RateKey, Reply};

use crate::{Inner, SiteInfo, auth, lock, wire};

/// The route of the consent form.
pub(crate) const CONSENT_ROUTE: &str = "/oauth/consent";

/// The route of the demo step-up of a consent (`--demo-signin` only).
pub(crate) const CONFIRM_ROUTE: &str = "/oauth/consent/confirm";

/// The API route of `agents.consent` (ADR-013, lane m4/api-gaps).
const API_CONSENT: &str = "/api/v1/oauth/consent";

/// The CSP of the pages of this module: no script at all, styles from the
/// cell only. `form-action` is not set, since a consent redirects to the
/// client's own redirect URI after its form post.
const CSP: &str = "default-src 'none'; style-src 'self'; img-src 'self'; \
     frame-ancestors 'none'; base-uri 'none'";

/// Whether `path` is under `/oauth`.
pub(crate) fn is_route(path: &str) -> bool {
    path == "/oauth" || path.starts_with("/oauth/")
}

/// The plain-language text of each scope on the consent page. Interim,
/// pending Daniel: ADR-013 leaves the consent texts open, so the test cell
/// writes its own. Daniel decided the `tenant:draft` text on 2026-11-20.
fn scope_text(s: fstp_oauth::Scope) -> &'static str {
    use fstp_oauth::Scope as S;
    match s {
        S::CallsRead => "Read calls, their Guides and deadlines.",
        S::ProposalsRead => "Read the proposals you may read.",
        S::ProposalsDraft => "Draft and edit proposals for you. Submitting stays yours.",
        S::ProposalsBinding => {
            "Complete binding proposal actions where the programme allows agents to."
        }
        S::Stage2Draft => "Draft stage 2 answers for you.",
        S::ReviewRead => "Read your review assignments.",
        S::ReviewDraft => "Draft scores and comments for you.",
        S::RankingRead => "Read the ranking view you may see.",
        S::FindingsRead => "Read findings you may see.",
        S::CreatorDraft => {
            "Read and edit programme drafts you work on. Prepare invitations, role changes and activation requests that you confirm in the platform."
        }
        S::CallsDraft => {
            "Draft and edit calls, and prepare a publication that you confirm in the platform."
        }
        S::AuditRead => "Read audit views you may see.",
        S::TenantDraft => {
            "Read your organisation's funder profiles and check brand colours. Prepare changes to funder profiles, brand tokens and interface labels. Nothing changes until you confirm each change in the platform."
        }
    }
}

/// Answers one request below `/oauth`.
pub(crate) async fn handle(info: &SiteInfo, inner: &Inner, req: Request) -> Response {
    let path = req.target.path().to_owned();
    let now = inner.ports.clock.read();
    let tokens = &inner.ports.tokens;
    match (req.method.clone(), path.as_str()) {
        (Method::POST, fstp_oauth::REGISTER_PATH) => {
            from_reply(tokens.register_client(peer_key(&req), &req.body, now))
        }
        (Method::GET, fstp_oauth::AUTHORIZE_PATH) => {
            let query = req.target.query().unwrap_or("").as_bytes().to_vec();
            let session = match auth::session(inner, &req).await {
                Some((s, _)) => session_key(s),
                None => peer_key(&req),
            };
            match tokens.authorize(session, &query, now) {
                Ok(AuthorizeOutcome::Consent(c)) => consent_page(info, &c),
                Ok(AuthorizeOutcome::Refused(r)) => refused_page(&r),
                Ok(AuthorizeOutcome::Redirect(to)) => see_other(&to),
                Err(_) => message_page(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unavailable",
                    &["The authorisation server is not available."],
                ),
            }
        }
        (Method::POST, CONSENT_ROUTE) => decide(info, inner, &req).await,
        (Method::POST, CONFIRM_ROUTE) if info.demo_signin => confirm(info, inner, &req).await,
        (Method::POST, fstp_oauth::TOKEN_PATH) => from_reply(tokens.token(&req.body, now)),
        (Method::POST, fstp_oauth::REVOKE_PATH) => from_reply(tokens.revoke_token(&req.body, now)),
        _ => wire::not_found(),
    }
}

/// The rate key of the peer of `req`, or the shared key.
fn peer_key(req: &Request) -> RateKey {
    req.peer_addr()
        .map_or_else(RateKey::shared, |a| RateKey::from_ip(a.ip()))
}

/// The rate key of a browser session: the low 64 bits of its id.
fn session_key(s: SessionId) -> RateKey {
    RateKey::from_raw(u64::try_from(s.raw() & u128::from(u64::MAX)).unwrap_or(u64::MAX))
}

/// The response of an `fstp-oauth` reply, or 503.
fn from_reply(r: Result<Reply, String>) -> Response {
    let Ok(r) = r else {
        return wire::refuse(StatusCode::SERVICE_UNAVAILABLE, "oauth");
    };
    let status = StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut resp = Response::new(status);
    for (k, v) in &r.headers {
        let _ = resp.headers.try_append(&k.to_ascii_lowercase(), v.as_str());
    }
    resp.body = r.body;
    resp
}

/// Whether a form post comes from a page of the cell origin.
fn same_origin(info: &SiteInfo, req: &Request) -> bool {
    let origin_ok = req
        .headers
        .get("origin")
        .is_some_and(|v| v.as_bytes() == info.origin.as_bytes());
    let site_ok = req
        .headers
        .get("sec-fetch-site")
        .is_none_or(|v| v.as_bytes() == b"same-origin");
    origin_ok && site_ok
}

/// The form of a post, decoded by the fuzzed `fstp-oauth` decoder.
fn form(req: &Request) -> Option<fstp_oauth::Form> {
    fstp_oauth::decode_form_urlencoded(&req.body).ok()
}

/// `POST /oauth/consent {consent, decision}`.
async fn decide(info: &SiteInfo, inner: &Inner, req: &Request) -> Response {
    if !same_origin(info, req) {
        return wire::refuse(StatusCode::FORBIDDEN, "csrf");
    }
    let Some(f) = form(req) else {
        return wire::bad("form");
    };
    let Some(handle) = f.get("consent").map(str::to_owned) else {
        return wire::bad("consent");
    };
    let now = inner.ports.clock.read();
    match f.get("decision") {
        Some("deny") => match inner.ports.tokens.deny(&handle, now) {
            Ok(AuthorizeOutcome::Redirect(to)) => see_other(&to),
            _ => expired_page(),
        },
        Some("approve") => approve(info, inner, req, &handle).await,
        _ => wire::bad("decision"),
    }
}

/// The approval of the consent `handle` through `agents.consent`.
async fn approve(info: &SiteInfo, inner: &Inner, req: &Request, handle: &str) -> Response {
    if !inner
        .ports
        .tokens
        .consent_is_live(handle, inner.ports.clock.read())
    {
        return expired_page();
    }
    let Some((session, _)) = auth::session(inner, req).await else {
        return sign_in_page(info, handle);
    };
    let reply = call_consent(info, inner, req, handle).await;
    let body = fstp_json::parse(&reply.body).ok();
    let member = |k: &str| {
        body.as_ref()
            .and_then(|v| v.get(k))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    if reply.status == StatusCode::OK
        && let Some(to) = member("redirect")
    {
        return see_other(&to);
    }
    if member("code").as_deref() == Some("step_up_required") {
        let challenge = body
            .as_ref()
            .and_then(|v| v.get("challenge"))
            .and_then(|c| c.get("challenge_id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let demo = info.demo_signin && lock(&inner.auth).is_demo_session(session);
        return if demo {
            confirm_page(handle, &challenge)
        } else {
            message_page(
                StatusCode::FORBIDDEN,
                "Step-up needed",
                &[
                    "Connecting an agent links a new device, so it needs a passkey step-up.",
                    "This consent page of the test cell offers no passkey ceremony. A demo sign-in confirms with a button instead.",
                ],
            )
        };
    }
    let code = member("code").unwrap_or_else(|| "refused".to_owned());
    let rule = member("rule").unwrap_or_default();
    message_page(
        reply.status,
        "Not connected",
        &[
            "The platform refused this connection.",
            &format!("Code: {code}. Rule: {rule}."),
        ],
    )
}

/// `POST /api/v1/oauth/consent {consent}` through the cell's own routes,
/// with the session cookie of `req`.
async fn call_consent(info: &SiteInfo, inner: &Inner, req: &Request, handle: &str) -> Response {
    let Ok(target) = RequestTarget::origin(API_CONSENT) else {
        return Response::new(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mut api = Request::new(Method::POST, target);
    for (k, v) in [
        ("host", info.host.as_str()),
        ("origin", info.origin.as_str()),
        ("x-fstp-request", "1"),
        ("content-type", "application/json"),
        ("accept", "application/json"),
    ] {
        let _ = api.headers.try_append(k, v);
    }
    for c in req.headers.get_all("cookie") {
        let _ = api.headers.try_append("cookie", c.as_bytes().to_vec());
    }
    let body = wire::obj(vec![("consent", Value::String(handle.to_owned()))]);
    api.body = body.to_compact().into_bytes();
    inner.web.serve(api).await
}

/// `POST /oauth/consent/confirm {consent, challenge}` on a cell started
/// with `--demo-signin`: the demo step-up of the consent, then the
/// approval again. Only a session that a demo sign-in opened may, and only
/// for a challenge of its own (`crate::demo_signin`).
async fn confirm(info: &SiteInfo, inner: &Inner, req: &Request) -> Response {
    if !same_origin(info, req) {
        return wire::refuse(StatusCode::FORBIDDEN, "csrf");
    }
    let Some(f) = form(req) else {
        return wire::bad("form");
    };
    let (Some(handle), Some(id)) = (
        f.get("consent").map(str::to_owned),
        f.get("challenge")
            .and_then(wire::unhex)
            .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok()),
    ) else {
        return wire::bad("challenge");
    };
    let Some((session, _)) = auth::session(inner, req).await else {
        return sign_in_page(info, &handle);
    };
    if !lock(&inner.auth).is_demo_session(session) {
        return wire::refuse(StatusCode::FORBIDDEN, "demo");
    }
    let Some((owner, challenge)) = inner.ports.step_up.challenge_for(&id) else {
        return wire::refuse(StatusCode::FORBIDDEN, "challenge");
    };
    if owner != session {
        return wire::refuse(StatusCode::FORBIDDEN, "challenge");
    }
    if fstp_api_core::port::StepUp::finish(&inner.ports.step_up, session, &challenge)
        .await
        .is_err()
    {
        return wire::refuse(StatusCode::FORBIDDEN, "challenge");
    }
    approve(info, inner, req, &handle).await
}

/// A 303 to `to`, which leaves this origin with the code.
fn see_other(to: &str) -> Response {
    let mut r = Response::new(StatusCode::SEE_OTHER);
    let _ = r.headers.try_insert("location", to);
    let _ = r.headers.try_insert("cache-control", "no-store");
    let _ = r.headers.try_insert("referrer-policy", "no-referrer");
    r
}

/// `s` escaped for HTML text and attribute values.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// A page of this module with `title` and the HTML `main`.
fn page(status: StatusCode, title: &str, main: &str) -> Response {
    let html = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<meta name=\"referrer\" content=\"no-referrer\">\n<title>{}</title>\n\
<link rel=\"stylesheet\" href=\"/assets/auth/tokens.css\">\n\
<link rel=\"stylesheet\" href=\"/assets/auth/auth.css\">\n\
</head>\n<body>\n<main id=\"main\">\n<h1>{}</h1>\n{main}</main>\n</body>\n</html>\n",
        esc(title),
        esc(title)
    );
    let mut r = Response::with_body(status, "text/html; charset=utf-8", html.into_bytes());
    for (k, v) in [
        ("content-security-policy", CSP),
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-robots-tag", "noindex"),
    ] {
        let _ = r.headers.try_insert(k, v);
    }
    r
}

/// A page of plain paragraphs.
fn message_page(status: StatusCode, title: &str, lines: &[&str]) -> Response {
    let main: String = lines
        .iter()
        .map(|l| format!("<p>{}</p>\n", esc(l)))
        .collect();
    page(status, title, &main)
}

/// The page of a request `fstp-oauth` refused: its OAuth error code, and
/// no redirect (TW-4).
fn refused_page(r: &Reply) -> Response {
    let code = fstp_json::parse(&r.body)
        .ok()
        .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_else(|| "invalid_request".to_owned());
    let status = StatusCode::from_u16(r.status).unwrap_or(StatusCode::BAD_REQUEST);
    message_page(
        status,
        "Request refused",
        &[
            "The agent's request to connect was refused. You were not sent back to it.",
            &format!("OAuth error: {code}."),
        ],
    )
}

/// The page of a consent that is gone: used, refused or older than ten
/// minutes.
fn expired_page() -> Response {
    message_page(
        StatusCode::BAD_REQUEST,
        "Request expired",
        &[
            "This connection request is no longer valid. Start the connection again from your agent.",
        ],
    )
}

/// The hidden member `name` of a form.
fn hidden(name: &str, value: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"{}\" value=\"{}\">\n",
        esc(name),
        esc(value)
    )
}

/// The consent page of `c` (ADR-013 "Consent", TW-8).
fn consent_page(info: &SiteInfo, c: &ConsentRequest) -> Response {
    let name = c.client_name.as_deref().unwrap_or("An agent with no name");
    let mut main = String::new();
    main.push_str("<section>\n<p>An AI agent asks to act for you on this platform.</p>\n");
    main.push_str(&format!(
        "<p data-oauth=\"client\"><strong>{}</strong> <span class=\"tag\">unverified</span></p>\n",
        esc(name)
    ));
    let device = if c.loopback_redirect {
        " This address is on your own device."
    } else {
        ""
    };
    main.push_str(&format!(
        "<p data-oauth=\"redirect-host\">After you decide, you go back to <strong>{}</strong>.{device}</p>\n</section>\n",
        esc(&c.redirect_host)
    ));
    main.push_str("<section>\n<h2>It asks to</h2>\n<ul class=\"items\" data-oauth=\"scopes\">\n");
    for s in c.scopes.iter() {
        main.push_str(&format!(
            "<li data-scope=\"{}\">{}</li>\n",
            s.as_str(),
            esc(scope_text(s))
        ));
    }
    main.push_str("</ul>\n");
    main.push_str(
        "<p>The agent can do no more than your roles allow. It never sees identity details or bank details.</p>\n\
<p>High-risk actions, such as publishing a call, stay prepare-only. You confirm each one in the platform.</p>\n\
<p>Connecting an agent links a new device, so the platform asks you to confirm it.</p>\n</section>\n",
    );
    if info.demo_signin {
        main.push_str(
            "<p>Demo cell: sign in first on the demo page, in this browser, then approve here.</p>\n",
        );
    }
    main.push_str(&decision_form(&c.handle));
    page(StatusCode::OK, "Connect an agent", &main)
}

/// The approve and deny form of the consent `handle`.
fn decision_form(handle: &str) -> String {
    format!(
        "<form method=\"post\" action=\"{CONSENT_ROUTE}\" class=\"actions\">\n{}\
<button type=\"submit\" name=\"decision\" value=\"approve\" class=\"primary\">Approve</button>\n\
<button type=\"submit\" name=\"decision\" value=\"deny\" class=\"secondary\">Deny</button>\n</form>\n",
        hidden("consent", handle)
    )
}

/// The page for an approval with no session: sign in, then approve again.
fn sign_in_page(info: &SiteInfo, handle: &str) -> Response {
    let how = if info.demo_signin {
        "Open the demo page of this cell, choose a person and sign in, in this browser. Then come back to this tab and approve again."
    } else {
        "Sign in to the platform in this browser, then come back to this tab and approve again."
    };
    let main = format!(
        "<p>You are not signed in on this browser.</p>\n<p>{}</p>\n{}",
        esc(how),
        decision_form(handle)
    );
    page(StatusCode::UNAUTHORIZED, "Sign in first", &main)
}

/// The demo step-up of a consent: one "Confirm" button, as the demo's
/// step-up dialog has (`crate::demo_signin`).
fn confirm_page(handle: &str, challenge: &str) -> Response {
    let main = format!(
        "<p>Connecting an agent links a new device. The platform asks you to confirm it.</p>\n\
<p>Demo sign-in: confirm with this button instead of a passkey.</p>\n\
<form method=\"post\" action=\"{CONFIRM_ROUTE}\" class=\"actions\">\n{}{}\
<button type=\"submit\" class=\"primary\" data-oauth=\"confirm\">Confirm</button>\n</form>\n",
        hidden("consent", handle),
        hidden("challenge", challenge)
    );
    page(StatusCode::OK, "Confirm the connection", &main)
}
