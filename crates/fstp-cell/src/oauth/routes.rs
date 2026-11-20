//! The OAuth 2.1 endpoints of the production cell (ADR-013 amendment of
//! 2026-11-20, lane L2).
//!
//! - `POST /oauth/register`: open dynamic registration (RFC 7591), rate
//!   limited per tunnel peer (ADR-024).
//! - `GET /oauth/authorize`: `fstp-oauth` judges the request. A refused
//!   one gets a page naming its OAuth error and never redirects (TW-4). A
//!   valid one answers 303 to the consent page of the platform,
//!   `/app/connect#<handle>`. The handle travels in the fragment, so no
//!   request line carries it. The page reads `agents.consent_request` and
//!   approves through `agents.consent` with a passkey step-up (I-78,
//!   I-77). No demo step-up exists here.
//! - `POST /oauth/token`: the code and refresh grants, under the recovery
//!   check (I-79).
//! - `POST /oauth/revoke`: RFC 7009 revocation (R-MC-03).
//! - `POST /oauth/deny` with `{consent}`: the user's denial from the
//!   consent page. It answers `{redirect}`, the client's redirect URI with
//!   `access_denied`, `state` and `iss`. The page's script sends it with
//!   `X-FSTP-Request` from the cell origin, which a plain cross-site form
//!   cannot.
//!
//! Every reply of the server is written in the order of its journal: the
//! changes of a call commit before its reply leaves (`super::AuthServer`).
//! A server that cannot commit answers 503.

use fstp_http::{Method, Request, Response, StatusCode};
use fstp_json::{Object, Value};
use fstp_oauth::{AuthorizeOutcome, RateKey, Reply};

use super::AuthServer;
use super::store::McpFault;

/// The consent page of the platform. The handle follows in the fragment.
pub const CONNECT_PAGE: &str = "/app/connect";

/// The route of the user's denial.
pub const DENY_ROUTE: &str = "/oauth/deny";

/// The CSP of the pages of this module: no script at all.
const CSP: &str = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

/// The longest `{consent}` body of a denial, in bytes.
const MAX_DENY_BODY: usize = 1024;

/// Answers one request below `/oauth` (module documentation).
pub async fn serve(server: &AuthServer, origin: &str, req: Request) -> Response {
    let path = req.target.path().to_owned();
    match (req.method.clone(), path.as_str()) {
        (Method::POST, fstp_oauth::REGISTER_PATH) => {
            let key = peer_key(&req);
            from_reply(
                server
                    .call(|s, _, now| s.register(key, &req.body, now))
                    .await,
            )
        }
        (Method::GET, fstp_oauth::AUTHORIZE_PATH) => authorize(server, &req).await,
        (Method::POST, fstp_oauth::TOKEN_PATH) => from_reply(
            server
                .call(|s, guard, now| s.token_guarded(&req.body, now, guard))
                .await,
        ),
        (Method::POST, fstp_oauth::REVOKE_PATH) => {
            from_reply(server.call(|s, _, now| s.revoke(&req.body, now)).await)
        }
        (Method::POST, DENY_ROUTE) => deny(server, origin, &req).await,
        (
            _,
            fstp_oauth::REGISTER_PATH
            | fstp_oauth::AUTHORIZE_PATH
            | fstp_oauth::TOKEN_PATH
            | fstp_oauth::REVOKE_PATH
            | DENY_ROUTE,
        ) => Response::new(StatusCode::METHOD_NOT_ALLOWED),
        _ => Response::new(StatusCode::NOT_FOUND),
    }
}

/// `GET /oauth/authorize` (module documentation).
async fn authorize(server: &AuthServer, req: &Request) -> Response {
    let query = req.target.query().unwrap_or("").as_bytes().to_vec();
    let session = session_key(req);
    match server
        .call(|s, _, now| s.authorize_from(session, &query, now))
        .await
    {
        Ok(AuthorizeOutcome::Consent(c)) => see_other(&format!("{CONNECT_PAGE}#{}", c.handle)),
        Ok(AuthorizeOutcome::Refused(r)) => refused_page(&r),
        // The endpoint never redirects before the user acts (TW-4).
        Ok(AuthorizeOutcome::Redirect(_)) | Err(_) => message_page(
            StatusCode::SERVICE_UNAVAILABLE,
            "Unavailable",
            &["The authorisation server is not available. Try again from your agent."],
        ),
    }
}

/// `POST /oauth/deny {consent}` (module documentation).
async fn deny(server: &AuthServer, origin: &str, req: &Request) -> Response {
    if !same_origin_script(origin, req) {
        return json(StatusCode::FORBIDDEN, &[("code", "forbidden")]);
    }
    let handle = (req.body.len() <= MAX_DENY_BODY)
        .then(|| fstp_json::parse(&req.body).ok())
        .flatten()
        .and_then(|v| v.get("consent").and_then(Value::as_str).map(str::to_owned));
    let Some(handle) = handle else {
        return json(StatusCode::BAD_REQUEST, &[("code", "bad_request")]);
    };
    match server.call(|s, _, now| s.deny(&handle, now)).await {
        Ok(AuthorizeOutcome::Redirect(to)) => json(StatusCode::OK, &[("redirect", to.as_str())]),
        Ok(_) => json(StatusCode::BAD_REQUEST, &[("code", "expired")]),
        Err(McpFault::Unavailable | McpFault::Corrupt) => {
            json(StatusCode::SERVICE_UNAVAILABLE, &[("code", "unavailable")])
        }
    }
}

/// Whether `req` comes from a script of the cell origin: `Origin` is the
/// cell origin, `Sec-Fetch-Site`, when sent, is `same-origin`, and the
/// `X-FSTP-Request` mark is present, which a cross-site form cannot set.
fn same_origin_script(origin: &str, req: &Request) -> bool {
    let mut origins = req.headers.get_all("origin");
    let origin_ok = match (origins.next(), origins.next()) {
        (Some(v), None) => v.as_bytes() == origin.as_bytes(),
        _ => false,
    };
    let site_ok = req
        .headers
        .get("sec-fetch-site")
        .is_none_or(|v| v.as_bytes() == b"same-origin");
    origin_ok && site_ok && req.headers.get("x-fstp-request").is_some()
}

/// The registration rate key of the tunnel peer of `req`, or the shared
/// key (ADR-024).
fn peer_key(req: &Request) -> RateKey {
    req.peer_addr()
        .map_or_else(RateKey::shared, |a| RateKey::from_ip(a.ip()))
}

/// The consent rate key of `req`: the labelled SHA-256 of its session
/// cookie when it sends one, and its peer's key otherwise. It only bounds
/// the pending consents one browser holds or evicts.
fn session_key(req: &Request) -> RateKey {
    let cookie = req.headers.get_all("cookie").find_map(|v| {
        v.to_str().and_then(|s| {
            s.split(';')
                .map(str::trim)
                .find_map(|p| p.strip_prefix("__Host-fstp="))
                .map(str::to_owned)
        })
    });
    match cookie {
        Some(c) => {
            let mut h = fstp_crypto::Sha256::new();
            h.update(b"fstp-oauth consent session v1\0");
            h.update(c.as_bytes());
            let d = h.finish();
            let mut raw = [0u8; 8];
            for (slot, b) in raw.iter_mut().zip(d) {
                *slot = b;
            }
            RateKey::from_raw(u64::from_be_bytes(raw))
        }
        None => peer_key(req),
    }
}

/// The response of a server reply, or 503.
fn from_reply(r: Result<Reply, McpFault>) -> Response {
    let Ok(r) = r else {
        return json(
            StatusCode::SERVICE_UNAVAILABLE,
            &[("error", "temporarily_unavailable")],
        );
    };
    let status = StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut resp = Response::new(status);
    for (k, v) in &r.headers {
        let _ = resp.headers.try_append(&k.to_ascii_lowercase(), v.as_str());
    }
    resp.body = r.body;
    resp
}

/// A JSON reply of string members.
fn json(status: StatusCode, members: &[(&str, &str)]) -> Response {
    let mut o = Object::new();
    for (k, v) in members {
        o.insert(*k, Value::from(*v));
    }
    let mut r = Response::with_body(
        status,
        "application/json",
        Value::Object(o).to_compact().into_bytes(),
    );
    let _ = r.headers.try_insert("cache-control", "no-store");
    r
}

/// A 303 to `to`.
fn see_other(to: &str) -> Response {
    let mut r = Response::new(StatusCode::SEE_OTHER);
    let _ = r.headers.try_insert("location", to);
    let _ = r.headers.try_insert("cache-control", "no-store");
    let _ = r.headers.try_insert("referrer-policy", "no-referrer");
    r
}

/// `s` escaped for HTML text.
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

/// A page of plain paragraphs, with no script and no form.
fn message_page(status: StatusCode, title: &str, lines: &[&str]) -> Response {
    let mut main = String::new();
    for l in lines {
        main.push_str(&format!("<p>{}</p>\n", esc(l)));
    }
    let html = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<meta name=\"referrer\" content=\"no-referrer\">\n<title>{t}</title>\n</head>\n\
<body>\n<main id=\"main\">\n<h1>{t}</h1>\n{main}</main>\n</body>\n</html>\n",
        t = esc(title)
    );
    let mut r = Response::with_body(status, "text/html; charset=utf-8", html.into_bytes());
    let _ = r.headers.try_insert("content-security-policy", CSP);
    let _ = r.headers.try_insert("cache-control", "no-store");
    r
}

/// The page of a request `fstp-oauth` refused: its OAuth error code and
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
