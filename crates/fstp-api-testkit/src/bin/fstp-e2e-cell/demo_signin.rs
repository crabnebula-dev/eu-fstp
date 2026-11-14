//! The demo sign-in of the test cell (lane m4/site scope item 8; Daniel,
//! 2026-11-04: "for the demo it makes NO SENSE to have to use and
//! generate passkeys. that is just overengineering."). Test only: it
//! lives in this binary and nowhere else (layering rule A9), and only a
//! cell started with `--demo-signin` serves it. Without the flag the
//! route below answers 404, as every unknown `/auth` path does, and
//! passkeys, enrolment and step-up work exactly as before.
//!
//! With the flag:
//!
//! - The demo page of the control base gives each person a "Sign in as
//!   <name>" link to `<cell origin>/auth/demo-signin#<token>`. The control
//!   base issues the token: 16 random bytes, single use, living at most
//!   [`LIFETIME_MICROS`] of the cell clock. The token travels in the
//!   fragment, so no server log holds it.
//! - `GET /auth/demo-signin` serves a page whose script reads the
//!   fragment, drops it from the address bar and posts it.
//!   `POST /auth/demo-signin {token}` passes the CSRF rule of the cell,
//!   takes the token, and opens a session for its account with the
//!   session cookie, as a passkey login does. A reused, expired, forged or
//!   missing token is refused with 403 and sets no cookie; the page then
//!   says so in an alert.
//! - Every `/app/` page of such a session loads one more module,
//!   `/assets/demo/notice.js`, which shows "Demo sign-in" in the top bar
//!   and turns the step-up dialog into a plain "Confirm" button. Confirm
//!   posts `{"challenge_id", "demo": true}` to `/auth/stepup`, which
//!   records the step-up for a demo session only (`auth.rs`). The
//!   command is retried as after a passkey step-up, so every other guard
//!   still runs.
//! - The M3 account page `/auth/account` of such a session loads
//!   `/assets/demo/account.js`, which shows the same notice. Its own
//!   step-up stays the passkey ceremony, which a demo account cannot give,
//!   so passkey and session management there is not part of the demo.
//!
//! - The top bar notice of a demo session is a "Switch person" button
//!   (lane m4/demo-switch). It opens a dialog that lists the people of
//!   the scene from `GET /auth/demo-signin/people`: each person the demo
//!   page lists, with their roles and the line on what they can do, and
//!   the current person marked. Choosing one posts
//!   `POST /auth/demo-signin/switch {account}`, which issues one fresh
//!   token as the demo page does, and the page redeems it at once on
//!   `POST /auth/demo-signin`. Both routes answer only a demo session
//!   of this cell, and the switch passes the CSRF rule. No token is ever
//!   listed: one is issued per click, for one person of the scene, and
//!   it is single use and short-lived like every other.
//!
//! The session is a passkey session in the fake sessions port, so the
//! management login rule of I-77 and the step-up rules hold for it as for
//! a passkey session. The cell marks it as a demo session. The
//! method of the session therefore reads as a passkey on `/app/me` and
//! `/auth/account`, and the notice on both pages says it is a demo
//! sign-in.

use fstp_domain::id::AccountId;
use fstp_http::{Method, Request, Response, StatusCode};

use fstp_json::{Array, Value};

use crate::wire::{self, dec, obj, refuse};
use crate::{Inner, SiteInfo, auth, lock};

/// The demo sign-in route on the cell origin (`e2e/site/contract.ts`).
pub(crate) const ROUTE: &str = "/auth/demo-signin";

/// The route that lists the people a demo session may switch to.
pub(crate) const PEOPLE_ROUTE: &str = "/auth/demo-signin/people";

/// The route that issues a token to switch a demo session to one person.
pub(crate) const SWITCH_ROUTE: &str = "/auth/demo-signin/switch";

/// Whether `path` is one of the demo sign-in routes on the cell origin.
pub(crate) fn is_route(path: &str) -> bool {
    path == ROUTE || path == PEOPLE_ROUTE || path == SWITCH_ROUTE
}

/// The longest a demo sign-in token lives, in microseconds of the cell
/// clock: five minutes.
pub(crate) const LIFETIME_MICROS: i64 = 5 * 60 * 1_000_000;

/// The module every `/app/` page of a demo session loads.
const NOTICE_MODULE: &str = "/assets/demo/notice.js";

/// The module the M3 account page of a demo session loads.
const ACCOUNT_MODULE: &str = "/assets/demo/account.js";

/// The M3 account page, which carries the notice too.
const ACCOUNT_PAGE: &str = "/auth/account";

/// The page of `GET /auth/demo-signin`: no text, no inline script or
/// style. Its module reads the token and says what happened.
const PAGE: &str = "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<meta name=\"referrer\" content=\"no-referrer\">\n<title></title>\n\
<link rel=\"stylesheet\" href=\"/assets/auth/tokens.css\">\n\
<link rel=\"stylesheet\" href=\"/assets/auth/auth.css\">\n\
<script type=\"module\" src=\"/assets/demo/signin.js\"></script>\n\
</head>\n<body>\n<main id=\"main\"></main>\n</body>\n</html>\n";

/// A sign-in link for `account` on the cell origin, with a fresh token.
pub(crate) fn link(info: &SiteInfo, inner: &Inner, account: AccountId) -> Result<String, String> {
    let now = inner.ports.clock.read().micros();
    let token = lock(&inner.auth).demo_token(account, now, LIFETIME_MICROS)?;
    Ok(format!("{}{ROUTE}#{token}", info.origin))
}

/// Whether `token` has the grammar of an issued token: 32 lowercase hex
/// digits.
fn well_formed(token: &str) -> bool {
    token.len() == 32
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Answers the routes of [`is_route`] on a cell started with the flag.
pub(crate) async fn handle(info: &SiteInfo, inner: &Inner, req: Request) -> Response {
    let path = req.target.path().to_owned();
    if path == PEOPLE_ROUTE {
        return match req.method {
            Method::GET => people(inner, &req).await,
            _ => Response::new(StatusCode::METHOD_NOT_ALLOWED),
        };
    }
    if path == SWITCH_ROUTE {
        return match req.method {
            Method::POST => switch(info, inner, &req).await,
            _ => Response::new(StatusCode::METHOD_NOT_ALLOWED),
        };
    }
    match req.method {
        Method::GET => {
            let mut r = info.auth_assets.page_with(PAGE.as_bytes());
            let _ = r.headers.try_insert("x-robots-tag", "noindex");
            r
        }
        Method::POST => {
            if !auth::csrf(info, &req) {
                return refuse(StatusCode::FORBIDDEN, "csrf");
            }
            let Some(body) = wire::body(&req) else {
                return wire::bad("body");
            };
            let Some(token) = wire::str_member(&body, "token").filter(|t| well_formed(t)) else {
                return refuse(StatusCode::FORBIDDEN, "token");
            };
            let now = inner.ports.clock.read().micros();
            let taken = lock(&inner.auth).take_demo_token(token, now, LIFETIME_MICROS);
            match taken {
                Some(account) => auth::open_demo_session(inner, account),
                None => refuse(StatusCode::FORBIDDEN, "token"),
            }
        }
        _ => Response::new(StatusCode::METHOD_NOT_ALLOWED),
    }
}

/// The account of the demo session of `req`, or the refusal: 401 with
/// no session, 403 for a session that no demo sign-in opened.
async fn demo_account(inner: &Inner, req: &Request) -> Result<AccountId, Response> {
    let Some((session, account)) = auth::session(inner, req).await else {
        return Err(refuse(StatusCode::UNAUTHORIZED, "session"));
    };
    if !lock(&inner.auth).is_demo_session(session) {
        return Err(refuse(StatusCode::FORBIDDEN, "demo"));
    }
    Ok(account)
}

/// `GET /auth/demo-signin/people`: the scene and its people for the
/// switcher, with the current person marked. No token is listed.
async fn people(inner: &Inner, req: &Request) -> Response {
    let current = match demo_account(inner, req).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let items: Vec<Value> = crate::demo::scene_people(inner, current)
        .into_iter()
        .map(|p| {
            obj(vec![
                ("account", dec(p.account.raw())),
                ("name", Value::String(p.name)),
                ("email", Value::String(p.email)),
                ("roles", Value::String(p.roles)),
                ("does", Value::String(p.does)),
                ("current", Value::Bool(p.account == current)),
            ])
        })
        .collect();
    wire::json(
        StatusCode::OK,
        &obj(vec![
            ("scene", Value::String(inner.scene())),
            ("people", Value::Array(Array::from(items))),
        ]),
    )
}

/// `POST /auth/demo-signin/switch {account}`: one fresh single-use token
/// for `account`, which must be a person the switcher lists. The page
/// redeems it on [`ROUTE`] at once.
async fn switch(info: &SiteInfo, inner: &Inner, req: &Request) -> Response {
    if !auth::csrf(info, req) {
        return refuse(StatusCode::FORBIDDEN, "csrf");
    }
    let current = match demo_account(inner, req).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let Some(body) = wire::body(req) else {
        return wire::bad("body");
    };
    let Some(raw) = wire::dec_member(&body, "account").and_then(|n| u128::try_from(n).ok()) else {
        return wire::bad("account");
    };
    let target = AccountId::from_raw(raw);
    if !crate::demo::scene_people(inner, current)
        .iter()
        .any(|p| p.account == target)
    {
        return refuse(StatusCode::FORBIDDEN, "account");
    }
    let now = inner.ports.clock.read().micros();
    let issued = lock(&inner.auth).demo_token(target, now, LIFETIME_MICROS);
    match issued {
        Ok(token) => wire::json(StatusCode::OK, &obj(vec![("token", Value::String(token))])),
        Err(_) => refuse(StatusCode::SERVICE_UNAVAILABLE, "random"),
    }
}

/// The demo module the page at `path` of a demo session loads: the
/// notice and the demo step-up on an `/app/` page, the notice alone on
/// the M3 account page, and none elsewhere.
pub(crate) fn module_for(path: &str) -> Option<&'static str> {
    if is_shell_path(path) {
        Some(NOTICE_MODULE)
    } else if path == ACCOUNT_PAGE {
        Some(ACCOUNT_MODULE)
    } else {
        None
    }
}

/// Whether `path` is served by the `/app/` shell.
pub(crate) fn is_shell_path(path: &str) -> bool {
    (path == "/app" || path.starts_with("/app/"))
        && path != "/app/assets"
        && !path.starts_with("/app/assets/")
}

/// Whether the request carries the cookie of a demo sign-in session.
pub(crate) async fn is_demo_session(inner: &Inner, req: &Request) -> bool {
    match auth::session(inner, req).await {
        Some((session, _)) => lock(&inner.auth).is_demo_session(session),
        None => false,
    }
}

/// The page reply `r` with the demo module `module` after the page's own
/// module. Any other reply is returned as it is.
pub(crate) fn mark_shell(mut r: Response, module: &str) -> Response {
    let html = r
        .headers
        .get("content-type")
        .is_some_and(|v| v.as_bytes().starts_with(b"text/html"));
    if r.status != StatusCode::OK || !html {
        return r;
    }
    let tag = format!("<script type=\"module\" src=\"{module}\"></script>\n</head>");
    let text = String::from_utf8_lossy(&r.body).into_owned();
    if let Some(at) = text.find("</head>") {
        let mut out = String::with_capacity(text.len().saturating_add(tag.len()));
        out.push_str(&text[..at]);
        out.push_str(&tag);
        out.push_str(&text[at.saturating_add("</head>".len())..]);
        r.body = out.into_bytes();
    }
    r
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// Scope item 8: a token has one grammar, and anything else is refused
    /// before the token table is read.
    #[test]
    fn demo_signin_token_grammar() {
        assert!(well_formed("0123456789abcdef0123456789abcdef"));
        assert!(!well_formed("0123456789ABCDEF0123456789abcdef"));
        assert!(!well_formed("0123456789abcdef"));
        assert!(!well_formed(""));
    }

    /// Scope item 8: the shell gets the notice module, and no other reply
    /// changes.
    #[test]
    fn demo_signin_marks_the_shell_only() {
        let shell = Response::with_body(
            StatusCode::OK,
            "text/html; charset=utf-8",
            b"<html><head><title>x</title></head><body></body></html>".to_vec(),
        );
        let marked = String::from_utf8(mark_shell(shell, NOTICE_MODULE).body).unwrap();
        assert!(
            marked.contains("/assets/demo/notice.js\"></script>\n</head>"),
            "{marked}"
        );
        let json = Response::with_body(StatusCode::OK, "application/json", b"{}".to_vec());
        assert_eq!(mark_shell(json, NOTICE_MODULE).body, b"{}".to_vec());
        assert!(is_shell_path("/app/"));
        assert!(is_shell_path("/app/me"));
        assert!(!is_shell_path("/app/assets/x.js"));
        assert!(!is_shell_path("/auth/login"));
        assert_eq!(module_for("/app/me"), Some(NOTICE_MODULE));
        assert_eq!(module_for("/auth/account"), Some(ACCOUNT_MODULE));
        assert_eq!(module_for("/auth/login"), None);
        assert_eq!(module_for("/demo"), None);
    }

    /// Lane m4/demo-switch: the switcher's routes are the demo sign-in
    /// routes, and no other path under `/auth` is.
    #[test]
    fn demo_switch_routes_are_demo_signin_routes() {
        assert!(is_route(ROUTE));
        assert!(is_route(PEOPLE_ROUTE));
        assert!(is_route(SWITCH_ROUTE));
        assert!(PEOPLE_ROUTE.starts_with(ROUTE) && SWITCH_ROUTE.starts_with(ROUTE));
        assert!(!is_route("/auth/demo-signin/"));
        assert!(!is_route("/auth/demo-signin/other"));
        assert!(!is_route("/auth/account"));
    }
}
