//! The demo page of one cell, on its loopback control base only (layering
//! rule A9). It is a plain HTML page with no script, for a person running
//! the demo by hand:
//!
//! - `GET /demo`: the scene, every unused one-time sign-in link with the
//!   person it is for, and every message the cell has sent, so a sign-up
//!   proof can be opened without an email server.
//! - `GET /demo/review?stage=<stage>` and `GET /demo/applicant?at=<at>`: a
//!   fresh cell seeded as `POST /test/scenario/*` seeds it.
//! - `GET /demo/reset`: the cell at first start, with its first tenant
//!   admin's link.
//! - `GET /demo/advance?minutes=<n>`: moves the cell clock forward.
//!
//! The scene and clock links change the cell on a GET, so a person can
//! follow them from this page. A request from this page carries
//! `Sec-Fetch-Site: same-origin`, which only the control base itself can
//! send. A cell origin is another site, so no cell page reaches these
//! routes: `Sec-Fetch-Site: cross-site` and any `Origin` are refused, as
//! on the other control routes.

use fstp_http::{Method, Request, Response, StatusCode};

use crate::{Site, control, lock, scenario, wire};

/// The review stages of [`scenario::ReviewAt`], in the order a call runs.
const REVIEW_STAGES: [&str; 7] = [
    "submitted",
    "stage1",
    "stage1_scored",
    "stage2",
    "ranked",
    "ranked_tie",
    "irc_review",
];

/// The applicant states of [`scenario::At`].
const APPLICANT_AT: [&str; 7] = [
    "OPEN_CALL",
    "STAGE2",
    "IRC_REVIEW_MINOR",
    "NEGOTIATION",
    "NOT_SELECTED",
    "DEFERRED_AFTER_CONCERN",
    "INELIGIBLE",
];

/// Whether `req` may use the demo routes: a loopback `Host` of the control
/// base, no `Origin`, and a `Sec-Fetch-Site` of `none` (typed or
/// bookmarked) or `same-origin` (a link on this page), or none at all.
fn allowed(site: &Site, req: &Request) -> bool {
    if req.method != Method::GET || req.headers.get("origin").is_some() {
        return false;
    }
    if let Some(v) = req.headers.get("sec-fetch-site")
        && !matches!(v.as_bytes(), b"none" | b"same-origin")
    {
        return false;
    }
    control::loopback_host(&site.info, req)
}

/// Answers one demo request.
pub(crate) async fn handle(site: &Site, req: Request) -> Response {
    if !allowed(site, &req) {
        return wire::refuse(StatusCode::FORBIDDEN, "control");
    }
    let path = req.target.path().to_owned();
    let done = match path.as_str() {
        "/demo" | "/demo/" => return page(site),
        "/demo/reset" => control::fresh(&site.info).map(|f| site.replace(f.inner)),
        "/demo/review" => match wire::query_param(&req, "stage") {
            Some(s) if REVIEW_STAGES.contains(&s.as_str()) => scenario::demo_review(site, &s).await,
            _ => return wire::bad("stage"),
        },
        "/demo/applicant" => match wire::query_param(&req, "at") {
            Some(a) if APPLICANT_AT.contains(&a.as_str()) => {
                scenario::demo_applicant(site, &a).await
            }
            _ => return wire::bad("at"),
        },
        "/demo/advance" => {
            match wire::query_param(&req, "minutes").and_then(|m| m.parse::<i64>().ok()) {
                Some(m) if (1..=10_080).contains(&m) => {
                    site.inner()
                        .ports
                        .clock
                        .advance(m.saturating_mul(60_000_000));
                    Ok(())
                }
                _ => return wire::bad("minutes"),
            }
        }
        _ => return wire::not_found(),
    };
    match done {
        Ok(()) => {
            let mut r = Response::new(StatusCode::SEE_OTHER);
            let _ = r.headers.try_insert("location", "/demo");
            r
        }
        Err(e) => wire::refuse(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

/// `s` escaped for HTML text and double-quoted attribute values.
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

/// The demo page.
fn page(site: &Site) -> Response {
    let inner = site.inner();
    let auth = lock(&inner.auth);
    let mut people = String::new();
    for (account, url) in auth.open_invites() {
        let email = auth.email_of(account).unwrap_or("");
        let who = scenario::persona_label(account).unwrap_or(email);
        people.push_str(&format!(
            "<li><a href=\"{u}\" target=\"_blank\" rel=\"noopener\">{w}</a> <small>{e}</small></li>\n",
            u = esc(&url),
            w = esc(who),
            e = esc(email),
        ));
    }
    if people.is_empty() {
        people.push_str("<li>Every sign-in link of this scene is used. Signed-in people sign in again at <a href=\"");
        people.push_str(&esc(&format!("{}/auth/login", site.info.origin)));
        people.push_str("\" target=\"_blank\" rel=\"noopener\">/auth/login</a>.</li>\n");
    }
    let mut mail = String::new();
    for m in auth.all_messages().iter().rev() {
        mail.push_str(&format!(
            "<li>{k} to {t}: <a href=\"{l}\" target=\"_blank\" rel=\"noopener\">open</a></li>\n",
            k = esc(m.kind),
            t = esc(&m.to),
            l = esc(&m.link),
        ));
    }
    if mail.is_empty() {
        mail.push_str("<li>No message yet. A sign-up on the cell puts its proof link here.</li>\n");
    }
    drop(auth);
    let now = inner.ports.clock.read().micros();
    let review: String = REVIEW_STAGES
        .iter()
        .map(|s| format!("<a href=\"/demo/review?stage={s}\">{s}</a> "))
        .collect();
    let applicant: String = APPLICANT_AT
        .iter()
        .map(|a| format!("<a href=\"/demo/applicant?at={a}\">{a}</a> "))
        .collect();
    let origin = esc(&site.info.origin);
    let body = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta http-equiv=\"refresh\" content=\"10\">\
<title>FSTP demo, cell {name}</title></head><body>\n\
<h1>FSTP demo, cell {name}</h1>\n\
<p>Test cell with synthetic data only. Cell: <a href=\"{origin}/auth/login\" target=\"_blank\" rel=\"noopener\">{origin}</a>. \
Cell clock: {now} µs. This page reloads every 10 seconds.</p>\n\
<p>Open each link in its own incognito window, choose \"Create a passkey\", and the person is signed in. A link works once.</p>\n\
<h2>People of this scene</h2>\n<ul>\n{people}</ul>\n\
<h2>Messages the cell sent</h2>\n<p>Newest first. To sign up, open {origin}/auth/signup, send a synthetic address such as demo@e2e.invalid, then open its link here.</p>\n<ul>\n{mail}</ul>\n\
<h2>Scenes</h2>\n<p>Each scene replaces the whole cell state and makes new links.</p>\n\
<p>Review: {review}</p>\n<p>Applicant: {applicant}</p>\n\
<p><a href=\"/demo/reset\">Reset</a> (an empty cell and its first tenant admin)</p>\n\
<p>Clock: <a href=\"/demo/advance?minutes=60\">+60 minutes</a> <a href=\"/demo/advance?minutes=1440\">+1 day</a></p>\n\
</body></html>\n",
        name = esc(site.info.name),
    );
    let mut r = Response::with_body(
        StatusCode::OK,
        "text/html; charset=utf-8",
        body.into_bytes(),
    );
    let _ = r.headers.try_insert("cache-control", "no-store");
    let _ = r.headers.try_insert(
        "content-security-policy",
        "default-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
    );
    let _ = r.headers.try_insert("x-content-type-options", "nosniff");
    let _ = r.headers.try_insert("referrer-policy", "no-referrer");
    r
}

#[cfg(test)]
mod tests {
    use super::esc;

    /// The page escapes every value it shows.
    #[test]
    fn demo_page_escapes_html() {
        assert_eq!(
            esc("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }
}
