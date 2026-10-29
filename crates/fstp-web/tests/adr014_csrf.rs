//! CSRF and `Origin` rules of the web adapter (ADR-014 "CSRF", M4 design
//! sections 3.9 and 5.2).
//!
//! State-changing requests need an `Origin` equal to the tenant origin and
//! an `X-FSTP-Request: 1` header. `web_common` states the readings these
//! tests share: the check covers every state-changing method under
//! `/api/v1/`, before routing, with or without a credential. Lane W4e's
//! test author wrote them before the adapter exists, so each is red
//! because the W0 stub of `fstp_web::handle_op_request` refuses.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod web_common;

use fstp_prop::Gen;
use web_common::{
    SESSION_COOKIE, TENANT_ORIGIN, all, csrf_refused, good_fields, is_csrf_refusal, request, serve,
    with, without,
};

/// State-changing requests over routes of the design and an unknown route.
const CHANGING: &[(&str, &str)] = &[
    ("POST", "/api/v1/programmes"),
    ("PUT", "/api/v1/programmes/p1/draft/fields"),
    ("POST", "/api/v1/calls/c1/publication"),
    ("PATCH", "/api/v1/proposals/x1/workspace"),
    ("DELETE", "/api/v1/me/sessions/s1"),
    ("POST", "/api/v1/no-such-route"),
];

/// The response to a state-changing request with `fields` and a `{}` body.
fn send(method: &str, path: &str, fields: &[(&str, &str)]) -> fstp_http::Response {
    serve(&request(method, path, fields, b"{}")).unwrap_or_else(|e| panic!("{method} {path}: {e}"))
}

/// ADR-014: a state-changing request with the tenant origin and the
/// request header is not refused by the CSRF rule.
#[test]
fn adr014_csrf_tenant_origin_and_header_pass() {
    all(CHANGING, |(m, p)| {
        let r = send(m, p, &good_fields());
        if is_csrf_refusal(&r) {
            Err("refused by the CSRF rule".to_owned())
        } else {
            Ok(())
        }
    });
}

/// ADR-014: a state-changing request without `Origin` is refused.
#[test]
fn adr014_csrf_missing_origin_is_refused() {
    all(CHANGING, |(m, p)| {
        csrf_refused(&send(m, p, &without("Origin")))
    });
}

/// ADR-014: an `Origin` other than the tenant origin is refused: another
/// site, another scheme or port, a subdomain, the vault origin, a
/// trailing slash, `null` and an empty value.
#[test]
fn adr014_csrf_foreign_origins_are_refused() {
    const FOREIGN: &[&str] = &[
        "https://evil.test",
        "http://tenant.fstp.test",
        "https://tenant.fstp.test:8443",
        "https://x.tenant.fstp.test",
        "https://id.tenant.fstp.test",
        "https://tenant.fstp.test.evil.test",
        "https://fstp.test",
        "https://tenant.fstp.test/",
        "null",
        "",
    ];
    let cases: Vec<(&str, &str, &str)> = CHANGING
        .iter()
        .flat_map(|(m, p)| FOREIGN.iter().map(move |o| (*m, *p, *o)))
        .collect();
    all(&cases, |(m, p, o)| {
        csrf_refused(&send(m, p, &with("Origin", &[o])))
    });
}

/// ADR-014: two `Origin` fields are refused, even when both name the
/// tenant origin.
#[test]
fn adr014_csrf_duplicated_origin_is_refused() {
    let pairs: [&[&'static str]; 3] = [
        &[TENANT_ORIGIN, TENANT_ORIGIN],
        &[TENANT_ORIGIN, "https://evil.test"],
        &["https://evil.test", TENANT_ORIGIN],
    ];
    let cases: Vec<(&str, &str, &[&'static str])> = CHANGING
        .iter()
        .flat_map(|(m, p)| pairs.iter().map(move |o| (*m, *p, *o)))
        .collect();
    all(&cases, |(m, p, o)| {
        csrf_refused(&send(m, p, &with("Origin", o)))
    });
}

/// ADR-014: a missing, wrong or duplicated `X-FSTP-Request` is refused.
#[test]
fn adr014_csrf_missing_or_wrong_request_header_is_refused() {
    let variants: [&[&'static str]; 7] = [
        &[],
        &["0"],
        &["true"],
        &["01"],
        &["1, 1"],
        &["2"],
        &["1", "1"],
    ];
    let cases: Vec<(&str, &str, &[&'static str])> = CHANGING
        .iter()
        .flat_map(|(m, p)| variants.iter().map(move |v| (*m, *p, *v)))
        .collect();
    all(&cases, |(m, p, v)| {
        csrf_refused(&send(m, p, &with("X-FSTP-Request", v)))
    });
}

/// ADR-014: the rule holds for a request without a session cookie, so a
/// login-style forgery is refused too.
#[test]
fn adr014_csrf_applies_without_a_session_cookie() {
    let fields: Vec<(&str, &str)> = without("Cookie")
        .into_iter()
        .filter(|(n, _)| *n != "Origin")
        .collect();
    all(CHANGING, |(m, p)| csrf_refused(&send(m, p, &fields)));
}

/// ADR-014 "Desktop client seam": M4 builds no bearer path for `/api/v1`,
/// so a bearer token does not lift the CSRF rule.
#[test]
fn adr014_csrf_bearer_token_does_not_bypass_in_m4() {
    let fields = [
        ("Authorization", "Bearer c3ludGhldGljLXRva2Vu"),
        ("Content-Type", "application/json"),
    ];
    all(CHANGING, |(m, p)| csrf_refused(&send(m, p, &fields)));
}

/// ADR-014: a `GET` with a session cookie and no `Origin` is not refused
/// by the CSRF rule, so navigation and reads work.
#[test]
fn adr014_csrf_safe_methods_need_no_origin() {
    let paths = ["/api/v1/me/notices", "/api/v1/programmes/p1/draft", "/app/"];
    all(&paths, |p| {
        let r = serve(&request("GET", p, &[("Cookie", SESSION_COOKIE)], b""))
            .unwrap_or_else(|e| panic!("GET {p}: {e}"));
        if is_csrf_refusal(&r) {
            Err("refused by the CSRF rule".to_owned())
        } else {
            Ok(())
        }
    });
}

/// Methods outside `GET` and `HEAD` that the CSRF reading also covers:
/// `OPTIONS`, `TRACE` and extension methods.
const OTHER_METHODS: &[&str] = &["OPTIONS", "TRACE", "PROPFIND", "FSTP-X"];

/// ADR-014: the CSRF rule covers every method except `GET` and `HEAD`.
/// `OPTIONS`, `TRACE` and an extension method without `Origin`, or with a
/// foreign one, are refused under `/api/v1/`.
#[test]
fn adr014_csrf_covers_options_and_extension_methods() {
    all(OTHER_METHODS, |m| {
        for fields in [
            without("Origin"),
            with("Origin", &["https://evil.test"]),
            without("X-FSTP-Request"),
        ] {
            let r = serve(&request(m, "/api/v1/programmes", &fields, b""))
                .unwrap_or_else(|e| panic!("{m}: {e}"));
            csrf_refused(&r)?;
        }
        Ok(())
    });
}

/// ADR-014: `OPTIONS`, `TRACE` and an extension method with the tenant
/// origin and the request header pass the CSRF rule. No CORS preflight is
/// answered, so the reply grants no cross-origin access.
#[test]
fn adr014_csrf_other_methods_with_tenant_origin_pass() {
    all(OTHER_METHODS, |m| {
        let r = serve(&request(m, "/api/v1/programmes", &good_fields(), b""))
            .unwrap_or_else(|e| panic!("{m}: {e}"));
        if is_csrf_refusal(&r) {
            return Err("refused by the CSRF rule".to_owned());
        }
        if r.headers
            .iter()
            .any(|(n, _)| n.as_str().starts_with("access-control-"))
        {
            return Err("the reply carries an Access-Control field".to_owned());
        }
        Ok(())
    });
}

/// A serialised origin that is not the tenant origin.
fn foreign_origin(g: &mut Gen) -> String {
    const LABELS: &[&str] = &["tenant", "fstp", "test", "evil", "id", "x", "tenant-fstp"];
    let scheme = if g.bool() { "https" } else { "http" };
    let labels = g.vec(1..=4, |g| (*g.pick(LABELS)).to_owned());
    let port = g.option(|g| g.u16_in(1..=65535));
    let mut o = format!("{scheme}://{}", labels.join("."));
    if let Some(p) = port {
        o.push_str(&format!(":{p}"));
    }
    if o == TENANT_ORIGIN {
        g.reject();
    }
    o
}

/// ADR-014: every generated origin other than the tenant origin is
/// refused on every state-changing method.
#[test]
fn adr014_csrf_generated_foreign_origin_is_refused() {
    fstp_prop::check("adr014_csrf_generated_foreign_origin_is_refused", |g| {
        let origin = foreign_origin(g);
        let (m, p) = *g.pick(CHANGING);
        g.note("origin", &origin);
        let mut fields: Vec<(&str, &str)> = without("Origin");
        fields.push(("Origin", origin.as_str()));
        csrf_refused(&send(m, p, &fields))
    });
}
