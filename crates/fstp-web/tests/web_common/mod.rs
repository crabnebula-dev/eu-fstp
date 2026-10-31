//! Shared helpers of the `fstp-web` tests (lane W4e, test author).
//!
//! The tests were written before the web adapter exists. They reach
//! production only through [`serve`] and [`parse_origin`]. Each either
//! calls the W0 stub, which refuses with `WebError::NotImplemented`, or
//! refuses with a [`Red::Seam`] that names the production API it waits
//! for. So every test is red for that reason only. The production agent
//! of lane W4e replaces each seam body with one call into `fstp_web`, and
//! the tests then run unchanged.
//!
//! # Readings the web tests share
//!
//! ADR-014 and M4 design sections 1.1, 3.8 and 3.9 fix the rules but not
//! every status code, body or order of checks. These tests read them as
//! follows. Each is an interim reading, pending Daniel, and each is stated
//! once here.
//!
//! - `fstp_web::handle_op_request` runs the `fstp-web` router over a stub
//!   dispatch and a stub asset set, for the tenant origin
//!   [`TENANT_ORIGIN`]. Only the dispatch and the assets differ from the
//!   router `fstp-cell` mounts, so routes, headers, CSRF, Origin and
//!   limits are the production ones.
//! - CSRF (ADR-014): every `POST`, `PUT`, `PATCH` and `DELETE` to a path
//!   under `/api/v1/` needs exactly one `Origin` equal to the tenant origin
//!   and exactly one `X-FSTP-Request: 1`. The check runs before routing,
//!   with or without a credential. A bearer token does not bypass it in
//!   M4, since the desktop client seam is not built. A refusal is 403 with
//!   the JSON body `{"code":"refused","rule":"ADR-014"}`.
//! - `GET` needs no `Origin`, so navigation and reads work.
//! - The body limit of `/api/v1` is the `fstp-http` default of 1 MiB. A
//!   longer body gets 413.
//! - `/mcp`, `/mcp/public`, `/oauth/**` and the two OAuth `/.well-known`
//!   documents wait for ADR-013. Each method gets 501 with the JSON body
//!   `{"code":"not_available","rule":"ADR-013"}`.
//! - `/app/` and every `/app/` path outside `/app/assets/` serve the same
//!   shell, with `Cache-Control: no-store`, so a cached shell never names
//!   a stale asset.
//! - Every `/api/v1` response carries `Cache-Control: no-store`.
//! - Every response carries `X-Content-Type-Options: nosniff`,
//!   `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy:
//!   same-origin`, `Cross-Origin-Resource-Policy: same-origin`, HSTS with a
//!   `max-age` of at least one year, and exactly one CSP. Every `/app`
//!   response carries [`APP_CSP`] and every `/p` response [`PUBLIC_CSP`],
//!   byte for byte. Every other CSP holds `default-src 'none'`,
//!   `frame-ancestors 'none'` and `base-uri 'none'`.
//! - No response carries `Set-Cookie` or an `Access-Control-Allow-*`
//!   field. Session cookies are M3's.

#![allow(dead_code, reason = "each test binary uses a different part")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test fixtures assert on known-good values"
)]

use std::fmt;

use fstp_http::Response;
use fstp_web::WebError;

// ---------------------------------------------------------------------------
// Readings.

/// The tenant host of the stub configuration.
pub(crate) const HOST: &str = "tenant.fstp.test";

/// The tenant origin of the stub configuration.
pub(crate) const TENANT_ORIGIN: &str = "https://tenant.fstp.test";

/// The CSP of every `/app` response, verbatim from design section 3.9 and
/// ADR-014.
pub(crate) const APP_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
     img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; \
     frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; \
     trusted-types fstp-dom";

/// The CSP of every `/p` response, verbatim from design section 3.10.
pub(crate) const PUBLIC_CSP: &str = "default-src 'none'; script-src 'none'; style-src 'self'; \
     img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// A session cookie field value: the M3 cookie name and 96 hexadecimal
/// digits. Synthetic.
pub(crate) const SESSION_COOKIE: &str = "__Host-fstp=\
     5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\
     5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

/// The largest `/api/v1` body that is not refused for its size.
pub(crate) const BODY_LIMIT: usize = 1024 * 1024;

/// One year in seconds, the least HSTS `max-age` these tests accept.
pub(crate) const ONE_YEAR: u64 = 31_536_000;

/// A sample of request paths over every surface of the router.
pub(crate) const SURFACES: &[&str] = &[
    "/app/",
    "/app/calls/c1",
    "/api/v1/me/notices",
    "/api/v1/no-such-route",
    "/p/supersafe/",
    "/p/supersafe/calls/c1/guide",
    "/mcp",
    "/mcp/public",
    "/oauth/authorize",
    "/oauth/token",
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-authorization-server",
    "/no-such-path",
];

// ---------------------------------------------------------------------------
// Seams.

/// Why a test could not reach production yet, or why production refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Red {
    /// The W0 stub refused with `NotImplemented`.
    Stub(&'static str),
    /// A seam waits for the named production API.
    Seam(&'static str),
    /// Production refused with a typed error other than `NotImplemented`.
    Refused(String),
}

impl fmt::Display for Red {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Red::Stub(op) => write!(f, "stub (lane W4e, NotImplemented): {op}"),
            Red::Seam(api) => write!(f, "seam (lane W4e, NotImplemented): {api}"),
            Red::Refused(e) => write!(f, "refused: {e}"),
        }
    }
}

/// Maps a web error to [`Red`], keeping the stub refusal apart.
fn red(e: WebError) -> Red {
    match e {
        WebError::NotImplemented(op) => Red::Stub(op),
        #[allow(unreachable_patterns, reason = "production adds refusal variants")]
        other => Red::Refused(format!("{other:?}")),
    }
}

/// Runs one raw request through the adapter and returns its response.
pub(crate) fn serve(raw: &[u8]) -> Result<Response, Red> {
    fstp_web::handle_op_request(raw)
        .map(fstp_web::WebReply::into_response)
        .map_err(red)
}

/// Parses an `Origin` value. `Ok` holds the parsed value for equality.
pub(crate) fn parse_origin(bytes: &[u8]) -> Result<fstp_web::Origin, Red> {
    fstp_web::parse_origin_header(bytes).map_err(red)
}

// ---------------------------------------------------------------------------
// Requests.

/// A raw HTTP/1.1 request to the tenant host. `fields` follow `Host` in
/// order. A body, or a state-changing method, adds `Content-Length`.
pub(crate) fn request(method: &str, path: &str, fields: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("{method} {path} HTTP/1.1\r\nHost: {HOST}\r\n").into_bytes();
    for (name, value) in fields {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    let changing = matches!(method, "POST" | "PUT" | "PATCH" | "DELETE");
    if changing || !body.is_empty() {
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// The response to a `GET` of `path` with no other field. Panics with the
/// reason when the adapter cannot answer.
pub(crate) fn get(path: &str) -> Response {
    serve(&request("GET", path, &[], b"")).unwrap_or_else(|e| panic!("GET {path}: {e}"))
}

/// The fields of a state-changing API request that passes CSRF, with a
/// session cookie and a JSON body type.
pub(crate) fn good_fields() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Cookie", SESSION_COOKIE),
        ("Origin", TENANT_ORIGIN),
        ("X-FSTP-Request", "1"),
        ("Content-Type", "application/json"),
    ]
}

/// [`good_fields`] without every field named `name`.
pub(crate) fn without(name: &str) -> Vec<(&'static str, &'static str)> {
    good_fields()
        .into_iter()
        .filter(|(n, _)| !n.eq_ignore_ascii_case(name))
        .collect()
}

/// [`good_fields`] with every field named `name` replaced by `values`.
pub(crate) fn with(
    name: &'static str,
    values: &[&'static str],
) -> Vec<(&'static str, &'static str)> {
    let mut f = without(name);
    for v in values {
        f.push((name, v));
    }
    f
}

// ---------------------------------------------------------------------------
// Predicates.

/// Every value of the response field `name`, as text.
pub(crate) fn header_values(resp: &Response, name: &str) -> Vec<String> {
    resp.headers
        .get_all(name)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .collect()
}

/// The one value of the response field `name`.
pub(crate) fn one_header(resp: &Response, name: &str) -> Result<String, String> {
    let mut v = header_values(resp, name);
    if v.len() == 1 {
        Ok(v.remove(0))
    } else {
        Err(format!(
            "{name}: {} values, want exactly one: {v:?}",
            v.len()
        ))
    }
}

/// `Ok` when the field `name` appears once with exactly `want`.
pub(crate) fn header_is(resp: &Response, name: &str, want: &str) -> Result<(), String> {
    let got = one_header(resp, name)?;
    if got == want {
        Ok(())
    } else {
        Err(format!("{name}: {got:?}, want {want:?}"))
    }
}

/// The response body as one JSON object's members, when it is one.
pub(crate) fn json_members(resp: &Response) -> Option<Vec<(String, String)>> {
    let v = fstp_json::parse(&resp.body).ok()?;
    let o = v.as_object()?;
    Some(
        o.iter()
            .map(|(k, v)| {
                (
                    k.to_owned(),
                    v.as_str().unwrap_or("<not a string>").to_owned(),
                )
            })
            .collect(),
    )
}

/// The string member `key` of a JSON object body.
pub(crate) fn json_str(resp: &Response, key: &str) -> Option<String> {
    json_members(resp)?
        .into_iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
}

/// Whether `resp` is the CSRF refusal of the readings above.
pub(crate) fn is_csrf_refusal(resp: &Response) -> bool {
    resp.status.as_u16() == 403
        && json_str(resp, "code").as_deref() == Some("refused")
        && json_str(resp, "rule").as_deref() == Some("ADR-014")
}

/// `Ok` when `resp` is the CSRF refusal.
pub(crate) fn csrf_refused(resp: &Response) -> Result<(), String> {
    if is_csrf_refusal(resp) {
        Ok(())
    } else {
        Err(format!(
            "not the CSRF refusal: status {}, body {:?}",
            resp.status.as_u16(),
            String::from_utf8_lossy(&resp.body)
        ))
    }
}

/// `Ok` when `resp` is the typed ADR-013 refusal of the readings above.
pub(crate) fn adr013_refused(resp: &Response) -> Result<(), String> {
    if resp.status.as_u16() != 501 {
        return Err(format!("status {}, want 501", resp.status.as_u16()));
    }
    let ct = one_header(resp, "content-type")?;
    if !ct.starts_with("application/json") {
        return Err(format!("content-type {ct:?}"));
    }
    let members = json_members(resp).ok_or("the body is not a JSON object")?;
    let want = [
        ("code".to_owned(), "not_available".to_owned()),
        ("rule".to_owned(), "ADR-013".to_owned()),
    ];
    let mut got = members;
    got.sort();
    if got != want {
        return Err(format!("body members {got:?}, want {want:?}"));
    }
    Ok(())
}

/// The directives of a CSP value, trimmed, in order.
pub(crate) fn csp_directives(csp: &str) -> Vec<String> {
    csp.split(';')
        .map(|d| d.trim().to_owned())
        .filter(|d| !d.is_empty())
        .collect()
}

/// `Ok` when `resp` carries the headers every response carries, for a
/// request to `path`.
pub(crate) fn baseline(resp: &Response, path: &str) -> Result<(), String> {
    header_is(resp, "x-content-type-options", "nosniff")?;
    header_is(resp, "referrer-policy", "no-referrer")?;
    header_is(resp, "cross-origin-opener-policy", "same-origin")?;
    header_is(resp, "cross-origin-resource-policy", "same-origin")?;
    let hsts = one_header(resp, "strict-transport-security")?;
    let age = hsts
        .split(';')
        .map(str::trim)
        .find_map(|d| d.strip_prefix("max-age="))
        .and_then(|n| n.parse::<u64>().ok())
        .ok_or_else(|| format!("HSTS {hsts:?} has no max-age"))?;
    if age < ONE_YEAR {
        return Err(format!("HSTS max-age {age} is under one year"));
    }
    let csp = one_header(resp, "content-security-policy")?;
    if path == "/app" || path.starts_with("/app/") {
        if csp != APP_CSP {
            return Err(format!("{path}: CSP {csp:?}, want the app CSP"));
        }
    } else if path.starts_with("/p/") {
        if csp != PUBLIC_CSP {
            return Err(format!("{path}: CSP {csp:?}, want the public CSP"));
        }
    } else {
        let d = csp_directives(&csp);
        for want in [
            "default-src 'none'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
        ] {
            if !d.iter().any(|x| x == want) {
                return Err(format!("{path}: CSP {csp:?} lacks {want:?}"));
            }
        }
    }
    Ok(())
}

/// `Ok` when `resp` sets no cookie and grants no cross-origin read.
pub(crate) fn no_cookie_no_cors(resp: &Response) -> Result<(), String> {
    if resp.headers.contains("set-cookie") {
        return Err("the response sets a cookie".to_owned());
    }
    let cors: Vec<String> = resp
        .headers
        .iter()
        .map(|(n, _)| n.as_str().to_ascii_lowercase())
        .filter(|n| n.starts_with("access-control-"))
        .collect();
    if cors.is_empty() {
        Ok(())
    } else {
        Err(format!("the response carries {cors:?}"))
    }
}

/// Whether `s` is 64 lowercase hexadecimal digits.
pub(crate) fn is_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Runs `check` over `cases` and panics with every failure at once.
pub(crate) fn all<T: fmt::Debug>(cases: &[T], check: impl Fn(&T) -> Result<(), String>) {
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|c| check(c).err().map(|e| format!("{c:?}: {e}")))
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}
