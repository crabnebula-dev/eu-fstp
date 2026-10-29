//! Public pages work without scripts, carry no tracking and set no cookie
//! (R-PB-04, TH-37, T-PUB-PRIVACY, `public-transparency.md`, M4 design
//! sections 3.10 and 8.8).
//!
//! `fstp-public` is not on the demo path, so `/p` is a stub route of
//! `fstp-web` in this lane. The rules hold for whatever `/p` answers: the
//! CSP of design section 3.10 with `script-src 'none'`, no `Set-Cookie`, a
//! session cookie that changes nothing, and no script or third-party
//! asset in the body.
//!
//! Lane W4e's test author wrote these tests before the adapter exists.
//! They reach it only through [`serve`], which calls the W0 stub of
//! `fstp_web::handle_op_request`. So each is red because the stub
//! refuses. Once `fstp_web::WebReply` exposes its response, the
//! production agent replaces the seam body with one conversion.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_web::WebError;

/// The tenant host of the stub configuration of `handle_op_request`.
const HOST: &str = "tenant.fstp.test";

/// The CSP of every `/p` response, verbatim from design section 3.10.
const PUBLIC_CSP: &str = "default-src 'none'; script-src 'none'; style-src 'self'; \
     img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// A session cookie field value: the M3 cookie name and 96 hexadecimal
/// digits. Synthetic.
const SESSION_COOKIE: &str = "__Host-fstp=\
     5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\
     5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

/// Every public route of design section 3.10, for a synthetic programme.
const PUBLIC_PATHS: &[&str] = &[
    "/p/supersafe/",
    "/p/supersafe/calls/c1",
    "/p/supersafe/calls/c1/guide",
    "/p/supersafe/funded",
    "/p/supersafe/finished",
    "/p/supersafe/feed.json",
    "/p/no-such-programme/",
];

/// One response, as these tests read it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Reply {
    status: u16,
    /// Field names in lowercase, with their values, in order.
    fields: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

impl Reply {
    /// Every value of the field `name`.
    fn values(&self, name: &str) -> Vec<String> {
        self.fields
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
            .collect()
    }
}

/// Runs a `GET` of `path` through the web adapter, with a session cookie
/// when `cookie` is set.
fn serve(path: &str, cookie: bool) -> Result<Reply, String> {
    let mut raw = format!("GET {path} HTTP/1.1\r\nHost: {HOST}\r\n");
    if cookie {
        raw.push_str(&format!("Cookie: {SESSION_COOKIE}\r\n"));
    }
    raw.push_str("\r\n");
    match fstp_web::handle_op_request(raw.as_bytes()) {
        Err(WebError::NotImplemented(op)) => Err(format!("stub (lane W4e, NotImplemented): {op}")),
        #[allow(unreachable_patterns, reason = "production adds refusal variants")]
        Err(other) => Err(format!("refused: {other:?}")),
        Ok(reply) => {
            let r = reply.into_response();
            Ok(Reply {
                status: r.status.as_u16(),
                fields: r
                    .headers
                    .iter()
                    .map(|(n, v)| (n.as_str().to_owned(), v.as_bytes().to_vec()))
                    .collect(),
                body: r.body,
            })
        }
    }
}

/// Runs `check` on the reply to every public path, with and without a
/// session cookie, and panics with every failure at once.
fn every_public_reply(check: impl Fn(&Reply) -> Result<(), String>) {
    let mut failures = Vec::new();
    for path in PUBLIC_PATHS {
        for cookie in [false, true] {
            let outcome = serve(path, cookie).and_then(|r| check(&r));
            if let Err(e) = outcome {
                failures.push(format!("{path} (cookie {cookie}): {e}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// R-PB-04: every public response carries exactly the public CSP, which
/// allows no script at all.
#[test]
fn r_pb_04_public_pages_carry_the_scriptless_csp() {
    every_public_reply(|r| {
        let csp = r.values("content-security-policy");
        if csp == [PUBLIC_CSP] {
            Ok(())
        } else {
            Err(format!("CSP {csp:?}"))
        }
    });
}

/// `Ok` when `r` sets no cookie.
fn sets_no_cookie(r: &Reply) -> Result<(), String> {
    let set = r.values("set-cookie");
    if set.is_empty() {
        Ok(())
    } else {
        Err(format!("Set-Cookie {set:?}"))
    }
}

/// R-PB-04, TH-37: no public response sets a cookie, with or without a
/// session cookie in the request.
#[test]
fn r_pb_04_th37_public_pages_set_no_cookie() {
    every_public_reply(sets_no_cookie);
}

/// R-PB-04, TH-37, T-PUB-PRIVACY: the test M4 design section 5.1 names
/// for TH-37. Every public route sets no cookie, and its body loads no
/// script and no third-party asset, with or without a session cookie.
#[test]
fn r_pb_04_public_routes_set_no_cookie_and_load_no_script() {
    every_public_reply(|r| sets_no_cookie(r).and_then(|()| loads_no_script(r)));
}

/// R-PB-04, TH-37: the session cookie is ignored on public pages. The
/// response with it equals the response without it, byte for byte.
#[test]
fn r_pb_04_th37_session_cookie_is_ignored() {
    let mut failures = Vec::new();
    for path in PUBLIC_PATHS {
        match (serve(path, false), serve(path, true)) {
            (Ok(a), Ok(b)) if a == b => {}
            (Ok(_), Ok(_)) => failures.push(format!("{path}: the cookie changed the response")),
            (Err(e), _) | (_, Err(e)) => failures.push(format!("{path}: {e}")),
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The quoted value of every `name=` attribute in `html`, lowercased.
fn attribute_values(html: &str, name: &str) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    for quote in ['"', '\''] {
        let needle = format!("{name}={quote}");
        let mut from = 0;
        while let Some(i) = lower[from..].find(&needle) {
            let start = from + i + needle.len();
            let end = lower[start..]
                .find(quote)
                .map_or(lower.len(), |e| start + e);
            out.push(lower[start..end].to_owned());
            from = end;
        }
    }
    out
}

/// `Ok` when the body of `r` holds no script, no embedded frame or
/// object, no event handler and no asset from another origin.
fn loads_no_script(r: &Reply) -> Result<(), String> {
    let html = String::from_utf8_lossy(&r.body).to_ascii_lowercase();
    for banned in ["<script", "<iframe", "<object", "<embed", "javascript:"] {
        if html.contains(banned) {
            return Err(format!("the body holds {banned:?}"));
        }
    }
    for tag in html.split('<').skip(1) {
        let head = tag.split('>').next().unwrap_or("");
        if head
            .split_ascii_whitespace()
            .skip(1)
            .any(|w| w.starts_with("on"))
        {
            return Err(format!("event handler attribute in <{head}>"));
        }
    }
    let mut sources = attribute_values(&html, "src");
    sources.extend(attribute_values(&html, "srcset"));
    sources.extend(attribute_values(&html, "poster"));
    for tag in html.split("<link").skip(1) {
        let head = tag.split('>').next().unwrap_or("");
        sources.extend(attribute_values(head, "href"));
    }
    for s in sources {
        let t = s.trim_start();
        if t.starts_with("http:") || t.starts_with("https:") || t.starts_with("//") {
            return Err(format!("an asset from another origin: {s:?}"));
        }
    }
    if html.contains("url(http") || html.contains("url(//") || html.contains("@import") {
        return Err("a style that loads from another origin".to_owned());
    }
    Ok(())
}

/// R-PB-04, TH-37: no public body holds a script, an embedded frame or
/// object, an event handler, or an asset from another origin.
#[test]
fn r_pb_04_th37_no_script_and_no_third_party_asset() {
    every_public_reply(loads_no_script);
}
