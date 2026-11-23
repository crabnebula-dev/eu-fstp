//! M10 finding F-083 (lane H-05b, H05b-1), TH-26, TH-37, R-PB-04,
//! adapted from the lane's proof of concept.
//!
//! The cell front read the raw request path to decide whether an answer is
//! public, and the router percent-decodes each segment before it matches.
//! So `/%70/{slug}/` reached the public page handler with the cell CSP and
//! no cookie strip, and every cell route answered under any encoded
//! spelling of its literal segments, `POST /api/v1/%63ommands` included.
//! Daniel decided on 2026-11-23 (ADR-026 amendment of that date) that the
//! front refuses a path that percent-encodes an unreserved character, and
//! takes the header profile from the endpoint that answered.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing)]

use fstp_cell::http::front::{CELL_CSP, PUBLIC_CSP};
use fstp_cell::routes::memory::LocalCell;
use fstp_cell::routes::{draft_table, public_table, registration_table, site_table, table};
use fstp_http::{Method, Request, RequestTarget, Response};

const CELL: [u8; 16] = [0xB2; 16];
const HOST: &str = "tenant-b.fstp.test";

fn request(method: &str, path: &str) -> Request {
    let m = Method::from_bytes(method.as_bytes()).unwrap();
    let mut req = Request::new(m, RequestTarget::origin(path).unwrap())
        .try_with_header("host", HOST)
        .unwrap();
    if method != "GET" {
        req = req
            .try_with_header("origin", format!("https://{HOST}"))
            .unwrap()
            .try_with_header("content-type", "application/json")
            .unwrap();
        req.body = b"{}".to_vec();
    }
    req
}

fn csp(r: &Response) -> String {
    r.headers
        .get("content-security-policy")
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .unwrap_or_default()
}

/// Control, R-PB-04: the plain spelling answers the public page with the
/// public CSP.
#[test]
fn m10_f083_control_plain_public_path_has_the_public_csp() {
    let c = LocalCell::start(CELL, HOST).unwrap();
    let r = c.serve(request("GET", "/p/supersafe/"));
    assert_eq!(r.status.as_u16(), 403);
    assert!(String::from_utf8_lossy(&r.body).contains("Not published yet"));
    assert_eq!(csp(&r), PUBLIC_CSP);
}

/// F-083, R-PB-04, TH-37: an encoded spelling of a public route is refused
/// with 400 before any handler runs, so no public answer leaves with the
/// cell profile.
#[test]
fn m10_f083_r_pb_04_encoded_public_path_is_refused() {
    let c = LocalCell::start(CELL, HOST).unwrap();
    for path in ["/%70/supersafe/", "/p/%73upersafe/", "/%50/supersafe/"] {
        let r = c.serve(request("GET", path));
        assert_eq!(r.status.as_u16(), 400, "{path}");
        assert!(
            !String::from_utf8_lossy(&r.body).contains("Not published yet"),
            "{path}: the public handler answered"
        );
    }
}

/// The path of `pattern` with each parameter filled, and the same path
/// with the first character of its first literal segment percent-encoded
/// in upper and in lower case hexadecimal.
fn spellings(pattern: &str) -> (String, [String; 2]) {
    let plain: String = pattern
        .split('/')
        .map(|s| if s.starts_with('{') { "abc" } else { s })
        .collect::<Vec<_>>()
        .join("/");
    let first = plain.as_bytes()[1];
    let rest = &plain[2..];
    (
        plain.clone(),
        [
            format!("/%{first:02X}{rest}"),
            format!("/%{first:02x}{rest}"),
        ],
    )
}

/// F-083, TH-26: every route of the cell has one spelling. A path that
/// percent-encodes an unreserved character of a literal segment is refused
/// with 400 under the rule TH-26, for every route of every table, before
/// any handler runs. That covers the raw command route of F-039 and F-040,
/// so no encoded spelling reaches its handler.
#[test]
fn m10_f083_th26_cell_routes_have_one_spelling() {
    let c = LocalCell::start(CELL, HOST).unwrap();
    let routes = table()
        .iter()
        .chain(public_table())
        .chain(site_table())
        .chain(draft_table())
        .chain(registration_table());
    let mut checked = 0;
    for route in routes {
        let (method, pattern, _) = route.parts();
        if pattern == "/healthz" {
            continue;
        }
        let (plain, encoded) = spellings(pattern);
        for path in encoded {
            let r = c.serve(request(method, &path));
            assert_eq!(
                r.status.as_u16(),
                400,
                "TH-26: {method} {path} ({plain}) answered"
            );
            assert!(
                matches!(
                    c.logs().last(),
                    Some(fstp_obs::LogEvent::Refused { rule: "TH-26", .. })
                ),
                "{method} {path}"
            );
            checked += 1;
        }
    }
    assert!(checked > 40, "{checked}");
    let r = c.serve(request("POST", "/api/v1/%63ommands"));
    assert_eq!(
        r.status.as_u16(),
        400,
        "F-039: the encoded raw route answered"
    );
    let r = c.serve(request("POST", "/api/v1/command%73"));
    assert_eq!(
        r.status.as_u16(),
        400,
        "F-039: the encoded raw route answered"
    );
}

/// F-083, R-PB-04, TH-37: the header profile follows the endpoint that
/// answered. Every public endpoint answers with the public CSP, and so
/// does the unrouted answer under `/p/`. Every other route answers with
/// the cell CSP.
#[test]
fn m10_f083_r_pb_04_header_profile_follows_the_endpoint() {
    let c = LocalCell::start(CELL, HOST).unwrap();
    for route in public_table() {
        let (method, pattern, _) = route.parts();
        let (plain, _) = spellings(pattern);
        let r = c.serve(request(method, &plain));
        assert_eq!(csp(&r), PUBLIC_CSP, "{method} {plain}");
        assert!(r.headers.get("set-cookie").is_none(), "{plain}");
    }
    let r = c.serve(request("GET", "/p/abc/no/such/page"));
    assert_eq!(csp(&r), PUBLIC_CSP, "the unrouted public answer");
    for route in table()
        .iter()
        .chain(draft_table())
        .chain(registration_table())
    {
        let (method, pattern, _) = route.parts();
        if pattern == "/healthz" {
            continue;
        }
        let (plain, _) = spellings(pattern);
        let r = c.serve(request(method, &plain));
        assert_eq!(csp(&r), CELL_CSP, "{method} {plain}");
    }
}
