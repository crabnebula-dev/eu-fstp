//! The cell's public routes answer as the web adapter answers them (exit
//! audit item 9, lane m4/pubtext): the platform stylesheets, the styled
//! "Page not found" page, the route refusal of an unknown `/p` path, the
//! SA-09 redirects and the ADR-021 gate of a ledger with no tenant part.
//! R-NF-03, R-PB-04, I-70, SA-09, ADR-021.
//!
//! The local cell's ledger holds no tenant part, so its organisation port
//! answers, and the default port fails closed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_cell::http::site;
use fstp_cell::routes::memory::LocalCell;
use fstp_http::{Method, Request, RequestTarget, Response};

const CELL: [u8; 16] = [0xB2; 16];
const HOST: &str = "tenant-b.fstp.test";

fn cell() -> LocalCell {
    LocalCell::start(CELL, HOST).unwrap()
}

/// `GET path`, as a script asks for it (no Fetch metadata, no HTML).
fn get(path: &str) -> Request {
    Request::new(Method::GET, RequestTarget::origin(path).unwrap())
        .try_with_header("host", HOST)
        .unwrap()
}

/// `GET path`, as a browser navigates to it.
fn navigate(path: &str) -> Request {
    get(path)
        .try_with_header("sec-fetch-mode", "navigate")
        .unwrap()
        .try_with_header("accept", "text/html")
        .unwrap()
}

fn header<'a>(r: &'a Response, name: &str) -> Option<&'a [u8]> {
    r.headers.get(name).map(|v| v.as_bytes())
}

fn body(r: &Response) -> String {
    String::from_utf8(r.body.clone()).unwrap()
}

/// R-NF-03, I-70: the cell serves each platform sheet at its content
/// address as CSS, and an unknown asset as the web adapter's 404.
#[test]
fn r_nf_03_cell_serves_the_platform_sheets() {
    let c = cell();
    let paths: Vec<&str> = site::sheet_paths().collect();
    assert_eq!(paths.len(), 2);
    for path in paths {
        let r = c.serve(get(path));
        assert_eq!(r.status.as_u16(), 200, "{path}");
        assert_eq!(header(&r, "content-type"), Some(site::CSS.as_bytes()));
        assert_eq!(Some(r.body.as_slice()), site::sheet(path));
    }
    let r = c.serve(get("/app/assets/tokens.css"));
    assert_eq!(r.status.as_u16(), 404);
    assert_eq!(body(&r), r#"{"code":"not_found"}"#);
}

/// ADR-021 decision 3, R-PB-04: with no tenant part and the default port,
/// a `/p` page answers 403 with the "not published yet" page, which links
/// the platform sheets and carries the public CSP. The feed keeps the
/// JSON refusal.
#[test]
fn adr021_cell_with_no_tenant_part_answers_not_published() {
    let c = cell();
    let r = c.serve(get("/p/supersafe/"));
    assert_eq!(r.status.as_u16(), 403);
    let html = body(&r);
    assert!(html.contains("Not published yet"), "{html}");
    for href in site::sheet_paths() {
        assert!(html.contains(&format!("href=\"{href}\"")), "{html}");
    }
    assert!(
        header(&r, "content-security-policy")
            .is_some_and(|v| v.starts_with(b"default-src 'none'; script-src 'none'"))
    );
    let r = c.serve(get("/p/supersafe/feed.json"));
    assert_eq!(r.status.as_u16(), 403);
    assert_eq!(body(&r), r#"{"code":"refused","rule":"ADR-021"}"#);
}

/// SA-09 amendment: a path under `/p/` that no route matches answers the
/// web adapter's route refusal to a script, and goes to the programme's
/// public home when a browser asks. Before activation every slug's home
/// answers its "not published yet" page, so the browser goes there, as
/// the web adapter's router sends it.
#[test]
fn sa09_unknown_public_path_answers_as_the_web_adapter() {
    let c = cell();
    for path in [
        "/p/supersafe/nope",
        "/p/supersafe",
        "/p/supersafe/calls/1/x",
    ] {
        let r = c.serve(get(path));
        assert_eq!(r.status.as_u16(), 404, "{path}");
        assert_eq!(body(&r), r#"{"code":"not_found","rule":"route"}"#, "{path}");
        let r = c.serve(navigate(path));
        assert_eq!(r.status.as_u16(), 303, "{path}");
        assert_eq!(header(&r, "location"), Some(b"/p/supersafe/".as_slice()));
    }
    // A malformed slug names no public home: the browser goes home.
    let r = c.serve(navigate("/p/Bad/"));
    assert_eq!(r.status.as_u16(), 303);
    assert_eq!(header(&r, "location"), Some(b"/app/".as_slice()));
}

/// SA-09: home `/app/`, where the redirects land, answers the styled
/// "Page not found" page with 404, the platform sheets and no script.
/// Another unknown path keeps its answers: 404 to a script, 303 home to
/// a browser.
#[test]
fn sa09_home_answers_the_styled_not_found_page() {
    let c = cell();
    for req in [get("/app/"), navigate("/app/")] {
        let r = c.serve(req);
        assert_eq!(r.status.as_u16(), 404);
        let html = body(&r);
        assert!(html.contains("Page not found"), "{html}");
        assert!(!html.to_ascii_lowercase().contains("<script"), "{html}");
        for href in site::sheet_paths() {
            assert!(html.contains(&format!("href=\"{href}\"")), "{html}");
        }
    }
    let r = c.serve(get("/nowhere"));
    assert_eq!(r.status.as_u16(), 404);
    assert!(r.body.is_empty());
    let r = c.serve(navigate("/nowhere"));
    assert_eq!(r.status.as_u16(), 303);
    assert_eq!(header(&r, "location"), Some(b"/app/".as_slice()));
}
