//! I-84, ADR-026 "Composition": the production front matches the cell
//! table first and hands every other path of the web adapter's surfaces
//! to `fstp_web`. So no method and path of the cell's tables may also be
//! a route of an `ApiCore` operation: such an operation could never be
//! reached, and the two paths into the gate would differ for one request.
//!
//! Two surfaces are shared by decision. Daniel decided on 2026-11-17
//! that the production cell serves the public surface `/p/` itself
//! (`crate::public`, M4 design section 3.10): each shared `/p/` route is
//! the same public read of the API core's registry, answered by the cell,
//! and the web adapter never sees `/p/` on this front. The other shared
//! template is the site stylesheet route
//! `GET /app/assets/{file}`: the front serves a platform stylesheet there
//! and hands every other file to the web adapter, so no request is
//! answered by the wrong side.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_cell::routes::{page_table, public_table, site_table, table};

/// Whether two route templates can match one concrete path: the same
/// number of segments, each pair equal or one of them a `{param}`.
fn overlap(a: &str, b: &str) -> bool {
    let (sa, sb): (Vec<&str>, Vec<&str>) = (a.split('/').collect(), b.split('/').collect());
    sa.len() == sb.len()
        && sa.iter().zip(&sb).all(|(x, y)| {
            x == y
                || (x.starts_with('{') && x.ends_with('}'))
                || (y.starts_with('{') && y.ends_with('}'))
        })
}

fn method(m: fstp_access::Method) -> &'static str {
    match m {
        fstp_access::Method::Get => "GET",
        fstp_access::Method::Post => "POST",
        fstp_access::Method::Put => "PUT",
        fstp_access::Method::Delete => "DELETE",
    }
}

/// I-84, ADR-026: no cell route and no `ApiCore` operation route share a
/// method and a path, and the templates overlap check has teeth.
#[test]
fn t_cell_and_web_routes_do_not_overlap() {
    assert!(overlap("/api/v1/calls/{call}", "/api/v1/calls/7"));
    assert!(!overlap("/api/v1/calls/{call}", "/api/v1/calls/7/x"));
    assert!(!overlap("/api/v1/commands", "/api/v1/calls"));
    let cell: Vec<(&str, &str)> = table()
        .iter()
        .chain(public_table())
        .chain(site_table())
        .chain(page_table())
        .map(|r| {
            let (m, p, _) = r.parts();
            (m, p)
        })
        .filter(|(_, p)| *p != fstp_cell::http::site::SHEET_ROUTE)
        .collect();
    assert!(!cell.is_empty());
    // The web adapter serves an operation's route under `/api/v1`, and a
    // public read under its own `/p/` path (`fstp_web`).
    let web: Vec<(&str, String, &str)> = fstp_access::OPS
        .iter()
        .filter_map(|op| {
            op.route.map(|(m, p)| {
                let path = if p.starts_with("/p/") {
                    p.to_owned()
                } else {
                    format!("/api/v1{p}")
                };
                (method(m), path, op.name)
            })
        })
        .collect();
    assert!(
        web.iter()
            .any(|(_, p, _)| p == "/api/v1/me/pending-actions"),
        "the API routes are compared under their prefix"
    );
    assert!(web.len() > 50, "the registry lists the API core's routes");
    let mut clashes = Vec::new();
    for (cm, cp) in &cell {
        for (wm, wp, name) in &web {
            if cm == wm && overlap(cp, wp.as_str()) {
                // The public surface is the cell's own: the same public
                // read, never a web route it shadows.
                let public =
                    cp.starts_with("/p/") && name.starts_with("public.") && *cp == wp.as_str();
                if !public {
                    clashes.push(format!("{cm} {cp} and {name} {wp}"));
                }
            }
        }
    }
    assert!(clashes.is_empty(), "I-84: shared routes {clashes:#?}");
}
