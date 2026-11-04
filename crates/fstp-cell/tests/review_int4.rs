//! Review reproducers for lane int4 (security and fidelity lens).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_cell::http::pages::{ASSET_ROUTES, PAGE_PATHS};
use fstp_cell::routes::{page_table, table};

/// I-78, H-01, ADR-008 "Every route needs a risk class": every path the
/// cell front serves is a `Route`, so it carries a reviewed risk class.
/// `Front::with_pages` used to register the page shells and asset routes
/// straight on the router, with no risk class.
///
/// Corrected by lane int4, fix round 1. The reproducer first asked for
/// the page rows in `routes::table()`. That table must stay exactly
/// design section 8.7 (`i78_h_01_production_routes_are_exactly_section_8_7`
/// here, `i78_production_routes_have_the_section_8_7_risk_classes` in
/// `fstp-celltest`), and section 8.7 lists no page but `GET /auth/magic`.
/// So the page rows are `Route`s of `routes::page_table()`, served only
/// by the `dev-pages` front through the shared checks.
#[test]
fn review_page_routes_bypass_the_risk_class_table() {
    let routed: Vec<(&str, &str)> = table()
        .iter()
        .chain(page_table())
        .map(|r| {
            let (m, p, _) = r.parts();
            (m, p)
        })
        .collect();
    let outside: Vec<&str> = PAGE_PATHS
        .iter()
        .chain(ASSET_ROUTES.iter())
        .copied()
        .filter(|p| !routed.contains(&("GET", *p)))
        .collect();
    assert!(
        outside.is_empty(),
        "the front serves GET routes with no risk class, outside every route table: {outside:?}"
    );
}
