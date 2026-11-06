//! The route map snapshot shared with the web app (ADR-015 "Rendering",
//! `SPEC/12-journey-ui.md` section 6 "SVG output is deterministic for
//! identical inputs (snapshot-testable)"; R-JV-05; lane j3).
//!
//! The `/app/` pages run under Trusted Types with no HTML sink, so the
//! browser cannot take the renderer's markup as a string. The web app
//! builds the same tree with `createElementNS` (`web/src/journey/svg.ts`).
//! This test pins the renderer's map of the design's prototype state in
//! `testdata/route_stage2.svg`, and `web/test/journey.test.ts`
//! (`r_jv_05_web_map_equals_the_renderer_snapshot`) checks that the web
//! builder serialises to the same bytes. A drift on either side fails.
//!
//! Set `FSTP_BLESS=1` to write the snapshot again after a deliberate
//! change, then review the diff.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::route::{self, Walk};

/// The snapshot file, below the crate.
const SNAPSHOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/route_stage2.svg");

/// The synthetic pseudonymous id the title names.
const SUBJECT: &str = "CSW-2026-0042";

/// The `<svg ...>...</svg>` slice of a rendered page.
fn svg_slice(page: &str) -> &str {
    let start = page.find("<svg").expect("the page holds an svg");
    let end = page.find("</svg>").expect("the svg is closed") + "</svg>".len();
    &page[start..end]
}

/// ADR-015, R-JV-05: the map of the design's STAGE2 state equals the
/// shared snapshot byte for byte.
#[test]
fn r_jv_05_route_map_equals_the_shared_snapshot() {
    let walk = Walk {
        legs: vec![
            ("DRAFT", "SUBMITTED"),
            ("SUBMITTED", "STAGE1"),
            ("STAGE1", "STAGE2"),
        ],
        position: "STAGE2",
    };
    let cats = route::catalogues(&[]);
    let page = route::svg_page(&walk, SUBJECT, &cats).unwrap();
    let page = String::from_utf8(page).unwrap();
    let got = format!("{}\n", svg_slice(&page));
    if std::env::var_os("FSTP_BLESS").is_some_and(|v| v == "1") {
        std::fs::write(SNAPSHOT, &got).unwrap();
    }
    let want = std::fs::read_to_string(SNAPSHOT).unwrap_or_default();
    assert_eq!(got, want, "the map differs from {SNAPSHOT}");
}
