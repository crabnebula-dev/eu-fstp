//! Review of lane j4 (markup safety and leaks): the public route map is
//! readable as served (I-70, R-JV-06, `SPEC/12-journey-ui.md` section 6).
//!
//! `fstp-api-core/src/dispatch/public.rs` renders every `/p` page with
//! `Chrome { stylesheet: None }`, so a served call page links no
//! stylesheet. An SVG `rect` and `text` with no `fill` paint in black.
//! The public map writes every node label and formal state name as black
//! text on a black node shape, so a sighted visitor reads none of it.
//!
//! Reviewer test. Red until the served call page carries the route's
//! paint: a same-origin stylesheet under the `/p` CSP, or a map that
//! paints its own shapes inside the closed subset.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use fstp_public::{Chrome, PublicPage, render_html};
use support::{count, sample_view};

/// I-70, R-JV-06: the call page as `/p` serves it (no stylesheet) holds
/// the route map, and every node shape of that map is painted by a rule
/// the page loads. Today no stylesheet is linked and no shape carries a
/// fill, so text and shape are both black (contrast 1:1).
#[test]
fn review_j4_i70_served_public_route_is_painted() {
    // The chrome production uses (`dispatch/public.rs`, `answer`).
    let served = Chrome { stylesheet: None };
    let html = render_html(
        &sample_view(true),
        &PublicPage::Call("3".to_owned()),
        &served,
    )
    .map(|d| d.as_str().to_owned())
    .unwrap_or_else(|e| panic!("the call page renders: {e}"));
    let shapes = count(&html, "class=\"node-shape\"");
    assert!(shapes > 0, "R-JV-06: the served call page holds the map");
    let styled = html.contains("rel=\"stylesheet\"");
    let self_painted = html
        .split("<rect")
        .skip(1)
        .all(|r| r.split('>').next().is_some_and(|a| a.contains(" fill=")));
    assert!(
        styled || self_painted,
        "I-70: {shapes} node shapes on the served call page paint in the SVG \
         default (black) under black label text: no stylesheet is linked and no \
         shape carries a fill"
    );
}
