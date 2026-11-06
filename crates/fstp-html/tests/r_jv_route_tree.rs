//! The route map as checked data (ADR-015 amendment of 2026-11-06,
//! `SPEC/12-journey-ui.md` section 6, TH-26, I-68, R-JV-05; lane j4).
//!
//! Daniel decided on 2026-11-06 that the map is laid out and rendered on
//! the server. In `/app/` the read returns the renderer's checked element
//! tree as data, and the browser only builds that tree with
//! `createElementNS` against the closed SVG subset. These tests pin
//! `fstp_html::route::tree` to `fstp_html::route::svg`:
//!
//! - the shared tree snapshot `testdata/route_stage2.tree.json` is the
//!   golden map `testdata/route_stage2.svg` as data (a reference test,
//!   green from the start; the web tests read both files);
//! - the tree of the prototype state equals that snapshot;
//! - over generated routes, the tree serialises to the bytes of the
//!   rendered map, its wire encoding is the closed shape, it stays in
//!   the closed SVG subset and the checker accepts it;
//! - a canary label stays text in the tree;
//! - `route::statuses` gives the list and the help panels the statuses
//!   the map draws.
//!
//! Lane j4 test author. Red until the implementer builds `route::tree`
//! and `route::statuses`: both stubs refuse every input.
//!
//! Set `FSTP_BLESS=1` to write the tree snapshot again from the golden
//! map after a deliberate change, then review the diff.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::route::{self, ROUTE, Walk, gen_overlay, gen_walk};
use common::tree::{self, TEl, TNode};
use fstp_html::{LabelOverride, check_wellformed};
use fstp_json::ToJson;
use fstp_prop::{check, prop_assert, prop_assert_eq};

/// The golden map, below the crate.
const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/route_stage2.svg");

/// The golden map as data, below the crate. The web tests read it.
const TREE_SNAPSHOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/route_stage2.tree.json"
);

/// The synthetic pseudonymous id the title names.
const SUBJECT: &str = "CSW-2026-0042";

/// The design's prototype state: STAGE2 after DRAFT, SUBMITTED, STAGE1.
fn stage2() -> Walk {
    Walk {
        legs: vec![
            ("DRAFT", "SUBMITTED"),
            ("SUBMITTED", "STAGE1"),
            ("STAGE1", "STAGE2"),
        ],
        position: "STAGE2",
    }
}

/// The `<svg ...>...</svg>` slice of a rendered page.
fn svg_slice(page: &str) -> Result<&str, String> {
    let start = page.find("<svg").ok_or("the page holds no svg")?;
    let end = page.find("</svg>").ok_or("the svg is not closed")? + "</svg>".len();
    Ok(&page[start..end])
}

/// The tree of `walk`, or why it was refused.
fn tree_of(
    walk: &Walk,
    subject: &str,
    overlay: Option<fstp_html::route::RouteOverlay>,
    cats: &fstp_html::Catalogues,
) -> Result<fstp_html::route::SvgTree, String> {
    fstp_html::route::tree(&route::def(), &route::view(subject, walk, overlay), cats)
        .map_err(|e| format!("route::tree refused: {e}"))
}

/// The rendered page of `walk` as text.
fn page_of(
    walk: &Walk,
    subject: &str,
    overlay: Option<fstp_html::route::RouteOverlay>,
    cats: &fstp_html::Catalogues,
) -> Result<String, String> {
    let el = fstp_html::route::svg(&route::def(), &route::view(subject, walk, overlay))
        .map_err(|e| format!("route::svg refused: {e}"))?;
    String::from_utf8(route::page(el, cats)?).map_err(|e| e.to_string())
}

/// ADR-015 amendment, R-JV-05: the tree snapshot is the golden map read
/// as data in the wire shape, so the web tests build from a tree whose
/// bytes are pinned. A reference test: it reads no production tree.
#[test]
fn r_jv_05_tree_snapshot_is_the_golden_map_as_data() {
    let golden = std::fs::read_to_string(GOLDEN).unwrap();
    let parsed = tree::parse(golden.trim_end()).unwrap();
    assert_eq!(
        tree::markup(&parsed),
        golden.trim_end(),
        "the reference reader and serialiser round-trip the golden map"
    );
    assert_eq!(
        tree::subset_faults(&parsed, route::PAGE),
        Vec::<String>::new(),
        "the reference subset accepts the golden map"
    );
    let got = format!("{}\n", tree::to_json(&parsed).to_compact());
    if std::env::var_os("FSTP_BLESS").is_some_and(|v| v == "1") {
        std::fs::write(TREE_SNAPSHOT, &got).unwrap();
    }
    let want = std::fs::read_to_string(TREE_SNAPSHOT).unwrap_or_default();
    assert_eq!(
        got, want,
        "the golden map as data differs from {TREE_SNAPSHOT}"
    );
}

/// ADR-015 amendment, TH-26, R-JV-05: the tree of the prototype state,
/// as the read sends it, equals the shared tree snapshot.
#[test]
fn adr015_route_tree_of_the_prototype_equals_the_tree_snapshot() {
    let cats = route::catalogues(&[]);
    let t = tree_of(&stage2(), SUBJECT, None, &cats).unwrap();
    let want =
        fstp_json::parse(std::fs::read_to_string(TREE_SNAPSHOT).unwrap().as_bytes()).unwrap();
    assert_eq!(
        t.to_json(),
        want,
        "route::tree differs from {TREE_SNAPSHOT}"
    );
}

/// ADR-015 amendment, `SPEC/12-journey-ui.md` section 6 ("SVG output is
/// deterministic"): over generated routes and overlays, the tree's own
/// markup and the reference serialisation of its data both equal the
/// bytes of the map `route::svg` renders.
#[test]
fn adr015_th26_route_tree_markup_equals_the_rendered_map() {
    let cats = route::catalogues(&[]);
    check(
        "adr015_th26_route_tree_markup_equals_the_rendered_map",
        |g| {
            let walk = gen_walk(g);
            let overlay = gen_overlay(g);
            let page = page_of(&walk, SUBJECT, overlay.clone(), &cats)?;
            let want = svg_slice(&page)?;
            let t = tree_of(&walk, SUBJECT, overlay, &cats)?;
            let own = t.markup();
            let data = tree::markup(&tree::of_tree(&t));
            prop_assert_eq!(own.as_str(), want, "the tree's markup");
            prop_assert_eq!(data.as_str(), want, "the tree's data serialised");
            Ok(())
        },
    );
}

/// ADR-015 amendment, TH-26: the wire encoding of every tree is the
/// closed shape of `common::tree`: elements with `tag`, `attrs` and
/// `children` only, texts with `text` only, attributes as name and value
/// in the writer's order.
#[test]
fn adr015_th26_route_tree_json_is_the_closed_shape() {
    let cats = route::catalogues(&[]);
    check("adr015_th26_route_tree_json_is_the_closed_shape", |g| {
        let walk = gen_walk(g);
        let t = tree_of(&walk, SUBJECT, gen_overlay(g), &cats)?;
        prop_assert_eq!(
            t.to_json(),
            tree::to_json(&tree::of_tree(&t)),
            "the wire encoding of the tree"
        );
        Ok(())
    });
}

/// Merges adjacent texts and drops empty ones, as a parser of the markup
/// would.
fn normalised(e: &TEl) -> Vec<String> {
    let mut faults = Vec::new();
    let mut last_text = false;
    for c in &e.children {
        match c {
            TNode::Text(t) => {
                if last_text {
                    faults.push(format!("two adjacent texts in {}", e.tag));
                }
                if t.is_empty() {
                    faults.push(format!("an empty text in {}", e.tag));
                }
                last_text = true;
            }
            TNode::El(x) => {
                last_text = false;
                faults.extend(normalised(x));
            }
        }
    }
    faults
}

/// TH-26, I-68, I-70, ADR-015 amendment: over generated routes, the tree
/// data stays in the closed SVG subset (no script, style, event
/// attribute, foreign element or colour of its own; links only to the
/// page's node fragments; markers inside the document), holds its texts
/// as a parser would, and the page that holds its serialisation passes
/// the well-formedness checker.
#[test]
fn th26_i68_route_tree_stays_in_the_closed_svg_subset() {
    let cats = route::catalogues(&[]);
    check("th26_i68_route_tree_stays_in_the_closed_svg_subset", |g| {
        let walk = gen_walk(g);
        let overlay = gen_overlay(g);
        let t = tree::of_tree(&tree_of(&walk, SUBJECT, overlay.clone(), &cats)?);
        let mut faults = tree::subset_faults(&t, route::PAGE);
        faults.extend(normalised(&t));
        prop_assert!(faults.is_empty(), "outside the subset: {faults:#?}");
        let page = page_of(&walk, SUBJECT, overlay, &cats)?;
        let spliced = page.replacen(svg_slice(&page)?, &tree::markup(&t), 1);
        prop_assert_eq!(
            check_wellformed(spliced.as_bytes()),
            Ok(()),
            "the checker refused the tree"
        );
        Ok(())
    });
}

/// I-68, TW-2: a terminology override and a subject id that hold markup
/// reach the tree as text nodes only. The tree holds no element or
/// attribute the canary names, the canary shows intact in its texts, and
/// its markup holds the canary escaped.
#[test]
fn i68_route_tree_keeps_a_canary_label_as_text() {
    const CANARY: &str = "<script>alert('j4')</script> & \"x\" <img src=x onerror=alert(1)>";
    const SUBJECT_CANARY: &str = "\"><svg onload=alert(1)><a href=\"javascript:x\">";
    let cats = route::catalogues(&[LabelOverride {
        locale: "en",
        id: "journey.node.stage2",
        message: CANARY,
    }]);
    let t = tree_of(&stage2(), SUBJECT_CANARY, None, &cats).unwrap();
    let data = tree::of_tree(&t);
    let faults = tree::subset_faults(&data, route::PAGE);
    assert_eq!(faults, Vec::<String>::new(), "the canary left the subset");
    for tag in ["script", "img", "style", "foreignObject"] {
        let mut found = Vec::new();
        tree::find(&data, tag, &mut found);
        assert!(found.is_empty(), "I-68: a {tag} element in the tree");
    }
    let shown = tree::text(&data);
    assert!(
        shown.contains(CANARY),
        "the canary label shows intact: {shown}"
    );
    assert!(
        shown.contains(SUBJECT_CANARY),
        "the canary subject shows intact"
    );
    let m = t.markup();
    assert!(
        !m.contains("<script") && !m.contains("<img"),
        "raw canary markup: {m}"
    );
    assert!(m.contains("&lt;script&gt;"), "the escaped canary: {m}");
}

/// The status name of the words that end a node's accessible name.
fn status_of_name(name: &str) -> Option<&'static str> {
    [
        ("completed", "completed"),
        ("current stage", "current"),
        ("upcoming", "upcoming"),
        ("possible pause, returns at the stage it left", "pause"),
        ("upcoming, final outcome", "positive_end"),
        ("possible final outcome", "negative_end"),
    ]
    .into_iter()
    .find(|(words, _)| name.ends_with(&format!("), {words}")))
    .map(|(_, s)| s)
}

/// R-JV-05, ADR-015 amendment ("the web derives them from the same
/// server data, never from its own layout"): `route::statuses` names
/// every state once in route order, with the status the map's node link
/// of that state names.
#[test]
fn r_jv_05_route_statuses_agree_with_the_map() {
    let cats = route::catalogues(&[]);
    check("r_jv_05_route_statuses_agree_with_the_map", |g| {
        let walk = gen_walk(g);
        let view = route::view(SUBJECT, &walk, None);
        let got = fstp_html::route::statuses(&route::def(), &view)
            .map_err(|e| format!("route::statuses refused: {e}"))?;
        let page = page_of(&walk, SUBJECT, None, &cats)?;
        let svg = tree::parse(svg_slice(&page)?)?;
        let mut links = Vec::new();
        tree::find(&svg, "a", &mut links);
        let drawn: Vec<(String, &'static str)> = links
            .iter()
            .map(|a| {
                let state = a
                    .attr("href")
                    .and_then(|h| h.rsplit_once("#node-"))
                    .map(|(_, s)| s.to_owned())
                    .unwrap_or_default();
                let status = a.attr("aria-label").and_then(status_of_name).unwrap_or("");
                (state, status)
            })
            .collect();
        let order: Vec<&str> = ROUTE.iter().map(|s| s.name).collect();
        let named: Vec<&str> = got.iter().map(|(s, _)| s.as_str()).collect();
        prop_assert_eq!(named, order, "route order");
        prop_assert_eq!(got, drawn, "the statuses the map draws");
        Ok(())
    });
}
