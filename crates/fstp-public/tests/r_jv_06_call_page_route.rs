//! The public call page shows the programme's route as static SVG
//! (R-JV-06, R-PB-04, ADR-015 "Rendering" and its amendment of
//! 2026-11-06, `SPEC/12-journey-ui.md` sections 6 and 8.5, I-96, TH-26;
//! lane j4).
//!
//! The map is laid out and rendered on the server by `fstp-html`, and
//! `/p` serves it as static SVG markup with no script. A public reader
//! has no position on the route, so the map shows every node as the
//! route's own (upcoming, pause or final outcome), never "current" or
//! "completed".
//!
//! The rest of the call page keeps every rule of `r_pb_04_pages.rs`. Its
//! `scriptless` check refuses `url(`, so the public map carries no marker
//! reference: an interim reading, pending the lead.
//!
//! Lane j4 test author. Red until the call page holds the route.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod support;

use fstp_prop::{check, prop_assert, prop_assert_eq};
use fstp_public::{Chrome, PublicPage, render_html};
use support::{chrome, count, gen_view, sample_view, scriptless};

/// The sixteen formal states of the proposal route (I-96).
const STATES: [&str; 16] = [
    "DRAFT",
    "SUBMITTED",
    "STAGE1",
    "STAGE2",
    "RANKED",
    "IRC_REVIEW",
    "NEGOTIATION",
    "GRANTED",
    "IN_EXECUTION",
    "COMPLETED",
    "DEFERRED",
    "INELIGIBLE",
    "NOT_SELECTED",
    "DECLINED",
    "WITHDRAWN",
    "TERMINATED",
];

/// The call page of `id` in the sample view, as text.
fn call_page(id: &str) -> String {
    let view = sample_view(true);
    match render_html(&view, &PublicPage::Call(id.to_owned()), &chrome()) {
        Ok(doc) => doc.as_str().to_owned(),
        Err(e) => panic!("the call page of {id}: {e}"),
    }
}

/// The one `<svg ...>...</svg>` of `html`, or why there is not one.
fn the_svg(html: &str) -> Result<&str, String> {
    let n = count(html, "<svg");
    if n != 1 {
        return Err(format!("{n} svg elements, not one"));
    }
    let start = html.find("<svg").unwrap_or(0);
    let end = html
        .find("</svg>")
        .map(|e| e + "</svg>".len())
        .ok_or("the svg is not closed")?;
    Ok(&html[start..end])
}

/// R-JV-06, R-PB-04, I-96: the call page holds one route map, the
/// renderer's `route-svg` group, in which every node names its formal
/// state. The page stays well formed and scriptless.
#[test]
fn r_jv_06_call_page_shows_the_route_as_static_svg() {
    let html = call_page("3");
    let svg = the_svg(&html).unwrap_or_else(|e| panic!("R-JV-06: {e}: {html}"));
    assert!(
        svg.starts_with("<svg class=\"route-svg\""),
        "the renderer's map: {svg}"
    );
    assert!(svg.contains(" role=\"group\""), "a named group: {svg}");
    assert!(svg.contains("<title"), "the map has a title: {svg}");
    for s in STATES {
        assert!(
            svg.contains(&format!("({s})")),
            "I-96: no node names {s}: {svg}"
        );
    }
    assert_eq!(fstp_html::check_wellformed(html.as_bytes()), Ok(()));
    assert_eq!(scriptless(&html), Ok(()), "R-PB-04");
}

/// R-JV-06, section 8.5: the public map shows no viewer's position. No
/// node is current or completed, no edge is done, and no ring or
/// `aria-current` marks a place on the route.
#[test]
fn r_jv_06_public_route_shows_no_viewer_position() {
    let html = call_page("3");
    let svg = the_svg(&html).unwrap_or_else(|e| panic!("R-JV-06: {e}: {html}"));
    for marker in [
        "current stage",
        "), completed",
        "svg-current",
        "svg-complete",
        "current-ring",
        "edge--done",
        "aria-current",
        "The current stage is",
    ] {
        assert!(
            !svg.contains(marker),
            "a viewer position: {marker} in {svg}"
        );
    }
}

/// R-JV-06, R-PB-04, TH-37: over generated views, every open call page
/// holds exactly one route map, and stays well formed and scriptless.
#[test]
fn r_jv_06_every_call_page_holds_one_route_map() {
    check("r_jv_06_every_call_page_holds_one_route_map", |g| {
        let view = gen_view(g);
        for c in &view.open_calls {
            let doc = render_html(&view, &PublicPage::Call(c.id.clone()), &chrome())
                .map_err(|e| format!("the call page of {}: {e}", c.id))?;
            let html = doc.as_str();
            prop_assert!(the_svg(html).is_ok(), "R-JV-06: {:?}", the_svg(html).err());
            prop_assert_eq!(fstp_html::check_wellformed(html.as_bytes()), Ok(()));
            prop_assert_eq!(scriptless(html), Ok(()), "R-PB-04");
        }
        Ok(())
    });
}

/// The start tags of `svg` named `name`, each as its attribute text.
fn start_tags<'a>(svg: &'a str, name: &str) -> Vec<&'a str> {
    let open = format!("<{name} ");
    let bare = format!("<{name}>");
    svg.match_indices('<')
        .map(|(i, _)| &svg[i..])
        .filter(|t| t.starts_with(&open) || t.starts_with(&bare))
        .filter_map(|t| t.split('>').next())
        .collect()
}

/// I-70, R-JV-06, review J4-REV-1: `/p` serves the call page with no
/// stylesheet (`Chrome { stylesheet: None }`), and an SVG shape or text
/// with no paint fills black. So the public map paints itself in the
/// page's own text colour: every node shape and edge strokes in
/// `currentColor` with no fill, and every text fills in `currentColor`
/// at a whole font size. No other colour appears.
#[test]
fn i70_served_public_route_paints_itself_in_the_text_colour() {
    let served = Chrome {
        stylesheet: None,
        funder: None,
    };
    let html = render_html(
        &sample_view(true),
        &PublicPage::Call("3".to_owned()),
        &served,
    )
    .map(|d| d.as_str().to_owned())
    .unwrap_or_else(|e| panic!("the call page renders: {e}"));
    assert!(
        !html.contains("rel=\"stylesheet\""),
        "the served page links no sheet"
    );
    let svg = the_svg(&html).unwrap_or_else(|e| panic!("R-JV-06: {e}: {html}"));
    let mut problems = Vec::new();
    let shapes = start_tags(svg, "rect");
    let edges: Vec<&str> = start_tags(svg, "path")
        .into_iter()
        .chain(start_tags(svg, "line"))
        .collect();
    let texts = start_tags(svg, "text");
    for t in shapes.iter().chain(&edges) {
        if !t.contains(" stroke=\"currentColor\"") {
            problems.push(format!("no stroke: {t}"));
        }
        if !t.starts_with("<line") && !t.contains(" fill=\"none\"") {
            problems.push(format!("a filled shape: {t}"));
        }
    }
    for t in &texts {
        if !t.contains(" fill=\"currentColor\"") || !t.contains(" font-size=\"") {
            problems.push(format!("an unpainted text: {t}"));
        }
    }
    assert_eq!(shapes.len(), 16, "one shape per node");
    assert!(!edges.is_empty(), "the map draws its edges");
    assert_eq!(
        texts.len(),
        16 * 3 + 2,
        "glyph, label, formal name, two notes"
    );
    assert_eq!(problems, Vec::<String>::new(), "I-70: unpainted parts");
    for v in svg
        .split(" fill=\"")
        .skip(1)
        .chain(svg.split(" stroke=\"").skip(1))
    {
        let value = v.split('"').next().unwrap_or("");
        assert!(
            value == "currentColor" || value == "none",
            "I-70: a colour of its own: {value}"
        );
    }
}
