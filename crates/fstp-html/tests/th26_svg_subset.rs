//! The closed SVG subset of the well-formedness checker (TH-26, H-05,
//! I-68, R-PB-04; ADR-015 "Rendering home and zones"; lane j3).
//!
//! ADR-015 puts the route SVG renderer in `fstp-html` and asks the
//! checker to accept the SVG elements and attributes the renderer emits,
//! and nothing else: no script, no event attribute, no foreign object,
//! no animation element and no reference to another resource. The
//! subset is defined once, in `common::reference` ("The SVG subset").
//!
//! - th26_svg_checker_accepts_each_fixed_svg: each fixed document of the
//!   subset, including the prototype's map in the subset's spelling.
//! - th26_svg_checker_refuses_each_fixed_refusal: each refusal breaks one
//!   rule of an accepted base document, which both sides accept first.
//! - th26_svg_checker_matches_the_reference: on generated SVG fragments
//!   with allowed and forbidden parts, the checker and the reference give
//!   the same verdict.
//!
//! Lane j3 test author. Red until the implementer extends the checker:
//! today it refuses every `svg` element.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::cases::with_body;
use common::reference;
use fstp_html::check_wellformed;
use fstp_prop::{Gen, check, prop_assert_eq};

/// A node link of the map, as the design draws it.
const NODE: &str = concat!(
    "<a href=\"/app/proposals/1001/progress#node-STAGE2\" aria-label=\"Stage 2 questions (STAGE2), current stage\" class=\"svg-current\">",
    "<title>Stage 2 questions (STAGE2), current stage</title>",
    "<rect class=\"current-ring\" x=\"332\" y=\"133\" width=\"116\" height=\"74\" rx=\"14\"></rect>",
    "<rect class=\"node-shape\" x=\"338\" y=\"139\" width=\"104\" height=\"62\" rx=\"10\"></rect>",
    "<text class=\"node-glyph\" x=\"347\" y=\"152\" aria-hidden=\"true\">\u{25CF}</text>",
    "<text class=\"node-label\" text-anchor=\"middle\"><tspan x=\"390\" y=\"162\">Stage 2</tspan>",
    "<tspan x=\"390\" y=\"174\">questions</tspan></text>",
    "<text class=\"node-formal\" x=\"390\" y=\"195\" text-anchor=\"middle\">STAGE2</text>",
    "</a>",
);

/// The base map: title, desc, a marker, edges and one node.
fn base_svg(inner: &str) -> String {
    format!(
        concat!(
            "<figure><svg class=\"route-svg\" viewbox=\"0 0 1110 430\" role=\"group\" aria-labelledby=\"rt rd\">",
            "<title id=\"rt\">Progress map for CSW-2026-0042</title>",
            "<desc id=\"rd\">The current stage is Stage 2 questions (STAGE2).</desc>",
            "<defs><marker id=\"arrow\" viewbox=\"0 0 10 10\" refx=\"9\" refy=\"5\" markerwidth=\"7\" markerheight=\"7\" orient=\"auto-start-reverse\">",
            "<path d=\"M0 0 L10 5 L0 10 z\" fill=\"currentColor\" class=\"arrow-head\"></path></marker></defs>",
            "<line id=\"edge-T-DRAFT-SUBMITTED\" class=\"edge edge--done\" x1=\"112\" y1=\"170\" x2=\"118\" y2=\"170\" marker-end=\"url(#arrow)\"></line>",
            "<path id=\"edge-T-DEFERRED-STAGE2\" class=\"edge edge--loop\" d=\"M503 288 Q 380 300 370 201\" marker-end=\"url(#arrow)\"></path>",
            "<g class=\"leave\"><path class=\"edge edge--leave\" d=\"M8 130 L8 118 L772 118 L772 130\"></path>",
            "<text class=\"node-formal\" x=\"12\" y=\"112\">Withdraw: possible in any state before GRANTED, including DEFERRED</text></g>",
            "{node}{inner}</svg></figure>",
        ),
        node = NODE,
        inner = inner,
    )
}

/// The base page with `inner` added at the end of the `svg`.
fn doc(inner: &str) -> Vec<u8> {
    with_body(&base_svg(inner))
}

/// Documents of the SVG subset.
fn accepted() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("the base map", doc("")),
        ("an empty svg", with_body("<svg></svg>")),
        (
            "svg in a paragraph",
            with_body("<p>Map: <svg role=\"img\" aria-label=\"x\"></svg></p>"),
        ),
        (
            "layout whitespace in svg containers",
            with_body(
                "<svg>\n  <g>\n    <rect x=\"0\" y=\"0\" width=\"1\" height=\"1\"></rect>\n  </g>\n</svg>",
            ),
        ),
        (
            "escaped markup in an svg title",
            with_body(
                "<svg><title>&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;</title></svg>",
            ),
        ),
        (
            "a circle and a group link",
            with_body(
                "<svg><a href=\"/app/proposals/1001/progress#node-DRAFT\"><g><circle cx=\"5\" cy=\"5\" r=\"4\"></circle></g></a></svg>",
            ),
        ),
        (
            "fill none",
            with_body("<svg><path d=\"M0 0\" fill=\"none\"></path></svg>"),
        ),
    ]
}

/// Documents outside the SVG subset, each breaking one rule of the base.
fn refused() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("script in svg", doc("<script>alert(1)</script>")),
        ("style in svg", doc("<style>a{}</style>")),
        (
            "foreign object",
            doc("<foreignobject><p>x</p></foreignobject>"),
        ),
        ("animate", doc("<animate></animate>")),
        ("set", doc("<set></set>")),
        (
            "animatetransform",
            doc("<animatetransform></animatetransform>"),
        ),
        ("animatemotion", doc("<animatemotion></animatemotion>")),
        ("use", doc("<use href=\"/x#arrow\"></use>")),
        ("image", doc("<image href=\"/a.png\"></image>")),
        ("iframe in svg", doc("<iframe></iframe>")),
        ("an HTML p in svg", doc("<p>x</p>")),
        ("an HTML div in svg", doc("<div>x</div>")),
        ("an HTML span in svg", doc("<span>x</span>")),
        ("nested svg", doc("<svg></svg>")),
        ("math in svg", doc("<math></math>")),
        (
            "onclick on an svg link",
            doc("<a href=\"/app/proposals/1001/progress#node-X\" onclick=\"alert(1)\"></a>"),
        ),
        ("onload on a rect", doc("<rect onload=\"alert(1)\"></rect>")),
        (
            "onmouseover on text",
            doc("<text onmouseover=\"x\">t</text>"),
        ),
        ("onfocus on a group", doc("<g onfocus=\"x\"></g>")),
        ("style attribute", doc("<rect style=\"fill:red\"></rect>")),
        (
            "namespaced href",
            doc("<a xlink:href=\"/app/proposals/1001/progress#node-X\"></a>"),
        ),
        (
            "javascript link",
            doc("<a href=\"javascript:alert(1)\"></a>"),
        ),
        ("data link", doc("<a href=\"data:text/html,x\"></a>")),
        (
            "marker to another origin",
            doc("<path d=\"M0 0\" marker-end=\"url(https://evil.example/m.svg#a)\"></path>"),
        ),
        (
            "marker not a reference",
            doc("<path d=\"M0 0\" marker-end=\"none\"></path>"),
        ),
        (
            "fill by reference",
            doc("<path d=\"M0 0\" fill=\"url(#g)\"></path>"),
        ),
        (
            "fill colour",
            doc("<path d=\"M0 0\" fill=\"#ff0000\"></path>"),
        ),
        (
            "stroke colour",
            doc("<path d=\"M0 0\" stroke=\"red\"></path>"),
        ),
        ("text directly in a group", doc("<g>x</g>")),
        ("text directly in svg", doc("x")),
        ("markup in an svg title", doc("<title><b>x</b></title>")),
        (
            "markup in a tspan",
            doc("<text><tspan><tspan>x</tspan></tspan></text>"),
        ),
        ("self-closing path", doc("<path d=\"M0 0\"/>")),
        (
            "nested svg link",
            doc("<a href=\"/x#a\"><a href=\"/x#b\"></a></a>"),
        ),
        ("tspan outside text", doc("<tspan>x</tspan>")),
        ("marker outside defs", doc("<marker id=\"m\"></marker>")),
        (
            "unknown svg element",
            doc("<polygon points=\"0,0 1,1\"></polygon>"),
        ),
        (
            "camel-case attribute",
            with_body("<svg viewBox=\"0 0 1 1\"></svg>"),
        ),
        ("camel-case element", doc("<foreignObject></foreignObject>")),
        ("cdata in svg", doc("<text><![CDATA[x]]></text>")),
        (
            "svg inside an HTML link",
            with_body("<a href=\"/x#x\"><svg></svg></a>"),
        ),
        (
            "svg inside a button",
            with_body("<button><svg></svg></button>"),
        ),
        (
            "svg element outside svg",
            with_body("<rect x=\"0\"></rect>"),
        ),
        (
            "svg title outside svg",
            with_body("<p><title>x</title></p>"),
        ),
        ("svg in a list", with_body("<ul><svg></svg></ul>")),
        (
            "xmlns attribute",
            with_body("<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"),
        ),
    ]
}

fn shown(doc: &[u8]) -> String {
    String::from_utf8_lossy(doc).into_owned()
}

/// TH-26, ADR-015: the checker accepts each fixed document of the SVG
/// subset, which the reference accepts too.
#[test]
fn th26_svg_checker_accepts_each_fixed_svg() {
    let mut failures = Vec::new();
    for (what, d) in accepted() {
        if let Err(e) = reference::parse(&d) {
            failures.push(format!("reference refuses {what}: {e}"));
        }
        if let Err(e) = check_wellformed(&d) {
            failures.push(format!("checker refuses {what}: {e}: {}", shown(&d)));
        }
    }
    assert_eq!(failures, Vec::<String>::new());
}

/// TH-26, I-68, ADR-015: the checker refuses script, style, event
/// attributes, foreign and animation elements, HTML inside `svg`,
/// references to other resources and every other break of the subset.
/// Each case changes an accepted base by one rule, and the reference
/// refuses it too, so the case tests the rule and not the base.
#[test]
fn th26_svg_checker_refuses_each_fixed_refusal() {
    assert_eq!(
        reference::parse(&doc("")).map(|_| ()),
        Ok(()),
        "the reference accepts the base"
    );
    let mut failures = Vec::new();
    for (what, d) in refused() {
        if reference::accepts(&d) {
            failures.push(format!("reference accepts {what}: {}", shown(&d)));
        }
        if check_wellformed(&d).is_ok() {
            failures.push(format!("checker accepts {what}: {}", shown(&d)));
        }
    }
    assert_eq!(failures, Vec::<String>::new());
    assert_eq!(
        check_wellformed(&doc("")),
        Ok(()),
        "the checker accepts the base"
    );
}

/// Elements a fragment draws: the subset's and some it refuses.
const TAGS: &[&str] = &[
    "g",
    "a",
    "title",
    "desc",
    "defs",
    "marker",
    "path",
    "line",
    "rect",
    "circle",
    "text",
    "tspan",
    "svg",
    "script",
    "style",
    "foreignobject",
    "animate",
    "set",
    "use",
    "image",
    "p",
    "div",
    "span",
    "b",
];

/// Attributes a fragment draws, with values, allowed and refused.
const ATTRS: &[(&str, &str)] = &[
    ("id", "n1"),
    ("class", "edge edge--done"),
    ("role", "group"),
    ("aria-label", "Draft (DRAFT), completed"),
    ("aria-hidden", "true"),
    ("href", "/app/p#node-DRAFT"),
    ("href", "javascript:alert(1)"),
    ("x", "10"),
    ("y1", "5"),
    ("width", "104"),
    ("rx", "2"),
    ("d", "M0 0 L10 5"),
    ("viewbox", "0 0 10 10"),
    ("refx", "9"),
    ("orient", "auto"),
    ("marker-end", "url(#arrow)"),
    ("marker-end", "url(https://evil.example/x#a)"),
    ("fill", "currentColor"),
    ("fill", "red"),
    ("text-anchor", "middle"),
    ("onclick", "alert(1)"),
    ("onload", "x"),
    ("style", "fill:red"),
    ("stroke", "red"),
    ("tabindex", "0"),
];

/// Texts a fragment draws, plain and escaped.
const TEXTS: &[&str] = &[
    "STAGE2",
    " ",
    "\n",
    "a &amp; b",
    "&lt;script&gt;",
    "Stage 2 questions",
];

/// A random fragment of up to `depth` levels.
fn fragment(g: &mut Gen, depth: u32) -> String {
    let n = g.usize_in(0..=3);
    let mut out = String::new();
    for _ in 0..n {
        if depth == 0 || g.u8_in(0..=3) == 0 {
            out.push_str(g.pick(TEXTS));
            continue;
        }
        let tag = *g.pick(TAGS);
        out.push('<');
        out.push_str(tag);
        let attrs = g.usize_in(0..=2);
        for _ in 0..attrs {
            let (k, v) = *g.pick(ATTRS);
            out.push_str(&format!(" {k}=\"{v}\""));
        }
        out.push('>');
        out.push_str(&fragment(g, depth - 1));
        out.push_str(&format!("</{tag}>"));
    }
    out
}

/// TH-26, ADR-015: on generated fragments inside an `svg`, with allowed
/// and forbidden elements, attributes and texts, the checker and the
/// reference give the same verdict. A checker that is laxer lets unsafe
/// output through; one that is stricter refuses the renderer.
#[test]
fn th26_svg_checker_matches_the_reference() {
    check("th26_svg_checker_matches_the_reference", |g| {
        let inner = fragment(g, 3);
        let d = with_body(&format!(
            "<svg viewbox=\"0 0 1110 430\" role=\"group\">{inner}</svg>"
        ));
        g.note("doc", &shown(&d));
        prop_assert_eq!(
            check_wellformed(&d).is_ok(),
            reference::accepts(&d),
            "checker and reference disagree"
        );
        Ok(())
    });
}
