//! The route SVG renderer and its text alternative (ADR-015 "Rendering",
//! `SPEC/12-journey-ui.md` section 6, `docs/design/02-voyager-route-diary.md`
//! "The progress map"; I-68, I-70, I-95, I-96, R-JV-01, R-JV-05,
//! R-NF-03).
//!
//! Each test renders `fstp_html::route::svg` or `fstp_html::route::list`
//! for routes a proposal can take, walked over the transition table of
//! `common::route`, and reads the page back with the reference parser of
//! `common::reference`, extended with the closed SVG subset. The
//! catalogues are the renderer's own English plain pack,
//! `route::CATALOGUE_EN`.
//!
//! Lane j3 test author. Red until the implementer builds the renderer:
//! the stub refuses every input and ships an empty catalogue.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::collections::BTreeSet;

use common::reference::{self, REl};
use common::route::{
    self, BRACKET_TEXT, EDGES, REENTER_TEXT, ROUTE, Row, Status, VIEWBOX, Walk, aria_label,
    descendants, gen_overlay, gen_walk, has_class, int_attr, kids, node_of, only, status, text,
};
use fstp_html::{LabelOverride, check_wellformed};
use fstp_prop::{check, prop_assert, prop_assert_eq};

/// The synthetic pseudonymous id the map's title names.
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

/// The `svg` element of the map of `walk`.
fn svg_of(walk: &Walk) -> Result<REl, String> {
    let cats = route::catalogues(&[]);
    let doc = route::svg_page(walk, SUBJECT, &cats)?;
    only(&doc, "svg")
}

/// The `ol` element of the list of `walk`.
fn list_of(walk: &Walk) -> Result<REl, String> {
    let cats = route::catalogues(&[]);
    let doc = route::list_page(walk, SUBJECT, &cats)?;
    only(&doc, "ol")
}

/// The node links of a map: the SVG `a` elements whose `href` names a
/// node, in document order.
fn node_links(svg: &REl) -> Vec<&REl> {
    descendants(svg, "a")
        .into_iter()
        .filter(|a| node_of(a).is_some())
        .collect()
}

/// The states of the route in route order.
fn route_order() -> Vec<&'static str> {
    ROUTE.iter().map(|s| s.name).collect()
}

/// ADR-015, `SPEC/12-journey-ui.md` section 6 ("SVG output is
/// deterministic for identical inputs"): equal inputs give equal bytes,
/// for the map and for the list, over generated routes and overlays.
#[test]
fn adr015_route_render_is_deterministic_for_equal_inputs() {
    let cats = route::catalogues(&[]);
    check(
        "adr015_route_render_is_deterministic_for_equal_inputs",
        |g| {
            let walk = gen_walk(g);
            let overlay = gen_overlay(g);
            let render = |w: &Walk| -> Result<(Vec<u8>, Vec<u8>), String> {
                let v = route::view(SUBJECT, w, overlay.clone());
                let svg = fstp_html::route::svg(&route::def(), &v)
                    .map_err(|e| format!("route::svg refused: {e}"))?;
                let list = fstp_html::route::list(&route::def(), &v)
                    .map_err(|e| format!("route::list refused: {e}"))?;
                Ok((route::page(svg, &cats)?, route::page(list, &cats)?))
            };
            let first = render(&walk)?;
            let again = render(&walk.clone())?;
            prop_assert_eq!(&first.0, &again.0, "the map bytes differ for equal inputs");
            prop_assert_eq!(&first.1, &again.1, "the list bytes differ for equal inputs");
            Ok(())
        },
    );
}

/// TH-26, ADR-015 ("Its fuzz targets cover the renderer"): the
/// well-formedness checker accepts every map and list the renderer
/// produces, and so does the reference parser of the subset.
#[test]
fn th26_checker_accepts_every_route_render() {
    let cats = route::catalogues(&[]);
    check("th26_checker_accepts_every_route_render", |g| {
        let walk = gen_walk(g);
        let overlay = gen_overlay(g);
        let v = route::view(SUBJECT, &walk, overlay);
        let svg = fstp_html::route::svg(&route::def(), &v)
            .map_err(|e| format!("route::svg refused: {e}"))?;
        let list = fstp_html::route::list(&route::def(), &v)
            .map_err(|e| format!("route::list refused: {e}"))?;
        let both = fstp_html::Document::new("en")
            .title(fstp_html::Node::text("Application progress"))
            .body(fstp_html::Element::new("main").child(svg).child(list))
            .render(&cats)
            .map_err(|e| format!("the writer refused the page: {e}"))?;
        prop_assert_eq!(
            check_wellformed(both.as_bytes()),
            Ok(()),
            "the checker refused a route page"
        );
        prop_assert!(
            reference::accepts(both.as_bytes()),
            "the route page is outside the reference subset: {}",
            both.as_str()
        );
        Ok(())
    });
}

/// I-96, R-JV-01, design "Node labels" and "Node styling": the map has
/// one keyboard-reachable link per state, `href="#node-STATE"`, whose
/// accessible name is the plain label, the formal state name and the
/// status words, repeated in its first child `title`. The node's own
/// text shows the formal state name in a `node-formal` text.
#[test]
fn i96_r_jv_01_every_node_names_its_formal_state() {
    check("i96_r_jv_01_every_node_names_its_formal_state", |g| {
        let walk = gen_walk(g);
        let svg = svg_of(&walk)?;
        let links = node_links(&svg);
        let seen: BTreeSet<&str> = links.iter().filter_map(|a| node_of(a)).collect();
        let want: BTreeSet<&str> = route_order().into_iter().collect();
        prop_assert_eq!(&seen, &want, "one node link per state");
        prop_assert_eq!(links.len(), 16, "no state is drawn twice");
        for a in links {
            let name = node_of(a).unwrap_or_default();
            let want = aria_label(name, &walk);
            prop_assert_eq!(
                a.attrs.get("aria-label").map(String::as_str),
                Some(want.as_str()),
                "aria-label of {}",
                name
            );
            let first = kids(a).first().copied();
            prop_assert!(
                first.is_some_and(|t| t.name == "title" && text(t) == want),
                "the first child of the {} link is a title equal to its name",
                name
            );
            let formal = descendants(a, "text")
                .into_iter()
                .any(|t| has_class(t, "node-formal") && text(t) == name);
            prop_assert!(formal, "the {} node shows its formal name in text", name);
        }
        Ok(())
    });
}

/// R-JV-05, design "Text alternative": the list holds exactly the map's
/// nodes, in route order (main line, pause, final outcomes), and the map
/// draws them in the same order. Each item links to the node's help
/// panel, shows the plain label with the formal name and the status
/// words, and only the current item carries `aria-current="step"`.
#[test]
fn r_jv_05_list_holds_the_map_nodes_in_route_order() {
    check("r_jv_05_list_holds_the_map_nodes_in_route_order", |g| {
        let walk = gen_walk(g);
        let svg = svg_of(&walk)?;
        let ol = list_of(&walk)?;
        let on_map: Vec<&str> = node_links(&svg).into_iter().filter_map(node_of).collect();
        let items = kids(&ol);
        let mut in_list = Vec::new();
        for li in &items {
            prop_assert_eq!(li.name.as_str(), "li", "the list holds only items");
            let links: Vec<&REl> = descendants(li, "a");
            prop_assert_eq!(links.len(), 1, "one link per item");
            let name = links.first().and_then(|a| node_of(a)).unwrap_or_default();
            in_list.push(name);
            let s = status(name, &walk);
            let shown = text(li);
            let head = format!("{} ({name})", route::state(name).plain);
            prop_assert!(
                shown.starts_with(&head),
                "the {} item starts with {:?}: {:?}",
                name,
                head,
                shown
            );
            prop_assert!(
                shown.contains(s.list_words()),
                "the {} item holds {:?}: {:?}",
                name,
                s.list_words(),
                shown
            );
            let current = li.attrs.get("aria-current").map(String::as_str);
            if s == Status::Current {
                prop_assert_eq!(current, Some("step"), "the current item");
            } else {
                prop_assert_eq!(current, None, "the {} item is not current", name);
            }
        }
        prop_assert_eq!(&in_list, &route_order(), "the list is in route order");
        prop_assert_eq!(
            &on_map,
            &in_list,
            "the map holds the list's nodes in its order"
        );
        Ok(())
    });
}

/// I-68, TW-2: a tenant terminology override that holds markup, and a
/// subject id that holds markup, reach the map and the list only as
/// escaped text. The page parses in the subset, holds no element or
/// handler the canary names, and shows the canary text intact.
#[test]
fn i68_route_canary_label_is_escaped_in_map_and_list() {
    const CANARY: &str = "<script>alert('j3')</script> & \"x\" <img src=x onerror=alert(1)>";
    const SUBJECT_CANARY: &str = "\"><svg onload=alert(1)><a href=\"javascript:x\">";
    let cats = route::catalogues(&[LabelOverride {
        locale: "en",
        id: "journey.node.stage2",
        message: CANARY,
    }]);
    for (what, doc) in [
        (
            "map",
            route::svg_page(&stage2(), SUBJECT_CANARY, &cats).unwrap(),
        ),
        (
            "list",
            route::list_page(&stage2(), SUBJECT_CANARY, &cats).unwrap(),
        ),
    ] {
        let s = String::from_utf8(doc.clone()).unwrap();
        for raw in ["<script", "<img", "<svg onload", "javascript:"] {
            if raw == "javascript:" {
                assert!(
                    !s.contains("href=\"javascript:"),
                    "{what}: a javascript: link"
                );
                continue;
            }
            assert!(!s.contains(raw), "{what}: raw {raw:?} in {s}");
        }
        assert!(s.contains("&lt;script&gt;"), "{what}: the escaped canary");
        let html = reference::parse(&doc).unwrap_or_else(|e| panic!("{what}: {e}"));
        let mut bad = Vec::new();
        route::walk_els(&html, &mut |e| {
            if matches!(e.name.as_str(), "script" | "img" | "style") {
                bad.push(e.name.clone());
            }
            for k in e.attrs.keys() {
                if k.starts_with("on") {
                    bad.push(format!("{} on {}", k, e.name));
                }
            }
        });
        assert_eq!(bad, Vec::<String>::new(), "{what}: elements or handlers");
        let shown = reference::texts(&html).concat() + &reference::attr_values(&html).concat();
        assert!(shown.contains(CANARY), "{what}: the canary shows intact");
    }
}

/// R-JV-05, `SPEC/12-journey-ui.md` section 6 ("Current position,
/// completed legs and upcoming legs differ by shape and text as well as
/// colour"), design "Node styling (never colour alone)": each status has
/// its own glyph text (hidden from screen readers) and its own words; the
/// current node alone has a ring; a negative end keeps square corners;
/// completed, current and upcoming nodes carry distinct token classes;
/// and an edge on a leg the viewer sees is drawn as done.
#[test]
fn r_jv_05_current_completed_upcoming_differ_in_shape_and_text() {
    check(
        "r_jv_05_current_completed_upcoming_differ_in_shape_and_text",
        |g| {
            let walk = gen_walk(g);
            let svg = svg_of(&walk)?;
            for a in node_links(&svg) {
                let name = node_of(a).unwrap_or_default();
                let s = status(name, &walk);
                prop_assert!(has_class(a, s.class()), "{} has class {}", name, s.class());
                let glyph = descendants(a, "text")
                    .into_iter()
                    .find(|t| has_class(t, "node-glyph"));
                prop_assert!(
                    glyph.is_some_and(|t| text(t) == s.glyph()
                        && t.attrs.get("aria-hidden").map(String::as_str) == Some("true")),
                    "{} shows the hidden glyph {}",
                    name,
                    s.glyph()
                );
                let rings = descendants(a, "rect")
                    .into_iter()
                    .filter(|r| has_class(r, "current-ring"))
                    .count();
                prop_assert_eq!(rings, usize::from(s == Status::Current), "ring on {}", name);
                let shape = descendants(a, "rect")
                    .into_iter()
                    .find(|r| has_class(r, "node-shape"));
                prop_assert!(shape.is_some(), "{} has a node-shape rect", name);
                let rx = shape.and_then(|r| int_attr(r, "rx")).unwrap_or(0);
                if s == Status::NegativeEnd {
                    prop_assert!(rx <= 2, "{} keeps square corners (rx {})", name, rx);
                } else if matches!(s, Status::Upcoming | Status::Completed) {
                    prop_assert!(rx >= 6, "{} has rounded corners (rx {})", name, rx);
                }
            }
            let classes: BTreeSet<&str> = [Status::Completed, Status::Current, Status::Upcoming]
                .iter()
                .map(|s| s.class())
                .collect();
            prop_assert_eq!(classes.len(), 3, "three distinct classes");
            for (f, t) in EDGES {
                let id = format!("edge-{}", route::edge_id(f, t));
                let edge = route::descendants_with_id(&svg, &id);
                prop_assert_eq!(edge.len(), 1, "edge {} drawn once", id);
                let done = walk.legs.contains(&(f, t));
                prop_assert_eq!(
                    edge.first().is_some_and(|e| has_class(e, "edge--done")),
                    done,
                    "edge {} is done exactly when it is a leg",
                    id
                );
            }
            Ok(())
        },
    );
}

/// I-95, design "Edges", "WITHDRAWN" and "DEFERRED re-entry": every row
/// of the transition table is drawn once, with the edge id of the
/// definition, and nothing else is an edge with an id. Negative edges and
/// the two re-entry loops carry their classes. WITHDRAWN is one bracket
/// with its one text, never an arrow per state, and the loop label sits
/// under DEFERRED once.
#[test]
fn i95_route_draws_each_transition_once_and_withdraw_as_one_bracket() {
    let svg = svg_of(&stage2()).unwrap();
    let mut ids = Vec::new();
    route::walk_els(&svg, &mut |e| {
        if let Some(id) = e.attrs.get("id")
            && id.starts_with("edge-")
        {
            ids.push(id.clone());
        }
    });
    let mut want: Vec<String> = EDGES
        .iter()
        .map(|(f, t)| format!("edge-{}", route::edge_id(f, t)))
        .collect();
    ids.sort();
    want.sort();
    assert_eq!(ids, want, "one edge element per transition");
    for (f, t) in EDGES {
        let id = format!("edge-{}", route::edge_id(f, t));
        let e = route::descendants_with_id(&svg, &id);
        let e = e.first().unwrap();
        assert!(has_class(e, "edge"), "{id} is an edge");
        let negative = matches!(t, "INELIGIBLE" | "NOT_SELECTED" | "DECLINED" | "TERMINATED");
        assert_eq!(has_class(e, "edge--negative"), negative, "{id} negative");
        assert_eq!(has_class(e, "edge--loop"), f == "DEFERRED", "{id} loop");
    }
    let texts: Vec<String> = descendants(&svg, "text").into_iter().map(text).collect();
    let count = |s: &str| texts.iter().filter(|t| t.as_str() == s).count();
    assert_eq!(count(BRACKET_TEXT), 1, "the bracket text once: {texts:?}");
    assert_eq!(count(REENTER_TEXT), 1, "the re-entry label once: {texts:?}");
    let leaves = {
        let mut n = 0;
        route::walk_els(&svg, &mut |e| {
            if has_class(e, "edge--leave") && e.attrs.contains_key("id") {
                n += 1;
            }
        });
        n
    };
    assert_eq!(leaves, 0, "the bracket is not drawn as transitions");
}

/// R-JV-05, design "Layout": four rows on a 1110 by 430 viewBox. The main
/// line runs left to right in route order on one row, WITHDRAWN sits
/// above it, DEFERRED sits between the main line and the outcomes and
/// between STAGE2 and IRC_REVIEW, and the outcomes share the lowest row.
#[test]
fn r_jv_05_route_layout_follows_the_design_rows() {
    let svg = svg_of(&stage2()).unwrap();
    assert_eq!(svg.attrs.get("viewbox").map(String::as_str), Some(VIEWBOX));
    let mut at = std::collections::BTreeMap::new();
    for a in node_links(&svg) {
        let name = node_of(a).unwrap().to_owned();
        let r = descendants(a, "rect")
            .into_iter()
            .find(|r| has_class(r, "node-shape"))
            .unwrap_or_else(|| panic!("{name} has a node-shape rect"));
        let (x, y) = (int_attr(r, "x").unwrap(), int_attr(r, "y").unwrap());
        let (w, h) = (
            int_attr(r, "width").unwrap(),
            int_attr(r, "height").unwrap(),
        );
        assert!(
            x >= 0 && y >= 0 && x + w <= 1110 && y + h <= 430,
            "{name} inside the viewBox"
        );
        at.insert(name, (x, y));
    }
    let y_of = |row: Row| -> BTreeSet<i64> {
        ROUTE
            .iter()
            .filter(|s| s.row == row)
            .map(|s| at[s.name].1)
            .collect()
    };
    let (main, withdraw, pause, outcome) = (
        y_of(Row::Main),
        y_of(Row::Withdraw),
        y_of(Row::Pause),
        y_of(Row::Outcome),
    );
    for (row, ys) in [
        ("main", &main),
        ("withdraw", &withdraw),
        ("pause", &pause),
        ("outcome", &outcome),
    ] {
        assert_eq!(ys.len(), 1, "the {row} row is one row: {ys:?}");
    }
    let one = |s: &BTreeSet<i64>| *s.first().unwrap();
    assert!(one(&withdraw) < one(&main), "WITHDRAWN above the main line");
    assert!(
        one(&main) < one(&pause) && one(&pause) < one(&outcome),
        "DEFERRED between the main line and the outcomes"
    );
    let xs: Vec<i64> = ROUTE
        .iter()
        .filter(|s| s.row == Row::Main)
        .map(|s| at[s.name].0)
        .collect();
    assert!(
        xs.windows(2).all(|w| w[0] < w[1]),
        "main line left to right: {xs:?}"
    );
    let x = |n: &str| at[n].0;
    assert!(
        x("STAGE2") < x("DEFERRED") && x("DEFERRED") < x("IRC_REVIEW"),
        "DEFERRED between STAGE2 and IRC_REVIEW"
    );
}

/// R-JV-05, design "Accessibility notes": the map is a group named by its
/// `title` "Progress map for <id>" and described by a `desc` that names
/// the current stage by plain label and formal state.
#[test]
fn r_jv_05_map_is_a_named_group_that_describes_the_current_stage() {
    let svg = svg_of(&stage2()).unwrap();
    assert_eq!(svg.attrs.get("role").map(String::as_str), Some("group"));
    let first = kids(&svg);
    let title = first.iter().find(|e| e.name == "title").copied().unwrap();
    let desc = first.iter().find(|e| e.name == "desc").copied().unwrap();
    assert_eq!(text(title), format!("Progress map for {SUBJECT}"));
    let d = text(desc);
    assert!(
        d.contains("Stage 2 questions") && d.contains("STAGE2"),
        "the desc names the current stage: {d:?}"
    );
    let ids = svg
        .attrs
        .get("aria-labelledby")
        .map(|v| v.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
        .unwrap_or_default();
    assert_eq!(
        ids,
        vec![
            title.attrs.get("id").cloned().unwrap_or_default(),
            desc.attrs.get("id").cloned().unwrap_or_default()
        ],
        "aria-labelledby names the title then the desc"
    );
    assert!(
        ids.iter().all(|i| !i.is_empty()),
        "the title and desc have ids"
    );
}

/// R-NF-03, I-70, `SPEC/12-journey-ui.md` section 6 ("Animations ...
/// respect prefers-reduced-motion and are decorative only"): the map
/// holds no SMIL animation, which no media query can stop, no style
/// element or attribute, and no colour of its own. Motion lives only on
/// the current ring's token class, which the token sheet stops under
/// `prefers-reduced-motion: reduce` (checked by the web suite). Every
/// `fill` is `currentColor` or `none`, so colour comes from the tenant
/// tokens that pass I-70.
#[test]
fn r_nf_03_map_holds_no_animation_style_or_own_colour() {
    check("r_nf_03_map_holds_no_animation_style_or_own_colour", |g| {
        let walk = gen_walk(g);
        let svg = svg_of(&walk)?;
        let mut problems = Vec::new();
        let mut rings = 0usize;
        route::walk_els(&svg, &mut |e| {
            if matches!(
                e.name.as_str(),
                "animate" | "set" | "animatetransform" | "animatemotion" | "style" | "script"
            ) {
                problems.push(format!("<{}>", e.name));
            }
            for (k, v) in &e.attrs {
                if k == "style" || k == "stroke" || k == "color" {
                    problems.push(format!("{k} on <{}>", e.name));
                }
                if k == "fill" && v != "currentColor" && v != "none" {
                    problems.push(format!("fill={v:?} on <{}>", e.name));
                }
            }
            if has_class(e, "current-ring") {
                rings += 1;
            }
        });
        prop_assert_eq!(problems, Vec::<String>::new(), "animation, style or colour");
        prop_assert_eq!(rings, 1, "one current ring, on the current node");
        Ok(())
    });
}

/// R-JV-01, I-96, J2-R5 (review finding J3-R4): a "grants only" reader
/// gets the legs of the grant alone, yet the stages every route to them
/// passes are named completed on the map and in the list, never
/// upcoming. RANKED stays upcoming, since a proposal can reach IRC_REVIEW
/// from STAGE2 through DEFERRED. The hidden legs stay hidden.
#[test]
fn r_jv_01_stages_behind_hidden_legs_are_completed() {
    let walk = Walk {
        legs: vec![("NEGOTIATION", "GRANTED"), ("GRANTED", "IN_EXECUTION")],
        position: "IN_EXECUTION",
    };
    let svg = svg_of(&walk).unwrap();
    let list = list_of(&walk).unwrap();
    let name = |state: &str| -> Option<String> {
        node_links(&svg)
            .into_iter()
            .find(|a| node_of(a) == Some(state))
            .and_then(|a| a.attrs.get("aria-label").cloned())
    };
    for done in [
        "DRAFT",
        "SUBMITTED",
        "STAGE1",
        "STAGE2",
        "IRC_REVIEW",
        "NEGOTIATION",
        "GRANTED",
    ] {
        let got = name(done).unwrap();
        assert!(got.ends_with("), completed"), "{done}: {got}");
    }
    assert!(name("RANKED").unwrap().ends_with("), upcoming"));
    assert!(name("IN_EXECUTION").unwrap().ends_with("), current stage"));
    let stage1 = descendants(&list, "li")
        .into_iter()
        .map(text)
        .find(|t| t.contains("(STAGE1)"))
        .unwrap();
    assert!(stage1.ends_with(": Completed"), "the list: {stage1}");
    let mut done_edges: Vec<String> = descendants(&svg, "line")
        .into_iter()
        .chain(descendants(&svg, "path"))
        .filter(|e| has_class(e, "edge--done"))
        .filter_map(|e| e.attrs.get("id").cloned())
        .collect();
    done_edges.sort();
    assert_eq!(
        done_edges,
        ["edge-T-GRANTED-IN_EXECUTION", "edge-T-NEGOTIATION-GRANTED"],
        "only the visible legs are drawn done"
    );
}
