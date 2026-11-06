//! The route map of `docs/design/02-voyager-route-diary.md` as an
//! executable reference (lane j3, test author).
//!
//! It restates the design's tables, written from the design text and the
//! prototype `design/prototypes/route-map.html` before the renderer
//! exists:
//!
//! - [`ROUTE`]: the sixteen states in route order (main line, pause, then
//!   final outcomes, as "Progress as a list" gives them), each with its
//!   plain label and its layout row;
//! - [`EDGES`]: the transition table of `SPEC/12-journey-ui.md` section
//!   5.1, and [`WITHDRAW_FROM`] for the one "leave the route" rule;
//! - [`Status`]: the node styling table, with the words of the accessible
//!   name, the words of the list, the glyph and the token class;
//! - generators of routes a proposal can take, walked over [`EDGES`];
//! - small readers over the decoded tree of `reference`.
//!
//! Interim readings, pending Daniel:
//!
//! - A node the viewer is at is "current stage", whatever its kind. A
//!   node on a leg the viewer may see, other than the current one, is
//!   "completed". Every other node takes its kind's words.
//! - The SVG nodes come in the same order as the list, so keyboard order
//!   on the map equals the list order.
//! - Node and list links are `{PAGE}#node-STATE`, since the subset refuses
//!   a fragment-only URL such as the design's `#node-STATE`.
//! - The SVG attribute names are lower case (`viewbox`); the HTML parser
//!   gives them their SVG spelling.

use fstp_html::route::{RouteDef, RouteEdge, RouteLeg, RouteNode, RouteOverlay, RouteView};
use fstp_html::{CatalogueSource, Catalogues, Element, Label, LabelOverride, Node, SafeUrl};
use fstp_prop::Gen;

use super::reference::{self, REl, RNode};

/// The layout rows of the design.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Row {
    /// WITHDRAWN, above the main line.
    Withdraw,
    /// DRAFT to COMPLETED.
    Main,
    /// DEFERRED, between STAGE2 and IRC_REVIEW.
    Pause,
    /// INELIGIBLE, NOT_SELECTED, DECLINED and TERMINATED.
    Outcome,
}

/// The kind of a node in the styling table, before position and legs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A stage of the main line.
    Stage,
    /// DEFERRED.
    Pause,
    /// COMPLETED.
    PositiveEnd,
    /// A negative final outcome.
    NegativeEnd,
}

/// One state of the route: formal name, plain label, row and kind.
pub(crate) struct State {
    pub(crate) name: &'static str,
    pub(crate) plain: &'static str,
    pub(crate) row: Row,
    pub(crate) kind: Kind,
}

const fn st(name: &'static str, plain: &'static str, row: Row, kind: Kind) -> State {
    State {
        name,
        plain,
        row,
        kind,
    }
}

/// The sixteen states in route order, with the plain labels of the
/// design's "Node labels" table.
pub(crate) const ROUTE: [State; 16] = [
    st("DRAFT", "Draft", Row::Main, Kind::Stage),
    st("SUBMITTED", "Submitted", Row::Main, Kind::Stage),
    st("STAGE1", "Stage 1 evaluation", Row::Main, Kind::Stage),
    st("STAGE2", "Stage 2 questions", Row::Main, Kind::Stage),
    st(
        "RANKED",
        "Ranked, awaiting committee decision",
        Row::Main,
        Kind::Stage,
    ),
    st("IRC_REVIEW", "Independent review", Row::Main, Kind::Stage),
    st("NEGOTIATION", "Negotiation", Row::Main, Kind::Stage),
    st("GRANTED", "Granted", Row::Main, Kind::Stage),
    st(
        "IN_EXECUTION",
        "Project in progress",
        Row::Main,
        Kind::Stage,
    ),
    st("COMPLETED", "Completed", Row::Main, Kind::PositiveEnd),
    st(
        "DEFERRED",
        "Deferred to the next call",
        Row::Pause,
        Kind::Pause,
    ),
    st(
        "INELIGIBLE",
        "Not eligible",
        Row::Outcome,
        Kind::NegativeEnd,
    ),
    st(
        "NOT_SELECTED",
        "Not selected",
        Row::Outcome,
        Kind::NegativeEnd,
    ),
    st("DECLINED", "Declined", Row::Outcome, Kind::NegativeEnd),
    st("WITHDRAWN", "Withdrawn", Row::Withdraw, Kind::NegativeEnd),
    st(
        "TERMINATED",
        "Grant terminated",
        Row::Outcome,
        Kind::NegativeEnd,
    ),
];

/// The node order of `crates/fstp-journey/definitions/proposal.v1.json`,
/// which differs from route order. The renderer orders by route, not by
/// its input.
pub(crate) const DEFINITION_ORDER: [&str; 16] = [
    "DRAFT",
    "SUBMITTED",
    "INELIGIBLE",
    "STAGE1",
    "NOT_SELECTED",
    "STAGE2",
    "RANKED",
    "IRC_REVIEW",
    "DEFERRED",
    "DECLINED",
    "NEGOTIATION",
    "WITHDRAWN",
    "GRANTED",
    "IN_EXECUTION",
    "COMPLETED",
    "TERMINATED",
];

/// The transition table of section 5.1, without the WITHDRAWN rule.
pub(crate) const EDGES: [(&str, &str); 20] = [
    ("DRAFT", "SUBMITTED"),
    ("SUBMITTED", "INELIGIBLE"),
    ("SUBMITTED", "STAGE1"),
    ("STAGE1", "NOT_SELECTED"),
    ("STAGE1", "STAGE2"),
    ("STAGE2", "RANKED"),
    ("STAGE2", "DEFERRED"),
    ("RANKED", "NOT_SELECTED"),
    ("RANKED", "IRC_REVIEW"),
    ("IRC_REVIEW", "NEGOTIATION"),
    ("IRC_REVIEW", "DEFERRED"),
    ("IRC_REVIEW", "DECLINED"),
    ("DEFERRED", "STAGE2"),
    ("DEFERRED", "IRC_REVIEW"),
    ("NEGOTIATION", "GRANTED"),
    ("NEGOTIATION", "DECLINED"),
    ("GRANTED", "IN_EXECUTION"),
    ("GRANTED", "TERMINATED"),
    ("IN_EXECUTION", "COMPLETED"),
    ("IN_EXECUTION", "TERMINATED"),
];

/// The states WITHDRAWN is reachable from (NOTE 10).
pub(crate) const WITHDRAW_FROM: [&str; 8] = [
    "DRAFT",
    "SUBMITTED",
    "STAGE1",
    "STAGE2",
    "RANKED",
    "IRC_REVIEW",
    "DEFERRED",
    "NEGOTIATION",
];

/// The terminal states.
pub(crate) const TERMINAL: [&str; 6] = [
    "INELIGIBLE",
    "NOT_SELECTED",
    "DECLINED",
    "WITHDRAWN",
    "COMPLETED",
    "TERMINATED",
];

/// The bracket text of the WITHDRAWN rule (design "WITHDRAWN").
pub(crate) const BRACKET_TEXT: &str =
    "Withdraw: possible in any state before GRANTED, including DEFERRED";

/// The loop label under DEFERRED (design "DEFERRED re-entry").
pub(crate) const REENTER_TEXT: &str = "re-enters at the stage it left";

/// The same-origin path of the page the map sits on (synthetic). Node
/// links are `{PAGE}#node-STATE`.
pub(crate) const PAGE: &str = "/app/proposals/1001/progress";

/// The viewBox of the design's layout, in the subset's lower-case
/// attribute spelling.
pub(crate) const VIEWBOX: &str = "0 0 1110 430";

/// The state `name` of [`ROUTE`].
pub(crate) fn state(name: &str) -> &'static State {
    ROUTE
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no state {name}"))
}

/// The catalogue label id of a node, as the definition file names it.
pub(crate) fn label_id(name: &str) -> String {
    format!("journey.node.{}", name.to_ascii_lowercase())
}

/// The edge id of the definition file, `T-FROM-TO`.
pub(crate) fn edge_id(from: &str, to: &str) -> String {
    format!("T-{from}-{to}")
}

/// The proposal definition as the renderer reads it, in definition order.
pub(crate) fn def() -> RouteDef {
    RouteDef {
        nodes: DEFINITION_ORDER
            .iter()
            .map(|n| RouteNode {
                state: (*n).to_owned(),
                label: Label::new(&label_id(n)),
            })
            .collect(),
        edges: EDGES
            .iter()
            .map(|(f, t)| RouteEdge {
                id: edge_id(f, t),
                from: (*f).to_owned(),
                to: (*t).to_owned(),
            })
            .collect(),
        withdraw: Some("WITHDRAWN".to_owned()),
    }
}

/// A route a proposal can take: its legs and its position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Walk {
    pub(crate) legs: Vec<(&'static str, &'static str)>,
    pub(crate) position: &'static str,
}

/// The states one step from `from`.
fn next_states(from: &str) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = EDGES
        .iter()
        .filter(|(f, _)| *f == from)
        .map(|(_, t)| *t)
        .collect();
    if WITHDRAW_FROM.contains(&from) {
        out.push("WITHDRAWN");
    }
    out
}

/// A random walk from DRAFT of up to 12 steps, stopping at a terminal.
pub(crate) fn gen_walk(g: &mut Gen) -> Walk {
    let steps = g.usize_in(0..=12);
    let mut position: &'static str = "DRAFT";
    let mut legs = Vec::new();
    for _ in 0..steps {
        if TERMINAL.contains(&position) {
            break;
        }
        let next = next_states(position);
        let to = *g.pick(&next);
        legs.push((position, to));
        position = to;
    }
    Walk { legs, position }
}

/// A random overlay, or none.
pub(crate) fn gen_overlay(g: &mut Gen) -> Option<RouteOverlay> {
    g.option(|g| RouteOverlay {
        stage2_window_days: g.u32_in(1..=60),
        reviewers_anonymous: g.bool(),
        irc_concern_deferred: g.bool(),
    })
}

/// The view of `walk` for `subject`.
pub(crate) fn view(subject: &str, walk: &Walk, overlay: Option<RouteOverlay>) -> RouteView {
    RouteView {
        subject: subject.to_owned(),
        page: SafeUrl::new(PAGE).unwrap_or_else(|e| panic!("{PAGE}: {e}")),
        position: walk.position.to_owned(),
        legs: walk
            .legs
            .iter()
            .map(|(f, t)| RouteLeg {
                from: (*f).to_owned(),
                to: (*t).to_owned(),
            })
            .collect(),
        overlay,
    }
}

/// The status of a node for one viewer (design "Node styling").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    Completed,
    Current,
    Upcoming,
    Pause,
    PositiveEnd,
    NegativeEnd,
}

impl Status {
    /// The words after the label in the accessible name.
    pub(crate) fn aria_words(self) -> &'static str {
        match self {
            Status::Completed => "completed",
            Status::Current => "current stage",
            Status::Upcoming => "upcoming",
            Status::Pause => "possible pause, returns at the stage it left",
            Status::PositiveEnd => "upcoming, final outcome",
            Status::NegativeEnd => "possible final outcome",
        }
    }

    /// Words the list item holds (design "Text alternative").
    pub(crate) fn list_words(self) -> &'static str {
        match self {
            Status::Completed => "Completed",
            Status::Current => "Current stage",
            Status::Upcoming => "Upcoming",
            Status::Pause => "Possible pause",
            Status::PositiveEnd => "Upcoming, final outcome",
            Status::NegativeEnd => "Possible final outcome",
        }
    }

    /// The glyph of the node (design "Node styling").
    pub(crate) fn glyph(self) -> &'static str {
        match self {
            Status::Completed => "\u{2713}",
            Status::Current => "\u{25CF}",
            Status::Upcoming => "\u{25CB}",
            Status::Pause => "\u{21BA}",
            Status::PositiveEnd => "\u{2605}",
            Status::NegativeEnd => "\u{25A0}",
        }
    }

    /// The token class of the node (`design/tokens.css`, "SVG node
    /// classes"). DEFERRED takes the upcoming stroke, as in the prototype.
    pub(crate) fn class(self) -> &'static str {
        match self {
            Status::Completed => "svg-complete",
            Status::Current => "svg-current",
            Status::Upcoming | Status::Pause => "svg-upcoming",
            Status::PositiveEnd => "svg-positive",
            Status::NegativeEnd => "svg-negative",
        }
    }
}

/// The expected status of `name` on `walk`.
pub(crate) fn status(name: &str, walk: &Walk) -> Status {
    if name == walk.position {
        return Status::Current;
    }
    if walk.legs.iter().any(|(f, t)| *f == name || *t == name) {
        return Status::Completed;
    }
    match state(name).kind {
        Kind::Stage => Status::Upcoming,
        Kind::Pause => Status::Pause,
        Kind::PositiveEnd => Status::PositiveEnd,
        Kind::NegativeEnd => Status::NegativeEnd,
    }
}

/// The accessible name of node `name` on `walk`.
pub(crate) fn aria_label(name: &str, walk: &Walk) -> String {
    format!(
        "{} ({name}), {}",
        state(name).plain,
        status(name, walk).aria_words()
    )
}

/// The English catalogues of the renderer, with `overrides` applied.
pub(crate) fn catalogues(overrides: &[LabelOverride<'_>]) -> Catalogues {
    let base = Catalogues::new(
        &CatalogueSource {
            locale: "en",
            entries: fstp_html::route::CATALOGUE_EN,
        },
        &[],
    )
    .unwrap_or_else(|e| panic!("route::CATALOGUE_EN builds: {e}"));
    if overrides.is_empty() {
        base
    } else {
        base.with_overrides(overrides)
            .unwrap_or_else(|e| panic!("the overrides apply to route::CATALOGUE_EN: {e}"))
    }
}

/// A page holding `el` in `main`, rendered with `cats`.
pub(crate) fn page(el: Element, cats: &Catalogues) -> Result<Vec<u8>, String> {
    fstp_html::Document::new("en")
        .title(Node::text("Application progress"))
        .body(Element::new("main").child(el))
        .render(cats)
        .map(fstp_html::HtmlDocument::into_bytes)
        .map_err(|e| format!("the writer refused the page: {e}"))
}

/// The rendered map of `walk`, as page bytes.
pub(crate) fn svg_page(walk: &Walk, subject: &str, cats: &Catalogues) -> Result<Vec<u8>, String> {
    let el = fstp_html::route::svg(&def(), &view(subject, walk, None))
        .map_err(|e| format!("route::svg refused: {e}"))?;
    page(el, cats)
}

/// The rendered list of `walk`, as page bytes.
pub(crate) fn list_page(walk: &Walk, subject: &str, cats: &Catalogues) -> Result<Vec<u8>, String> {
    let el = fstp_html::route::list(&def(), &view(subject, walk, None))
        .map_err(|e| format!("route::list refused: {e}"))?;
    page(el, cats)
}

/// The one `name` element below `main` of a parsed page.
pub(crate) fn only(doc: &[u8], name: &str) -> Result<REl, String> {
    let html = reference::parse(doc).map_err(|e| format!("not in the subset: {e}"))?;
    let found = descendants(&html, name);
    match found.as_slice() {
        [one] => Ok((*one).clone()),
        other => Err(format!("{} <{name}> elements, not one", other.len())),
    }
}

/// Every descendant of `el` named `name`, in document order.
pub(crate) fn descendants<'a>(el: &'a REl, name: &str) -> Vec<&'a REl> {
    let mut out = Vec::new();
    walk_els(el, &mut |e| {
        if e.name == name {
            out.push(e);
        }
    });
    out
}

/// Every descendant of `el` whose `id` is `id`, in document order.
pub(crate) fn descendants_with_id<'a>(el: &'a REl, id: &str) -> Vec<&'a REl> {
    let mut out = Vec::new();
    walk_els(el, &mut |e| {
        if e.attrs.get("id").is_some_and(|v| v == id) {
            out.push(e);
        }
    });
    out
}

/// Calls `f` on every descendant element of `el`, in document order.
pub(crate) fn walk_els<'a>(el: &'a REl, f: &mut dyn FnMut(&'a REl)) {
    for n in &el.children {
        if let RNode::El(e) = n {
            f(e);
            walk_els(e, f);
        }
    }
}

/// The child elements of `el`.
pub(crate) fn kids(el: &REl) -> Vec<&REl> {
    el.children
        .iter()
        .filter_map(|n| match n {
            RNode::El(e) => Some(e),
            RNode::Text(_) => None,
        })
        .collect()
}

/// The text of `el`, concatenated, with runs of whitespace as one space
/// and trimmed.
pub(crate) fn text(el: &REl) -> String {
    let joined = reference::texts(el).concat();
    joined.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Whether the `class` attribute of `el` holds `class`.
pub(crate) fn has_class(el: &REl, class: &str) -> bool {
    el.attrs
        .get("class")
        .is_some_and(|c| c.split_whitespace().any(|x| x == class))
}

/// The state a `{PAGE}#node-STATE` link names.
pub(crate) fn node_of(el: &REl) -> Option<&str> {
    el.attrs
        .get("href")?
        .strip_prefix(PAGE)?
        .strip_prefix("#node-")
}

/// The integer attribute `name` of `el`.
pub(crate) fn int_attr(el: &REl, name: &str) -> Option<i64> {
    el.attrs.get(name)?.parse().ok()
}
