//! The route SVG renderer and its text alternative (ADR-015 "Rendering"
//! and "Rendering home and zones", `SPEC/12-journey-ui.md` section 6,
//! `docs/design/02-voyager-route-diary.md` "The progress map").
//!
//! The renderer is a pure function of a [`RouteDef`] (the journey
//! definition's nodes, edges and "any non-terminal state before GRANTED"
//! rule) and one viewer's [`RouteView`] (the projected position, the legs
//! the viewer may see and the overlay). It builds [`Element`] trees, so
//! every text goes through the escaping writer. Equal inputs give equal
//! bytes.
//!
//! - [`svg`] builds the `svg` element of the map.
//! - [`list`] builds the `ol` text alternative of the same route
//!   (R-JV-05).
//! - [`CATALOGUE_EN`] holds the English plain-pack entries both read.
//!
//! Interim readings, pending Daniel:
//!
//! - A node the viewer is at is "current stage", whatever its kind. A
//!   node on a leg the viewer may see is "completed". Every other node
//!   takes its kind's words.
//! - The map draws its nodes in list order, so keyboard order on the map
//!   equals the list order.
//! - Node links are `{page}#node-STATE`, since [`SafeUrl`] refuses a
//!   fragment-only URL such as the design's `#node-STATE`.
//! - Attribute names are lower case (`viewbox`); the HTML parser gives
//!   them their SVG spelling. `fill` is only `currentColor` or `none`, so
//!   every colour comes from the tenant tokens (I-70).
//! - A node label wraps at spaces into at most three lines of about 17
//!   characters ([`Lines`]), after the catalogue resolves it, so a
//!   terminology override wraps too. The web app's builder
//!   (`web/src/journey/svg.ts`) wraps the same way.
//! - The overlay does not change the drawing. The help panels of the
//!   page read it (R-JV-07).

use crate::{Element, EntrySource, HtmlError, Label, Lines, MessageKind, Node, SafeUrl};

/// One node of the route, as the journey definition names it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RouteNode {
    /// The formal state name, such as `STAGE2` (I-96).
    pub state: String,
    /// The catalogue label of the node, such as `journey.node.stage2`.
    pub label: Label,
}

/// One edge of the route: one row of the transition table (I-95).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RouteEdge {
    /// The stable edge id, such as `T-STAGE2-RANKED`.
    pub id: String,
    /// The formal state it leaves.
    pub from: String,
    /// The formal state it enters.
    pub to: String,
}

/// The journey definition as the renderer reads it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RouteDef {
    /// Every node, in definition order.
    pub nodes: Vec<RouteNode>,
    /// Every edge, in definition order.
    pub edges: Vec<RouteEdge>,
    /// The target of the "any non-terminal state before GRANTED" rule,
    /// `WITHDRAWN` for the proposal graph. Drawn as one bracket, never as
    /// one arrow per state (NOTE 10).
    pub withdraw: Option<String>,
}

/// One completed leg the viewer may see.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RouteLeg {
    /// The formal state it left.
    pub from: String,
    /// The formal state it entered.
    pub to: String,
}

/// The overlay outputs the map reads (section 5.5, R-JV-07).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RouteOverlay {
    /// P-07: the stage 2 window length in days.
    pub stage2_window_days: u32,
    /// P-11: whether reviewers are anonymous to the applicant.
    pub reviewers_anonymous: bool,
    /// NOTE 7: whether an IRC concern defers the proposal.
    pub irc_concern_deferred: bool,
}

/// One viewer's projection of one proposal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RouteView {
    /// The pseudonymous proposal id the title names.
    pub subject: String,
    /// The same-origin path of the page that holds the help panels. Each
    /// node and list item links to `{page}#node-STATE`. Interim reading,
    /// pending Daniel: the design writes `href="#node-STATE"`, but the
    /// writer's subset refuses a fragment-only URL (the W1d reading that
    /// `#top` is unsafe), so the link names the page path too.
    pub page: SafeUrl,
    /// The formal state of the current position.
    pub position: String,
    /// The completed legs the viewer may see, in route order.
    pub legs: Vec<RouteLeg>,
    /// The overlay, `None` before the call is published.
    pub overlay: Option<RouteOverlay>,
}

const fn label(id: &'static str, message: &'static str) -> EntrySource<'static> {
    EntrySource {
        id,
        kind: MessageKind::Label,
        message,
    }
}

/// The English plain-pack catalogue entries the renderer reads: the node
/// labels, status words, bracket and loop texts, and the title and
/// description of the map (`docs/design/02-voyager-route-diary.md`
/// "Node labels", "Node styling" and "Text alternative"). The web
/// catalogue `web/src/journey/messages.en.ts` holds the same words.
pub const CATALOGUE_EN: &[EntrySource<'static>] = &[
    label("journey.node.draft", "Draft"),
    label("journey.node.submitted", "Submitted"),
    label("journey.node.stage1", "Stage 1 evaluation"),
    label("journey.node.stage2", "Stage 2 questions"),
    label("journey.node.ranked", "Ranked, awaiting committee decision"),
    label("journey.node.irc_review", "Independent review"),
    label("journey.node.negotiation", "Negotiation"),
    label("journey.node.granted", "Granted"),
    label("journey.node.in_execution", "Project in progress"),
    label("journey.node.completed", "Completed"),
    label("journey.node.deferred", "Deferred to the next call"),
    label("journey.node.ineligible", "Not eligible"),
    label("journey.node.not_selected", "Not selected"),
    label("journey.node.declined", "Declined"),
    label("journey.node.withdrawn", "Withdrawn"),
    label("journey.node.terminated", "Grant terminated"),
    label("journey.route.map_title", "Progress map for {subject}"),
    label("journey.route.current_is", "The current stage is"),
    label(
        "journey.route.leave_label",
        "Withdraw: possible in any state before GRANTED, including DEFERRED",
    ),
    label(
        "journey.route.reenter_label",
        "re-enters at the stage it left",
    ),
    label("journey.route.name.completed", "completed"),
    label("journey.route.name.current", "current stage"),
    label("journey.route.name.upcoming", "upcoming"),
    label(
        "journey.route.name.pause",
        "possible pause, returns at the stage it left",
    ),
    label("journey.route.name.positive_end", "upcoming, final outcome"),
    label("journey.route.name.negative_end", "possible final outcome"),
    label("journey.route.status.completed", "Completed"),
    label("journey.route.status.current", "Current stage"),
    label("journey.route.status.upcoming", "Upcoming"),
    label("journey.route.status.pause", "Possible pause"),
    label(
        "journey.route.status.positive_end",
        "Upcoming, final outcome",
    ),
    label(
        "journey.route.status.negative_end",
        "Possible final outcome",
    ),
];

// ---------------------------------------------------------------------------
// Layout (design "Layout": four rows on a 1110 by 430 viewBox)
// ---------------------------------------------------------------------------

/// The viewBox, in the subset's lower-case attribute spelling.
const VIEWBOX: &str = "0 0 1110 430";
/// Node width and height.
const NODE_W: i32 = 104;
const NODE_H: i32 = 62;
/// The top of each row.
const WITHDRAW_Y: i32 = 14;
const MAIN_Y: i32 = 139;
const PAUSE_Y: i32 = 249;
const OUTCOME_Y: i32 = 359;
/// The bracket line of the WITHDRAWN rule.
const BRACKET_Y: i32 = 118;
/// The wrapping of a node label: about 17 characters of the label font in
/// one node width, at most three lines.
const LABEL_WIDTH: usize = 17;
const LABEL_LINES: usize = 3;
const LABEL_STEP: i32 = 12;

/// The kind of a node in the styling table, before position and legs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Stage,
    Pause,
    PositiveEnd,
    NegativeEnd,
}

/// Where a state sits: route order is the order of this table (main
/// line, pause, then final outcomes, as "Progress as a list" gives them).
struct Place {
    state: &'static str,
    x: i32,
    y: i32,
    kind: Kind,
}

const fn main(state: &'static str, x: i32) -> Place {
    Place {
        state,
        x,
        y: MAIN_Y,
        kind: Kind::Stage,
    }
}

const fn end(state: &'static str, x: i32, y: i32) -> Place {
    Place {
        state,
        x,
        y,
        kind: Kind::NegativeEnd,
    }
}

/// The sixteen states of the proposal route in route order, with their
/// places on the design's rows (`design/prototypes/route-map.html`):
/// main line nodes 110 apart from `x` 8.
const PLACES: [Place; 16] = [
    main("DRAFT", 8),
    main("SUBMITTED", 118),
    main("STAGE1", 228),
    main("STAGE2", 338),
    main("RANKED", 448),
    main("IRC_REVIEW", 558),
    main("NEGOTIATION", 668),
    main("GRANTED", 778),
    main("IN_EXECUTION", 888),
    Place {
        state: "COMPLETED",
        x: 998,
        y: MAIN_Y,
        kind: Kind::PositiveEnd,
    },
    Place {
        state: "DEFERRED",
        x: 503,
        y: PAUSE_Y,
        kind: Kind::Pause,
    },
    end("INELIGIBLE", 118, OUTCOME_Y),
    end("NOT_SELECTED", 338, OUTCOME_Y),
    end("DECLINED", 668, OUTCOME_Y),
    end("WITHDRAWN", 338, WITHDRAW_Y),
    end("TERMINATED", 888, OUTCOME_Y),
];

/// The state every route starts at.
const START: &str = "DRAFT";

/// Whether every route from DRAFT to `t` over the edges of `def` passes
/// `k`: `k` dominates `t`. RANKED does not dominate IRC_REVIEW, since a
/// proposal can reach it from STAGE2 through DEFERRED.
fn dominates(def: &RouteDef, k: &str, t: &str) -> bool {
    if k == t {
        return false;
    }
    if k == START {
        return true;
    }
    let mut seen: Vec<&str> = vec![START];
    let mut todo: Vec<&str> = vec![START];
    while let Some(at) = todo.pop() {
        for e in def.edges.iter().filter(|e| e.from == at) {
            if e.to != k && !seen.contains(&e.to.as_str()) {
                seen.push(&e.to);
                todo.push(&e.to);
            }
        }
    }
    !seen.contains(&t)
}

/// Whether the stage `s` is certainly behind the route of `view`: it lies
/// on every route to the position or to an end of a visible leg. A
/// "grants only" reader sees the legs of the grant alone (J2-R5), and the
/// stages before them are still passed. The withdrawal target is
/// reachable from many states, so it proves nothing.
fn passed(def: &RouteDef, view: &RouteView, s: &str) -> bool {
    let withdraw = def.withdraw.as_deref();
    view.legs
        .iter()
        .flat_map(|l| [l.from.as_str(), l.to.as_str()])
        .chain([view.position.as_str()])
        .filter(|t| Some(*t) != withdraw)
        .any(|t| dominates(def, s, t))
}

fn place(state: &str) -> Option<&'static Place> {
    PLACES.iter().find(|p| p.state == state)
}

impl Place {
    fn cx(&self) -> i32 {
        self.x.saturating_add(NODE_W / 2)
    }

    fn cy(&self) -> i32 {
        self.y.saturating_add(NODE_H / 2)
    }

    fn right(&self) -> i32 {
        self.x.saturating_add(NODE_W)
    }

    fn bottom(&self) -> i32 {
        self.y.saturating_add(NODE_H)
    }
}

/// The status of a node for one viewer (design "Node styling").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Completed,
    Current,
    Upcoming,
    Pause,
    PositiveEnd,
    NegativeEnd,
}

impl Status {
    /// The catalogue suffix of the status words.
    fn key(self) -> &'static str {
        match self {
            Status::Completed => "completed",
            Status::Current => "current",
            Status::Upcoming => "upcoming",
            Status::Pause => "pause",
            Status::PositiveEnd => "positive_end",
            Status::NegativeEnd => "negative_end",
        }
    }

    /// The glyph, hidden from screen readers: the shape cue beside the
    /// stroke, so status never rests on colour alone.
    fn glyph(self) -> &'static str {
        match self {
            Status::Completed => "\u{2713}",
            Status::Current => "\u{25CF}",
            Status::Upcoming => "\u{25CB}",
            Status::Pause => "\u{21BA}",
            Status::PositiveEnd => "\u{2605}",
            Status::NegativeEnd => "\u{25A0}",
        }
    }

    /// The token class of the SVG node (`web/src/site/tokens.css`).
    /// DEFERRED takes the upcoming stroke, as in the prototype.
    fn svg_class(self) -> &'static str {
        match self {
            Status::Completed => "svg-complete",
            Status::Current => "svg-current",
            Status::Upcoming | Status::Pause => "svg-upcoming",
            Status::PositiveEnd => "svg-positive",
            Status::NegativeEnd => "svg-negative",
        }
    }

    /// The token class of the list item.
    fn list_class(self) -> &'static str {
        match self {
            Status::Completed => "journey-node journey-node--complete",
            Status::Current => "journey-node journey-node--current",
            Status::Upcoming | Status::Pause => "journey-node journey-node--upcoming",
            Status::PositiveEnd => "journey-node journey-node--terminal-positive",
            Status::NegativeEnd => "journey-node journey-node--terminal-negative",
        }
    }

    /// The corner radius of the node shape: square corners mark a
    /// negative end.
    fn rx(self) -> &'static str {
        match self {
            Status::NegativeEnd => "2",
            _ => "10",
        }
    }
}

fn refuse(rule: &'static str) -> HtmlError {
    HtmlError::Page {
        element: "svg",
        rule,
    }
}

/// One node of the route, ready to draw.
struct Drawn<'a> {
    node: &'a RouteNode,
    place: &'static Place,
    status: Status,
}

/// The nodes of `def` in route order, with their status for `view`.
/// Refuses a node the layout does not place, a position or a leg that
/// names a state outside the definition, and a state given twice.
fn drawn<'a>(def: &'a RouteDef, view: &RouteView) -> Result<Vec<Drawn<'a>>, HtmlError> {
    let known = |s: &str| def.nodes.iter().any(|n| n.state == s);
    if !known(&view.position) {
        return Err(refuse("the position is not a state of the definition"));
    }
    if view.legs.iter().any(|l| !known(&l.from) || !known(&l.to)) {
        return Err(refuse("a leg names a state outside the definition"));
    }
    for (i, n) in def.nodes.iter().enumerate() {
        if place(&n.state).is_none() {
            return Err(refuse("the layout has no place for a state"));
        }
        if def
            .nodes
            .iter()
            .skip(i.saturating_add(1))
            .any(|m| m.state == n.state)
        {
            return Err(refuse("the definition names a state twice"));
        }
    }
    // The legs stay as the read gave them. A stage that every route to a
    // point shown passes is completed too (J3-R4).
    let mut out = Vec::new();
    for p in &PLACES {
        let Some(node) = def.nodes.iter().find(|n| n.state == p.state) else {
            continue;
        };
        let on_leg = view
            .legs
            .iter()
            .any(|l| l.from == node.state || l.to == node.state);
        let status = if node.state == view.position {
            Status::Current
        } else if on_leg || (p.kind == Kind::Stage && passed(def, view, &node.state)) {
            Status::Completed
        } else {
            match p.kind {
                Kind::Stage => Status::Upcoming,
                Kind::Pause => Status::Pause,
                Kind::PositiveEnd => Status::PositiveEnd,
                Kind::NegativeEnd => Status::NegativeEnd,
            }
        };
        out.push(Drawn {
            node,
            place: p,
            status,
        });
    }
    Ok(out)
}

/// The link of a node to its help panel: `{page}#node-STATE`.
fn node_href(view: &RouteView, state: &str) -> Result<SafeUrl, HtmlError> {
    SafeUrl::new(&format!("{}#node-{state}", view.page.as_str()))
}

/// The accessible name of a node: "{plain label} ({STATE}), {status
/// words}" (I-96, R-JV-01).
fn node_name(d: &Drawn<'_>) -> Vec<Node> {
    vec![
        Node::label(&d.node.label, &[]),
        Node::text(&format!(" ({}), ", d.node.state)),
        Node::label(
            &Label::new(&format!("journey.route.name.{}", d.status.key())),
            &[],
        ),
    ]
}

fn num(n: i32) -> String {
    n.to_string()
}

fn rect(class: &str, x: i32, y: i32, w: i32, h: i32, rx: &str) -> Element {
    Element::new("rect")
        .attr("class", class)
        .attr("x", &num(x))
        .attr("y", &num(y))
        .attr("width", &num(w))
        .attr("height", &num(h))
        .attr("rx", rx)
}

/// The SVG node of `d`: a link named by its label, formal state and
/// status, with its shape, glyph, label lines and formal name.
fn node_svg(d: &Drawn<'_>, view: &RouteView) -> Result<Element, HtmlError> {
    let p = d.place;
    let mut a = Element::new("a")
        .attr_url("href", node_href(view, &d.node.state)?)
        .attr_parts("aria-label", node_name(d))
        .attr("class", d.status.svg_class())
        .child(Element::new("title").children(node_name(d)));
    if d.status == Status::Current {
        a = a.child(rect(
            "current-ring",
            p.x.saturating_sub(6),
            p.y.saturating_sub(6),
            NODE_W.saturating_add(12),
            NODE_H.saturating_add(12),
            "14",
        ));
    }
    Ok(
        a.child(rect("node-shape", p.x, p.y, NODE_W, NODE_H, d.status.rx()))
            .child(
                Element::new("text")
                    .attr("class", "node-glyph")
                    .attr("x", &num(p.x.saturating_add(9)))
                    .attr("y", &num(p.y.saturating_add(13)))
                    .attr("aria-hidden", "true")
                    .text(d.status.glyph()),
            )
            .child(
                Element::new("text")
                    .attr("class", "node-label")
                    .attr("text-anchor", "middle")
                    .child(Node::label_lines(
                        &d.node.label,
                        &[],
                        Lines {
                            x: p.cx(),
                            y: p.y.saturating_add(30),
                            step: LABEL_STEP,
                            width: LABEL_WIDTH,
                            max: LABEL_LINES,
                        },
                    )),
            )
            .child(
                Element::new("text")
                    .attr("class", "node-formal")
                    .attr("x", &num(p.cx()))
                    .attr("y", &num(p.y.saturating_add(56)))
                    .attr("text-anchor", "middle")
                    .text(&d.node.state),
            ),
    )
}

/// The drawing of one edge between the places of its states.
enum Shape {
    Line(i32, i32, i32, i32),
    Path(String),
}

fn edge_shape(from: &Place, to: &Place) -> Shape {
    if from.y == MAIN_Y && to.y == MAIN_Y {
        let (x1, x2) = if from.x < to.x {
            (from.right(), to.x)
        } else {
            (from.x, to.right())
        };
        return Shape::Line(x1, from.cy(), x2, to.cy());
    }
    if to.y == OUTCOME_Y {
        return Shape::Path(format!(
            "M{} {} L{} {}",
            from.cx(),
            from.bottom(),
            to.cx(),
            to.y
        ));
    }
    if to.kind == Kind::Pause {
        // Into the pause: from the stage's lower edge to the pause's side.
        let left = from.cx() < to.cx();
        let (sx, cx, ex) = if left {
            (
                from.cx().saturating_add(20),
                from.cx().saturating_add(40),
                to.x,
            )
        } else {
            (
                from.cx().saturating_sub(20),
                from.cx().saturating_sub(30),
                to.right(),
            )
        };
        let cy = if left {
            to.cy()
        } else {
            to.y.saturating_add(1)
        };
        return Shape::Path(format!(
            "M{sx} {} Q {cx} {cy} {ex} {}",
            from.bottom(),
            to.y.saturating_add(25)
        ));
    }
    if from.kind == Kind::Pause {
        // The re-entry loop: from the pause's side back up to the stage.
        let left = to.cx() < from.cx();
        let (sx, cx, ex) = if left {
            (
                from.x,
                to.cx().saturating_sub(10),
                to.cx().saturating_sub(20),
            )
        } else {
            (
                from.right(),
                to.cx().saturating_add(10),
                to.cx().saturating_add(20),
            )
        };
        return Shape::Path(format!(
            "M{sx} {} Q {cx} {} {ex} {}",
            from.y.saturating_add(39),
            from.y.saturating_add(51),
            to.bottom()
        ));
    }
    Shape::Path(format!(
        "M{} {} L{} {}",
        from.cx(),
        from.cy(),
        to.cx(),
        to.cy()
    ))
}

/// The edges of `def`, each once with its definition id (I-95). An edge
/// into the "leave the route" target is the bracket's, not drawn here.
fn edges_svg(def: &RouteDef, view: &RouteView) -> Result<Vec<Element>, HtmlError> {
    let mut out = Vec::new();
    for (i, e) in def.edges.iter().enumerate() {
        if def.withdraw.as_deref() == Some(e.to.as_str()) {
            continue;
        }
        if def.edges.iter().take(i).any(|x| x.id == e.id) {
            return Err(refuse("the definition names an edge id twice"));
        }
        let known = |s: &str| def.nodes.iter().any(|n| n.state == s);
        let (Some(from), Some(to)) = (place(&e.from), place(&e.to)) else {
            return Err(refuse("an edge names a state the layout has no place for"));
        };
        if !known(&e.from) || !known(&e.to) {
            return Err(refuse("an edge names a state outside the definition"));
        }
        let mut class = String::from("edge");
        if view.legs.iter().any(|l| l.from == e.from && l.to == e.to) {
            class.push_str(" edge--done");
        }
        if to.kind == Kind::NegativeEnd {
            class.push_str(" edge--negative");
        }
        let looped = from.kind == Kind::Pause;
        if looped {
            class.push_str(" edge--loop");
        }
        let marker = if looped {
            "url(#arrow-loop)"
        } else {
            "url(#arrow)"
        };
        let id = format!("edge-{}", e.id);
        let el = match edge_shape(from, to) {
            Shape::Line(x1, y1, x2, y2) => Element::new("line")
                .attr("id", &id)
                .attr("class", &class)
                .attr("x1", &num(x1))
                .attr("y1", &num(y1))
                .attr("x2", &num(x2))
                .attr("y2", &num(y2))
                .attr("marker-end", marker),
            Shape::Path(d) => Element::new("path")
                .attr("id", &id)
                .attr("class", &class)
                .attr("d", &d)
                .attr("marker-end", marker),
        };
        out.push(el);
    }
    Ok(out)
}

fn marker(id: &str) -> Element {
    Element::new("marker")
        .attr("id", id)
        .attr("viewbox", "0 0 10 10")
        .attr("refx", "9")
        .attr("refy", "5")
        .attr("markerwidth", "7")
        .attr("markerheight", "7")
        .attr("orient", "auto-start-reverse")
        .child(
            Element::new("path")
                .attr("class", "arrow-head")
                .attr("d", "M0 0 L10 5 L0 10 z")
                .attr("fill", "currentColor"),
        )
}

/// The bracket of the "leave the route" rule (NOTE 10): one bracket over
/// the states it covers, one arrow up to its target, one text. Never one
/// arrow per state.
fn bracket_svg(def: &RouteDef, view: &RouteView) -> Option<Element> {
    let target = place(def.withdraw.as_deref()?)?;
    let first = place("DRAFT")?;
    let last = place("NEGOTIATION")?;
    let left = first.x;
    let right = last.right();
    let mut class = String::from("edge edge--leave");
    if view
        .legs
        .iter()
        .any(|l| Some(l.to.as_str()) == def.withdraw.as_deref())
    {
        class.push_str(" edge--done");
    }
    Some(
        Element::new("g")
            .attr("class", "leave")
            .child(Element::new("path").attr("class", &class).attr(
                "d",
                &format!(
                    "M{left} {} L{left} {BRACKET_Y} L{right} {BRACKET_Y} L{right} {}",
                    MAIN_Y.saturating_sub(9),
                    MAIN_Y.saturating_sub(9)
                ),
            ))
            .child(
                Element::new("path")
                    .attr("class", &class)
                    .attr(
                        "d",
                        &format!(
                            "M{} {BRACKET_Y} L{} {}",
                            target.cx(),
                            target.cx(),
                            target.bottom()
                        ),
                    )
                    .attr("marker-end", "url(#arrow)"),
            )
            .child(
                Element::new("text")
                    .attr("class", "node-formal")
                    .attr("x", &num(left.saturating_add(4)))
                    .attr("y", &num(BRACKET_Y.saturating_sub(6)))
                    .label(&Label::new("journey.route.leave_label"), &[]),
            ),
    )
}

/// The `svg` element of the map of `view` over `def`: a named group with
/// a title and a description of the current stage, the edges, the
/// bracket, the re-entry label and one link per node in route order.
///
/// Pure and deterministic: equal inputs give equal trees. Refuses a
/// definition the layout cannot place and a view outside the definition.
pub fn svg(def: &RouteDef, view: &RouteView) -> Result<Element, HtmlError> {
    let nodes = drawn(def, view)?;
    let current = nodes
        .iter()
        .find(|d| d.status == Status::Current)
        .ok_or_else(|| refuse("the position has no node"))?;
    let mut svg = Element::new("svg")
        .attr("class", "route-svg")
        .attr("viewbox", VIEWBOX)
        .attr("role", "group")
        .attr("aria-labelledby", "route-title route-desc")
        .child(Element::new("title").attr("id", "route-title").label(
            &Label::new("journey.route.map_title"),
            &[("subject", &view.subject)],
        ))
        .child(
            Element::new("desc")
                .attr("id", "route-desc")
                .label(&Label::new("journey.route.current_is"), &[])
                .text(" ")
                .label(&current.node.label, &[])
                .text(&format!(" ({}).", current.node.state)),
        )
        .child(
            Element::new("defs")
                .child(marker("arrow"))
                .child(marker("arrow-loop")),
        );
    for e in edges_svg(def, view)? {
        svg = svg.child(e);
    }
    if let Some(pause) = nodes.iter().find(|d| d.place.kind == Kind::Pause) {
        svg = svg.child(
            Element::new("text")
                .attr("class", "node-formal")
                .attr("x", &num(pause.place.cx()))
                .attr("y", &num(pause.place.bottom().saturating_add(17)))
                .attr("text-anchor", "middle")
                .label(&Label::new("journey.route.reenter_label"), &[]),
        );
    }
    if let Some(b) = bracket_svg(def, view) {
        svg = svg.child(b);
    }
    for d in &nodes {
        svg = svg.child(node_svg(d, view)?);
    }
    Ok(svg)
}

/// The `ol` text alternative of the map of `view` over `def` (R-JV-05):
/// every node in route order, each linking to its help panel with its
/// plain label, formal state and status words. The current item carries
/// `aria-current="step"`.
pub fn list(def: &RouteDef, view: &RouteView) -> Result<Element, HtmlError> {
    let mut ol = Element::new("ol").attr("class", "journey-list");
    for d in drawn(def, view)? {
        let mut li = Element::new("li").attr("class", d.status.list_class());
        if d.status == Status::Current {
            li = li.attr("aria-current", "step");
        }
        li = li
            .child(
                Element::new("a")
                    .attr_url("href", node_href(view, &d.node.state)?)
                    .label(&d.node.label, &[])
                    .text(" ")
                    .child(
                        Element::new("span")
                            .attr("class", "state-name")
                            .text(&format!("({})", d.node.state)),
                    ),
            )
            .child(Element::new("span").text(": ").label(
                &Label::new(&format!("journey.route.status.{}", d.status.key())),
                &[],
            ));
        ol = ol.child(li);
    }
    Ok(ol)
}
