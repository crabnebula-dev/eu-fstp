//! Fuzz target `route_svg_render` of `fstp-html` (TH-26, I-68, ADR-015
//! "Its fuzz targets cover the renderer"; lane j3).
//!
//! The input drives one route a proposal can take over the transition
//! table, a subject id, the page path, an overlay and a tenant override
//! of one node label, each with arbitrary text. For each rendered map and
//! list:
//!
//! - rendering never panics, and equal inputs give equal bytes;
//! - when the renderer and the writer accept the page, the
//!   well-formedness checker accepts it too, with the closed SVG subset;
//! - the override text never reaches the page as markup: the page holds
//!   no `<script` and no raw `<img`.

#![no_main]

use fstp_html::route::{RouteDef, RouteEdge, RouteLeg, RouteNode, RouteOverlay, RouteView};
use fstp_html::{
    CatalogueSource, Catalogues, Document, Element, Label, LabelOverride, Node, SafeUrl,
};
use libfuzzer_sys::fuzz_target;

/// The sixteen states, in definition order.
const STATES: [&str; 16] = [
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

/// The transition table, with the WITHDRAWN rule spelled out.
const EDGES: [(&str, &str); 28] = [
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
    ("DRAFT", "WITHDRAWN"),
    ("SUBMITTED", "WITHDRAWN"),
    ("STAGE1", "WITHDRAWN"),
    ("STAGE2", "WITHDRAWN"),
    ("RANKED", "WITHDRAWN"),
    ("IRC_REVIEW", "WITHDRAWN"),
    ("DEFERRED", "WITHDRAWN"),
    ("NEGOTIATION", "WITHDRAWN"),
];

struct Ops<'a> {
    data: &'a [u8],
    at: usize,
}

impl Ops<'_> {
    fn byte(&mut self) -> Option<u8> {
        let b = self.data.get(self.at).copied();
        self.at = self.at.saturating_add(1);
        b
    }

    /// A string of up to 31 input bytes, decoded lossily.
    fn chunk(&mut self) -> String {
        let n = usize::from(self.byte().unwrap_or(0) % 32);
        let start = self.at.min(self.data.len());
        let end = start.saturating_add(n).min(self.data.len());
        self.at = end;
        String::from_utf8_lossy(self.data.get(start..end).unwrap_or(&[])).into_owned()
    }
}

fn label_id(state: &str) -> String {
    format!("journey.node.{}", state.to_ascii_lowercase())
}

fn def() -> RouteDef {
    RouteDef {
        nodes: STATES
            .iter()
            .map(|s| RouteNode {
                state: (*s).to_owned(),
                label: Label::new(&label_id(s)),
            })
            .collect(),
        edges: EDGES
            .iter()
            .filter(|(_, t)| *t != "WITHDRAWN")
            .map(|(f, t)| RouteEdge {
                id: format!("T-{f}-{t}"),
                from: (*f).to_owned(),
                to: (*t).to_owned(),
            })
            .collect(),
        withdraw: Some("WITHDRAWN".to_owned()),
    }
}

fn view(ops: &mut Ops<'_>) -> Option<RouteView> {
    let subject = ops.chunk();
    let path = ops.chunk();
    let page = SafeUrl::new(&format!("/app/proposals/{path}/progress"))
        .or_else(|_| SafeUrl::new("/app/proposals/1/progress"))
        .ok()?;
    let mut position = "DRAFT";
    let mut legs = Vec::new();
    let steps = ops.byte().unwrap_or(0) % 16;
    for _ in 0..steps {
        let next: Vec<&str> = EDGES
            .iter()
            .filter(|(f, _)| *f == position)
            .map(|(_, t)| *t)
            .collect();
        let Some(b) = ops.byte() else { break };
        let Some(to) = next.get(usize::from(b) % next.len().max(1)).copied() else {
            break;
        };
        legs.push(RouteLeg {
            from: position.to_owned(),
            to: to.to_owned(),
        });
        position = to;
    }
    // Sometimes a position or a leg the table does not hold, which the
    // renderer must refuse or draw safely.
    if ops.byte().unwrap_or(0) == 0xff {
        position = "NOT_A_STATE";
    }
    let overlay = (ops.byte().unwrap_or(0).is_multiple_of(2)).then(|| RouteOverlay {
        stage2_window_days: u32::from(ops.byte().unwrap_or(0)),
        reviewers_anonymous: ops.byte().unwrap_or(0).is_multiple_of(2),
        irc_concern_deferred: ops.byte().unwrap_or(0).is_multiple_of(2),
    });
    Some(RouteView {
        subject,
        page,
        position: position.to_owned(),
        legs,
        overlay,
    })
}

fn render(el: Element, cats: &Catalogues) -> Option<String> {
    Document::new("en")
        .title(Node::text("Application progress"))
        .body(Element::new("main").child(el))
        .render(cats)
        .ok()
        .map(|d| d.as_str().to_owned())
}

fuzz_target!(|data: &[u8]| {
    let mut ops = Ops { data, at: 0 };
    let state = STATES[usize::from(ops.byte().unwrap_or(0)) % STATES.len()];
    let canary = ops.chunk();
    let Some(v) = view(&mut ops) else {
        return;
    };
    let Ok(base) = Catalogues::new(
        &CatalogueSource {
            locale: "en",
            entries: fstp_html::route::CATALOGUE_EN,
        },
        &[],
    ) else {
        return;
    };
    let id = label_id(state);
    let cats = base
        .with_overrides(&[LabelOverride {
            locale: "en",
            id: &id,
            message: &canary,
        }])
        .unwrap_or(base);
    let d = def();
    for build in [fstp_html::route::svg, fstp_html::route::list] {
        let first = build(&d, &v);
        assert_eq!(
            first,
            build(&d.clone(), &v.clone()),
            "equal inputs, other tree"
        );
        let Ok(el) = first else { continue };
        let Some(page) = render(el.clone(), &cats) else {
            continue;
        };
        assert_eq!(
            Some(&page),
            render(el, &cats).as_ref(),
            "equal inputs, other bytes"
        );
        assert_eq!(
            fstp_html::check_wellformed(page.as_bytes()),
            Ok(()),
            "the checker refused a route page: {page}"
        );
        assert!(!page.contains("<script"), "a script in {page}");
        assert!(!page.contains("<img"), "an image in {page}");
    }
});
