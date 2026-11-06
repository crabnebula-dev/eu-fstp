//! The route of a proposal on the public call page (R-JV-06, ADR-015
//! "Rendering" and its amendment of 2026-11-06, `SPEC/12-journey-ui.md`
//! sections 6 and 8.5).
//!
//! `fstp-html` lays out and renders the map on the server
//! ([`fstp_html::route::public_svg`]), and the call page serves it as
//! static SVG markup, with no script, under the `/p` CSP. A public reader
//! has no position on the route, so every node shows the words of its
//! kind and no stage is current or completed.
//!
//! The route is the proposal state machine: its states in definition
//! order and the rows of its transition table, which the journey
//! definition `proposal.v1.json` restates and its drift check pins
//! (I-95). These are fixed tables of the domain, not cell state, so the
//! pages still read only the view (I-87).
//!
//! Interim readings, pending Daniel:
//!
//! - An edge id is `T-{FROM}-{TO}`, as the journey definition spells it.
//! - The row that leaves more than one state, withdrawal, is the "leave
//!   the route" rule, drawn as one bracket (NOTE 10).

use fstp_domain::{StateTag, TRANSITIONS};
use fstp_html::route::{RouteDef, RouteEdge, RouteNode};
use fstp_html::{Element, HtmlError, Label};

/// The proposal route as the renderer reads it.
pub(crate) fn route_def() -> RouteDef {
    let nodes = StateTag::ALL
        .iter()
        .map(|s| RouteNode {
            state: s.spec_name().to_owned(),
            label: Label::new(&format!(
                "journey.node.{}",
                s.spec_name().to_ascii_lowercase()
            )),
        })
        .collect();
    let mut edges: Vec<RouteEdge> = Vec::new();
    let mut withdraw = None;
    for r in TRANSITIONS {
        match r.from {
            [from] => {
                let id = format!("T-{}-{}", from.spec_name(), r.to.spec_name());
                if !edges.iter().any(|e| e.id == id) {
                    edges.push(RouteEdge {
                        id,
                        from: from.spec_name().to_owned(),
                        to: r.to.spec_name().to_owned(),
                    });
                }
            }
            _ => withdraw = Some(r.to.spec_name().to_owned()),
        }
    }
    RouteDef {
        nodes,
        edges,
        withdraw,
    }
}

/// The `svg` element of the public route map.
pub(crate) fn map() -> Result<Element, HtmlError> {
    fstp_html::route::public_svg(&route_def())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// I-95, NOTE 10: the public route holds the sixteen states, one edge
    /// per single-source row of the transition table, and the withdrawal
    /// rule as its "leave the route" target.
    #[test]
    fn i95_public_route_is_the_transition_table() {
        let def = route_def();
        assert_eq!(def.nodes.len(), 16);
        let single = TRANSITIONS.iter().filter(|r| r.from.len() == 1).count();
        assert_eq!(def.edges.len(), single);
        assert_eq!(def.withdraw.as_deref(), Some("WITHDRAWN"));
    }
}
