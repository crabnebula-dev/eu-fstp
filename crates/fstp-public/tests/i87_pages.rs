//! Pages, feed and tools read only the view (I-87, R-PB-04, P-52; M4
//! design sections 3.10 and 8.4).
//!
//! The properties run over generated views (`support::gen_view`) whose
//! every text leaf is a unique canary. The reference leaves of each page
//! come from the module documentation of `src/html.rs`, written into
//! `support::page_leaves`. The `fstp-html` recording sink gives every
//! dynamic text node a page writes, so no HTML parser is needed.
//!
//! Leaves compare as sets, since a page may write one leaf twice, such
//! as a call title in `title` and in `h1`. Interim, pending Daniel: the
//! design says multiset.
//!
//! Status: red. The W0 stubs of `render_traced`, `render_html`, `feed` and
//! `select` refuse with `PublicError::NotImplemented`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod support;

use std::collections::BTreeSet;

use fstp_html::{TraceEvent, TracePlace};
use fstp_json::Value;
use fstp_prop::check;
use fstp_public::feed::feed;
use fstp_public::tools::select;
use fstp_public::{PublicError, PublicPage, PublicPart, PublicQuery, render_html, render_traced};
use support::{
    aggregate_leaves, call_leaves, chrome, gen_view, grant_leaves, json_leaves, page_leaves,
    traced_pages,
};

/// The dynamic text nodes of a trace.
fn text_nodes(trace: &[TraceEvent]) -> BTreeSet<String> {
    trace
        .iter()
        .filter_map(|e| match e {
            TraceEvent::Dynamic {
                place: TracePlace::Text,
                value,
            } => Some(value.clone()),
            _ => None,
        })
        .collect()
}

/// I-87: every dynamic text node of each page is a leaf of the page's
/// part of the view, and every such leaf is written.
#[test]
fn i87_page_render_trace_equals_view_leaves() {
    check("i87_page_render_trace_equals_view_leaves", |g| {
        let view = gen_view(g);
        for p in traced_pages(&view) {
            let (_, trace) =
                render_traced(&view, &p, &chrome()).map_err(|e| format!("{p:?}: {e}"))?;
            let got = text_nodes(&trace);
            let want = page_leaves(&view, &p).ok_or_else(|| format!("{p:?}: no leaves"))?;
            if got != want {
                return Err(format!(
                    "{p:?}: written but not a leaf {:?}; a leaf not written {:?}",
                    got.difference(&want).collect::<Vec<_>>(),
                    want.difference(&got).collect::<Vec<_>>()
                ));
            }
        }
        Ok(())
    });
}

/// I-87: every leaf of each page's part of the view appears in the page
/// bytes. Each leaf is a unique canary that escapes to itself.
#[test]
fn i87_every_view_leaf_reaches_its_page() {
    check("i87_every_view_leaf_reaches_its_page", |g| {
        let view = gen_view(g);
        for p in traced_pages(&view) {
            let doc = render_html(&view, &p, &chrome()).map_err(|e| format!("{p:?}: {e}"))?;
            for leaf in page_leaves(&view, &p).ok_or_else(|| format!("{p:?}: no leaves"))? {
                if !doc.as_str().contains(&leaf) {
                    return Err(format!("{p:?}: {leaf:?} is not on the page"));
                }
            }
        }
        Ok(())
    });
}

/// I-87, R-PB-02: equal views give equal page bytes, and the traced and
/// plain renders agree, so a page depends on the view alone.
#[test]
fn i87_equal_views_give_equal_page_bytes() {
    check("i87_equal_views_give_equal_page_bytes", |g| {
        let view = gen_view(g);
        let twin = view.clone();
        for p in traced_pages(&view) {
            let a = render_html(&view, &p, &chrome()).map_err(|e| format!("{p:?}: {e}"))?;
            let b = render_html(&twin, &p, &chrome()).map_err(|e| format!("{p:?}: {e}"))?;
            let (c, _) = render_traced(&twin, &p, &chrome()).map_err(|e| format!("{p:?}: {e}"))?;
            if a != b || a != c {
                return Err(format!("{p:?}: equal views gave different bytes"));
            }
        }
        Ok(())
    });
}

/// The leaves of every traced page of `view`, together.
fn all_page_leaves(view: &fstp_public::PublicView) -> Result<BTreeSet<String>, String> {
    let mut out = BTreeSet::new();
    for p in traced_pages(view) {
        out.extend(page_leaves(view, &p).ok_or_else(|| format!("{p:?}: no leaves"))?);
    }
    Ok(out)
}

/// I-87, P-52: with P-52 on, the feed holds exactly the leaves of the
/// pages. With P-52 off it is refused, never an empty feed.
#[test]
fn i87_feed_equals_pages() {
    check("i87_feed_equals_pages", |g| {
        let view = gen_view(g);
        match (view.programme.feed, feed(&view)) {
            (false, Err(PublicError::FeedOff)) => Ok(()),
            (false, other) => Err(format!("P-52 off gave {other:?}")),
            (true, Ok(v)) => {
                let got = json_leaves(&v);
                let want = all_page_leaves(&view)?;
                if got == want {
                    Ok(())
                } else {
                    Err(format!(
                        "in the feed only {:?}; on the pages only {:?}",
                        got.difference(&want).collect::<Vec<_>>(),
                        want.difference(&got).collect::<Vec<_>>()
                    ))
                }
            }
            (true, Err(e)) => Err(format!("P-52 on: {e}")),
        }
    });
}

/// The reference leaves of `part` of `view`, from `src/tools.rs`.
fn part_leaves(view: &fstp_public::PublicView, part: &PublicPart) -> Option<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    match part {
        PublicPart::Programme => {
            out.insert(view.programme.name.clone());
            out.insert(view.programme.narrative.clone());
            out.extend(view.aggregates.iter().flat_map(aggregate_leaves));
        }
        PublicPart::OpenCalls => out.extend(view.open_calls.iter().flat_map(call_leaves)),
        PublicPart::Call(id) => {
            out.extend(call_leaves(view.open_calls.iter().find(|c| &c.id == id)?))
        }
        PublicPart::Guide(id) => {
            let c = view.open_calls.iter().find(|c| &c.id == id)?;
            c.guide.as_ref()?;
            out.insert(c.id.clone());
        }
        PublicPart::Deadlines => {
            for c in &view.open_calls {
                out.extend([
                    c.id.clone(),
                    c.title.clone(),
                    c.deadline.clone(),
                    c.deadline_zone.clone(),
                ]);
            }
        }
        PublicPart::Eligibility => {
            for c in &view.open_calls {
                out.extend([c.id.clone(), c.title.clone()]);
                out.extend(c.eligibility.iter().cloned());
            }
        }
        PublicPart::Funded => out.extend(view.funded.iter().flat_map(grant_leaves)),
        PublicPart::Finished => out.extend(view.finished.iter().flat_map(grant_leaves)),
    }
    Some(out)
}

/// Every part of `view` a tool can select, and two calls it lacks.
fn parts(view: &fstp_public::PublicView) -> Vec<PublicPart> {
    let mut out = vec![
        PublicPart::Programme,
        PublicPart::OpenCalls,
        PublicPart::Deadlines,
        PublicPart::Eligibility,
        PublicPart::Funded,
        PublicPart::Finished,
        PublicPart::Call("999".to_owned()),
        PublicPart::Guide("999".to_owned()),
    ];
    for c in &view.open_calls {
        out.push(PublicPart::Call(c.id.clone()));
        out.push(PublicPart::Guide(c.id.clone()));
    }
    out
}

/// I-87: each public tool answers exactly the leaves of its part of the
/// view, and a call the view lacks is not found. A Guide answer holds the
/// published document as its `html` member.
#[test]
fn i87_select_equals_view_parts() {
    check("i87_select_equals_view_parts", |g| {
        let view = gen_view(g);
        for part in parts(&view) {
            let q = PublicQuery {
                part: part.clone(),
                search: None,
            };
            match (part_leaves(&view, &part), select(&view, &q)) {
                (None, Err(PublicError::NotFound)) => {}
                (None, other) => return Err(format!("{part:?}: {other:?}")),
                (Some(_), Err(e)) => return Err(format!("{part:?}: {e}")),
                (Some(want), Ok(v)) => {
                    let got = json_leaves(&v);
                    if got != want {
                        return Err(format!("{part:?}: {got:?} is not {want:?}"));
                    }
                    if let PublicPart::Guide(id) = &part {
                        let doc = view
                            .open_calls
                            .iter()
                            .find(|c| &c.id == id)
                            .and_then(|c| c.guide.as_ref())
                            .map(|gd| gd.document.as_str().to_owned());
                        if v.get("html").and_then(Value::as_str).map(str::to_owned) != doc {
                            return Err(format!("{part:?}: the html is not the Guide"));
                        }
                    }
                }
            }
        }
        Ok(())
    });
}

/// I-87: the open calls tool with a search text answers exactly the open
/// calls whose title contains it, ignoring ASCII case.
#[test]
fn i87_select_search_filters_open_call_titles() {
    check("i87_select_search_filters_open_call_titles", |g| {
        let view = gen_view(g);
        let Some(first) = view.open_calls.first() else {
            return Ok(());
        };
        let probe = first
            .title
            .get(..first.title.len().min(6))
            .unwrap_or("")
            .to_ascii_uppercase();
        let q = PublicQuery {
            part: PublicPart::OpenCalls,
            search: Some(probe.clone()),
        };
        let v = select(&view, &q).map_err(|e| e.to_string())?;
        let got: BTreeSet<String> = v
            .get("calls")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.get("id").and_then(Value::as_str).map(str::to_owned))
                    .collect()
            })
            .ok_or_else(|| format!("no calls array: {}", v.to_compact()))?;
        let want: BTreeSet<String> = view
            .open_calls
            .iter()
            .filter(|c| c.title.to_ascii_uppercase().contains(&probe))
            .map(|c| c.id.clone())
            .collect();
        if got == want {
            Ok(())
        } else {
            Err(format!("search {probe:?}: {got:?} is not {want:?}"))
        }
    });
}

/// I-87, P-52: the feed of the sample view with P-52 off is refused, and
/// with P-52 on it names each part as a member.
#[test]
fn i87_feed_members_are_the_page_parts() {
    assert_eq!(
        feed(&support::sample_view(false)),
        Err(PublicError::FeedOff)
    );
    let v = feed(&support::sample_view(true)).unwrap_or_else(|e| panic!("{e}"));
    let keys: Vec<&str> = v
        .as_object()
        .map(|o| o.keys().collect())
        .unwrap_or_default();
    assert_eq!(keys, ["programme", "open_calls", "funded", "finished"]);
}

/// I-87: a Guide page has no trace of its own. It is the published
/// document, which `r_pb_04_pages.rs` checks.
#[test]
fn i87_guide_page_has_no_trace() {
    let view = support::sample_view(true);
    let id = view.open_calls[0].id.clone();
    assert_eq!(
        render_traced(&view, &PublicPage::Guide(id), &chrome()).map(|_| ()),
        Err(PublicError::NotFound)
    );
}
