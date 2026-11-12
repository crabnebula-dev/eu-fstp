//! Shared references of the public page, feed and tool tests (I-87,
//! R-PB-01 to R-PB-05, M4 design section 3.10).
//!
//! Every view here is built by hand from the designed types, so a page
//! test does not depend on the filter. The leaves of each page's part of
//! a view are written from `src/html.rs` and `src/tools.rs` module
//! documentation, never from production output:
//!
//! - every page: the programme name;
//! - the programme page: the narrative; per open call its id, title,
//!   P-04 minimum and maximum, deadline and deadline zone; per aggregate
//!   its call, count and total;
//! - a call page: the call's id, title, opening, deadline, deadline zone,
//!   budget, P-04 minimum and maximum, and each P-09 text;
//! - the funded and finished pages: per grant its call, title, summary,
//!   and the grantee and amount when present.
//!
//! Enum fields, such as a grant's level and status, are catalogue labels,
//! so they are not leaves. All data is synthetic.

#![allow(dead_code, reason = "each test binary uses a part of the support")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use fstp_html::{CatalogueSource, Catalogues, Document, Element, Node};
use fstp_json::Value;
use fstp_prop::Gen;
use fstp_public::{
    Chrome, GrantStatus, Level, PublicAggregate, PublicCall, PublicGrant, PublicGuide, PublicPage,
    PublicProgramme, PublicView,
};

/// The chrome every test renders with.
pub(crate) fn chrome() -> Chrome {
    Chrome {
        stylesheet: Some("/p/assets/public.css".to_owned()),
    }
}

/// A Guide document with the text `marker`, rendered by `fstp-html`.
pub(crate) fn guide_document(marker: &str) -> String {
    let cats = Catalogues::new(
        &CatalogueSource {
            locale: "en",
            entries: &[],
        },
        &[],
    )
    .expect("an empty catalogue builds");
    Document::new("en")
        .title(Node::text(marker))
        .body(
            Element::new("main")
                .child(Element::new("h1").text(marker))
                .child(Element::new("p").text("Synthetic Guide body. Not legal text.")),
        )
        .render(&cats)
        .expect("the synthetic Guide renders")
        .as_str()
        .to_owned()
}

/// One synthetic open call with leaves prefixed by `tag`.
pub(crate) fn call(id: &str, tag: &str, guide: bool) -> PublicCall {
    PublicCall {
        id: id.to_owned(),
        title: format!("{tag} Synthetic Open Call"),
        opens: "2026-11-02T09:00:00Z".to_owned(),
        deadline: "2027-01-29T16:00:00Z".to_owned(),
        deadline_zone: "Europe/Brussels".to_owned(),
        budget: "250000.00".to_owned(),
        grant_min: "5000.00".to_owned(),
        grant_max: "100000.00".to_owned(),
        eligibility: vec![
            format!("{tag} synthetic eligibility rule one"),
            format!("{tag} synthetic eligibility rule two"),
        ],
        guide: guide.then(|| PublicGuide {
            version: 1,
            document: guide_document(&format!("{tag} Synthetic Guide")),
        }),
    }
}

/// One synthetic grant of `call` at `level`.
pub(crate) fn grant(call: &str, tag: &str, level: Level, status: GrantStatus) -> PublicGrant {
    PublicGrant {
        call: call.to_owned(),
        level,
        status,
        title: format!("{tag} synthetic project title"),
        summary: format!("{tag} synthetic public summary, approved by the grantee."),
        grantee: (level >= Level::ProjectAndGrantee).then(|| format!("{tag} Synthetic Grantee")),
        amount: (level == Level::Full).then(|| "40000.00".to_owned()),
        deliverables: Vec::new(),
    }
}

/// A synthetic view with two open calls, three funded grants, one
/// finished grant and one aggregate, with the feed `feed`.
pub(crate) fn sample_view(feed: bool) -> PublicView {
    PublicView {
        programme: PublicProgramme {
            slug: "supersafe".to_owned(),
            name: "SuperSAFE Synthetic Programme".to_owned(),
            narrative: "Synthetic narrative of a synthetic programme.".to_owned(),
            feed,
        },
        open_calls: vec![call("3", "Alpha", true), call("4", "Beta", false)],
        funded: vec![
            grant("1", "Gamma", Level::Project, GrantStatus::Granted),
            grant(
                "1",
                "Delta",
                Level::ProjectAndGrantee,
                GrantStatus::InExecution,
            ),
            grant("1", "Epsilon", Level::Full, GrantStatus::Granted),
        ],
        finished: vec![grant("1", "Zeta", Level::Full, GrantStatus::Completed)],
        aggregates: vec![PublicAggregate {
            call: "1".to_owned(),
            grants: 4,
            total: "160000.00".to_owned(),
        }],
    }
}

/// Every page of `view` that has a trace: the programme page, each call
/// page, funded and finished.
pub(crate) fn traced_pages(view: &PublicView) -> Vec<PublicPage> {
    let mut out = vec![PublicPage::Programme];
    out.extend(
        view.open_calls
            .iter()
            .map(|c| PublicPage::Call(c.id.clone())),
    );
    out.push(PublicPage::Funded);
    out.push(PublicPage::Finished);
    out
}

/// Every page of `view`, the Guide pages of calls with a Guide included.
pub(crate) fn all_pages(view: &PublicView) -> Vec<PublicPage> {
    let mut out = traced_pages(view);
    out.extend(
        view.open_calls
            .iter()
            .filter(|c| c.guide.is_some())
            .map(|c| PublicPage::Guide(c.id.clone())),
    );
    out
}

/// The text leaves of one call.
pub(crate) fn call_leaves(c: &PublicCall) -> Vec<String> {
    let mut out = vec![
        c.id.clone(),
        c.title.clone(),
        c.opens.clone(),
        c.deadline.clone(),
        c.deadline_zone.clone(),
        c.budget.clone(),
        c.grant_min.clone(),
        c.grant_max.clone(),
    ];
    out.extend(c.eligibility.iter().cloned());
    out
}

/// The text leaves of one grant.
pub(crate) fn grant_leaves(g: &PublicGrant) -> Vec<String> {
    let mut out = vec![g.call.clone(), g.title.clone(), g.summary.clone()];
    out.extend(g.grantee.iter().cloned());
    out.extend(g.amount.iter().cloned());
    out
}

/// The text leaves of one aggregate.
pub(crate) fn aggregate_leaves(a: &PublicAggregate) -> Vec<String> {
    vec![a.call.clone(), a.grants.to_string(), a.total.clone()]
}

/// The text leaves of `page`'s part of `view` (module documentation).
/// `None` for a page whose call the view lacks, and for a Guide page.
pub(crate) fn page_leaves(view: &PublicView, page: &PublicPage) -> Option<BTreeSet<String>> {
    let mut out = BTreeSet::from([view.programme.name.clone()]);
    match page {
        PublicPage::Programme => {
            out.insert(view.programme.narrative.clone());
            for c in &view.open_calls {
                out.extend([
                    c.id.clone(),
                    c.title.clone(),
                    c.grant_min.clone(),
                    c.grant_max.clone(),
                    c.deadline.clone(),
                    c.deadline_zone.clone(),
                ]);
            }
            for a in &view.aggregates {
                out.extend(aggregate_leaves(a));
            }
        }
        PublicPage::Call(id) => {
            let c = view.open_calls.iter().find(|c| &c.id == id)?;
            out.extend(call_leaves(c));
        }
        PublicPage::Funded => out.extend(view.funded.iter().flat_map(grant_leaves)),
        PublicPage::Finished => out.extend(view.finished.iter().flat_map(grant_leaves)),
        PublicPage::Guide(_) => return None,
    }
    Some(out)
}

/// The members of a feed or tool answer that are not text leaves: enum
/// tokens, the slug, flags and the Guide's own document.
pub(crate) const NOT_LEAVES: [&str; 6] = ["level", "status", "slug", "feed", "version", "html"];

/// Every string and number of `v`, numbers as their lexeme, outside the
/// members [`NOT_LEAVES`] names.
pub(crate) fn json_leaves(v: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    collect(v, &mut out);
    out
}

fn collect(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::String(s) => {
            out.insert(s.clone());
        }
        Value::Number(n) => {
            out.insert(n.to_string());
        }
        Value::Array(a) => {
            for x in a.iter() {
                collect(x, out);
            }
        }
        Value::Object(o) => {
            for (k, x) in o.iter() {
                if !NOT_LEAVES.contains(&k) {
                    collect(x, out);
                }
            }
        }
        Value::Null | Value::Bool(_) => {}
    }
}

/// `Ok` when `html` holds no script, no frame or object, no event handler
/// and no asset or form target from another origin (R-PB-04, TH-37).
pub(crate) fn scriptless(html: &str) -> Result<(), String> {
    let lower = html.to_ascii_lowercase();
    for banned in [
        "<script",
        "<iframe",
        "<object",
        "<embed",
        "<form",
        "javascript:",
        "@import",
        "url(",
    ] {
        if lower.contains(banned) {
            return Err(format!("the page holds {banned:?}"));
        }
    }
    for tag in lower.split('<').skip(1) {
        let head = tag.split('>').next().unwrap_or("");
        if head
            .split_ascii_whitespace()
            .skip(1)
            .any(|w| w.starts_with("on"))
        {
            return Err(format!("an event handler in <{head}>"));
        }
        for attr in ["src=", "href=", "action=", "srcset=", "poster="] {
            for q in ['"', '\''] {
                let needle = format!("{attr}{q}");
                let mut rest = head;
                while let Some(i) = rest.find(&needle) {
                    let value = &rest[i + needle.len()..];
                    if value.starts_with("http:")
                        || value.starts_with("https:")
                        || value.starts_with("//")
                    {
                        return Err(format!("an address on another origin in <{head}>"));
                    }
                    rest = value;
                }
            }
        }
    }
    Ok(())
}

/// The number of non-overlapping occurrences of `needle` in `hay`.
pub(crate) fn count(hay: &str, needle: &str) -> usize {
    hay.matches(needle).count()
}

// ---------------------------------------------------------------------------
// Generated views
// ---------------------------------------------------------------------------

/// A fresh canary leaf: `tag`, a running number and a random tail of
/// letters and digits, so every leaf of a view is unique and escapes to
/// itself.
fn canary(g: &mut Gen, n: &mut u32, tag: &str) -> String {
    *n = n.saturating_add(1);
    let tail: String = g
        .vec(4..=8, |g| *g.pick(b"abcdefghijkmnpqrstuvwxyz23456789"))
        .into_iter()
        .map(char::from)
        .collect();
    format!("{tag}{n}x{tail}")
}

/// A generated view: up to three open calls, up to three grants in each
/// phase and up to two aggregates, every leaf a unique canary.
pub(crate) fn gen_view(g: &mut Gen) -> PublicView {
    let mut n = 0_u32;
    let programme = PublicProgramme {
        slug: format!("prog{}", g.u8_in(0..=9)),
        name: canary(g, &mut n, "name"),
        narrative: canary(g, &mut n, "narr"),
        feed: g.bool(),
    };
    let calls = g.u8_in(0..=3);
    let mut open_calls = Vec::new();
    for i in 0..calls {
        let guide = g.bool();
        let eligibility = (0..g.u8_in(0..=3))
            .map(|_| canary(g, &mut n, "elig"))
            .collect();
        open_calls.push(PublicCall {
            id: format!("{}", u32::from(i).saturating_add(100)),
            title: canary(g, &mut n, "title"),
            opens: canary(g, &mut n, "opens"),
            deadline: canary(g, &mut n, "dl"),
            deadline_zone: canary(g, &mut n, "zone"),
            budget: canary(g, &mut n, "budget"),
            grant_min: canary(g, &mut n, "min"),
            grant_max: canary(g, &mut n, "max"),
            eligibility,
            guide: guide.then(|| PublicGuide {
                version: 1,
                document: guide_document("Synthetic Guide"),
            }),
        });
    }
    let grants = |g: &mut Gen, n: &mut u32, finished: bool| -> Vec<PublicGrant> {
        (0..g.u8_in(0..=3))
            .map(|_| {
                let level = *g.pick(&[Level::Project, Level::ProjectAndGrantee, Level::Full]);
                let status = if finished {
                    GrantStatus::Completed
                } else {
                    *g.pick(&[GrantStatus::Granted, GrantStatus::InExecution])
                };
                PublicGrant {
                    call: canary(g, n, "gcall"),
                    level,
                    status,
                    title: canary(g, n, "gtitle"),
                    summary: canary(g, n, "gsum"),
                    grantee: (level >= Level::ProjectAndGrantee).then(|| canary(g, n, "who")),
                    amount: (level == Level::Full).then(|| canary(g, n, "amt")),
                    deliverables: Vec::new(),
                }
            })
            .collect()
    };
    let funded = grants(g, &mut n, false);
    let finished = grants(g, &mut n, true);
    let aggregates = (0..g.u8_in(0..=2))
        .map(|_| PublicAggregate {
            call: canary(g, &mut n, "acall"),
            grants: g.u32_in(1_000..=9_999),
            total: canary(g, &mut n, "total"),
        })
        .collect();
    PublicView {
        programme,
        open_calls,
        funded,
        finished,
        aggregates,
    }
}
