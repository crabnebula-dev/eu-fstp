//! The public tool encoder. It takes only a `&PublicView` (rule A6).
//!
//! [`select`] answers one public tool with exactly the data of the public
//! pages, under the same filter, because it reads only the view (I-87).
//! The JSON shapes, interim, pending Daniel, pinned by
//! `tests/i87_pages.rs`:
//!
//! - `programme`: `{slug, name, narrative, feed, aggregates: [{call,
//!   grants, total}]}`.
//! - `open_calls`: `{calls: [call]}`, with each call as
//!   `{id, title, opens, deadline, deadline_zone, budget, grant_min,
//!   grant_max, eligibility: [text]}`, filtered by the search text.
//! - `call`: one call object. `guide`: `{call, version, html}`.
//! - `deadlines`: `{deadlines: [{call, title, deadline, deadline_zone}]}`.
//! - `eligibility`: `{eligibility: [{call, title, rules: [text]}]}`.
//! - `funded` and `finished`: `{grants: [grant]}`, with each grant as
//!   `{call, level, status, title, summary, grantee, amount}`. A member
//!   the level does not show is absent, never null.
//!   A finished grant whose grantee includes accepted deliverables also
//!   has `deliverables: [{licence, snapshot}]` (M9 lane P2). With none,
//!   the member is absent.
//!
//! A call the view does not hold is [`PublicError::NotFound`].

use fstp_json::{Object, Value};

use crate::PublicError;
use crate::query::{PublicPart, PublicQuery};
use crate::view::{GrantStatus, PublicAggregate, PublicCall, PublicGrant, PublicView};

/// The answer to one public tool query.
pub fn select(view: &PublicView, query: &PublicQuery) -> Result<Value, PublicError> {
    let out = match &query.part {
        PublicPart::Programme => programme(view),
        PublicPart::OpenCalls => open_calls(view, query.search.as_deref()),
        PublicPart::Call(id) => call(find(view, id)?),
        PublicPart::Guide(id) => {
            let c = find(view, id)?;
            let g = c.guide.as_ref().ok_or(PublicError::NotFound)?;
            object(vec![
                ("call", Value::from(c.id.as_str())),
                ("version", Value::from(g.version)),
                ("html", Value::from(g.document.as_str())),
            ])
        }
        PublicPart::Deadlines => object(vec![(
            "deadlines",
            Value::from(
                view.open_calls
                    .iter()
                    .map(|c| {
                        object(vec![
                            ("call", Value::from(c.id.as_str())),
                            ("title", Value::from(c.title.as_str())),
                            ("deadline", Value::from(c.deadline.as_str())),
                            ("deadline_zone", Value::from(c.deadline_zone.as_str())),
                        ])
                    })
                    .collect::<Vec<Value>>(),
            ),
        )]),
        PublicPart::Eligibility => object(vec![(
            "eligibility",
            Value::from(
                view.open_calls
                    .iter()
                    .map(|c| {
                        object(vec![
                            ("call", Value::from(c.id.as_str())),
                            ("title", Value::from(c.title.as_str())),
                            ("rules", strings(&c.eligibility)),
                        ])
                    })
                    .collect::<Vec<Value>>(),
            ),
        )]),
        PublicPart::Funded => grants(&view.funded),
        PublicPart::Finished => grants(&view.finished),
    };
    Ok(out)
}

/// The open call `id` of `view`.
fn find<'a>(view: &'a PublicView, id: &str) -> Result<&'a PublicCall, PublicError> {
    view.open_calls
        .iter()
        .find(|c| c.id == id)
        .ok_or(PublicError::NotFound)
}

/// An object of `members`, in order. Every name here is a distinct
/// constant, so no insert replaces another.
pub(crate) fn object(members: Vec<(&'static str, Value)>) -> Value {
    let mut o = Object::new();
    for (k, v) in members {
        let _ = o.insert(k, v);
    }
    Value::Object(o)
}

fn strings(items: &[String]) -> Value {
    Value::from(
        items
            .iter()
            .map(|s| Value::from(s.as_str()))
            .collect::<Vec<Value>>(),
    )
}

/// The programme part.
pub(crate) fn programme(view: &PublicView) -> Value {
    let p = &view.programme;
    object(vec![
        ("slug", Value::from(p.slug.as_str())),
        ("name", Value::from(p.name.as_str())),
        ("narrative", Value::from(p.narrative.as_str())),
        ("feed", Value::Bool(p.feed)),
        (
            "aggregates",
            Value::from(
                view.aggregates
                    .iter()
                    .map(aggregate)
                    .collect::<Vec<Value>>(),
            ),
        ),
    ])
}

fn aggregate(a: &PublicAggregate) -> Value {
    object(vec![
        ("call", Value::from(a.call.as_str())),
        ("grants", Value::from(a.grants)),
        ("total", Value::from(a.total.as_str())),
    ])
}

/// The open calls part, filtered by `search` over the titles, ignoring
/// ASCII case.
pub(crate) fn open_calls(view: &PublicView, search: Option<&str>) -> Value {
    let probe = search.map(str::to_ascii_lowercase);
    let calls: Vec<Value> = view
        .open_calls
        .iter()
        .filter(|c| {
            probe
                .as_deref()
                .is_none_or(|p| c.title.to_ascii_lowercase().contains(p))
        })
        .map(call)
        .collect();
    object(vec![("calls", Value::from(calls))])
}

/// One call object.
fn call(c: &PublicCall) -> Value {
    object(vec![
        ("id", Value::from(c.id.as_str())),
        ("title", Value::from(c.title.as_str())),
        ("opens", Value::from(c.opens.as_str())),
        ("deadline", Value::from(c.deadline.as_str())),
        ("deadline_zone", Value::from(c.deadline_zone.as_str())),
        ("budget", Value::from(c.budget.as_str())),
        ("grant_min", Value::from(c.grant_min.as_str())),
        ("grant_max", Value::from(c.grant_max.as_str())),
        ("eligibility", strings(&c.eligibility)),
    ])
}

/// A funded or finished part.
pub(crate) fn grants(list: &[PublicGrant]) -> Value {
    object(vec![(
        "grants",
        Value::from(list.iter().map(grant).collect::<Vec<Value>>()),
    )])
}

/// One grant object. A member the level does not show is absent.
fn grant(g: &PublicGrant) -> Value {
    let mut o = Object::new();
    let _ = o.insert("call", Value::from(g.call.as_str()));
    let _ = o.insert("level", Value::from(g.level.token()));
    let _ = o.insert("status", Value::from(status_token(g.status)));
    let _ = o.insert("title", Value::from(g.title.as_str()));
    let _ = o.insert("summary", Value::from(g.summary.as_str()));
    if let Some(who) = &g.grantee {
        let _ = o.insert("grantee", Value::from(who.as_str()));
    }
    if let Some(a) = &g.amount {
        let _ = o.insert("amount", Value::from(a.as_str()));
    }
    if !g.deliverables.is_empty() {
        let list: Vec<Value> = g
            .deliverables
            .iter()
            .map(|d| {
                object(vec![
                    ("licence", Value::from(d.licence.as_str())),
                    ("snapshot", Value::from(d.snapshot.as_str())),
                ])
            })
            .collect();
        let _ = o.insert("deliverables", Value::from(list));
    }
    Value::Object(o)
}

/// The token of a grant phase, as `state-machine.md` names the state.
pub(crate) fn status_token(s: GrantStatus) -> &'static str {
    match s {
        GrantStatus::Granted => "GRANTED",
        GrantStatus::InExecution => "IN_EXECUTION",
        GrantStatus::Completed => "COMPLETED",
    }
}
