//! Self-test of the render-trace sink (I-87 seam, M4 design sections 1.1
//! and 8.4).
//!
//! `i87_page_render_trace_equals_view_leaves` in lane W2c compares the
//! sink's record of a public page with the leaves of its `PublicView`, with
//! no HTML parser. That test is only as good as the sink: a dynamic value
//! that reaches the page without passing the sink would escape it. So the
//! sink must record every dynamic value, as the caller passed it, once per
//! time it is written, and every catalogue message by id, and nothing else.
//! Recording must not change the bytes.
//!
//! Red against the W0 stub: the writer and the sink do not exist yet, and
//! `common::bind` refuses with `NotImplemented`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::bind::{self, Ctx, Event};
use common::chars::is_typed;
use common::message::{self, Kind};
use common::reference;
use common::spec::{self, Attr, Msg, Node, Page};
use fstp_prop::{check, prop_assert, prop_assert_eq};

/// I-87: the trace is exactly the page's dynamic values and message ids,
/// in document order, with the place each was written. Values are traced
/// as passed, before escaping or replacement.
#[test]
fn i87_trace_records_every_dynamic_value_and_message() {
    let spec_cats = message::fixture();
    check("i87_trace_records_every_dynamic_value_and_message", |g| {
        let cats = bind::catalogues(&spec_cats).map_err(|e| e.to_string())?;
        let page = spec::page(g, &spec_cats, spec::ANY);
        match bind::render(&page, &cats) {
            Err(e) => prop_assert!(is_typed(&e), "{e}"),
            Ok(r) => prop_assert_eq!(r.trace, spec::expected_trace(&page, &spec_cats)?),
        }
        Ok(())
    });
}

/// I-87: the recording sink and the production sink give the same bytes,
/// and refuse the same pages.
#[test]
fn i87_trace_does_not_change_the_bytes() {
    let spec_cats = message::fixture();
    check("i87_trace_does_not_change_the_bytes", |g| {
        let cats = bind::catalogues(&spec_cats).map_err(|e| e.to_string())?;
        let page = spec::page(g, &spec_cats, spec::ANY);
        let traced = bind::render(&page, &cats).map(|r| r.bytes);
        let plain = bind::render_untraced(&page, &cats);
        if let Err(e) = &traced {
            prop_assert!(is_typed(e), "{e}");
        }
        prop_assert_eq!(traced, plain);
        Ok(())
    });
}

/// The canary of the `n`th dynamic text value. Its start and end markers
/// differ, so adjacent text nodes that merge on the page never join two
/// canaries into a third.
fn text_canary(n: usize) -> String {
    format!("\u{2603}{n}\u{2604}")
}

/// The canary of the `n`th URL. The prefixed URL stays a safe path. Its
/// start and end markers share no character, as for the text canary.
fn url_canary(n: usize) -> String {
    format!("/KQ{n}ZX")
}

fn mark_msg(m: &mut Msg, n: &mut usize) {
    for (_, v) in &mut m.args {
        *v = format!("{}{v}", text_canary(*n));
        *n += 1;
    }
}

fn mark(nodes: &mut [Node], n: &mut usize) {
    for node in nodes {
        match node {
            Node::Text(t) => {
                *t = format!("{}{t}", text_canary(*n));
                *n += 1;
            }
            Node::Msg(m) => mark_msg(m, n),
            Node::El(e) => {
                for (_, a) in &mut e.attrs {
                    match a {
                        Attr::Text(t) => {
                            *t = format!("{}{t}", text_canary(*n));
                            *n += 1;
                        }
                        Attr::Url(u) => {
                            *u = format!("{}{u}", url_canary(*n));
                            *n += 1;
                        }
                        Attr::Flag => {}
                        Attr::Msg(m) => mark_msg(m, n),
                    }
                }
                mark(&mut e.children, n);
            }
        }
    }
}

/// Gives every dynamic value of `page` a unique canary prefix and returns
/// the canaries.
fn canaries(page: &mut Page) -> Vec<String> {
    let mut n = 0;
    mark(&mut page.title, &mut n);
    if let Some(u) = &mut page.stylesheet {
        *u = format!("{}{u}", url_canary(n));
        n += 1;
    }
    mark(&mut page.body, &mut n);
    (0..n)
        .flat_map(|i| [text_canary(i), url_canary(i)])
        .collect()
}

fn count(haystack: &[String], needle: &str) -> usize {
    haystack.iter().map(|h| h.matches(needle).count()).sum()
}

/// I-87: with a unique canary in every dynamic value, each canary appears
/// in the decoded page exactly as many times as the sink recorded it, and
/// the sink recorded it once per time the page uses it. So no dynamic
/// value reaches the page around the sink.
#[test]
fn i87_every_traced_value_reaches_the_page_once_per_use() {
    let spec_cats = message::fixture();
    check(
        "i87_every_traced_value_reaches_the_page_once_per_use",
        |g| {
            let cats = bind::catalogues(&spec_cats).map_err(|e| e.to_string())?;
            let mut page = spec::page(g, &spec_cats, spec::VALID);
            let marks = canaries(&mut page);
            let r = bind::render(&page, &cats).map_err(|e| format!("refused: {e}"))?;
            let tree = reference::parse(&r.bytes).map_err(|e| format!("not in the subset: {e}"))?;
            let mut on_page = reference::texts(&tree);
            on_page.extend(reference::attr_values(&tree));
            let traced: Vec<String> = r
                .trace
                .iter()
                .filter_map(|e| match e {
                    Event::Dynamic { value, .. } => Some(value.clone()),
                    Event::Message { .. } => None,
                })
                .collect();
            let expected: Vec<String> = spec::expected_trace(&page, &spec_cats)?
                .into_iter()
                .filter_map(|e| match e {
                    Event::Dynamic { value, .. } => Some(value),
                    Event::Message { .. } => None,
                })
                .collect();
            for m in &marks {
                let want = count(&expected, m);
                prop_assert_eq!(count(&traced, m), want, "canary {m:?} in the trace");
                prop_assert_eq!(count(&on_page, m), want, "canary {m:?} on the page");
            }
            Ok(())
        },
    );
}

/// I-87, R-NF-04: a message traces its id, then each argument once per
/// placeholder use, in the order of the locale's message. The French
/// `call.budget` uses `amount` twice.
#[test]
fn i87_message_trace_lists_each_placeholder_use() {
    let spec_cats = message::fixture();
    let cats = bind::catalogues(&spec_cats).unwrap_or_else(|e| panic!("{e}"));
    let budget = Msg {
        kind: Kind::Label,
        id: "call.budget".to_owned(),
        args: vec![("amount".to_owned(), "5 000,00 <EUR>".to_owned())],
    };
    let mut page = spec::page_with("fr", vec![Node::Msg(budget)]);
    page.title = vec![Node::Msg(Msg {
        kind: Kind::Label,
        id: "nav.home".to_owned(),
        args: Vec::new(),
    })];
    let r = bind::render(&page, &cats).unwrap_or_else(|e| panic!("{e}"));
    let amount = Event::Dynamic {
        ctx: Ctx::Text,
        value: "5 000,00 <EUR>".to_owned(),
    };
    assert_eq!(
        r.trace,
        vec![
            Event::Message {
                kind: Kind::Label,
                id: "nav.home".to_owned(),
                ctx: Ctx::Text,
            },
            Event::Message {
                kind: Kind::Label,
                id: "call.budget".to_owned(),
                ctx: Ctx::Text,
            },
            amount.clone(),
            amount,
        ]
    );
}

/// I-87, I-72: catalogue literals are never traced as dynamic text. A page
/// of messages with no argument traces only message ids.
#[test]
fn i87_catalogue_literals_are_not_dynamic() {
    let spec_cats = message::fixture();
    let cats = bind::catalogues(&spec_cats).unwrap_or_else(|e| panic!("{e}"));
    let home = |kind| Msg {
        kind,
        id: "nav.home".to_owned(),
        args: Vec::new(),
    };
    let mut page = spec::page_with(
        "en",
        vec![spec::el(
            "nav",
            vec![("aria-label", Attr::Msg(home(Kind::Label)))],
            vec![Node::Msg(home(Kind::Label))],
        )],
    );
    page.title = vec![Node::Msg(home(Kind::Label))];
    let r = bind::render(&page, &cats).unwrap_or_else(|e| panic!("{e}"));
    let ev = |ctx| Event::Message {
        kind: Kind::Label,
        id: "nav.home".to_owned(),
        ctx,
    };
    assert_eq!(
        r.trace,
        vec![
            ev(Ctx::Text),
            ev(Ctx::Attr("aria-label".to_owned())),
            ev(Ctx::Text)
        ]
    );
}
