//! The page model the tests render, its generators, and the expected tree
//! and trace of a page.
//!
//! A page is what a caller of the writer expresses: a locale, a title, an
//! optional stylesheet and a body of elements, dynamic texts and catalogue
//! messages. The writer adds only the fixed skeleton:
//!
//! ```text
//! <!DOCTYPE html><html lang="{locale}"><head><meta charset="utf-8">
//! <title>{title}</title>[<link rel="stylesheet" href="{url}">]</head>
//! <body>{body}</body></html>
//! ```
//!
//! Interim reading, pending Daniel: the locale and the skeleton are not
//! dynamic, so the trace holds neither. Every value the caller passes is
//! dynamic and traced, the stylesheet URL included.

use fstp_prop::Gen;

use super::bind::{Ctx, Event};
use super::chars::{self, replace_nonplain};
use super::message::{self, CatSpec, Kind};
use super::reference::{REl, RNode};

/// A catalogue message with its arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Msg {
    /// Label or approved wording.
    pub(crate) kind: Kind,
    /// The message id.
    pub(crate) id: String,
    /// The arguments, by placeholder name.
    pub(crate) args: Vec<(String, String)>,
}

/// An attribute value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Attr {
    /// A dynamic text value.
    Text(String),
    /// A dynamic URL.
    Url(String),
    /// A boolean attribute that is present.
    Flag,
    /// A catalogue message.
    Msg(Msg),
}

/// A body node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Node {
    /// An element.
    El(El),
    /// A dynamic text.
    Text(String),
    /// A catalogue message.
    Msg(Msg),
}

/// An element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct El {
    /// The tag name.
    pub(crate) tag: &'static str,
    /// The attributes, in the order the caller gives them.
    pub(crate) attrs: Vec<(&'static str, Attr)>,
    /// The children.
    pub(crate) children: Vec<Node>,
}

/// A page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Page {
    /// The locale whose catalogue renders the messages.
    pub(crate) locale: String,
    /// The title content: `Node::Text` and `Node::Msg` only.
    pub(crate) title: Vec<Node>,
    /// The stylesheet URL, if any.
    pub(crate) stylesheet: Option<String>,
    /// The body content.
    pub(crate) body: Vec<Node>,
}

/// An element with attributes and children.
pub(crate) fn el(tag: &'static str, attrs: Vec<(&'static str, Attr)>, children: Vec<Node>) -> Node {
    Node::El(El {
        tag,
        attrs,
        children,
    })
}

/// A dynamic text node.
pub(crate) fn text(s: &str) -> Node {
    Node::Text(s.to_owned())
}

/// A page in `locale` with a plain title and `body`.
pub(crate) fn page_with(locale: &str, body: Vec<Node>) -> Page {
    Page {
        locale: locale.to_owned(),
        title: vec![text("Page")],
        stylesheet: None,
        body,
    }
}

// ---------------------------------------------------------------------------
// Expected tree.

fn resolve(cats: &CatSpec, locale: &str, m: &Msg) -> Result<(String, Vec<String>), String> {
    let args: Vec<(String, String)> = m
        .args
        .iter()
        .map(|(k, v)| (k.clone(), replace_nonplain(v)))
        .collect();
    cats.resolve(locale, m.kind, &m.id, &args)
}

fn push_text(out: &mut Vec<RNode>, t: String) {
    if t.is_empty() {
        return;
    }
    if let Some(RNode::Text(prev)) = out.last_mut() {
        prev.push_str(&t);
    } else {
        out.push(RNode::Text(t));
    }
}

fn expect_nodes(nodes: &[Node], cats: &CatSpec, locale: &str) -> Result<Vec<RNode>, String> {
    let mut out = Vec::new();
    for n in nodes {
        match n {
            Node::Text(t) => push_text(&mut out, replace_nonplain(t)),
            Node::Msg(m) => push_text(&mut out, resolve(cats, locale, m)?.0),
            Node::El(e) => {
                let mut r = REl::new(e.tag);
                for (name, a) in &e.attrs {
                    let v = match a {
                        Attr::Text(t) => replace_nonplain(t),
                        Attr::Url(u) => u.clone(),
                        Attr::Flag => String::new(),
                        Attr::Msg(m) => resolve(cats, locale, m)?.0,
                    };
                    r.attrs.insert((*name).to_owned(), v);
                }
                r.children = expect_nodes(&e.children, cats, locale)?;
                out.push(RNode::El(r));
            }
        }
    }
    Ok(out)
}

/// The decoded tree a correct writer produces for `page`, when it accepts
/// it. Characters that are not plain appear as U+FFFD.
pub(crate) fn expected_tree(page: &Page, cats: &CatSpec) -> Result<REl, String> {
    let mut meta = REl::new("meta");
    meta.attrs.insert("charset".to_owned(), "utf-8".to_owned());
    let mut title = REl::new("title");
    title.children = expect_nodes(&page.title, cats, &page.locale)?;
    let mut head = REl::new("head");
    head.children.push(RNode::El(meta));
    head.children.push(RNode::El(title));
    if let Some(u) = &page.stylesheet {
        let mut link = REl::new("link");
        link.attrs.insert("rel".to_owned(), "stylesheet".to_owned());
        link.attrs.insert("href".to_owned(), u.clone());
        head.children.push(RNode::El(link));
    }
    let mut body = REl::new("body");
    body.children = expect_nodes(&page.body, cats, &page.locale)?;
    let mut html = REl::new("html");
    html.attrs.insert("lang".to_owned(), page.locale.clone());
    html.children = vec![RNode::El(head), RNode::El(body)];
    Ok(html)
}

// ---------------------------------------------------------------------------
// Expected trace.

fn trace_msg(
    out: &mut Vec<Event>,
    cats: &CatSpec,
    locale: &str,
    m: &Msg,
    ctx: &Ctx,
) -> Result<(), String> {
    let (_, uses) = resolve(cats, locale, m)?;
    out.push(Event::Message {
        kind: m.kind,
        id: m.id.clone(),
        ctx: ctx.clone(),
    });
    for name in uses {
        let value = m
            .args
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        out.push(Event::Dynamic {
            ctx: ctx.clone(),
            value,
        });
    }
    Ok(())
}

fn trace_nodes(
    out: &mut Vec<Event>,
    nodes: &[Node],
    cats: &CatSpec,
    locale: &str,
) -> Result<(), String> {
    for n in nodes {
        match n {
            Node::Text(t) => out.push(Event::Dynamic {
                ctx: Ctx::Text,
                value: t.clone(),
            }),
            Node::Msg(m) => trace_msg(out, cats, locale, m, &Ctx::Text)?,
            Node::El(e) => {
                for (name, a) in &e.attrs {
                    match a {
                        Attr::Text(t) => out.push(Event::Dynamic {
                            ctx: Ctx::Attr((*name).to_owned()),
                            value: t.clone(),
                        }),
                        Attr::Url(u) => out.push(Event::Dynamic {
                            ctx: Ctx::Url((*name).to_owned()),
                            value: u.clone(),
                        }),
                        Attr::Flag => {}
                        Attr::Msg(m) => {
                            trace_msg(out, cats, locale, m, &Ctx::Attr((*name).to_owned()))?;
                        }
                    }
                }
                trace_nodes(out, &e.children, cats, locale)?;
            }
        }
    }
    Ok(())
}

/// The trace the test sink records for `page`: every dynamic value as the
/// caller passed it and every message id, in document order. The
/// attributes of one element come in the order the caller gave them.
pub(crate) fn expected_trace(page: &Page, cats: &CatSpec) -> Result<Vec<Event>, String> {
    let mut out = Vec::new();
    trace_nodes(&mut out, &page.title, cats, &page.locale)?;
    if let Some(u) = &page.stylesheet {
        out.push(Event::Dynamic {
            ctx: Ctx::Url("href".to_owned()),
            value: u.clone(),
        });
    }
    trace_nodes(&mut out, &page.body, cats, &page.locale)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Facts about a page.

fn visit_values(nodes: &[Node], texts: &mut Vec<String>, urls: &mut Vec<String>) {
    for n in nodes {
        match n {
            Node::Text(t) => texts.push(t.clone()),
            Node::Msg(m) => texts.extend(m.args.iter().map(|(_, v)| v.clone())),
            Node::El(e) => {
                for (_, a) in &e.attrs {
                    match a {
                        Attr::Text(t) => texts.push(t.clone()),
                        Attr::Url(u) => urls.push(u.clone()),
                        Attr::Flag => {}
                        Attr::Msg(m) => texts.extend(m.args.iter().map(|(_, v)| v.clone())),
                    }
                }
                visit_values(&e.children, texts, urls);
            }
        }
    }
}

/// The dynamic text values of `page` (URLs excluded) and its URLs.
pub(crate) fn values(page: &Page) -> (Vec<String>, Vec<String>) {
    let mut texts = Vec::new();
    let mut urls = Vec::new();
    visit_values(&page.title, &mut texts, &mut urls);
    if let Some(u) = &page.stylesheet {
        urls.push(u.clone());
    }
    visit_values(&page.body, &mut texts, &mut urls);
    (texts, urls)
}

/// Whether every dynamic text of `page` is plain.
pub(crate) fn texts_plain(page: &Page) -> bool {
    values(page).0.iter().all(|t| chars::all_plain(t))
}

/// Whether every URL of `page` is safe.
pub(crate) fn urls_safe(page: &Page) -> bool {
    values(page).1.iter().all(|u| chars::is_safe_url(u))
}

// ---------------------------------------------------------------------------
// Generators.

/// How a generator draws dynamic values.
#[derive(Clone, Copy)]
pub(crate) struct Draw {
    /// Draws a dynamic text.
    pub(crate) text: fn(&mut Gen) -> String,
    /// Draws a URL.
    pub(crate) url: fn(&mut Gen) -> String,
}

/// Hostile texts, some not plain, and URLs both safe and unsafe.
pub(crate) const ANY: Draw = Draw {
    text: chars::dynamic,
    url: chars::url,
};

/// Plain hostile texts and safe URLs only, which the writer must accept.
pub(crate) const VALID: Draw = Draw {
    text: chars::hostile_plain,
    url: safe_url,
};

/// A URL that is always safe.
pub(crate) fn safe_url(g: &mut Gen) -> String {
    loop {
        let u = chars::url(g);
        if chars::is_safe_url(&u) {
            return u;
        }
        if g.bool() {
            return "/".to_owned();
        }
    }
}

/// A message of `cats` with generated arguments.
pub(crate) fn msg(g: &mut Gen, cats: &CatSpec, draw: Draw) -> Msg {
    let e = g.pick(&cats.default.entries).clone();
    let names = message::parse(e.message.as_bytes())
        .map(|p| message::names(&p))
        .unwrap_or_default();
    let args = names.into_iter().map(|n| (n, (draw.text)(g))).collect();
    Msg {
        kind: e.kind,
        id: e.id,
        args,
    }
}

#[derive(Clone, Copy, Default)]
struct Cx {
    depth: u8,
    in_a: bool,
    in_form: bool,
    in_button: bool,
}

impl Cx {
    fn down(self) -> Cx {
        Cx {
            depth: self.depth.saturating_add(1),
            ..self
        }
    }
}

const MAX_DEPTH: u8 = 4;

fn leaf(g: &mut Gen, cats: &CatSpec, draw: Draw) -> Node {
    if g.u8_in(0..=2) == 0 {
        Node::Msg(msg(g, cats, draw))
    } else {
        Node::Text((draw.text)(g))
    }
}

/// Global attributes: `title` and `aria-label`, each optional.
fn global_attrs(g: &mut Gen, cats: &CatSpec, draw: Draw) -> Vec<(&'static str, Attr)> {
    let mut out = Vec::new();
    if g.u8_in(0..=3) == 0 {
        out.push(("title", Attr::Text((draw.text)(g))));
    }
    if g.u8_in(0..=3) == 0 {
        let v = if g.bool() {
            Attr::Msg(msg(g, cats, draw))
        } else {
            Attr::Text((draw.text)(g))
        };
        out.push(("aria-label", v));
    }
    out
}

fn text_only(g: &mut Gen, cats: &CatSpec, draw: Draw) -> Vec<Node> {
    g.vec(0..=2, |g| leaf(g, cats, draw))
}

fn flow(g: &mut Gen, cx: Cx, cats: &CatSpec, draw: Draw) -> Vec<Node> {
    g.vec(0..=3, |g| flow_node(g, cx, cats, draw))
}

fn phrasing(g: &mut Gen, cx: Cx, cats: &CatSpec, draw: Draw) -> Vec<Node> {
    g.vec(0..=3, |g| phrasing_node(g, cx, cats, draw))
}

fn flow_node(g: &mut Gen, cx: Cx, cats: &CatSpec, draw: Draw) -> Node {
    if cx.depth >= MAX_DEPTH {
        return leaf(g, cats, draw);
    }
    let d = cx.down();
    let mut attrs = global_attrs(g, cats, draw);
    match g.u8_in(0..=11) {
        0 => el("div", attrs, flow(g, d, cats, draw)),
        1 => el("section", attrs, flow(g, d, cats, draw)),
        2 => el("p", attrs, phrasing(g, d, cats, draw)),
        3 => el("h2", attrs, phrasing(g, d, cats, draw)),
        4 => {
            let tag = if g.bool() { "ul" } else { "ol" };
            let items = g.vec(0..=3, |g| {
                let a = global_attrs(g, cats, draw);
                el("li", a, flow(g, d.down(), cats, draw))
            });
            el(tag, attrs, items)
        }
        5 => {
            let items = g.vec(0..=3, |g| {
                let tag = if g.bool() { "dt" } else { "dd" };
                let kids = if tag == "dt" {
                    phrasing(g, d.down(), cats, draw)
                } else {
                    flow(g, d.down(), cats, draw)
                };
                el(tag, Vec::new(), kids)
            });
            el("dl", attrs, items)
        }
        6 => {
            let mut parts = Vec::new();
            if g.bool() {
                parts.push(el("caption", Vec::new(), phrasing(g, d.down(), cats, draw)));
            }
            let rows = g.vec(1..=2, |g| {
                let cells = g.vec(1..=2, |g| {
                    if g.bool() {
                        el("th", Vec::new(), phrasing(g, d.down().down(), cats, draw))
                    } else {
                        el("td", Vec::new(), flow(g, d.down().down(), cats, draw))
                    }
                });
                el("tr", Vec::new(), cells)
            });
            parts.push(el("tbody", Vec::new(), rows));
            el("table", attrs, parts)
        }
        7 => el("pre", attrs, phrasing(g, d, cats, draw)),
        8 if !cx.in_form => {
            if g.bool() {
                attrs.push(("action", Attr::Url((draw.url)(g))));
            }
            let inner = Cx { in_form: true, ..d };
            el("form", attrs, flow(g, inner, cats, draw))
        }
        9 => el("blockquote", attrs, flow(g, d, cats, draw)),
        10 => phrasing_node(g, cx, cats, draw),
        _ => leaf(g, cats, draw),
    }
}

fn phrasing_node(g: &mut Gen, cx: Cx, cats: &CatSpec, draw: Draw) -> Node {
    if cx.depth >= MAX_DEPTH {
        return leaf(g, cats, draw);
    }
    let d = cx.down();
    let mut attrs = global_attrs(g, cats, draw);
    match g.u8_in(0..=13) {
        0 => el("span", attrs, phrasing(g, d, cats, draw)),
        1 => el("strong", attrs, phrasing(g, d, cats, draw)),
        2 => el("em", attrs, phrasing(g, d, cats, draw)),
        3 => el("code", attrs, phrasing(g, d, cats, draw)),
        4 if !cx.in_a => {
            if g.bool() {
                attrs.push(("href", Attr::Url((draw.url)(g))));
            }
            let inner = Cx { in_a: true, ..d };
            el("a", attrs, phrasing(g, inner, cats, draw))
        }
        5 => el("br", attrs, Vec::new()),
        6 => {
            attrs.push(("src", Attr::Url((draw.url)(g))));
            attrs.push(("alt", Attr::Text((draw.text)(g))));
            el("img", attrs, Vec::new())
        }
        7 => {
            if g.bool() {
                attrs.push(("value", Attr::Text((draw.text)(g))));
            }
            if g.bool() {
                attrs.push(("placeholder", Attr::Text((draw.text)(g))));
            }
            if g.bool() {
                attrs.push(("required", Attr::Flag));
            }
            el("input", attrs, Vec::new())
        }
        8 if !cx.in_button => {
            if g.bool() {
                attrs.push(("disabled", Attr::Flag));
            }
            let inner = Cx {
                in_button: true,
                ..d
            };
            el("button", attrs, phrasing(g, inner, cats, draw))
        }
        9 => el("label", attrs, phrasing(g, d, cats, draw)),
        10 => {
            if g.bool() {
                attrs.push(("placeholder", Attr::Text((draw.text)(g))));
            }
            el("textarea", attrs, text_only(g, cats, draw))
        }
        11 => {
            let options = g.vec(1..=3, |g| {
                let mut a = Vec::new();
                if g.bool() {
                    a.push(("value", Attr::Text((draw.text)(g))));
                }
                if g.u8_in(0..=3) == 0 {
                    a.push(("selected", Attr::Flag));
                }
                el("option", a, text_only(g, cats, draw))
            });
            el("select", attrs, options)
        }
        12 => {
            attrs.push(("datetime", Attr::Text((draw.text)(g))));
            el("time", attrs, phrasing(g, d, cats, draw))
        }
        _ => leaf(g, cats, draw),
    }
}

/// A whole page in a locale of `cats`.
pub(crate) fn page(g: &mut Gen, cats: &CatSpec, draw: Draw) -> Page {
    let locales = cats.locales();
    let locale = (*g.pick(&locales)).to_owned();
    let title = text_only(g, cats, draw);
    let stylesheet = g.option(|g| (draw.url)(g));
    let body = flow(g, Cx::default(), cats, draw);
    Page {
        locale,
        title,
        stylesheet,
        body,
    }
}

// ---------------------------------------------------------------------------
// One context at a time.

/// A place where a dynamic value can be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Place {
    /// Text in a `p`.
    TextInP,
    /// Text in the `title` (RCDATA).
    TextInTitle,
    /// Text in a `textarea` (RCDATA, leading line feed dropped).
    TextInTextarea,
    /// Text in a `pre` (leading line feed dropped).
    TextInPre,
    /// Text in an `option`.
    TextInOption,
    /// Text in a table cell.
    TextInCell,
    /// Text in a list item.
    TextInListItem,
    /// The global `title` attribute.
    AttrTitle,
    /// The `alt` attribute of an image.
    AttrAlt,
    /// The `value` attribute of an input.
    AttrValue,
    /// The `placeholder` attribute of a textarea.
    AttrPlaceholder,
    /// The `aria-label` attribute.
    AttrAriaLabel,
    /// The `href` of a link.
    UrlHref,
    /// The `src` of an image.
    UrlSrc,
    /// The `action` of a form.
    UrlAction,
    /// The `href` of the stylesheet link in the head.
    UrlStylesheet,
    /// A message argument in text.
    ArgInText,
    /// A message argument in an attribute.
    ArgInAttr,
}

impl Place {
    /// Whether the place holds a URL.
    pub(crate) fn is_url(self) -> bool {
        matches!(
            self,
            Place::UrlHref | Place::UrlSrc | Place::UrlAction | Place::UrlStylesheet
        )
    }
}

fn arg(id: &str, kind: Kind, name: &str, v: &str) -> Msg {
    Msg {
        kind,
        id: id.to_owned(),
        args: vec![(name.to_owned(), v.to_owned())],
    }
}

/// The smallest page that writes `v` at `place`, in `locale`.
pub(crate) fn at(place: Place, locale: &str, v: &str) -> Page {
    let s = || v.to_owned();
    let mut p = page_with(locale, Vec::new());
    p.body = match place {
        Place::TextInP => vec![el("p", vec![], vec![text(v)])],
        Place::TextInTitle => {
            p.title = vec![text(v)];
            vec![]
        }
        Place::TextInTextarea => vec![el(
            "div",
            vec![],
            vec![el("textarea", vec![], vec![text(v)])],
        )],
        Place::TextInPre => vec![el("pre", vec![], vec![text(v)])],
        Place::TextInOption => vec![el(
            "div",
            vec![],
            vec![el(
                "select",
                vec![],
                vec![el("option", vec![], vec![text(v)])],
            )],
        )],
        Place::TextInCell => vec![el(
            "table",
            vec![],
            vec![el(
                "tbody",
                vec![],
                vec![el("tr", vec![], vec![el("td", vec![], vec![text(v)])])],
            )],
        )],
        Place::TextInListItem => vec![el("ul", vec![], vec![el("li", vec![], vec![text(v)])])],
        Place::AttrTitle => vec![el("p", vec![("title", Attr::Text(s()))], vec![text("x")])],
        Place::AttrAlt => vec![el(
            "p",
            vec![],
            vec![el(
                "img",
                vec![
                    ("src", Attr::Url("/i.png".to_owned())),
                    ("alt", Attr::Text(s())),
                ],
                vec![],
            )],
        )],
        Place::AttrValue => vec![el(
            "form",
            vec![("action", Attr::Url("/f".to_owned()))],
            vec![el("input", vec![("value", Attr::Text(s()))], vec![])],
        )],
        Place::AttrPlaceholder => vec![el(
            "div",
            vec![],
            vec![el(
                "textarea",
                vec![("placeholder", Attr::Text(s()))],
                vec![],
            )],
        )],
        Place::AttrAriaLabel => vec![el("nav", vec![("aria-label", Attr::Text(s()))], vec![])],
        Place::UrlHref => vec![el(
            "p",
            vec![],
            vec![el("a", vec![("href", Attr::Url(s()))], vec![text("link")])],
        )],
        Place::UrlSrc => vec![el(
            "p",
            vec![],
            vec![el(
                "img",
                vec![("src", Attr::Url(s())), ("alt", Attr::Text("x".to_owned()))],
                vec![],
            )],
        )],
        Place::UrlAction => vec![el("form", vec![("action", Attr::Url(s()))], vec![])],
        Place::UrlStylesheet => {
            p.stylesheet = Some(s());
            vec![]
        }
        Place::ArgInText => vec![el(
            "p",
            vec![],
            vec![Node::Msg(arg("call.deadline", Kind::Label, "date", v))],
        )],
        Place::ArgInAttr => vec![el(
            "p",
            vec![(
                "title",
                Attr::Msg(arg("call.budget", Kind::Label, "amount", v)),
            )],
            vec![text("x")],
        )],
    };
    p
}
