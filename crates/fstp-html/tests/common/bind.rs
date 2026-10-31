//! The one seam between these tests and the writer API.
//!
//! Gap, reported by the W1d test author. The W0 stub exports only
//! `check_wellformed`, `parse_message_format` and `parse_accept_language`,
//! and the M4 design names no signature for the writer, the catalogues,
//! `Label`, `ApprovedText` or the trace sink. So the tests state what they
//! need here, in terms of the page model of `spec`, and every function
//! refuses with `NotImplemented` until the writer exists.
//!
//! The implementer replaces each body with calls to the public API of
//! `fstp_html` and nothing else. A body here must not escape, filter,
//! decode, reorder or record anything itself, because then the tests would
//! check this file instead of the crate. In particular:
//!
//! - `render` must emit every node of the page through the writer, every
//!   `Node::Text` and `Attr::Text` as a dynamic text, every `Attr::Url`
//!   through the writer's URL type, and every `Node::Msg` and `Attr::Msg`
//!   as a `Label` or `ApprovedText` of the catalogue;
//! - the trace must come from the crate's test sink, converted one event
//!   at a time;
//! - `render_untraced` must use the sink production uses.

use fstp_html::HtmlError;

use super::message::{CatSpec, Kind, LocaleCat, Override};
use super::spec::{Attr, Msg, Node, Page};

/// Where a dynamic value or message was written.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Ctx {
    /// A text node (including `title` and `textarea` content).
    Text,
    /// The value of the named attribute.
    Attr(String),
    /// The value of the named URL attribute.
    Url(String),
}

/// One event of the render trace.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Event {
    /// A dynamic value, as the caller passed it, before escaping.
    Dynamic {
        /// Where it was written.
        ctx: Ctx,
        /// The value.
        value: String,
    },
    /// A catalogue message, by id. Its literals are not dynamic; its
    /// arguments follow as `Dynamic` events, one per placeholder use.
    Message {
        /// Label or approved wording.
        kind: Kind,
        /// The message id.
        id: String,
        /// Where it was written.
        ctx: Ctx,
    },
}

/// A rendered page and its trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Rendered {
    /// The document bytes.
    pub(crate) bytes: Vec<u8>,
    /// What the test sink recorded, in the order it was recorded.
    pub(crate) trace: Vec<Event>,
}

/// A built catalogue set: the crate's catalogue type.
#[derive(Debug)]
pub(crate) struct Catalogues {
    inner: fstp_html::Catalogues,
}

fn kind_to(k: Kind) -> fstp_html::MessageKind {
    match k {
        Kind::Label => fstp_html::MessageKind::Label,
        Kind::Approved => fstp_html::MessageKind::Approved,
    }
}

fn kind_from(k: fstp_html::MessageKind) -> Kind {
    match k {
        fstp_html::MessageKind::Label => Kind::Label,
        fstp_html::MessageKind::Approved => Kind::Approved,
    }
}

fn entries(cat: &LocaleCat) -> Vec<fstp_html::EntrySource<'_>> {
    cat.entries
        .iter()
        .map(|e| fstp_html::EntrySource {
            id: &e.id,
            kind: kind_to(e.kind),
            message: &e.message,
        })
        .collect()
}

fn borrowed(args: &[(String, String)]) -> Vec<(&str, &str)> {
    args.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

/// Builds a catalogue set from its sources. Refuses a set that breaks a
/// rule of `message::CatSpec::check`.
pub(crate) fn catalogues(spec: &CatSpec) -> Result<Catalogues, HtmlError> {
    let default_entries = entries(&spec.default);
    let other_entries: Vec<Vec<fstp_html::EntrySource<'_>>> =
        spec.others.iter().map(entries).collect();
    let others: Vec<fstp_html::CatalogueSource<'_>> = spec
        .others
        .iter()
        .zip(&other_entries)
        .map(|(c, e)| fstp_html::CatalogueSource {
            locale: &c.locale,
            entries: e,
        })
        .collect();
    let default = fstp_html::CatalogueSource {
        locale: &spec.default.locale,
        entries: &default_entries,
    };
    let inner = fstp_html::Catalogues::new(&default, &others)?;
    Ok(Catalogues { inner })
}

/// Applies terminology overrides. Refuses an override of an unknown id,
/// of an `ApprovedText` (I-72), with a bad message, or with other
/// placeholder names than the entry it replaces.
pub(crate) fn with_overrides(
    cats: &Catalogues,
    overrides: &[Override],
) -> Result<Catalogues, HtmlError> {
    let list: Vec<fstp_html::LabelOverride<'_>> = overrides
        .iter()
        .map(|o| fstp_html::LabelOverride {
            locale: &o.locale,
            id: &o.id,
            message: &o.message,
        })
        .collect();
    let inner = cats.inner.with_overrides(&list)?;
    Ok(Catalogues { inner })
}

/// Resolves one message to its text. Refuses an unknown locale or id, a
/// kind that differs from the entry's, and arguments whose names differ
/// from the placeholders.
pub(crate) fn resolve(
    cats: &Catalogues,
    locale: &str,
    kind: Kind,
    id: &str,
    args: &[(String, String)],
) -> Result<String, HtmlError> {
    let args = borrowed(args);
    match kind {
        Kind::Label => cats
            .inner
            .resolve_label(locale, &fstp_html::Label::new(id), &args),
        Kind::Approved => {
            cats.inner
                .resolve_approved(locale, &fstp_html::ApprovedText::new(id), &args)
        }
    }
}

fn msg_node(m: &Msg) -> fstp_html::Node {
    let args = borrowed(&m.args);
    match m.kind {
        Kind::Label => fstp_html::Node::label(&fstp_html::Label::new(&m.id), &args),
        Kind::Approved => fstp_html::Node::approved(&fstp_html::ApprovedText::new(&m.id), &args),
    }
}

fn node(n: &Node) -> Result<fstp_html::Node, HtmlError> {
    Ok(match n {
        Node::Text(t) => fstp_html::Node::text(t),
        Node::Msg(m) => msg_node(m),
        Node::El(e) => {
            let mut out = fstp_html::Element::new(e.tag);
            for (name, a) in &e.attrs {
                out = match a {
                    Attr::Text(t) => out.attr(name, t),
                    Attr::Url(u) => out.attr_url(name, fstp_html::SafeUrl::new(u)?),
                    Attr::Flag => out.flag(name),
                    Attr::Msg(m) => {
                        let args = borrowed(&m.args);
                        match m.kind {
                            Kind::Label => {
                                out.attr_label(name, &fstp_html::Label::new(&m.id), &args)
                            }
                            Kind::Approved => {
                                out.attr_approved(name, &fstp_html::ApprovedText::new(&m.id), &args)
                            }
                        }
                    }
                };
            }
            for c in &e.children {
                out = out.child(node(c)?);
            }
            fstp_html::Node::from(out)
        }
    })
}

fn document(page: &Page) -> Result<fstp_html::Document, HtmlError> {
    let mut doc = fstp_html::Document::new(&page.locale);
    for n in &page.title {
        doc = doc.title(node(n)?);
    }
    if let Some(u) = &page.stylesheet {
        doc = doc.stylesheet(fstp_html::SafeUrl::new(u)?);
    }
    for n in &page.body {
        doc = doc.body(node(n)?);
    }
    Ok(doc)
}

fn place(p: &fstp_html::TracePlace) -> Ctx {
    match p {
        fstp_html::TracePlace::Text => Ctx::Text,
        fstp_html::TracePlace::Attr(name) => Ctx::Attr((*name).to_owned()),
        fstp_html::TracePlace::Url(name) => Ctx::Url((*name).to_owned()),
    }
}

fn event(e: &fstp_html::TraceEvent) -> Event {
    match e {
        fstp_html::TraceEvent::Dynamic { place: p, value } => Event::Dynamic {
            ctx: place(p),
            value: value.clone(),
        },
        fstp_html::TraceEvent::Message { kind, id, place: p } => Event::Message {
            kind: kind_from(*kind),
            id: id.clone(),
            ctx: place(p),
        },
    }
}

/// Renders `page` with the recording test sink.
pub(crate) fn render(page: &Page, cats: &Catalogues) -> Result<Rendered, HtmlError> {
    let (doc, trace) = document(page)?.render_traced(&cats.inner)?;
    Ok(Rendered {
        bytes: doc.into_bytes(),
        trace: trace.iter().map(event).collect(),
    })
}

/// Renders `page` with the sink production uses.
pub(crate) fn render_untraced(page: &Page, cats: &Catalogues) -> Result<Vec<u8>, HtmlError> {
    Ok(document(page)?.render(&cats.inner)?.into_bytes())
}

/// Chooses the locale for an `Accept-Language` value from `available`.
/// Returns `default` when nothing matches or the value does not parse.
pub(crate) fn negotiate(
    header: &[u8],
    available: &[&str],
    default: &str,
) -> Result<String, HtmlError> {
    Ok(fstp_html::negotiate_locale(header, available, default))
}
