//! The Guide renderer: HTML through `fstp-html`, the canonical document
//! and the bound texts (I-51, I-52, I-68, M4 design section 3.10).
//!
//! - Every text, template literal and bound value alike, goes through the
//!   escaping writer of `fstp-html`. Nothing is inserted raw (I-68).
//! - Each bound value stands in an element of class `guide-value`. A
//!   value a person may not edit by hand also has class `guide-locked`,
//!   so parameter-bound text is always marked locked (I-51).
//! - The canonical document is the content of the page, one JSON line per
//!   block after a version line, with every value tagged by its key. It is
//!   a deterministic function of the bound template, and two different
//!   pages never share it. The publication digest is taken over it
//!   (I-52). Interim, pending Daniel.
//! - The page is in English, the language of the template, under the
//!   title [`GUIDE_TITLE`]. The template header is not rendered.

use fstp_domain::rules::ParamId;
use fstp_html::{
    CatalogueSource, Catalogues, Document, Element, HtmlDocument, HtmlError, Node, check_wellformed,
};

use crate::markdown::{Block, Inline};
use crate::resolve::{Key, Value};
use crate::{GuideError, Template};

/// The title of every rendered Guide.
pub const GUIDE_TITLE: &str = "Guide for Applicants";

/// The language of every rendered Guide: that of the template.
pub const GUIDE_LOCALE: &str = "en";

/// The version line of the canonical document.
const CANONICAL_VERSION: &str = "[\"fstp.guide\",1]";

/// One bound placeholder occurrence of a rendered Guide.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundText {
    /// The placeholder key.
    pub key: &'static str,
    /// The parameter it shows, for a parameter-bound key.
    pub param: Option<ParamId>,
    /// The text it shows, without markup.
    pub text: String,
    /// Whether a person may edit it by hand before publication. Never
    /// true for parameter-bound text (I-51).
    pub editable: bool,
}

/// A rendered Guide.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedGuide {
    html: HtmlDocument,
    canonical: Vec<u8>,
    bound: Vec<BoundText>,
}

impl RenderedGuide {
    /// The HTML document.
    pub fn html(&self) -> &HtmlDocument {
        &self.html
    }

    /// The canonical document the publication digest is taken over.
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    /// Every bound placeholder occurrence, in document order.
    pub fn bound(&self) -> &[BoundText] {
        &self.bound
    }

    /// Checks the HTML with the `fstp-html` well-formedness checker.
    pub fn check_wellformed(&self) -> Result<(), GuideError> {
        check_wellformed(self.html.as_bytes()).map_err(|e| html_err(&e))
    }
}

/// The rule an HTML error names.
fn html_err(e: &HtmlError) -> GuideError {
    GuideError::Html(match e {
        HtmlError::NotWellFormed { rule, .. }
        | HtmlError::MessageSyntax { rule, .. }
        | HtmlError::AcceptLanguage { rule }
        | HtmlError::Catalogue { rule, .. }
        | HtmlError::Message { rule, .. }
        | HtmlError::Page { rule, .. }
        | HtmlError::Attribute { rule, .. } => rule,
        HtmlError::UnsafeUrl => "an unsafe URL",
        HtmlError::UnknownLocale => "an unknown locale",
        _ => "the writer refused the page",
    })
}

/// Writes `s` as a JSON string.
fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Writes `items` as a JSON array, each with `item`.
fn json_list<T>(out: &mut String, items: &[T], mut item: impl FnMut(&mut String, &T)) {
    out.push('[');
    for (i, x) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        item(out, x);
    }
    out.push(']');
}

/// The canonical form of a value.
fn canon_value(out: &mut String, v: &Value) {
    match v {
        Value::Text(t) => {
            out.push_str("[\"text\",");
            json_str(out, t);
        }
        Value::Link(u) => {
            out.push_str("[\"link\",");
            json_str(out, u.as_str());
        }
        Value::Paragraphs(p) => {
            out.push_str("[\"paragraphs\",");
            json_list(out, p, |o, s| json_str(o, s));
        }
        Value::List(items) => {
            out.push_str("[\"list\",");
            json_list(out, items, |o, s| json_str(o, s));
        }
        Value::Table { head, rows } => {
            out.push_str("[\"table\",");
            json_list(out, head, |o, s| json_str(o, s));
            out.push(',');
            json_list(out, rows, |o, r| json_list(o, r, |o, s| json_str(o, s)));
        }
    }
    out.push(']');
}

/// The element class of a bound value.
fn class(k: Key) -> &'static str {
    if k.resolver().editable() {
        "guide-value"
    } else {
        "guide-value guide-locked"
    }
}

fn heading_tag(level: u8) -> &'static str {
    match level {
        1 => "h1",
        2 => "h2",
        _ => "h3",
    }
}

/// A table element of `head` cells and `rows`, each cell written by
/// `cell`.
fn table<T>(
    head: &[T],
    rows: &[Vec<T>],
    mut cell: impl FnMut(&T, &mut Element) -> Result<(), GuideError>,
) -> Result<Element, GuideError> {
    let mut tr = Element::new("tr");
    for c in head {
        let mut th = Element::new("th").attr("scope", "col");
        cell(c, &mut th)?;
        tr.push_child(th);
    }
    let mut el = Element::new("table").child(Element::new("thead").child(tr));
    if !rows.is_empty() {
        let mut tbody = Element::new("tbody");
        for r in rows {
            let mut tr = Element::new("tr");
            for c in r {
                let mut td = Element::new("td");
                cell(c, &mut td)?;
                tr.push_child(td);
            }
            tbody.push_child(tr);
        }
        el.push_child(tbody);
    }
    Ok(el)
}

/// The writer of one Guide.
struct Writer<'t> {
    template: &'t Template,
    canon: String,
    bound: Vec<BoundText>,
}

impl Writer<'_> {
    /// The value of `k`, recorded as one bound occurrence.
    fn take(&mut self, k: Key) -> Result<&Value, GuideError> {
        let v = self
            .template
            .value(k)
            .ok_or_else(|| GuideError::Unresolved {
                key: k.name(),
                reason: "the template is not bound; bind it to its inputs first",
            })?;
        let r = k.resolver();
        self.bound.push(BoundText {
            key: r.key,
            param: r.param,
            text: v.plain(),
            editable: r.editable(),
        });
        self.canon.push_str("[\"v\",");
        json_str(&mut self.canon, r.key);
        self.canon.push(',');
        canon_value(&mut self.canon, v);
        self.canon.push(']');
        Ok(v)
    }

    fn inlines(&mut self, list: &[Inline], parent: &mut Element) -> Result<(), GuideError> {
        self.canon.push('[');
        for (i, n) in list.iter().enumerate() {
            if i > 0 {
                self.canon.push(',');
            }
            match n {
                Inline::Text(t) => {
                    self.canon.push_str("[\"t\",");
                    json_str(&mut self.canon, t);
                    self.canon.push(']');
                    parent.push_child(Node::text(t));
                }
                Inline::Strong(c) => {
                    self.canon.push_str("[\"strong\",");
                    let mut el = Element::new("strong");
                    self.inlines(c, &mut el)?;
                    self.canon.push(']');
                    parent.push_child(el);
                }
                Inline::Code(c) => {
                    self.canon.push_str("[\"code\",");
                    json_str(&mut self.canon, c);
                    self.canon.push(']');
                    parent.push_child(Element::new("code").text(c));
                }
                Inline::Link { content, url } => {
                    self.canon.push_str("[\"a\",");
                    json_str(&mut self.canon, url.as_str());
                    self.canon.push(',');
                    let mut el = Element::new("a").attr_url("href", url.clone());
                    self.inlines(content, &mut el)?;
                    self.canon.push(']');
                    parent.push_child(el);
                }
                Inline::Slot(k) => {
                    let el = match self.take(*k)? {
                        Value::Text(t) => Element::new("span").attr("class", class(*k)).text(t),
                        Value::Link(u) => Element::new("a")
                            .attr("class", class(*k))
                            .attr_url("href", u.clone())
                            .text(u.as_str()),
                        _ => return Err(GuideError::Html("a block value in an inline place")),
                    };
                    parent.push_child(el);
                }
            }
        }
        self.canon.push(']');
        Ok(())
    }

    /// The elements of a block value.
    fn value_block(v: &Value, parent: &mut Element) -> Result<(), GuideError> {
        match v {
            Value::Paragraphs(p) => {
                for s in p {
                    parent.push_child(Element::new("p").text(s));
                }
            }
            Value::List(items) => {
                let mut ul = Element::new("ul");
                for s in items {
                    ul.push_child(Element::new("li").text(s));
                }
                parent.push_child(ul);
            }
            Value::Table { head, rows } => {
                parent.push_child(table(head, rows, |s, el| {
                    el.push_child(Node::text(s));
                    Ok(())
                })?);
            }
            Value::Text(_) | Value::Link(_) => {
                return Err(GuideError::Html("an inline value in a block place"));
            }
        }
        Ok(())
    }

    fn list(&mut self, tag: &'static str, items: &[Vec<Inline>]) -> Result<Element, GuideError> {
        self.canon.push('[');
        let mut el = Element::new(tag);
        for (i, item) in items.iter().enumerate() {
            if i > 0 {
                self.canon.push(',');
            }
            let mut li = Element::new("li");
            self.inlines(item, &mut li)?;
            el.push_child(li);
        }
        self.canon.push(']');
        Ok(el)
    }

    fn block(&mut self, b: &Block, parent: &mut Element) -> Result<(), GuideError> {
        let el = match b {
            Block::Heading { level, content } => {
                self.canon.push_str(&format!("[\"h\",{level},"));
                let mut el = Element::new(heading_tag(*level));
                self.inlines(content, &mut el)?;
                el
            }
            Block::Paragraph(lines) => {
                self.canon.push_str("[\"p\",[");
                let mut el = Element::new("p");
                for (i, l) in lines.iter().enumerate() {
                    if i > 0 {
                        self.canon.push(',');
                        el.push_child(Node::text("\n"));
                    }
                    self.inlines(l, &mut el)?;
                }
                self.canon.push(']');
                el
            }
            Block::Rule => {
                self.canon.push_str("[\"hr\"");
                Element::new("hr")
            }
            Block::Table { head, rows } => {
                self.canon.push_str("[\"table\",[");
                let mut cells: Vec<Element> = Vec::new();
                for (i, c) in head.iter().enumerate() {
                    if i > 0 {
                        self.canon.push(',');
                    }
                    let mut th = Element::new("th").attr("scope", "col");
                    self.inlines(c, &mut th)?;
                    cells.push(th);
                }
                self.canon.push_str("],[");
                let mut body: Vec<Vec<Element>> = Vec::new();
                for (i, r) in rows.iter().enumerate() {
                    if i > 0 {
                        self.canon.push(',');
                    }
                    self.canon.push('[');
                    let mut tds = Vec::new();
                    for (j, c) in r.iter().enumerate() {
                        if j > 0 {
                            self.canon.push(',');
                        }
                        let mut td = Element::new("td");
                        self.inlines(c, &mut td)?;
                        tds.push(td);
                    }
                    self.canon.push(']');
                    body.push(tds);
                }
                self.canon.push(']');
                let mut tr = Element::new("tr");
                for th in cells {
                    tr.push_child(th);
                }
                let mut el = Element::new("table").child(Element::new("thead").child(tr));
                if !body.is_empty() {
                    let mut tbody = Element::new("tbody");
                    for tds in body {
                        let mut tr = Element::new("tr");
                        for td in tds {
                            tr.push_child(td);
                        }
                        tbody.push_child(tr);
                    }
                    el.push_child(tbody);
                }
                el
            }
            Block::Bullets(items) => {
                self.canon.push_str("[\"ul\",");
                self.list("ul", items)?
            }
            Block::Numbered(items) => {
                self.canon.push_str("[\"ol\",");
                self.list("ol", items)?
            }
            Block::Slot(k) => {
                let mut div = Element::new("div").attr("class", class(*k));
                let v = self.take(*k)?.clone();
                Writer::value_block(&v, &mut div)?;
                div
            }
        };
        if !matches!(b, Block::Slot(_)) {
            self.canon.push(']');
        }
        self.canon.push('\n');
        parent.push_child(el);
        Ok(())
    }
}

/// Renders a bound template (module documentation).
pub(crate) fn render(template: &Template) -> Result<RenderedGuide, GuideError> {
    let mut w = Writer {
        template,
        canon: String::new(),
        bound: Vec::new(),
    };
    w.canon.push_str(CANONICAL_VERSION);
    w.canon.push_str("\n[\"title\",");
    json_str(&mut w.canon, GUIDE_TITLE);
    w.canon.push_str("]\n");
    let mut main = Element::new("main")
        .attr("class", "guide")
        .child(Element::new("h1").text(GUIDE_TITLE));
    for b in template.body() {
        w.block(b, &mut main)?;
    }
    let cats = Catalogues::new(
        &CatalogueSource {
            locale: GUIDE_LOCALE,
            entries: &[],
        },
        &[],
    )
    .map_err(|e| html_err(&e))?;
    let html = Document::new(GUIDE_LOCALE)
        .title(Node::text(GUIDE_TITLE))
        .body(main)
        .render(&cats)
        .map_err(|e| html_err(&e))?;
    Ok(RenderedGuide {
        html,
        canonical: w.canon.into_bytes(),
        bound: w.bound,
    })
}
