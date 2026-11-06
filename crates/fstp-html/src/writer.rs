//! The escaping HTML writer (I-68, TW-2, R-PB-04) and its render trace
//! (I-87 seam).
//!
//! A caller describes a page as a [`Document`] of [`Element`]s, dynamic
//! texts, [`SafeUrl`]s and catalogue messages. [`Document::render`]
//! writes it as a document of the writer's subset. There is no way to put
//! a caller's string into the output unescaped: every text and attribute
//! value is escaped for its context, every URL is a [`SafeUrl`], and tag
//! and attribute names come from fixed allowlists.
//!
//! Interim readings, pending Daniel:
//!
//! - a dynamic text holding a character that is not plain is written
//!   with U+FFFD in its place, so CR, NUL, C1 controls and noncharacters
//!   never reach the page;
//! - a page that breaks a rule of the subset is refused whole, with a
//!   typed error, and never repaired;
//! - nesting deeper than [`MAX_DEPTH`] elements below `body` is refused;
//! - `<meta name>` is one of `description`, `viewport`, `robots` and
//!   `color-scheme`, and the only `<link>` is a stylesheet.
//!
//! [`Document::render_traced`] runs the same code with the recording
//! sink. The trace holds every dynamic value as the caller passed it,
//! once per time it is written, and every message by id, in document
//! order. Attributes come in the order the caller gave them, before the
//! element's children. The locale and the fixed skeleton are not traced.

use crate::HtmlError;
use crate::catalogue::{
    ApprovedText, Catalogues, Label, LocaleCatalogue, MessageKind, message_err,
};
use crate::message::{Part, arg};
use crate::subset::{
    BOOLEAN_ATTRS, DROPS_LEADING_LF, Open, URL_ATTRS, VOID, attr_allowed_in, holds_no_text,
    is_lang_tag, is_plain, is_rcdata, svg_value_ok, svg_value_ruled,
};
use crate::url::SafeUrl;

/// The deepest element nesting below `body` the writer accepts. A child
/// of `body` is at level 1, so a chain of `MAX_DEPTH` nested elements
/// renders and one more is refused.
pub const MAX_DEPTH: usize = 256;

/// The `<meta name>` values the writer accepts.
const META_NAMES: &[&str] = &["description", "viewport", "robots", "color-scheme"];

/// A rendered document of the writer's subset.
///
/// Only the writer makes one. It has no constructor from bytes or a
/// string and hands out no mutable access, so its bytes are always the
/// writer's own output.
///
/// ```compile_fail
/// let doc = fstp_html::HtmlDocument { text: String::from("<script>") };
/// ```
///
/// ```compile_fail
/// let doc: fstp_html::HtmlDocument = String::from("<script>").into();
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtmlDocument {
    text: String,
}

impl HtmlDocument {
    /// The document bytes, UTF-8.
    pub fn as_bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }

    /// The document text.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The document bytes, by value.
    pub fn into_bytes(self) -> Vec<u8> {
        self.text.into_bytes()
    }
}

/// Where the writer put a traced value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TracePlace {
    /// A text node, including `title` and `textarea` content.
    Text,
    /// The value of the named attribute.
    Attr(&'static str),
    /// The value of the named URL attribute.
    Url(&'static str),
}

/// One event of the render trace.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TraceEvent {
    /// A dynamic value, as the caller passed it, before escaping or
    /// replacement.
    Dynamic {
        /// Where it was written.
        place: TracePlace,
        /// The value.
        value: String,
    },
    /// A catalogue message, by id. Its literals are not dynamic. Its
    /// arguments follow as `Dynamic` events, one per placeholder use.
    Message {
        /// Label or approved wording.
        kind: MessageKind,
        /// The message id.
        id: String,
        /// Where it was written.
        place: TracePlace,
    },
}

/// A catalogue message with its arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Msg {
    kind: MessageKind,
    id: String,
    args: Vec<(String, String)>,
}

impl Msg {
    fn label(label: &Label, args: &[(&str, &str)]) -> Msg {
        Msg {
            kind: MessageKind::Label,
            id: label.id().to_owned(),
            args: crate::catalogue::owned_args(args),
        }
    }

    fn approved(text: &ApprovedText, args: &[(&str, &str)]) -> Msg {
        Msg {
            kind: MessageKind::Approved,
            id: text.id().to_owned(),
            args: crate::catalogue::owned_args(args),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Repr {
    El(Element),
    Text(String),
    Msg(Msg),
    Lines(Msg, Lines),
}

/// A node of a page: an element, a dynamic text or a catalogue message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node(Repr);

impl Node {
    /// A dynamic text, escaped where it is written.
    pub fn text(value: &str) -> Node {
        Node(Repr::Text(value.to_owned()))
    }

    /// An interface string of the catalogue, with its arguments.
    pub fn label(label: &Label, args: &[(&str, &str)]) -> Node {
        Node(Repr::Msg(Msg::label(label, args)))
    }

    /// Approved wording of the catalogue, with its arguments (I-72).
    pub fn approved(text: &ApprovedText, args: &[(&str, &str)]) -> Node {
        Node(Repr::Msg(Msg::approved(text, args)))
    }

    /// An interface string of the catalogue, wrapped into SVG lines: one
    /// `tspan` per line, laid out by `lines`. It stands only inside an
    /// SVG `text` element. The text is wrapped at spaces after the
    /// catalogue resolves it, so a terminology override wraps too.
    pub fn label_lines(label: &Label, args: &[(&str, &str)], lines: Lines) -> Node {
        Node(Repr::Lines(Msg::label(label, args), lines))
    }
}

/// How [`Node::label_lines`] lays out the lines of a message, in SVG user
/// units.
///
/// The words, split at spaces, fill each line greedily up to `width`
/// characters. A longer word stands on a line of its own. Words beyond
/// `max` lines join the last line. The lines are centred on `y`, `step`
/// apart, and each starts at `x`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Lines {
    /// The `x` of every line.
    pub x: i32,
    /// The `y` of the middle of the lines.
    pub y: i32,
    /// The distance from one line to the next.
    pub step: i32,
    /// The most characters a line takes, unless one word is longer.
    pub width: usize,
    /// The most lines.
    pub max: usize,
}

impl Lines {
    /// The lines of `text`. No line is empty, and a text with no word has
    /// no line.
    pub fn wrap(&self, text: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for word in text.split(' ').filter(|w| !w.is_empty()) {
            let fits = out.last().is_some_and(|l| {
                l.chars()
                    .count()
                    .saturating_add(1)
                    .saturating_add(word.chars().count())
                    <= self.width
            });
            let full = out.len() >= self.max.max(1);
            match out.last_mut() {
                Some(l) if fits || full => {
                    l.push(' ');
                    l.push_str(word);
                }
                _ => out.push(word.to_owned()),
            }
        }
        out
    }

    /// The `y` of line `i` of `n`.
    pub fn y_of(&self, i: usize, n: usize) -> i32 {
        let n = i32::try_from(n).unwrap_or(i32::MAX);
        let i = i32::try_from(i).unwrap_or(i32::MAX);
        let first = self.y.saturating_sub(
            n.saturating_sub(1)
                .saturating_mul(self.step)
                .checked_div(2)
                .unwrap_or(0),
        );
        first.saturating_add(i.saturating_mul(self.step))
    }
}

impl From<Element> for Node {
    fn from(e: Element) -> Node {
        Node(Repr::El(e))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AttrValue {
    Text(String),
    Url(SafeUrl),
    Flag,
    Msg(Msg),
    Parts(Vec<Node>),
}

/// An element of a page body.
///
/// The builder methods never fail. The writer checks the tag, the
/// attributes and the placement when it renders, and refuses the page if
/// any rule is broken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Element {
    tag: &'static str,
    attrs: Vec<(&'static str, AttrValue)>,
    children: Vec<Node>,
}

impl Element {
    /// An element with no attribute and no child.
    pub fn new(tag: &'static str) -> Element {
        Element {
            tag,
            attrs: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Adds a dynamic text attribute.
    pub fn attr(mut self, name: &'static str, value: &str) -> Element {
        self.attrs.push((name, AttrValue::Text(value.to_owned())));
        self
    }

    /// Adds a URL attribute (`href`, `src` or `action`).
    pub fn attr_url(mut self, name: &'static str, url: SafeUrl) -> Element {
        self.attrs.push((name, AttrValue::Url(url)));
        self
    }

    /// Adds a boolean attribute that is present.
    pub fn flag(mut self, name: &'static str) -> Element {
        self.attrs.push((name, AttrValue::Flag));
        self
    }

    /// Adds an attribute whose value is an interface string.
    pub fn attr_label(
        mut self,
        name: &'static str,
        label: &Label,
        args: &[(&str, &str)],
    ) -> Element {
        self.attrs
            .push((name, AttrValue::Msg(Msg::label(label, args))));
        self
    }

    /// Adds an attribute whose value joins `parts` in order: dynamic texts
    /// and catalogue messages, such as an accessible name made of a
    /// label, a formal state name and status words. An element part is
    /// refused when the page renders.
    pub fn attr_parts(mut self, name: &'static str, parts: Vec<Node>) -> Element {
        self.attrs.push((name, AttrValue::Parts(parts)));
        self
    }

    /// Adds an attribute whose value is approved wording.
    pub fn attr_approved(
        mut self,
        name: &'static str,
        text: &ApprovedText,
        args: &[(&str, &str)],
    ) -> Element {
        self.attrs
            .push((name, AttrValue::Msg(Msg::approved(text, args))));
        self
    }

    /// Adds a child node.
    pub fn child(mut self, node: impl Into<Node>) -> Element {
        self.children.push(node.into());
        self
    }

    /// Adds every node of `nodes` as a child.
    pub fn children(mut self, nodes: impl IntoIterator<Item = Node>) -> Element {
        self.children.extend(nodes);
        self
    }

    /// Adds a dynamic text child.
    pub fn text(self, value: &str) -> Element {
        self.child(Node::text(value))
    }

    /// Adds an interface string child.
    pub fn label(self, label: &Label, args: &[(&str, &str)]) -> Element {
        self.child(Node::label(label, args))
    }

    /// Adds an approved wording child.
    pub fn approved(self, text: &ApprovedText, args: &[(&str, &str)]) -> Element {
        self.child(Node::approved(text, args))
    }

    /// Adds a child node in place.
    pub fn push_child(&mut self, node: impl Into<Node>) {
        self.children.push(node.into());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum HeadItem {
    Stylesheet(SafeUrl),
    Meta { name: &'static str, content: String },
}

/// A whole page: its locale, title, head items and body.
///
/// The writer adds only the fixed skeleton:
///
/// ```text
/// <!DOCTYPE html><html lang="{locale}"><head><meta charset="utf-8">
/// <title>{title}</title>{head items}</head><body>{body}</body></html>
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    locale: String,
    title: Vec<Node>,
    head: Vec<HeadItem>,
    body: Vec<Node>,
}

impl Document {
    /// An empty page in `locale`. The locale must be a language tag with
    /// a catalogue in the set the page is rendered with.
    pub fn new(locale: &str) -> Document {
        Document {
            locale: locale.to_owned(),
            title: Vec::new(),
            head: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Adds a title node: a dynamic text or a catalogue message.
    pub fn title(mut self, node: Node) -> Document {
        self.title.push(node);
        self
    }

    /// Adds a stylesheet link to the head.
    pub fn stylesheet(mut self, url: SafeUrl) -> Document {
        self.head.push(HeadItem::Stylesheet(url));
        self
    }

    /// Adds `<meta name content>` to the head. The content is dynamic.
    pub fn meta(mut self, name: &'static str, content: &str) -> Document {
        self.head.push(HeadItem::Meta {
            name,
            content: content.to_owned(),
        });
        self
    }

    /// Adds a body node.
    pub fn body(mut self, node: impl Into<Node>) -> Document {
        self.body.push(node.into());
        self
    }

    /// Adds a body node in place.
    pub fn push_body(&mut self, node: impl Into<Node>) {
        self.body.push(node.into());
    }

    /// Renders the page with `cats`. This is the production path: it
    /// records nothing.
    pub fn render(&self, cats: &Catalogues) -> Result<HtmlDocument, HtmlError> {
        render(self, cats, &mut NoTrace)
    }

    /// Renders the page with the recording test sink, and returns the
    /// trace with the bytes. The bytes equal those of
    /// [`Document::render`], and a page one refuses the other refuses.
    pub fn render_traced(
        &self,
        cats: &Catalogues,
    ) -> Result<(HtmlDocument, Vec<TraceEvent>), HtmlError> {
        let mut trace = Vec::new();
        let doc = render(self, cats, &mut trace)?;
        Ok((doc, trace))
    }
}

/// Where the writer reports what it writes.
trait Sink {
    fn dynamic(&mut self, place: &TracePlace, value: &str);
    fn message(&mut self, kind: MessageKind, id: &str, place: &TracePlace);
}

/// The production sink.
struct NoTrace;

impl Sink for NoTrace {
    fn dynamic(&mut self, _place: &TracePlace, _value: &str) {}
    fn message(&mut self, _kind: MessageKind, _id: &str, _place: &TracePlace) {}
}

/// The recording test sink.
impl Sink for Vec<TraceEvent> {
    fn dynamic(&mut self, place: &TracePlace, value: &str) {
        self.push(TraceEvent::Dynamic {
            place: place.clone(),
            value: value.to_owned(),
        });
    }

    fn message(&mut self, kind: MessageKind, id: &str, place: &TracePlace) {
        self.push(TraceEvent::Message {
            kind,
            id: id.to_owned(),
            place: place.clone(),
        });
    }
}

/// Escapes text content, normal and RCDATA alike. A character that is
/// not plain becomes U+FFFD.
fn push_text(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c if is_plain(c) => out.push(c),
            _ => out.push('\u{FFFD}'),
        }
    }
}

/// Escapes text content inside `svg`: as [`push_text`], and quotes too.
fn push_svg_text(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => push_text(out, c.encode_utf8(&mut [0; 4])),
        }
    }
}

/// Escapes a double-quoted attribute value. A character that is not
/// plain becomes U+FFFD.
fn push_attr(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c if is_plain(c) => out.push(c),
            _ => out.push('\u{FFFD}'),
        }
    }
}

fn page_err(element: &'static str, rule: &'static str) -> HtmlError {
    HtmlError::Page { element, rule }
}

fn attr_err(element: &'static str, attribute: &'static str, rule: &'static str) -> HtmlError {
    HtmlError::Attribute {
        element,
        attribute,
        rule,
    }
}

struct Writer<'c, 's, S> {
    out: String,
    cat: &'c LocaleCatalogue,
    open: Open,
    sink: &'s mut S,
}

fn render<S: Sink>(
    doc: &Document,
    cats: &Catalogues,
    sink: &mut S,
) -> Result<HtmlDocument, HtmlError> {
    if !is_lang_tag(&doc.locale) {
        return Err(HtmlError::UnknownLocale);
    }
    let cat = cats.locale(&doc.locale)?;
    let mut w = Writer {
        out: String::new(),
        cat,
        open: Open::default(),
        sink,
    };
    w.out.push_str("<!DOCTYPE html><html lang=\"");
    push_attr(&mut w.out, &doc.locale);
    w.out.push_str("\"><head><meta charset=\"utf-8\"><title>");
    for n in &doc.title {
        match &n.0 {
            Repr::Text(t) => w.text(t),
            Repr::Msg(m) => w.message(m, &TracePlace::Text)?,
            Repr::El(_) | Repr::Lines(..) => {
                return Err(page_err("title", "the title holds only text and messages"));
            }
        }
    }
    w.out.push_str("</title>");
    for item in &doc.head {
        match item {
            HeadItem::Stylesheet(url) => {
                w.sink.dynamic(&TracePlace::Url("href"), url.as_str());
                w.out.push_str("<link rel=\"stylesheet\" href=\"");
                push_attr(&mut w.out, url.as_str());
                w.out.push_str("\">");
            }
            HeadItem::Meta { name, content } => {
                if !META_NAMES.contains(name) {
                    return Err(attr_err("meta", "name", "the meta name is not allowed"));
                }
                w.sink.dynamic(&TracePlace::Attr("content"), content);
                w.out.push_str("<meta name=\"");
                w.out.push_str(name);
                w.out.push_str("\" content=\"");
                push_attr(&mut w.out, content);
                w.out.push_str("\">");
            }
        }
    }
    w.out.push_str("</head><body>");
    w.open.push("html");
    w.open.push("body");
    for n in &doc.body {
        w.node(n, "body")?;
    }
    w.out.push_str("</body></html>");
    Ok(HtmlDocument { text: w.out })
}

impl<S: Sink> Writer<'_, '_, S> {
    fn text(&mut self, t: &str) {
        self.sink.dynamic(&TracePlace::Text, t);
        let escape = self.text_escape();
        escape(&mut self.out, t);
    }

    /// The text escaper here. Inside `svg` it escapes quotes as well, so
    /// no text of foreign content reads as attribute markup.
    fn text_escape(&self) -> fn(&mut String, &str) {
        if self.open.in_svg() {
            push_svg_text
        } else {
            push_text
        }
    }

    /// Writes a message at `place`: its literals, and each argument once
    /// per placeholder use.
    fn message(&mut self, m: &Msg, place: &TracePlace) -> Result<(), HtmlError> {
        let format = self.cat.get(m.kind, &m.id)?;
        format
            .check_args(&m.args)
            .map_err(|rule| message_err(&m.id, rule))?;
        self.sink.message(m.kind, &m.id, place);
        let escape: fn(&mut String, &str) = match place {
            TracePlace::Text => self.text_escape(),
            TracePlace::Attr(_) | TracePlace::Url(_) => push_attr,
        };
        for part in format.parts() {
            match part {
                Part::Lit(l) => escape(&mut self.out, l),
                Part::Arg(n) => {
                    let v = arg(&m.args, n);
                    self.sink.dynamic(place, v);
                    escape(&mut self.out, v);
                }
            }
        }
        Ok(())
    }

    /// Writes `n` as a child of `parent`.
    fn node(&mut self, n: &Node, parent: &'static str) -> Result<(), HtmlError> {
        match &n.0 {
            Repr::El(e) => {
                if is_rcdata(self.open.in_svg(), parent) {
                    return Err(page_err(parent, "the element holds only text and messages"));
                }
                self.element(e)
            }
            Repr::Text(_) | Repr::Msg(_) | Repr::Lines(..)
                if holds_no_text(self.open.in_svg(), parent) =>
            {
                Err(page_err(parent, "the element holds no text"))
            }
            Repr::Text(t) => {
                self.text(t);
                Ok(())
            }
            Repr::Msg(m) => self.message(m, &TracePlace::Text),
            Repr::Lines(m, lines) => self.lines(m, lines, parent),
        }
    }

    /// Writes message `m` as SVG lines inside `parent`, one `tspan` each.
    fn lines(&mut self, m: &Msg, lines: &Lines, parent: &'static str) -> Result<(), HtmlError> {
        if parent != "text" || !self.open.in_svg() {
            return Err(page_err(parent, "label lines stand only in an SVG text"));
        }
        self.open
            .check("tspan")
            .map_err(|rule| page_err("tspan", rule))?;
        let format = self.cat.get(m.kind, &m.id)?;
        let text = format
            .format(&m.args)
            .map_err(|rule| message_err(&m.id, rule))?;
        self.sink.message(m.kind, &m.id, &TracePlace::Text);
        for part in format.parts() {
            if let Part::Arg(n) = part {
                self.sink.dynamic(&TracePlace::Text, arg(&m.args, n));
            }
        }
        let wrapped = lines.wrap(&text);
        let n = wrapped.len();
        for (i, line) in wrapped.iter().enumerate() {
            self.out.push_str("<tspan x=\"");
            self.out.push_str(&lines.x.to_string());
            self.out.push_str("\" y=\"");
            self.out.push_str(&lines.y_of(i, n).to_string());
            self.out.push_str("\">");
            push_svg_text(&mut self.out, line);
            self.out.push_str("</tspan>");
        }
        Ok(())
    }

    fn element(&mut self, e: &Element) -> Result<(), HtmlError> {
        let tag = e.tag;
        // The open stack holds `html`, `body` and the ancestors below
        // `body`. The new element sits one level below the last of them.
        if self.open.depth().saturating_sub(2) >= MAX_DEPTH {
            return Err(page_err(tag, "the page nests too deep"));
        }
        self.open.check(tag).map_err(|rule| page_err(tag, rule))?;
        let void = VOID.contains(&tag);
        if void && !e.children.is_empty() {
            return Err(page_err(tag, "a void element holds no children"));
        }
        self.out.push('<');
        self.out.push_str(tag);
        for (i, (name, value)) in e.attrs.iter().enumerate() {
            self.attribute(tag, name, value)?;
            if e.attrs.iter().take(i).any(|(n, _)| n == name) {
                return Err(attr_err(tag, name, "the attribute is given twice"));
            }
        }
        self.out.push('>');
        if void {
            return Ok(());
        }
        if DROPS_LEADING_LF.contains(&tag) {
            self.out.push('\n');
        }
        self.open.push(tag);
        for c in &e.children {
            self.node(c, tag)?;
        }
        self.open.pop();
        self.out.push_str("</");
        self.out.push_str(tag);
        self.out.push('>');
        Ok(())
    }

    fn attribute(
        &mut self,
        tag: &'static str,
        name: &'static str,
        value: &AttrValue,
    ) -> Result<(), HtmlError> {
        // The new element is not open yet, so `svg` itself counts here.
        let svg = self.open.in_svg() || tag == "svg";
        if !attr_allowed_in(svg, tag, name) {
            return Err(attr_err(
                tag,
                name,
                "the attribute is not allowed on the element",
            ));
        }
        let is_url = URL_ATTRS.contains(&name);
        match value {
            AttrValue::Flag => {
                if !BOOLEAN_ATTRS.contains(&name) {
                    return Err(attr_err(tag, name, "the attribute is not boolean"));
                }
                self.out.push(' ');
                self.out.push_str(name);
                return Ok(());
            }
            AttrValue::Url(_) if !is_url => {
                return Err(attr_err(tag, name, "the attribute takes no URL"));
            }
            AttrValue::Text(_) | AttrValue::Msg(_) | AttrValue::Parts(_) if is_url => {
                return Err(attr_err(tag, name, "the attribute takes a SafeUrl"));
            }
            AttrValue::Text(t) if svg && svg_value_ruled(name) && !svg_value_ok(name, t) => {
                return Err(attr_err(tag, name, "the value is outside the SVG subset"));
            }
            AttrValue::Msg(_) | AttrValue::Parts(_) if svg && svg_value_ruled(name) => {
                return Err(attr_err(tag, name, "the SVG attribute takes a fixed text"));
            }
            _ => {}
        }
        self.out.push(' ');
        self.out.push_str(name);
        self.out.push_str("=\"");
        match value {
            AttrValue::Text(t) => {
                self.sink.dynamic(&TracePlace::Attr(name), t);
                push_attr(&mut self.out, t);
            }
            AttrValue::Url(u) => {
                self.sink.dynamic(&TracePlace::Url(name), u.as_str());
                push_attr(&mut self.out, u.as_str());
            }
            AttrValue::Msg(m) => self.message(m, &TracePlace::Attr(name))?,
            AttrValue::Parts(parts) => {
                for p in parts {
                    match &p.0 {
                        Repr::Text(t) => {
                            self.sink.dynamic(&TracePlace::Attr(name), t);
                            push_attr(&mut self.out, t);
                        }
                        Repr::Msg(m) => self.message(m, &TracePlace::Attr(name))?,
                        Repr::El(_) | Repr::Lines(..) => {
                            return Err(attr_err(tag, name, "an attribute holds only text"));
                        }
                    }
                }
            }
            AttrValue::Flag => {}
        }
        self.out.push('"');
        Ok(())
    }
}
