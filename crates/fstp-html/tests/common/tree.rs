//! The checked map tree as data, as an executable reference (ADR-015
//! amendment of 2026-11-06, lane j4 test author).
//!
//! Daniel decided on 2026-11-06 that the read returns the renderer's
//! checked element tree as data and the browser only builds it. This
//! module restates the wire shape of that tree, written before the
//! production tree exists:
//!
//! - an element is `{"tag": NAME, "attrs": [{"name": N, "value": V}],
//!   "children": [NODE]}`, attributes in the writer's order;
//! - a text node is `{"text": CHARS}`, the characters before escaping;
//! - adjacent texts are one text node and no text node is empty, as a
//!   parser of the markup gives them.
//!
//! It holds an ordered reader of the writer's `svg` markup ([`parse`]),
//! the reference encoding ([`to_json`]), the reference serialiser
//! ([`markup`]) and the closed SVG subset ([`subset_faults`]).

use fstp_html::route::{SvgElement, SvgNode, SvgTree};
use fstp_json::{Array, Object, Value};

/// One node of the reference tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TNode {
    El(TEl),
    Text(String),
}

/// One element of the reference tree, attributes in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TEl {
    pub(crate) tag: String,
    pub(crate) attrs: Vec<(String, String)>,
    pub(crate) children: Vec<TNode>,
}

impl TEl {
    /// The value of attribute `name`.
    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// The reference tree of a production tree.
pub(crate) fn of_tree(t: &SvgTree) -> TEl {
    of_element(t.root())
}

fn of_element(e: &SvgElement) -> TEl {
    TEl {
        tag: e.tag().to_owned(),
        attrs: e.attrs().to_vec(),
        children: e
            .children()
            .iter()
            .map(|c| match c {
                SvgNode::Element(x) => TNode::El(of_element(x)),
                SvgNode::Text(s) => TNode::Text(s.clone()),
            })
            .collect(),
    }
}

/// Reads the writer's spelling of one `svg` element: no whitespace
/// between tags, attributes double quoted, every element closed by its
/// end tag, and the five character references of the writer.
pub(crate) fn parse(s: &str) -> Result<TEl, String> {
    let mut p = Reader { s, i: 0 };
    let el = p.element()?;
    if p.i != s.len() {
        return Err(format!("text after the root element at byte {}", p.i));
    }
    Ok(el)
}

struct Reader<'a> {
    s: &'a str,
    i: usize,
}

impl Reader<'_> {
    fn rest(&self) -> &str {
        self.s.get(self.i..).unwrap_or("")
    }

    fn eat(&mut self, lit: &str) -> bool {
        if self.rest().starts_with(lit) {
            self.i += lit.len();
            true
        } else {
            false
        }
    }

    fn name(&mut self) -> Result<String, String> {
        let n: String = self
            .rest()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        if n.is_empty() {
            return Err(format!("no name at byte {}", self.i));
        }
        self.i += n.len();
        Ok(n)
    }

    fn element(&mut self) -> Result<TEl, String> {
        if !self.eat("<") {
            return Err(format!("no start tag at byte {}", self.i));
        }
        let tag = self.name()?;
        let mut attrs = Vec::new();
        while self.eat(" ") {
            let n = self.name()?;
            if !self.eat("=\"") {
                return Err(format!("attribute {n} is not double quoted"));
            }
            let end = self
                .rest()
                .find('"')
                .ok_or_else(|| format!("attribute {n} is not closed"))?;
            let raw = self.rest().get(..end).unwrap_or("").to_owned();
            self.i += end + 1;
            attrs.push((n, decode(&raw)?));
        }
        if !self.eat(">") {
            return Err(format!("start tag {tag} is not closed"));
        }
        let mut children = Vec::new();
        let close = format!("</{tag}>");
        loop {
            if self.eat(&close) {
                break;
            }
            if self.rest().starts_with("</") {
                return Err(format!(
                    "{tag} is closed by another end tag at byte {}",
                    self.i
                ));
            }
            if self.rest().starts_with('<') {
                children.push(TNode::El(self.element()?));
                continue;
            }
            let end = self
                .rest()
                .find('<')
                .ok_or_else(|| format!("{tag} is not closed"))?;
            let raw = self.rest().get(..end).unwrap_or("").to_owned();
            self.i += end;
            children.push(TNode::Text(decode(&raw)?));
        }
        Ok(TEl {
            tag,
            attrs,
            children,
        })
    }
}

/// Decodes the character references of the writer.
fn decode(raw: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        out.push_str(rest.get(..at).unwrap_or(""));
        let tail = rest.get(at..).unwrap_or("");
        let end = tail
            .find(';')
            .ok_or_else(|| format!("an unclosed reference in {raw:?}"))?;
        let r = tail.get(..=end).unwrap_or("");
        let c = match r {
            "&amp;" => '&',
            "&lt;" => '<',
            "&gt;" => '>',
            "&quot;" => '"',
            "&#39;" => '\'',
            other => return Err(format!("the reference {other} is not the writer's")),
        };
        out.push(c);
        rest = tail.get(end + 1..).unwrap_or("");
    }
    out.push_str(rest);
    Ok(out)
}

/// The writer's escaping inside `svg`: quotes are escaped in text too.
fn escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The reference serialisation of `e`, as the writer spells it.
pub(crate) fn markup(e: &TEl) -> String {
    let mut out = format!("<{}", e.tag);
    for (n, v) in &e.attrs {
        out.push_str(&format!(" {n}=\"{}\"", escape(v)));
    }
    out.push('>');
    for c in &e.children {
        match c {
            TNode::El(x) => out.push_str(&markup(x)),
            TNode::Text(t) => out.push_str(&escape(t)),
        }
    }
    out.push_str(&format!("</{}>", e.tag));
    out
}

/// The reference wire encoding of `e`.
pub(crate) fn to_json(e: &TEl) -> Value {
    let mut attrs = Array::new();
    for (n, v) in &e.attrs {
        let mut a = Object::new();
        let _ = a.insert("name", Value::from(n.as_str()));
        let _ = a.insert("value", Value::from(v.as_str()));
        attrs.push(Value::Object(a));
    }
    let mut children = Array::new();
    for c in &e.children {
        children.push(match c {
            TNode::El(x) => to_json(x),
            TNode::Text(t) => {
                let mut o = Object::new();
                let _ = o.insert("text", Value::from(t.as_str()));
                Value::Object(o)
            }
        });
    }
    let mut o = Object::new();
    let _ = o.insert("tag", Value::from(e.tag.as_str()));
    let _ = o.insert("attrs", Value::Array(attrs));
    let _ = o.insert("children", Value::Array(children));
    Value::Object(o)
}

/// The elements of the closed SVG subset with the attributes each may
/// carry beyond the global ones (`docs/design/02-voyager-route-diary.md`,
/// ADR-015, the checker's SVG table).
const SUBSET: &[(&str, &[&str])] = &[
    ("svg", &["viewbox"]),
    ("title", &[]),
    ("desc", &[]),
    ("defs", &[]),
    (
        "marker",
        &[
            "viewbox",
            "refx",
            "refy",
            "markerwidth",
            "markerheight",
            "orient",
        ],
    ),
    ("g", &[]),
    ("a", &["href"]),
    ("path", &["d", "marker-start", "marker-end", "fill"]),
    (
        "line",
        &["x1", "y1", "x2", "y2", "marker-start", "marker-end"],
    ),
    ("rect", &["x", "y", "width", "height", "rx", "ry"]),
    ("circle", &["cx", "cy", "r"]),
    ("text", &["x", "y", "dx", "dy", "text-anchor"]),
    ("tspan", &["x", "y", "dx", "dy"]),
];

/// The attributes every element of the subset may carry, beside `aria-`.
const GLOBAL: &[&str] = &["id", "class", "role", "tabindex", "lang", "dir"];

/// Every way `root` leaves the closed subset, for a map whose node links
/// go to `page`: an element or attribute outside it, a link other than
/// `{page}#node-STATE`, a marker outside the document, a `fill` other
/// than `currentColor` or `none`, a text node in an element that holds
/// none, or an empty text node.
pub(crate) fn subset_faults(root: &TEl, page: &str) -> Vec<String> {
    let mut out = Vec::new();
    if root.tag != "svg" {
        out.push(format!("the root is {}, not svg", root.tag));
    }
    walk(root, page, &mut out);
    out
}

fn walk(e: &TEl, page: &str, out: &mut Vec<String>) {
    match SUBSET.iter().find(|(t, _)| *t == e.tag) {
        None => out.push(format!("element {} is outside the subset", e.tag)),
        Some((_, own)) => {
            for (n, v) in &e.attrs {
                let aria = n.starts_with("aria-")
                    && n.len() > 5
                    && n.bytes().skip(5).all(|b| b.is_ascii_lowercase());
                if !(GLOBAL.contains(&n.as_str()) || own.contains(&n.as_str()) || aria) {
                    out.push(format!("attribute {n} on {}", e.tag));
                }
                if let Some(f) = value_fault(n, v, page) {
                    out.push(format!("{n}={v:?} on {}: {f}", e.tag));
                }
            }
        }
    }
    let holds_text = matches!(e.tag.as_str(), "title" | "desc" | "text" | "tspan");
    for c in &e.children {
        match c {
            TNode::El(x) => walk(x, page, out),
            TNode::Text(t) if !holds_text => {
                out.push(format!("text {t:?} in {}", e.tag));
            }
            TNode::Text(t) if t.is_empty() => out.push(format!("an empty text in {}", e.tag)),
            TNode::Text(_) => {}
        }
    }
}

fn value_fault(name: &str, value: &str, page: &str) -> Option<&'static str> {
    match name {
        "href" => {
            let state = value.strip_prefix(page)?.strip_prefix("#node-");
            match state {
                Some(s)
                    if !s.is_empty()
                        && s.bytes()
                            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') =>
                {
                    None
                }
                _ => Some("not a node link of the page"),
            }
        }
        "fill" if value != "currentColor" && value != "none" => Some("a colour of its own"),
        "marker-start" | "marker-end" => {
            let id = value
                .strip_prefix("url(#")
                .and_then(|r| r.strip_suffix(')'));
            match id {
                Some(i)
                    if !i.is_empty()
                        && i.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') =>
                {
                    None
                }
                _ => Some("a marker outside the document"),
            }
        }
        _ => None,
    }
}

/// Every element of `e` named `tag`, in document order.
pub(crate) fn find<'a>(e: &'a TEl, tag: &str, out: &mut Vec<&'a TEl>) {
    for c in &e.children {
        if let TNode::El(x) = c {
            if x.tag == tag {
                out.push(x);
            }
            find(x, tag, out);
        }
    }
}

/// The texts of `e`, concatenated in document order.
pub(crate) fn text(e: &TEl) -> String {
    let mut s = String::new();
    for c in &e.children {
        match c {
            TNode::El(x) => s.push_str(&text(x)),
            TNode::Text(t) => s.push_str(t),
        }
    }
    s
}
