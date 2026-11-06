//! Reference parser for the writer's HTML subset.
//!
//! Interim reading, pending Daniel. The M4 design names a well-formedness
//! checker "of the writer's subset" (section 1.1) and says escaped text
//! never closes an element or attribute (section 9). It does not define
//! the subset. This module defines it as an executable reference, so the
//! production checker `fstp_html::check_wellformed` can be compared
//! against it.
//!
//! A document of the subset is one whose HTML parse tree equals its literal
//! nesting, holds no script, style, comment or event handler, and needs no
//! parser recovery. It must hold:
//!
//! - `<!DOCTYPE html>` (or `<!doctype html>`), optional whitespace, then
//!   one `html` element with a valid `lang`, and nothing after `</html>`;
//! - `head` with `<meta charset="utf-8">` first, `title` second, then only
//!   `meta` (`name` and `content`) and `link` (`rel` and a safe `href`);
//! - `body` holding only elements of [`BODY_ELEMENTS`];
//! - lower-case tag and attribute names from fixed allowlists, double-quoted
//!   or bare attribute values, no duplicate attribute, and whitespace
//!   before every attribute;
//! - explicit end tags for every non-void element, no end tag for a void
//!   element, and `/>` only on void elements;
//! - plain characters only (see `chars`), `&` only as a terminated
//!   character reference to a plain character, and no raw `<` in text;
//! - the parent, child and ancestor rules under which the HTML tree
//!   builder would move or close an element (for example a `div` inside
//!   a `p`, a `tr` directly in a `table`, or nested `a` elements);
//! - safe URLs (see `chars::is_safe_url`) in `href`, `src` and `action`;
//! - inside `svg`, only the closed SVG subset of [`SVG_ELEMENTS`] (lane j3,
//!   ADR-015). See "The SVG subset" below.
//!
//! The parse result is the decoded tree. Character references are decoded,
//! the line feed the HTML parser drops after `<pre>` and `<textarea>` is
//! dropped, and whitespace-only text inside container elements, which the
//! subset allows for layout, is removed.
//!
//! # The SVG subset (lane j3, test author)
//!
//! Interim reading, pending Daniel. ADR-015 puts the route SVG renderer in
//! `fstp-html` and asks the checker to accept the closed SVG subset the
//! renderer emits, and nothing else. An `svg` element may stand where the
//! body rules allow phrasing content, but never inside `a` or `button`.
//! Inside it:
//!
//! - only the elements of [`SVG_ELEMENTS`], each with the parents of
//!   `svg_placement`. No script, style, foreign object, image, `use`,
//!   animation element or HTML element, since an HTML start tag would
//!   break out of foreign content;
//! - `title`, `desc` and `tspan` hold text only, and `text` holds text and
//!   `tspan`. `title` is an SVG element there, not RCDATA. Every other SVG
//!   element holds only layout whitespace, which is removed;
//! - lower-case attribute names from the allowlist of `svg_attrs`, which
//!   the HTML parser adjusts (`viewbox` becomes `viewBox`), plus `id`,
//!   `class`, `role`, `tabindex`, `lang`, `dir` and `aria-` names. No
//!   `on` handler, no `style` and no namespaced name;
//! - `href` is a safe URL, `marker-start` and `marker-end` are
//!   `url(#name)`, and `fill` is `currentColor` or `none`, so no attribute
//!   reaches another resource or carries a colour outside the tokens;
//! - explicit end tags, as for every non-void element, and no nested `a`.

use std::collections::BTreeMap;

use super::chars::{is_plain, is_safe_url};

/// A node of the decoded tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RNode {
    /// An element.
    El(REl),
    /// A text node, decoded.
    Text(String),
}

/// An element of the decoded tree. Attribute values are decoded, and a
/// bare attribute has the empty value, as in the DOM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct REl {
    /// The tag name.
    pub(crate) name: String,
    /// The attributes, by name.
    pub(crate) attrs: BTreeMap<String, String>,
    /// The children, in order.
    pub(crate) children: Vec<RNode>,
}

impl REl {
    /// An element with no attribute and no child.
    pub(crate) fn new(name: &str) -> REl {
        REl {
            name: name.to_owned(),
            attrs: BTreeMap::new(),
            children: Vec::new(),
        }
    }
}

/// Elements with no content and no end tag.
pub(crate) const VOID: &[&str] = &["br", "hr", "img", "input", "meta", "link", "wbr"];

/// Elements whose content is escapable raw text (RCDATA).
pub(crate) const RCDATA: &[&str] = &["title", "textarea"];

/// Elements after whose start tag the HTML parser drops one line feed.
pub(crate) const DROPS_LEADING_LF: &[&str] = &["pre", "textarea"];

/// Elements allowed below `body`.
pub(crate) const BODY_ELEMENTS: &[&str] = &[
    "header",
    "footer",
    "nav",
    "main",
    "section",
    "article",
    "aside",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "p",
    "div",
    "span",
    "a",
    "ul",
    "ol",
    "li",
    "dl",
    "dt",
    "dd",
    "table",
    "caption",
    "thead",
    "tbody",
    "tfoot",
    "tr",
    "th",
    "td",
    "strong",
    "em",
    "b",
    "i",
    "code",
    "small",
    "abbr",
    "time",
    "br",
    "wbr",
    "hr",
    "img",
    "form",
    "label",
    "input",
    "button",
    "select",
    "option",
    "textarea",
    "pre",
    "blockquote",
    "fieldset",
    "legend",
    "details",
    "summary",
    "figure",
    "figcaption",
];

/// Elements whose start tag closes an open `p` in the HTML tree builder.
const P_CLOSERS: &[&str] = &[
    "article",
    "aside",
    "blockquote",
    "details",
    "div",
    "dl",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "header",
    "main",
    "nav",
    "ol",
    "p",
    "section",
    "summary",
    "ul",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "pre",
    "form",
    "li",
    "dd",
    "dt",
    "table",
    "hr",
];

const HEADINGS: &[&str] = &["h1", "h2", "h3", "h4", "h5", "h6"];

/// Elements whose start tag closes an open element of the same name.
const NO_SELF_NESTING: &[&str] = &["a", "form", "button"];

/// Elements that hold only certain child elements and whitespace.
const CONTAINERS: &[&str] = &[
    "html", "head", "table", "thead", "tbody", "tfoot", "tr", "ul", "ol", "dl", "select",
];

/// Attributes allowed on every element. `aria-` names are allowed too.
const GLOBAL_ATTRS: &[&str] = &[
    "id", "class", "lang", "dir", "title", "hidden", "role", "tabindex",
];

/// Attributes whose value is a URL.
pub(crate) const URL_ATTRS: &[&str] = &["href", "src", "action"];

/// The elements of the closed SVG subset (lane j3, ADR-015). `svg` opens
/// it, and every other one stands only inside `svg`.
pub(crate) const SVG_ELEMENTS: &[&str] = &[
    "svg", "title", "desc", "defs", "marker", "g", "a", "path", "line", "rect", "circle", "text",
    "tspan",
];

/// SVG elements that hold only layout whitespace and elements.
const SVG_CONTAINERS: &[&str] = &[
    "svg", "defs", "marker", "g", "a", "path", "line", "rect", "circle",
];

/// Attributes allowed on every element of the SVG subset. `aria-` names
/// are allowed too.
const SVG_GLOBAL_ATTRS: &[&str] = &["id", "class", "role", "tabindex", "lang", "dir"];

/// Attributes allowed on one SVG element, beyond the global ones. Names
/// are lower case; the HTML parser adjusts them to their SVG spelling.
fn svg_attrs(el: &str) -> &'static [&'static str] {
    match el {
        "svg" => &["viewbox"],
        "a" => &["href"],
        "marker" => &[
            "viewbox",
            "refx",
            "refy",
            "markerwidth",
            "markerheight",
            "orient",
        ],
        "path" => &["d", "marker-start", "marker-end", "fill"],
        "line" => &["x1", "y1", "x2", "y2", "marker-start", "marker-end"],
        "rect" => &["x", "y", "width", "height", "rx", "ry"],
        "circle" => &["cx", "cy", "r"],
        "text" => &["x", "y", "dx", "dy", "text-anchor"],
        "tspan" => &["x", "y", "dx", "dy"],
        _ => &[],
    }
}

fn svg_attr_allowed(el: &str, attr: &str) -> bool {
    if SVG_GLOBAL_ATTRS.contains(&attr) || svg_attrs(el).contains(&attr) {
        return true;
    }
    attr.strip_prefix("aria-")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_lowercase()))
}

/// Whether `value` is `url(#name)` with a name of ASCII letters, digits,
/// `-` and `_`: a reference inside the same document only.
fn is_local_url_ref(value: &str) -> bool {
    value
        .strip_prefix("url(#")
        .and_then(|r| r.strip_suffix(')'))
        .is_some_and(|n| {
            !n.is_empty()
                && n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// The value rules of the SVG subset beyond the safe URL rule.
fn svg_value_ok(attr: &str, value: &str) -> bool {
    match attr {
        "marker-start" | "marker-end" => is_local_url_ref(value),
        "fill" => value == "currentColor" || value == "none",
        _ => true,
    }
}

/// Checks where an element may open inside `svg`. `svg_anc` holds the
/// open ancestors from the `svg` element down.
fn svg_placement(name: &str, parent: &str, svg_anc: &[&str]) -> Result<(), String> {
    let allowed: &[&str] = match parent {
        "svg" => &[
            "title", "desc", "defs", "g", "a", "path", "line", "rect", "circle", "text",
        ],
        "g" => &[
            "title", "desc", "g", "a", "path", "line", "rect", "circle", "text",
        ],
        "a" => &[
            "title", "desc", "g", "path", "line", "rect", "circle", "text",
        ],
        "defs" => &["marker"],
        "marker" => &["path"],
        "text" => &["tspan"],
        _ => &[],
    };
    if !allowed.contains(&name) {
        return Err(format!(
            "<{parent}> inside svg may not hold it (closed SVG subset)"
        ));
    }
    if name == "a" && svg_anc.contains(&"a") {
        return Err("an SVG a inside an SVG a".to_owned());
    }
    Ok(())
}

/// Attributes allowed on one element, beyond the global ones.
fn element_attrs(el: &str) -> &'static [&'static str] {
    match el {
        "a" => &["href", "rel", "hreflang"],
        "img" => &["src", "alt", "width", "height"],
        "link" => &["rel", "href", "type", "media", "sizes"],
        "meta" => &["charset", "name", "content"],
        "form" => &["action", "method", "enctype", "novalidate"],
        "input" => &[
            "type",
            "name",
            "value",
            "placeholder",
            "required",
            "disabled",
            "readonly",
            "checked",
            "autocomplete",
            "maxlength",
            "minlength",
            "min",
            "max",
            "step",
            "pattern",
            "size",
            "multiple",
            "inputmode",
        ],
        "button" => &["type", "name", "value", "disabled"],
        "select" => &["name", "required", "disabled", "multiple", "size"],
        "option" => &["value", "selected", "disabled", "label"],
        "textarea" => &[
            "name",
            "rows",
            "cols",
            "required",
            "disabled",
            "readonly",
            "placeholder",
            "maxlength",
            "minlength",
        ],
        "label" => &["for"],
        "th" => &["scope", "colspan", "rowspan", "headers", "abbr"],
        "td" => &["colspan", "rowspan", "headers"],
        "time" => &["datetime"],
        "ol" => &["start", "reversed", "type"],
        "li" => &["value"],
        "details" => &["open"],
        _ => &[],
    }
}

fn attr_allowed(el: &str, attr: &str) -> bool {
    if GLOBAL_ATTRS.contains(&attr) || element_attrs(el).contains(&attr) {
        return true;
    }
    attr.strip_prefix("aria-")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_lowercase()))
}

/// Whether `s` is a language tag the subset accepts in `lang`:
/// `[A-Za-z]{2,8}` then any number of `-[A-Za-z0-9]{1,8}`.
pub(crate) fn is_lang_tag(s: &str) -> bool {
    let mut parts = s.split('-');
    let Some(first) = parts.next() else {
        return false;
    };
    (2..=8).contains(&first.len())
        && first.bytes().all(|b| b.is_ascii_alphabetic())
        && parts.all(|p| (1..=8).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// Parses `bytes` as a document of the subset and returns its decoded
/// `html` element, or the reason it is not one.
pub(crate) fn parse(bytes: &[u8]) -> Result<REl, String> {
    let s = std::str::from_utf8(bytes).map_err(|e| format!("not UTF-8: {e}"))?;
    let mut p = Parser { s, i: 0 };
    if !p.eat("<!DOCTYPE html>") && !p.eat("<!doctype html>") {
        return Err("the document does not start with the doctype".to_owned());
    }
    p.skip_ws();
    let html = p.element(&[])?;
    if p.i != s.len() {
        return Err(format!("content after </html> at byte {}", p.i));
    }
    Ok(html)
}

/// Whether `bytes` is a document of the subset.
pub(crate) fn accepts(bytes: &[u8]) -> bool {
    parse(bytes).is_ok()
}

struct Parser<'a> {
    s: &'a str,
    i: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ctx {
    Text,
    Attr,
}

impl Parser<'_> {
    fn rest(&self) -> &str {
        self.s.get(self.i..).unwrap_or("")
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn eat(&mut self, lit: &str) -> bool {
        if self.rest().starts_with(lit) {
            self.i += lit.len();
            true
        } else {
            false
        }
    }

    fn skip_ws(&mut self) -> usize {
        let mut n = 0;
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' || c == '\n' {
                self.i += 1;
                n += 1;
            } else {
                break;
            }
        }
        n
    }

    fn name(&mut self, digits: bool) -> Result<String, String> {
        let start = self.i;
        while let Some(c) = self.peek() {
            let ok = c.is_ascii_lowercase()
                || (self.i > start && ((c == '-' && !digits) || c.is_ascii_digit()));
            if !ok {
                break;
            }
            self.i += 1;
        }
        if self.i == start {
            return Err(format!("expected a lower-case name at byte {start}"));
        }
        Ok(self.s[start..self.i].to_owned())
    }

    /// Reads characters until `stop` or the end, decoding references.
    fn chars(&mut self, stop: char, ctx: Ctx) -> Result<String, String> {
        let mut out = String::new();
        while let Some(c) = self.peek() {
            if c == stop {
                break;
            }
            if c == '<' && ctx == Ctx::Text {
                break;
            }
            if c == '&' {
                self.i += 1;
                out.push(self.reference()?);
                continue;
            }
            if !is_plain(c) {
                return Err(format!(
                    "character U+{:04X} at byte {} is not plain",
                    u32::from(c),
                    self.i
                ));
            }
            out.push(c);
            self.i += c.len_utf8();
        }
        Ok(out)
    }

    /// Decodes one character reference; the `&` is consumed.
    fn reference(&mut self) -> Result<char, String> {
        let at = self.i;
        if self.eat("#") {
            let hex = self.eat("x") || self.eat("X");
            let mut cp: u32 = 0;
            let mut n = 0;
            while let Some(c) = self.peek() {
                let Some(d) = c.to_digit(if hex { 16 } else { 10 }) else {
                    break;
                };
                cp = cp
                    .saturating_mul(if hex { 16 } else { 10 })
                    .saturating_add(d)
                    .min(0x11_0000);
                n += 1;
                self.i += 1;
            }
            if n == 0 || !self.eat(";") {
                return Err(format!("malformed numeric reference at byte {at}"));
            }
            return match char::from_u32(cp) {
                Some(c) if is_plain(c) => Ok(c),
                _ => Err(format!("reference to U+{cp:04X} at byte {at} is not plain")),
            };
        }
        let start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_alphanumeric()) {
            self.i += 1;
        }
        let name = &self.s[start..self.i];
        if !self.eat(";") {
            return Err(format!("unterminated reference at byte {at}"));
        }
        match name {
            "amp" => Ok('&'),
            "lt" => Ok('<'),
            "gt" => Ok('>'),
            "quot" => Ok('"'),
            "apos" => Ok('\''),
            _ => Err(format!(
                "named reference &{name}; at byte {at} is not allowed"
            )),
        }
    }

    /// Parses one element whose open ancestors are `anc` (outermost first).
    fn element(&mut self, anc: &[&str]) -> Result<REl, String> {
        let at = self.i;
        if !self.eat("<") {
            return Err(format!("expected a start tag at byte {at}"));
        }
        let name = self.name(true)?;
        placement(&name, anc).map_err(|e| format!("<{name}> at byte {at}: {e}"))?;
        let mut el = REl::new(&name);
        let void = VOID.contains(&name.as_str());
        // Inside `svg`, or the `svg` element itself: the SVG subset rules.
        let in_svg = anc.contains(&"svg") || name == "svg";
        loop {
            let ws = self.skip_ws();
            if self.eat(">") {
                break;
            }
            if self.eat("/") {
                if !void {
                    return Err(format!("self-closing syntax on <{name}> at byte {at}"));
                }
                if !self.eat(">") {
                    return Err(format!("expected > after / in <{name}>"));
                }
                break;
            }
            if ws == 0 {
                return Err(format!("no whitespace before an attribute of <{name}>"));
            }
            let attr = self.name(false)?;
            let allowed = if in_svg {
                svg_attr_allowed(&name, &attr)
            } else {
                attr_allowed(&name, &attr)
            };
            if !allowed {
                return Err(format!("attribute {attr} is not allowed on <{name}>"));
            }
            let value = if self.eat("=") {
                if !self.eat("\"") {
                    return Err(format!("attribute {attr} of <{name}> is not double-quoted"));
                }
                let v = self.chars('"', Ctx::Attr)?;
                if !self.eat("\"") {
                    return Err(format!("unterminated attribute {attr} of <{name}>"));
                }
                v
            } else {
                String::new()
            };
            if in_svg && !svg_value_ok(&attr, &value) {
                return Err(format!(
                    "{attr}={value:?} on <{name}> is outside the SVG subset"
                ));
            }
            if URL_ATTRS.contains(&attr.as_str()) && !is_safe_url(&value) {
                return Err(format!("{attr}={value:?} on <{name}> is not a safe URL"));
            }
            if el.attrs.insert(attr.clone(), value).is_some() {
                return Err(format!("duplicate attribute {attr} on <{name}>"));
            }
        }
        if void {
            return Ok(el);
        }
        let mut inner: Vec<&str> = anc.to_vec();
        inner.push(&name);
        let end = format!("</{name}>");
        let mut first = true;
        if RCDATA.contains(&name.as_str()) && !in_svg {
            let mut text = self.chars('<', Ctx::Text)?;
            if !self.eat(&end) {
                return Err(format!("<{name}> holds markup or is not closed"));
            }
            if DROPS_LEADING_LF.contains(&name.as_str()) && text.starts_with('\n') {
                text.remove(0);
            }
            if !text.is_empty() {
                el.children.push(RNode::Text(text));
            }
            return finish(el);
        }
        loop {
            if self.eat(&end) {
                break;
            }
            let rest = self.rest();
            if rest.is_empty() {
                return Err(format!("<{name}> at byte {at} is not closed"));
            }
            if rest.starts_with("</") {
                return Err(format!(
                    "unexpected end tag at byte {} inside <{name}>",
                    self.i
                ));
            }
            if rest.starts_with("<!") || rest.starts_with("<?") {
                return Err(format!(
                    "comment, CDATA, doctype or processing instruction at byte {}",
                    self.i
                ));
            }
            if rest.starts_with('<') {
                let child = self.element(&inner)?;
                el.children.push(RNode::El(child));
            } else {
                let mut text = self.chars('<', Ctx::Text)?;
                if first && DROPS_LEADING_LF.contains(&name.as_str()) && text.starts_with('\n') {
                    text.remove(0);
                }
                let container = if in_svg {
                    SVG_CONTAINERS.contains(&name.as_str())
                } else {
                    CONTAINERS.contains(&name.as_str())
                };
                if container {
                    if !text.chars().all(|c| c == ' ' || c == '\t' || c == '\n') {
                        return Err(format!("text directly inside <{name}>"));
                    }
                } else if !text.is_empty() {
                    el.children.push(RNode::Text(text));
                }
            }
            first = false;
        }
        finish(el)
    }
}

/// Checks where element `name` may open, given its open ancestors.
fn placement(name: &str, anc: &[&str]) -> Result<(), String> {
    let parent = anc.last().copied();
    match parent {
        None => {
            return if name == "html" {
                Ok(())
            } else {
                Err("the root element is not html".to_owned())
            };
        }
        Some("html") => {
            return if name == "head" || name == "body" {
                Ok(())
            } else {
                Err("only head and body may be children of html".to_owned())
            };
        }
        Some("head") => {
            return if matches!(name, "meta" | "title" | "link") {
                Ok(())
            } else {
                Err("only meta, title and link may be children of head".to_owned())
            };
        }
        Some(_) => {}
    }
    if let Some(at) = anc.iter().position(|a| *a == "svg") {
        return svg_placement(name, parent.unwrap_or(""), anc.get(at..).unwrap_or(&[]));
    }
    if name == "svg" {
        if anc.iter().any(|a| matches!(*a, "a" | "button")) {
            return Err("svg inside an interactive element".to_owned());
        }
    } else if SVG_ELEMENTS.contains(&name) && !BODY_ELEMENTS.contains(&name) {
        return Err("an SVG element outside svg".to_owned());
    }
    if name != "svg" && !BODY_ELEMENTS.contains(&name) {
        return Err("the element is not in the allowlist below body".to_owned());
    }
    let parent = parent.unwrap_or("");
    let required_parent: Option<&[&str]> = match name {
        "li" => Some(&["ul", "ol"]),
        "dt" | "dd" => Some(&["dl"]),
        "caption" | "thead" | "tbody" | "tfoot" => Some(&["table"]),
        "tr" => Some(&["thead", "tbody", "tfoot"]),
        "th" | "td" => Some(&["tr"]),
        "option" => Some(&["select"]),
        _ => None,
    };
    if let Some(parents) = required_parent
        && !parents.contains(&parent)
    {
        return Err(format!("its parent is {parent}, not one of {parents:?}"));
    }
    let allowed_children: Option<&[&str]> = match parent {
        "ul" | "ol" => Some(&["li"]),
        "dl" => Some(&["dt", "dd"]),
        "table" => Some(&["caption", "thead", "tbody", "tfoot"]),
        "thead" | "tbody" | "tfoot" => Some(&["tr"]),
        "tr" => Some(&["th", "td"]),
        "select" => Some(&["option"]),
        "option" => Some(&[]),
        _ => None,
    };
    if let Some(children) = allowed_children
        && !children.contains(&name)
    {
        return Err(format!("<{parent}> may not hold it"));
    }
    if P_CLOSERS.contains(&name) && anc.contains(&"p") {
        return Err("it would close an open p".to_owned());
    }
    if HEADINGS.contains(&name) && anc.iter().any(|a| HEADINGS.contains(a)) {
        return Err("a heading inside a heading".to_owned());
    }
    if NO_SELF_NESTING.contains(&name) && anc.contains(&name) {
        return Err("it is nested in an element of the same name".to_owned());
    }
    if name == "table" && anc.contains(&"caption") {
        return Err("a table inside a caption".to_owned());
    }
    Ok(())
}

fn element_children(el: &REl) -> Vec<&REl> {
    el.children
        .iter()
        .filter_map(|n| match n {
            RNode::El(e) => Some(e),
            RNode::Text(_) => None,
        })
        .collect()
}

/// Checks the rules that need the whole element.
fn finish(el: REl) -> Result<REl, String> {
    match el.name.as_str() {
        "html" => {
            let lang = el.attrs.get("lang").map(String::as_str).unwrap_or("");
            if !is_lang_tag(lang) {
                return Err(format!("html lang={lang:?} is not a language tag"));
            }
            if el.attrs.keys().any(|k| k != "lang" && k != "dir") {
                return Err("html holds an attribute other than lang and dir".to_owned());
            }
            let kids: Vec<&str> = element_children(&el)
                .iter()
                .map(|e| e.name.as_str())
                .collect();
            if kids != ["head", "body"] {
                return Err(format!("html holds {kids:?}, not head then body"));
            }
        }
        "head" => {
            if !el.attrs.is_empty() {
                return Err("head has attributes".to_owned());
            }
            let kids = element_children(&el);
            let first_ok = kids.first().is_some_and(|m| {
                m.name == "meta"
                    && m.attrs.len() == 1
                    && m.attrs.get("charset").map(String::as_str) == Some("utf-8")
            });
            if !first_ok {
                return Err("head does not start with <meta charset=\"utf-8\">".to_owned());
            }
            if kids.get(1).is_none_or(|t| t.name != "title") {
                return Err("the second child of head is not title".to_owned());
            }
            for k in kids.iter().skip(2) {
                match k.name.as_str() {
                    "meta" => {
                        let keys: Vec<&str> = k.attrs.keys().map(String::as_str).collect();
                        if keys != ["content", "name"] {
                            return Err(format!("a later meta holds {keys:?}"));
                        }
                    }
                    "link" => {
                        if !k.attrs.contains_key("rel") || !k.attrs.contains_key("href") {
                            return Err("link needs rel and href".to_owned());
                        }
                    }
                    other => return Err(format!("head holds a second {other}")),
                }
            }
        }
        _ => {}
    }
    Ok(el)
}

/// Every text node of `el`, in document order, attribute values excluded.
pub(crate) fn texts(el: &REl) -> Vec<String> {
    let mut out = Vec::new();
    collect_texts(el, &mut out);
    out
}

fn collect_texts(el: &REl, out: &mut Vec<String>) {
    for n in &el.children {
        match n {
            RNode::Text(t) => out.push(t.clone()),
            RNode::El(e) => collect_texts(e, out),
        }
    }
}

/// Every attribute value of `el` and its descendants.
pub(crate) fn attr_values(el: &REl) -> Vec<String> {
    let mut out: Vec<String> = el.attrs.values().cloned().collect();
    for n in &el.children {
        if let RNode::El(e) = n {
            out.extend(attr_values(e));
        }
    }
    out
}
