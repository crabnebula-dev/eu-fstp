//! The writer's HTML subset: characters, allowlists and placement rules.
//!
//! Interim reading, pending Daniel. The M4 design names a checker "of the
//! writer's subset" (section 1.1) but does not define the subset. This
//! module defines it once, and both the writer and
//! [`check_wellformed`](crate::check_wellformed) use it, so the writer
//! never emits a document the checker refuses.
//!
//! A document of the subset is one whose HTML parse tree equals its
//! literal nesting. It holds no script, style, comment or event handler,
//! and it needs no parser recovery.

/// Whether `c` is a noncharacter: U+FDD0 to U+FDEF, or the last two code
/// points of a plane.
pub(crate) fn is_nonchar(c: char) -> bool {
    let cp = u32::from(c);
    (0xFDD0..=0xFDEF).contains(&cp) || (cp & 0xFFFE) == 0xFFFE
}

/// Whether `c` is plain: tab, line feed, or a scalar value from U+0020 up
/// that is not DEL, a C1 control or a noncharacter.
///
/// CR is not plain, because the HTML parser rewrites it, so a text that
/// holds CR cannot come back unchanged.
pub(crate) fn is_plain(c: char) -> bool {
    match c {
        '\t' | '\n' => true,
        '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' => false,
        _ => !is_nonchar(c),
    }
}

/// Elements with no content and no end tag.
pub(crate) const VOID: &[&str] = &["br", "hr", "img", "input", "meta", "link", "wbr"];

/// Elements whose content is escapable raw text (RCDATA).
pub(crate) const RCDATA: &[&str] = &["title", "textarea"];

/// Elements after whose start tag the HTML parser drops one line feed.
pub(crate) const DROPS_LEADING_LF: &[&str] = &["pre", "textarea"];

/// Elements allowed only as children of `head`.
const HEAD_ELEMENTS: &[&str] = &["meta", "title", "link"];

/// The document skeleton elements.
const SKELETON: &[&str] = &["html", "head", "body"];

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

/// Elements that hold only certain child elements and layout whitespace.
pub(crate) const CONTAINERS: &[&str] = &[
    "html", "head", "table", "thead", "tbody", "tfoot", "tr", "ul", "ol", "dl", "select",
];

/// Attributes allowed on every element. `aria-` names are allowed too.
const GLOBAL_ATTRS: &[&str] = &[
    "id", "class", "lang", "dir", "title", "hidden", "role", "tabindex",
];

/// Attributes whose value is a URL.
pub(crate) const URL_ATTRS: &[&str] = &["href", "src", "action"];

/// Attributes the writer lets a caller set as a bare flag.
pub(crate) const BOOLEAN_ATTRS: &[&str] = &[
    "hidden",
    "required",
    "disabled",
    "readonly",
    "checked",
    "multiple",
    "novalidate",
    "selected",
    "open",
    "reversed",
];

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

/// Whether attribute `attr` is allowed on element `el`.
pub(crate) fn attr_allowed(el: &str, attr: &str) -> bool {
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

/// The static spelling of element `name`, if the subset knows it.
pub(crate) fn intern(name: &str) -> Option<&'static str> {
    SKELETON
        .iter()
        .chain(HEAD_ELEMENTS)
        .chain(BODY_ELEMENTS)
        .find(|n| **n == name)
        .copied()
}

/// The open elements, outermost first, with counts of the ones the
/// placement rules look for among the ancestors.
#[derive(Debug, Default)]
pub(crate) struct Open {
    stack: Vec<&'static str>,
    p: usize,
    headings: usize,
    a: usize,
    form: usize,
    button: usize,
    caption: usize,
}

impl Open {
    /// The number of open elements.
    pub(crate) fn depth(&self) -> usize {
        self.stack.len()
    }

    /// The innermost open element.
    pub(crate) fn parent(&self) -> Option<&'static str> {
        self.stack.last().copied()
    }

    fn counter(&mut self, name: &str) -> Option<&mut usize> {
        match name {
            "p" => Some(&mut self.p),
            "a" => Some(&mut self.a),
            "form" => Some(&mut self.form),
            "button" => Some(&mut self.button),
            "caption" => Some(&mut self.caption),
            _ if HEADINGS.contains(&name) => Some(&mut self.headings),
            _ => None,
        }
    }

    /// Opens `name` below the innermost open element.
    pub(crate) fn push(&mut self, name: &'static str) {
        if let Some(c) = self.counter(name) {
            *c = c.saturating_add(1);
        }
        self.stack.push(name);
    }

    /// Closes the innermost open element.
    pub(crate) fn pop(&mut self) {
        if let Some(name) = self.stack.pop()
            && let Some(c) = self.counter(name)
        {
            *c = c.saturating_sub(1);
        }
    }

    /// Checks that element `name` may open here. The HTML tree builder
    /// would move or close an element that breaks one of these rules.
    pub(crate) fn check(&self, name: &str) -> Result<(), &'static str> {
        match self.parent() {
            None => {
                return if name == "html" {
                    Ok(())
                } else {
                    Err("the root element is not html")
                };
            }
            Some("html") => {
                return if name == "head" || name == "body" {
                    Ok(())
                } else {
                    Err("only head and body may be children of html")
                };
            }
            Some("head") => {
                return if HEAD_ELEMENTS.contains(&name) {
                    Ok(())
                } else {
                    Err("only meta, title and link may be children of head")
                };
            }
            Some(_) => {}
        }
        if !BODY_ELEMENTS.contains(&name) {
            return Err("the element is not allowed below body");
        }
        let parent = self.parent().unwrap_or("");
        let required_parent: Option<&[&str]> = match name {
            "li" => Some(&["ul", "ol"]),
            "dt" | "dd" => Some(&["dl"]),
            "caption" | "thead" | "tbody" | "tfoot" => Some(&["table"]),
            "tr" => Some(&["thead", "tbody", "tfoot"]),
            "th" | "td" => Some(&["tr"]),
            "option" => Some(&["select"]),
            _ => None,
        };
        if required_parent.is_some_and(|parents| !parents.contains(&parent)) {
            return Err("the element needs another parent");
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
        if allowed_children.is_some_and(|children| !children.contains(&name)) {
            return Err("the parent may not hold the element");
        }
        if P_CLOSERS.contains(&name) && self.p > 0 {
            return Err("the element would close an open p");
        }
        if HEADINGS.contains(&name) && self.headings > 0 {
            return Err("a heading inside a heading");
        }
        let nested = match name {
            "a" => self.a > 0,
            "form" => self.form > 0,
            "button" => self.button > 0,
            _ => false,
        };
        if nested {
            return Err("the element is nested in an element of the same name");
        }
        if name == "table" && self.caption > 0 {
            return Err("a table inside a caption");
        }
        Ok(())
    }
}
