//! The well-formedness checker of the writer's subset (TH-26, H-05).
//!
//! The checker accepts exactly the documents of the subset of
//! [`subset`](crate::subset). It must hold:
//!
//! - `<!DOCTYPE html>` (or `<!doctype html>`), optional whitespace, then
//!   one `html` element with a valid `lang`, and nothing after `</html>`;
//! - `head` with `<meta charset="utf-8">` first, `title` second, then only
//!   `meta` (`name` and `content`) and `link` (`rel` and a safe `href`);
//! - lower-case tag and attribute names from fixed allowlists,
//!   double-quoted or bare attribute values, no duplicate attribute, and
//!   whitespace before every attribute;
//! - explicit end tags for every non-void element, no end tag for a void
//!   element, and `/>` only on void elements;
//! - plain characters only, `&` only as a terminated reference to a plain
//!   character, and no raw `<` in text;
//! - the placement rules of the HTML tree builder;
//! - safe URLs in `href`, `src` and `action`.
//!
//! It walks the input once with an explicit stack, so deep nesting cannot
//! exhaust the call stack. It is fuzzed (`html_wellformed_check`).

use std::collections::BTreeMap;

use crate::HtmlError;
use crate::subset::{
    CONTAINERS, Open, RCDATA, URL_ATTRS, VOID, attr_allowed, intern, is_lang_tag, is_plain,
};
use crate::url::is_safe_url;

/// Checks that `bytes` is a well-formed document of the writer's subset.
/// Fuzzed (`html_wellformed_check`).
pub fn check_wellformed(bytes: &[u8]) -> Result<(), HtmlError> {
    let s = std::str::from_utf8(bytes).map_err(|e| HtmlError::NotWellFormed {
        at: e.valid_up_to(),
        rule: "the document is not UTF-8",
    })?;
    Checker {
        s,
        i: 0,
        open: Open::default(),
        frames: Vec::new(),
    }
    .document()
}

type Attrs<'a> = BTreeMap<&'a str, String>;

/// A finished element, as its parent's rules need it. Only `html` and
/// `head` keep their children.
struct Kid<'a> {
    name: &'static str,
    attrs: Attrs<'a>,
}

/// An open element.
struct Frame<'a> {
    name: &'static str,
    attrs: Attrs<'a>,
    kids: Vec<Kid<'a>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ctx {
    Text,
    Attr,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NameKind {
    Tag,
    Attr,
}

struct Checker<'a> {
    s: &'a str,
    i: usize,
    open: Open,
    frames: Vec<Frame<'a>>,
}

impl<'a> Checker<'a> {
    fn err(&self, rule: &'static str) -> HtmlError {
        HtmlError::NotWellFormed { at: self.i, rule }
    }

    fn rest(&self) -> &'a str {
        self.s.get(self.i..).unwrap_or("")
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn advance(&mut self, n: usize) {
        self.i = self.i.saturating_add(n);
    }

    fn eat(&mut self, lit: &str) -> bool {
        if self.rest().starts_with(lit) {
            self.advance(lit.len());
            true
        } else {
            false
        }
    }

    /// Eats `</name>`.
    fn eat_end(&mut self, name: &str) -> bool {
        let rest = self.rest();
        let matched = rest
            .strip_prefix("</")
            .and_then(|r| r.strip_prefix(name))
            .is_some_and(|r| r.starts_with('>'));
        if matched {
            self.advance(name.len().saturating_add(3));
        }
        matched
    }

    fn skip_ws(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some(' ' | '\t' | '\n')) {
            self.advance(1);
        }
        self.i.saturating_sub(start)
    }

    fn name(&mut self, kind: NameKind) -> Result<&'a str, HtmlError> {
        let start = self.i;
        while let Some(c) = self.peek() {
            let later = self.i > start;
            let ok = c.is_ascii_lowercase()
                || (later
                    && match kind {
                        NameKind::Tag => c.is_ascii_digit(),
                        NameKind::Attr => c == '-',
                    });
            if !ok {
                break;
            }
            self.advance(1);
        }
        match self.s.get(start..self.i) {
            Some(n) if !n.is_empty() => Ok(n),
            _ => Err(self.err("expected a lower-case name")),
        }
    }

    /// Reads characters until `stop` or the end, decoding references.
    fn chars(&mut self, stop: char, ctx: Ctx) -> Result<String, HtmlError> {
        let mut out = String::new();
        while let Some(c) = self.peek() {
            if c == stop || (c == '<' && ctx == Ctx::Text) {
                break;
            }
            if c == '&' {
                self.advance(1);
                out.push(self.reference()?);
                continue;
            }
            if !is_plain(c) {
                return Err(self.err("a character that is not plain"));
            }
            out.push(c);
            self.advance(c.len_utf8());
        }
        Ok(out)
    }

    /// Decodes one character reference; the `&` is consumed.
    fn reference(&mut self) -> Result<char, HtmlError> {
        if self.eat("#") {
            let hex = self.eat("x") || self.eat("X");
            let radix = if hex { 16 } else { 10 };
            let mut cp: u32 = 0;
            let mut digits = 0usize;
            while let Some(d) = self.peek().and_then(|c| c.to_digit(radix)) {
                cp = cp.saturating_mul(radix).saturating_add(d).min(0x11_0000);
                digits = digits.saturating_add(1);
                self.advance(1);
            }
            if digits == 0 || !self.eat(";") {
                return Err(self.err("a malformed numeric reference"));
            }
            return match char::from_u32(cp) {
                Some(c) if is_plain(c) => Ok(c),
                _ => Err(self.err("a reference to a character that is not plain")),
            };
        }
        let start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_alphanumeric()) {
            self.advance(1);
        }
        let name = self.s.get(start..self.i).unwrap_or("");
        if !self.eat(";") {
            return Err(self.err("an unterminated reference"));
        }
        match name {
            "amp" => Ok('&'),
            "lt" => Ok('<'),
            "gt" => Ok('>'),
            "quot" => Ok('"'),
            "apos" => Ok('\''),
            _ => Err(self.err("a named reference outside the five allowed")),
        }
    }

    fn document(mut self) -> Result<(), HtmlError> {
        if !self.eat("<!DOCTYPE html>") && !self.eat("<!doctype html>") {
            return Err(self.err("the document does not start with the doctype"));
        }
        self.skip_ws();
        if !self.rest().starts_with('<') {
            return Err(self.err("expected the html start tag"));
        }
        self.start_tag()?;
        while let Some(name) = self.frames.last().map(|f| f.name) {
            if self.eat_end(name) {
                self.open.pop();
                if let Some(frame) = self.frames.pop() {
                    self.finish(frame)?;
                }
                continue;
            }
            let rest = self.rest();
            if rest.is_empty() {
                return Err(self.err("an element is not closed"));
            }
            if rest.starts_with("</") {
                return Err(self.err("an unexpected end tag"));
            }
            if rest.starts_with("<!") || rest.starts_with("<?") {
                return Err(self.err("a comment, CDATA, doctype or processing instruction"));
            }
            if rest.starts_with('<') {
                self.start_tag()?;
            } else {
                let text = self.chars('<', Ctx::Text)?;
                if CONTAINERS.contains(&name)
                    && !text.chars().all(|c| matches!(c, ' ' | '\t' | '\n'))
                {
                    return Err(self.err("text directly inside a container element"));
                }
            }
        }
        if self.i != self.s.len() {
            return Err(self.err("content after </html>"));
        }
        Ok(())
    }

    /// Parses one start tag at `<`, and the whole element when it is void
    /// or RCDATA. Otherwise it opens a frame.
    fn start_tag(&mut self) -> Result<(), HtmlError> {
        self.advance(1);
        let raw = self.name(NameKind::Tag)?;
        let name = intern(raw).ok_or_else(|| self.err("the element is not in the subset"))?;
        self.open.check(name).map_err(|rule| self.err(rule))?;
        let void = VOID.contains(&name);
        let attrs = self.attributes(name, void)?;
        if void {
            self.complete(name, attrs);
            return Ok(());
        }
        if RCDATA.contains(&name) {
            self.chars('<', Ctx::Text)?;
            if !self.eat_end(name) {
                return Err(self.err("an RCDATA element holds markup or is not closed"));
            }
            self.complete(name, attrs);
            return Ok(());
        }
        self.open.push(name);
        self.frames.push(Frame {
            name,
            attrs,
            kids: Vec::new(),
        });
        Ok(())
    }

    fn attributes(&mut self, el: &'static str, void: bool) -> Result<Attrs<'a>, HtmlError> {
        let mut attrs = Attrs::new();
        loop {
            let ws = self.skip_ws();
            if self.eat(">") {
                return Ok(attrs);
            }
            if self.eat("/") {
                if !void {
                    return Err(self.err("self-closing syntax on a non-void element"));
                }
                if !self.eat(">") {
                    return Err(self.err("expected > after /"));
                }
                return Ok(attrs);
            }
            if ws == 0 {
                return Err(self.err("no whitespace before an attribute"));
            }
            let attr = self.name(NameKind::Attr)?;
            if !attr_allowed(el, attr) {
                return Err(self.err("the attribute is not allowed on the element"));
            }
            let value = if self.eat("=") {
                if !self.eat("\"") {
                    return Err(self.err("the attribute value is not double-quoted"));
                }
                let v = self.chars('"', Ctx::Attr)?;
                if !self.eat("\"") {
                    return Err(self.err("an unterminated attribute value"));
                }
                v
            } else {
                String::new()
            };
            if URL_ATTRS.contains(&attr) && !is_safe_url(&value) {
                return Err(self.err("the URL is not safe"));
            }
            if attrs.insert(attr, value).is_some() {
                return Err(self.err("a duplicate attribute"));
            }
        }
    }

    /// Hands a finished element to its parent, which keeps it only when
    /// it is `html` or `head`.
    fn complete(&mut self, name: &'static str, attrs: Attrs<'a>) {
        if let Some(parent) = self.frames.last_mut()
            && (parent.name == "html" || parent.name == "head")
        {
            parent.kids.push(Kid { name, attrs });
        }
    }

    /// Checks the rules that need the whole element.
    fn finish(&mut self, frame: Frame<'a>) -> Result<(), HtmlError> {
        match frame.name {
            "html" => {
                let lang = frame.attrs.get("lang").map_or("", String::as_str);
                if !is_lang_tag(lang) {
                    return Err(self.err("html lang is not a language tag"));
                }
                if frame.attrs.keys().any(|k| *k != "lang" && *k != "dir") {
                    return Err(self.err("html holds an attribute other than lang and dir"));
                }
                let names: Vec<&str> = frame.kids.iter().map(|k| k.name).collect();
                if names != ["head", "body"] {
                    return Err(self.err("html does not hold head then body"));
                }
            }
            "head" => {
                if !frame.attrs.is_empty() {
                    return Err(self.err("head has attributes"));
                }
                let first_ok = frame.kids.first().is_some_and(|m| {
                    m.name == "meta"
                        && m.attrs.len() == 1
                        && m.attrs.get("charset").map(String::as_str) == Some("utf-8")
                });
                if !first_ok {
                    return Err(self.err("head does not start with <meta charset=\"utf-8\">"));
                }
                if frame.kids.get(1).is_none_or(|t| t.name != "title") {
                    return Err(self.err("the second child of head is not title"));
                }
                for k in frame.kids.iter().skip(2) {
                    let ok = match k.name {
                        "meta" => k.attrs.keys().copied().eq(["content", "name"]),
                        "link" => k.attrs.contains_key("rel") && k.attrs.contains_key("href"),
                        _ => false,
                    };
                    if !ok {
                        return Err(self.err("head holds an element outside its rules"));
                    }
                }
            }
            _ => {}
        }
        self.complete(frame.name, frame.attrs);
        Ok(())
    }
}
