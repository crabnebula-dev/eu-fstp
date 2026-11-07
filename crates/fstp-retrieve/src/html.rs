//! In-house HTML-to-text converter (TH-12, TH-01).
//!
//! The converter is a single forward scan, not a DOM builder. It keeps
//! visible text and drops everything a page can use to hide content from
//! a reader:
//!
//! - script, style, noscript, iframe and the other raw text elements are
//!   skipped up to their end tag, whatever their content holds;
//! - template, svg and math are skipped with their whole subtree;
//! - comments, doctypes, processing instructions, tags and attributes are
//!   dropped;
//! - character references are decoded, whitespace collapses to one space,
//!   and control characters are removed. Block elements start a new line,
//!   and `pre` keeps its whitespace.
//!
//! The output never exceeds the byte limit. It is data and never an
//! instruction: the proxy wraps it in `UntrustedText`.

/// Converted text and whether the byte limit cut it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlainText {
    /// The text.
    pub text: String,
    /// The limit cut the text short.
    pub truncated: bool,
}

/// Elements whose content is raw text, skipped up to the end tag.
const RAW: &[&str] = &[
    "script",
    "style",
    "noscript",
    "iframe",
    "noembed",
    "noframes",
    "xmp",
    "textarea",
    "plaintext",
];

/// Elements whose content is escapable text, kept on its own line.
const RCDATA: &[&str] = &["title"];

/// Elements skipped with their whole subtree.
const SUBTREE: &[&str] = &["template", "svg", "math"];

/// Elements that start and end a line.
const BLOCK: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "body",
    "br",
    "caption",
    "dd",
    "details",
    "dialog",
    "div",
    "dl",
    "dt",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "head",
    "header",
    "hgroup",
    "hr",
    "html",
    "legend",
    "li",
    "main",
    "nav",
    "ol",
    "option",
    "p",
    "section",
    "summary",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "tr",
    "ul",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gap {
    None,
    Space,
    Line,
}

/// The bounded output writer.
pub(crate) struct Out {
    text: String,
    max: usize,
    truncated: bool,
    gap: Gap,
}

fn is_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{a0}'
}

impl Out {
    pub(crate) fn new(max: usize) -> Out {
        Out {
            text: String::new(),
            max,
            truncated: false,
            gap: Gap::None,
        }
    }

    pub(crate) fn full(&self) -> bool {
        self.truncated
    }

    pub(crate) fn finish(self) -> PlainText {
        PlainText {
            text: self.text,
            truncated: self.truncated,
        }
    }

    fn at_line_start(&self) -> bool {
        self.text.is_empty() || self.text.ends_with('\n')
    }

    fn push(&mut self, c: char) {
        if self.truncated {
            return;
        }
        if self.text.len().saturating_add(c.len_utf8()) > self.max {
            self.truncated = true;
            return;
        }
        self.text.push(c);
    }

    fn flush(&mut self) {
        let gap = std::mem::replace(&mut self.gap, Gap::None);
        if self.at_line_start() {
            return;
        }
        match gap {
            Gap::None => {}
            Gap::Space => self.push(' '),
            Gap::Line => self.push('\n'),
        }
    }

    fn line(&mut self) {
        if !self.text.is_empty() {
            self.gap = Gap::Line;
        }
    }

    /// Flowing text: whitespace collapses, controls are removed.
    fn flow(&mut self, c: char) {
        if is_space(c) {
            if self.gap == Gap::None {
                self.gap = Gap::Space;
            }
        } else if !c.is_control() {
            self.flush();
            self.push(c);
        }
    }

    /// Preformatted text: whitespace is kept, `\r` and other controls are
    /// removed.
    pub(crate) fn pre(&mut self, c: char) {
        let c = match c {
            '\n' => '\n',
            '\r' => return,
            c if is_space(c) => ' ',
            c if c.is_control() => return,
            c => c,
        };
        self.flush();
        self.push(c);
    }
}

/// Converts `html` to text of at most `max` bytes.
#[must_use]
pub fn html_to_text(html: &str, max: usize) -> PlainText {
    let mut out = Out::new(max);
    // The subtree being skipped and its nesting depth.
    let mut skip: Option<(String, u32)> = None;
    let mut pre = 0u32;
    let mut rest = html;
    while !rest.is_empty() && !out.full() {
        if let Some(after) = rest.strip_prefix('<') {
            match markup(after) {
                Markup::Text => {
                    emit(&mut out, skip.is_some(), pre, '<');
                    rest = after;
                }
                Markup::Ignored(next) => rest = next,
                Markup::Start {
                    name,
                    self_closing,
                    next,
                } => {
                    rest = next;
                    let n = name.as_str();
                    if RAW.contains(&n) {
                        rest = raw_content(rest, n).1;
                    } else if let Some((open, depth)) = &mut skip {
                        if *open == name && !self_closing {
                            *depth = depth.saturating_add(1);
                        }
                    } else if RCDATA.contains(&n) {
                        let (content, next) = raw_content(rest, n);
                        rest = next;
                        out.line();
                        text_run(&mut out, content, false);
                        out.line();
                    } else if SUBTREE.contains(&n) {
                        if !self_closing {
                            skip = Some((name, 1));
                        }
                    } else if n == "pre" {
                        out.line();
                        pre = pre.saturating_add(1);
                        rest = rest
                            .strip_prefix("\r\n")
                            .or_else(|| rest.strip_prefix('\n'))
                            .unwrap_or(rest);
                    } else if BLOCK.contains(&n) {
                        out.line();
                    }
                }
                Markup::End { name, next } => {
                    rest = next;
                    if let Some((open, depth)) = &mut skip {
                        if *open == name {
                            *depth = depth.saturating_sub(1);
                            if *depth == 0 {
                                skip = None;
                            }
                        }
                    } else if name == "pre" {
                        pre = pre.saturating_sub(1);
                        out.line();
                    } else if BLOCK.contains(&name.as_str()) {
                        out.line();
                    }
                }
            }
        } else {
            let end = rest.find('<').unwrap_or(rest.len());
            let (run, next) = rest.split_at_checked(end).unwrap_or((rest, ""));
            if skip.is_none() {
                text_run(&mut out, run, pre > 0);
            }
            rest = next;
        }
    }
    out.finish()
}

fn emit(out: &mut Out, skipping: bool, pre: u32, c: char) {
    if skipping {
        return;
    }
    if pre > 0 {
        out.pre(c);
    } else {
        out.flow(c);
    }
}

/// Writes a run of text with character references decoded.
fn text_run(out: &mut Out, run: &str, pre: bool) {
    let mut rest = run;
    while !rest.is_empty() && !out.full() {
        let (c, next) = if rest.starts_with('&') {
            entity(rest)
        } else {
            let mut chars = rest.chars();
            match chars.next() {
                Some(c) => (c, chars.as_str()),
                None => break,
            }
        };
        if pre {
            out.pre(c);
        } else {
            out.flow(c);
        }
        rest = next;
    }
}

enum Markup<'a> {
    /// A `<` that starts no markup.
    Text,
    /// A comment, doctype, processing instruction or empty end tag.
    Ignored(&'a str),
    Start {
        name: String,
        self_closing: bool,
        next: &'a str,
    },
    End {
        name: String,
        next: &'a str,
    },
}

/// Reads the markup after a `<`.
fn markup(after: &str) -> Markup<'_> {
    if after.starts_with("!--") {
        // `<!-->` and `<!--->` close at once (HTML abrupt closing).
        let from = after.get(1..).unwrap_or("");
        return Markup::Ignored(match from.find("-->") {
            Some(i) => from.get(i.saturating_add(3)..).unwrap_or(""),
            None => "",
        });
    }
    if after.starts_with('!') || after.starts_with('?') {
        return Markup::Ignored(past_gt(after));
    }
    if let Some(end) = after.strip_prefix('/') {
        if end.starts_with(|c: char| c.is_ascii_alphabetic()) {
            let (name, rest) = tag_name(end);
            let (_, next) = tag_end(rest);
            return Markup::End { name, next };
        }
        if let Some(next) = end.strip_prefix('>') {
            return Markup::Ignored(next);
        }
        return Markup::Ignored(past_gt(end));
    }
    if after.starts_with(|c: char| c.is_ascii_alphabetic()) {
        let (name, rest) = tag_name(after);
        let (self_closing, next) = tag_end(rest);
        return Markup::Start {
            name,
            self_closing,
            next,
        };
    }
    Markup::Text
}

fn past_gt(s: &str) -> &str {
    match s.find('>') {
        Some(i) => s.get(i.saturating_add(1)..).unwrap_or(""),
        None => "",
    }
}

fn tag_name(s: &str) -> (String, &str) {
    let end = s
        .find(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>')
        .unwrap_or(s.len());
    let (name, rest) = s.split_at_checked(end).unwrap_or((s, ""));
    (name.to_ascii_lowercase(), rest)
}

/// Skips attributes up to the closing `>`. Quoted values may hold `>`.
fn tag_end(s: &str) -> (bool, &str) {
    let mut rest = s;
    let mut self_closing = false;
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_ascii_whitespace());
        let mut chars = rest.chars();
        match chars.next() {
            None => return (false, ""),
            Some('>') => return (self_closing, chars.as_str()),
            Some('/') => {
                self_closing = chars.as_str().starts_with('>');
                rest = chars.as_str();
            }
            Some(_) => {
                self_closing = false;
                // The attribute name; a leading `=` belongs to it.
                let name_end = rest
                    .char_indices()
                    .skip(1)
                    .find(|&(_, c)| c.is_ascii_whitespace() || matches!(c, '/' | '>' | '='))
                    .map_or(rest.len(), |(i, _)| i);
                rest = rest.get(name_end..).unwrap_or("");
                let after_ws = rest.trim_start_matches(|c: char| c.is_ascii_whitespace());
                if let Some(v) = after_ws.strip_prefix('=') {
                    let v = v.trim_start_matches(|c: char| c.is_ascii_whitespace());
                    rest = attr_value(v);
                }
            }
        }
    }
}

fn attr_value(v: &str) -> &str {
    for q in ['"', '\''] {
        if let Some(inner) = v.strip_prefix(q) {
            return match inner.find(q) {
                Some(i) => inner.get(i.saturating_add(1)..).unwrap_or(""),
                None => "",
            };
        }
    }
    let end = v
        .find(|c: char| c.is_ascii_whitespace() || c == '>')
        .unwrap_or(v.len());
    v.get(end..).unwrap_or("")
}

/// Splits raw text content at the end tag `</name`, which must be followed
/// by whitespace, `/` or `>`. Returns the content and what follows the end
/// tag. Without an end tag the content runs to the end of input.
fn raw_content<'a>(s: &'a str, name: &str) -> (&'a str, &'a str) {
    let bytes = s.as_bytes();
    for (i, _) in s.match_indices("</") {
        let start = i.saturating_add(2);
        let stop = start.saturating_add(name.len());
        let named = s
            .get(start..stop)
            .is_some_and(|n| n.eq_ignore_ascii_case(name));
        let delimited = bytes
            .get(stop)
            .is_some_and(|b| b.is_ascii_whitespace() || matches!(b, b'/' | b'>'));
        if named && delimited {
            let content = s.get(..i).unwrap_or("");
            let (_, next) = tag_end(s.get(stop..).unwrap_or(""));
            return (content, next);
        }
    }
    (s, "")
}

/// Named character references the converter decodes. Others stay as text.
const NAMED: &[(&str, char)] = &[
    ("amp", '&'),
    ("lt", '<'),
    ("gt", '>'),
    ("quot", '"'),
    ("apos", '\''),
    ("nbsp", '\u{a0}'),
    ("copy", '\u{a9}'),
    ("reg", '\u{ae}'),
    ("trade", '\u{2122}'),
    ("hellip", '\u{2026}'),
    ("mdash", '\u{2014}'),
    ("ndash", '\u{2013}'),
    ("lsquo", '\u{2018}'),
    ("rsquo", '\u{2019}'),
    ("ldquo", '\u{201c}'),
    ("rdquo", '\u{201d}'),
    ("laquo", '\u{ab}'),
    ("raquo", '\u{bb}'),
    ("middot", '\u{b7}'),
    ("bull", '\u{2022}'),
    ("euro", '\u{20ac}'),
    ("shy", '\u{ad}'),
];

/// Decodes the character reference at the start of `s`, which starts with
/// `&`. An unknown reference yields a literal `&`.
fn entity(s: &str) -> (char, &str) {
    let after = s.get(1..).unwrap_or("");
    if let Some(num) = after.strip_prefix('#') {
        let (hex, digits) = match num.strip_prefix(['x', 'X']) {
            Some(h) => (true, h),
            None => (false, num),
        };
        let radix = if hex { 16 } else { 10 };
        let end = digits
            .find(|c: char| !c.is_digit(radix))
            .unwrap_or(digits.len());
        if end > 0 {
            let (ds, rest) = digits.split_at_checked(end).unwrap_or((digits, ""));
            let mut v: u32 = 0;
            for c in ds.chars() {
                let d = c.to_digit(radix).unwrap_or(0);
                v = v.saturating_mul(radix).saturating_add(d);
            }
            let c = match v {
                0 => '\u{fffd}',
                v => char::from_u32(v).unwrap_or('\u{fffd}'),
            };
            return (c, rest.strip_prefix(';').unwrap_or(rest));
        }
        return ('&', after);
    }
    let end = after
        .find(|c: char| !c.is_ascii_alphanumeric())
        .unwrap_or(after.len());
    if end <= 32
        && let Some((name, rest)) = after.split_at_checked(end)
        && let Some(rest) = rest.strip_prefix(';')
        && let Some((_, c)) = NAMED.iter().find(|(n, _)| *n == name)
    {
        return (*c, rest);
    }
    ('&', after)
}
