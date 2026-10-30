//! The Markdown subset of the Guide (TH-26, I-68, M4 design section 3.10:
//! "`fstp-guide` parses only the subset the template uses (headings,
//! paragraphs, lists, tables, emphasis and links), refuses anything
//! else").
//!
//! The subset, read from the shipped template. Interim, pending Daniel:
//!
//! - ATX headings of levels 1 to 3: `#`, a space and text, with no
//!   closing `#`;
//! - paragraphs of one or more lines, joined by soft line breaks;
//! - the thematic break, exactly `---`;
//! - pipe tables: a header row, the delimiter row `| --- | --- |` and body
//!   rows, each `| cell | cell |` with as many cells as the header;
//! - flat bullet lists of `- ` items, and flat ordered lists of `1. `,
//!   `2. ` items numbered from 1 in order;
//! - strong emphasis `**text**` and code spans `` `text` `` on one line;
//! - inline links `[text](https://...)` to an address `fstp_html::SafeUrl`
//!   accepts;
//! - in a template, `{{key}}` placeholders. A block placeholder stands
//!   alone between blank lines. An inline one stands in text.
//!
//! Every block follows a blank line or the start of the text, and every
//! block but a paragraph or a list ends at its line. No line starts or
//! ends with a space. A list that follows a list of its own kind across
//! blank lines would be one loose list, so it is refused.
//!
//! Every other construct is refused with a typed error, never passed
//! through as text. The characters `<`, `\` and `~`, the pairs `![` and
//! `[^`, character references such as `&lt;` or `&#60;`, tabs, carriage
//! returns, other control characters and noncharacters are refused
//! everywhere, code spans and link addresses included. So raw HTML,
//! autolinks, escapes, hard breaks, strikethrough, tilde fences, images,
//! footnotes and references never reach the renderer. A single `*`, any
//! `_`, a `[` that does not open an inline link and a stray `]` are
//! refused outside code spans.

use fstp_html::SafeUrl;

use crate::resolve::{Key, Shape, lookup};
use crate::{GuideError, KeyName, MAX_KEY_BYTES, is_key_byte};

/// Whether `{{key}}` is a placeholder or plain text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// The Markdown subset alone. Braces are text.
    Markdown,
    /// The subset with placeholders.
    Template,
}

/// An inline node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Inline {
    /// Plain text.
    Text(String),
    /// Strong emphasis.
    Strong(Vec<Inline>),
    /// A code span.
    Code(String),
    /// An inline link.
    Link {
        /// The link text.
        content: Vec<Inline>,
        /// The address.
        url: SafeUrl,
    },
    /// An inline placeholder.
    Slot(Key),
}

/// A block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Block {
    /// A heading of level 1 to 3.
    Heading {
        /// The level.
        level: u8,
        /// The heading text.
        content: Vec<Inline>,
    },
    /// A paragraph: its lines, joined by soft breaks.
    Paragraph(Vec<Vec<Inline>>),
    /// The thematic break.
    Rule,
    /// A pipe table.
    Table {
        /// The header cells.
        head: Vec<Vec<Inline>>,
        /// The body rows.
        rows: Vec<Vec<Vec<Inline>>>,
    },
    /// A bullet list.
    Bullets(Vec<Vec<Inline>>),
    /// An ordered list, numbered from 1.
    Numbered(Vec<Vec<Inline>>),
    /// A block placeholder.
    Slot(Key),
}

const NO_BLANK: &str = "a block starts without a blank line before it";
const LOOSE: &str =
    "a list follows a list of its own kind across a blank line, which makes one loose list";
const BLOCK_ALONE: &str = "a block placeholder must stand alone between blank lines";

fn md(line: u32, rule: &'static str) -> GuideError {
    GuideError::Markdown { line, rule }
}

fn ph(line: u32, rule: &'static str) -> GuideError {
    GuideError::Placeholder { line, rule }
}

/// Parses `text` in `mode`.
pub(crate) fn parse(text: &str, mode: Mode) -> Result<Vec<Block>, GuideError> {
    check_chars(text)?;
    let mut p = Parser {
        mode,
        blocks: Vec::new(),
        open: Open::None,
        after_blank: true,
        last_list: None,
    };
    let mut no: u32 = 0;
    for line in text.split('\n') {
        no = no.saturating_add(1);
        p.line(no, line)?;
    }
    p.close(no)?;
    Ok(p.blocks)
}

/// Whether `c` is a noncharacter: U+FDD0 to U+FDEF, or the last two code
/// points of a plane.
fn is_nonchar(c: char) -> bool {
    let cp = u32::from(c);
    (0xFDD0..=0xFDEF).contains(&cp) || (cp & 0xFFFE) == 0xFFFE
}

/// Whether the text after an `&` starts a character reference: `#`, or
/// letters and digits closed by `;`.
fn reference_at(rest: &str) -> bool {
    if rest.starts_with('#') {
        return true;
    }
    let n = rest.bytes().take_while(u8::is_ascii_alphanumeric).count();
    n > 0 && rest.get(n..).is_some_and(|r| r.starts_with(';'))
}

/// Refuses the characters and pairs the subset never holds, wherever they
/// stand (module documentation).
fn check_chars(text: &str) -> Result<(), GuideError> {
    let mut line: u32 = 1;
    for (at, c) in text.char_indices() {
        let rest = text.get(at.saturating_add(c.len_utf8())..).unwrap_or("");
        let rule = match c {
            '\n' => {
                line = line.saturating_add(1);
                continue;
            }
            '<' => "< starts raw HTML or an autolink",
            '\\' => "a backslash starts an escape or a hard line break",
            '~' => "~ starts strikethrough or a fenced code block",
            '!' if rest.starts_with('[') => "images are outside the subset",
            '[' if rest.starts_with('^') => "footnotes are outside the subset",
            '&' if reference_at(rest) => "character references are outside the subset",
            c if c.is_control() => {
                "tabs, carriage returns and other control characters are outside the subset"
            }
            c if is_nonchar(c) => "noncharacters are outside the subset",
            _ => continue,
        };
        return Err(md(line, rule));
    }
    Ok(())
}

/// The kind of a list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ListKind {
    Bullets,
    Numbered,
}

/// The block being read.
enum Open {
    None,
    Para(Vec<Vec<Inline>>),
    Bullets(Vec<Vec<Inline>>),
    Numbered(Vec<Vec<Inline>>),
    Table {
        head: Vec<Vec<Inline>>,
        delimited: bool,
        rows: Vec<Vec<Vec<Inline>>>,
    },
    Slot(Key),
}

/// What one line is.
enum Class<'a> {
    Blank,
    Heading(u8, &'a str),
    Rule,
    Bullet(&'a str),
    Ordered(u32, &'a str),
    Row(&'a str),
    Text(&'a str),
}

struct Parser {
    mode: Mode,
    blocks: Vec<Block>,
    open: Open,
    /// Whether the previous line was blank, or no line came yet.
    after_blank: bool,
    /// The kind of the last closed block, when it was a list.
    last_list: Option<ListKind>,
}

impl Parser {
    fn inline_line(&self, no: u32, s: &str) -> Result<Vec<Inline>, GuideError> {
        inlines(
            s,
            Cx {
                mode: self.mode,
                line: no,
                in_strong: false,
                in_link: false,
            },
        )
    }

    fn cells(&self, no: u32, row: &str) -> Result<Vec<Vec<Inline>>, GuideError> {
        cells(no, row)?
            .into_iter()
            .map(|c| self.inline_line(no, c))
            .collect()
    }

    fn line(&mut self, no: u32, s: &str) -> Result<(), GuideError> {
        let class = classify(no, s)?;
        if let Class::Blank = class {
            self.close(no)?;
            self.after_blank = true;
            return Ok(());
        }
        let open = std::mem::replace(&mut self.open, Open::None);
        self.open = match (open, class) {
            (Open::Para(mut lines), Class::Text(t)) => {
                lines.push(self.inline_line(no, t)?);
                Open::Para(lines)
            }
            (Open::Bullets(mut items), Class::Bullet(c)) => {
                items.push(self.inline_line(no, c)?);
                Open::Bullets(items)
            }
            (Open::Numbered(mut items), Class::Ordered(n, c)) => {
                let want = u32::try_from(items.len())
                    .ok()
                    .and_then(|l| l.checked_add(1));
                if want != Some(n) {
                    return Err(md(no, "an ordered list is not numbered 1, 2, 3 in order"));
                }
                items.push(self.inline_line(no, c)?);
                Open::Numbered(items)
            }
            (
                Open::Table {
                    head,
                    delimited,
                    mut rows,
                },
                Class::Row(r),
            ) => {
                let raw = cells(no, r)?;
                if raw.len() != head.len() {
                    return Err(md(
                        no,
                        "a table row has another number of cells than its header row",
                    ));
                }
                if delimited {
                    rows.push(self.cells(no, r)?);
                } else if !raw.iter().all(|c| *c == "---") {
                    return Err(md(
                        no,
                        "the second row of a table is not the delimiter row | --- |",
                    ));
                }
                Open::Table {
                    head,
                    delimited: true,
                    rows,
                }
            }
            (Open::Slot(k), _) => {
                return Err(GuideError::Placement {
                    key: k.name(),
                    rule: BLOCK_ALONE,
                });
            }
            (Open::None, class) => {
                if !self.after_blank {
                    return Err(md(no, NO_BLANK));
                }
                self.start(no, class)?
            }
            (_, _) => return Err(md(no, NO_BLANK)),
        };
        self.after_blank = false;
        Ok(())
    }

    /// Starts a block at a line that follows a blank line.
    fn start(&mut self, no: u32, class: Class<'_>) -> Result<Open, GuideError> {
        let last = self.last_list.take();
        Ok(match class {
            Class::Blank => Open::None,
            Class::Heading(level, c) => {
                let content = self.inline_line(no, c)?;
                self.blocks.push(Block::Heading { level, content });
                Open::None
            }
            Class::Rule => {
                self.blocks.push(Block::Rule);
                Open::None
            }
            Class::Bullet(c) => {
                if last == Some(ListKind::Bullets) {
                    return Err(md(no, LOOSE));
                }
                Open::Bullets(vec![self.inline_line(no, c)?])
            }
            Class::Ordered(n, c) => {
                if n != 1 {
                    return Err(md(no, "an ordered list does not start at 1"));
                }
                if last == Some(ListKind::Numbered) {
                    return Err(md(no, LOOSE));
                }
                Open::Numbered(vec![self.inline_line(no, c)?])
            }
            Class::Row(r) => Open::Table {
                head: self.cells(no, r)?,
                delimited: false,
                rows: Vec::new(),
            },
            Class::Text(t) => match self.lone_block_slot(no, t)? {
                Some(k) => Open::Slot(k),
                None => Open::Para(vec![self.inline_line(no, t)?]),
            },
        })
    }

    /// The block placeholder `t` is, when the whole line is one.
    fn lone_block_slot(&self, no: u32, t: &str) -> Result<Option<Key>, GuideError> {
        if self.mode != Mode::Template {
            return Ok(None);
        }
        let Some(name) = t.strip_prefix("{{").and_then(|r| r.strip_suffix("}}")) else {
            return Ok(None);
        };
        if name.is_empty() || !name.bytes().all(is_key_byte) {
            return Ok(None);
        }
        let key = slot_key(no, name)?;
        Ok((key.resolver().shape == Shape::Block).then_some(key))
    }

    /// Closes the block being read.
    fn close(&mut self, no: u32) -> Result<(), GuideError> {
        let block = match std::mem::replace(&mut self.open, Open::None) {
            Open::None => return Ok(()),
            Open::Para(lines) => Block::Paragraph(lines),
            Open::Bullets(items) => Block::Bullets(items),
            Open::Numbered(items) => Block::Numbered(items),
            Open::Table {
                head,
                delimited,
                rows,
            } => {
                if !delimited {
                    return Err(md(
                        no,
                        "a table needs the delimiter row | --- | after its header row",
                    ));
                }
                Block::Table { head, rows }
            }
            Open::Slot(k) => Block::Slot(k),
        };
        self.last_list = match block {
            Block::Bullets(_) => Some(ListKind::Bullets),
            Block::Numbered(_) => Some(ListKind::Numbered),
            _ => None,
        };
        self.blocks.push(block);
        Ok(())
    }
}

/// The ordered list marker at the start of `s`: its digits, its
/// delimiter and the rest, when the delimiter is followed by a space or
/// the end of the line.
fn ordered_marker(s: &str) -> Option<(&str, char, &str)> {
    let d = s.bytes().take_while(u8::is_ascii_digit).count();
    if d == 0 {
        return None;
    }
    let (digits, after) = s.split_at_checked(d)?;
    let delim = after.chars().next().filter(|c| matches!(c, '.' | ')'))?;
    let rest = after.get(1..)?;
    (rest.is_empty() || rest.starts_with(' ')).then_some((digits, delim, rest))
}

/// Refuses list item text that would open a nested block.
fn item_content(no: u32, c: &str) -> Result<&str, GuideError> {
    let nested = matches!(
        c.bytes().next(),
        Some(b' ' | b'#' | b'>' | b'-' | b'+' | b'|' | b'=')
    ) || ordered_marker(c).is_some();
    if nested {
        return Err(md(
            no,
            "a list item starts with another block; nested blocks are outside the subset",
        ));
    }
    Ok(c)
}

/// Classifies one line (module documentation).
fn classify(no: u32, l: &str) -> Result<Class<'_>, GuideError> {
    if l.is_empty() {
        return Ok(Class::Blank);
    }
    if l.starts_with(' ') {
        return Err(md(
            no,
            "a line starts with a space; indentation, indented code and nested lists are outside the subset",
        ));
    }
    if l.ends_with(' ') {
        return Err(md(
            no,
            "a line ends with a space; hard line breaks and blank lines holding spaces are outside the subset",
        ));
    }
    if l.starts_with('#') {
        let hashes = l.bytes().take_while(|b| *b == b'#').count();
        let content = l.get(hashes..).and_then(|r| r.strip_prefix(' '));
        return match (u8::try_from(hashes), content) {
            (Ok(level @ 1..=3), Some(c)) if !c.starts_with(' ') && !c.ends_with('#') => {
                Ok(Class::Heading(level, c))
            }
            _ => Err(md(
                no,
                "a line starting with # is not a heading of level 1 to 3 with text and no closing #",
            )),
        };
    }
    if l == "---" {
        return Ok(Class::Rule);
    }
    if l.bytes().all(|b| b == b'-') || l.bytes().all(|b| b == b'=') {
        return Err(md(
            no,
            "a line of only - or = signs other than the thematic break --- is a setext underline",
        ));
    }
    if let Some(c) = l.strip_prefix("- ") {
        return item_content(no, c).map(Class::Bullet);
    }
    if l.starts_with('-') {
        return Err(md(
            no,
            "a line starting with - is a list item `- text` or the thematic break `---`",
        ));
    }
    if l == "+" || l.starts_with("+ ") {
        return Err(md(no, "+ list items are outside the subset"));
    }
    if l.starts_with('>') {
        return Err(md(no, "block quotes are outside the subset"));
    }
    if l.starts_with("```") {
        return Err(md(no, "fenced code blocks are outside the subset"));
    }
    if let Some((digits, delim, rest)) = ordered_marker(l) {
        if delim != '.' {
            return Err(md(no, "ordered list items are written `1. text`"));
        }
        let n: u32 = match digits.parse() {
            Ok(n) if digits.len() <= 9 => n,
            _ => return Err(md(no, "an ordered list number has more than nine digits")),
        };
        let Some(c) = rest.strip_prefix(' ') else {
            return Err(md(no, "an ordered list item has no text"));
        };
        return item_content(no, c).map(|c| Class::Ordered(n, c));
    }
    if l.starts_with('|') {
        return Ok(Class::Row(l));
    }
    Ok(Class::Text(l))
}

/// The cells of a table row `| cell | cell |`.
fn cells(no: u32, row: &str) -> Result<Vec<&str>, GuideError> {
    let inner = row
        .strip_prefix("| ")
        .and_then(|r| r.strip_suffix(" |"))
        .ok_or_else(|| {
            md(
                no,
                "a table row is not `| cell | cell |` with one space inside each bar",
            )
        })?;
    let cells: Vec<&str> = inner.split(" | ").collect();
    if cells
        .iter()
        .any(|c| c.is_empty() || c.starts_with(' ') || c.ends_with(' ') || c.contains('|'))
    {
        return Err(md(
            no,
            "a table cell is empty, padded with more than one space, or holds a bar",
        ));
    }
    Ok(cells)
}

/// The key of placeholder `name`, or why it is refused.
fn slot_key(no: u32, name: &str) -> Result<Key, GuideError> {
    if name.len() > MAX_KEY_BYTES {
        return Err(ph(no, "a placeholder key is longer than 64 bytes"));
    }
    match (lookup(name), KeyName::new(name)) {
        (Some(k), _) => Ok(k),
        (None, Some(n)) => Err(GuideError::UnknownPlaceholder(n)),
        (None, None) => Err(ph(no, "a placeholder key is not a key")),
    }
}

/// The context of an inline run.
#[derive(Clone, Copy)]
struct Cx {
    mode: Mode,
    line: u32,
    in_strong: bool,
    in_link: bool,
}

/// Whether `c` counts as punctuation for the emphasis rules: anything
/// that is neither alphanumeric nor whitespace.
fn is_punct(c: char) -> bool {
    !c.is_alphanumeric() && !c.is_whitespace()
}

/// Whether `c`, next to a delimiter run, keeps a punctuation-edged run a
/// delimiter: the edge of the line, a space or ASCII punctuation.
fn friendly(c: Option<char>) -> bool {
    c.is_none_or(|c| c == ' ' || c.is_ascii_punctuation())
}

fn flush(out: &mut Vec<Inline>, text: &mut String) {
    if !text.is_empty() {
        out.push(Inline::Text(std::mem::take(text)));
    }
}

/// Parses the inline run `s`.
fn inlines(s: &str, cx: Cx) -> Result<Vec<Inline>, GuideError> {
    let mut out = Vec::new();
    let mut text = String::new();
    let mut rest = s;
    let mut prev: Option<char> = None;
    while let Some(c) = rest.chars().next() {
        let after = rest.get(c.len_utf8()..).unwrap_or("");
        let (node, tail) = match c {
            '`' => {
                let (code, tail) = code_span(after, cx)?;
                (Some(Inline::Code(code.to_owned())), tail)
            }
            '*' => strong(after, prev, cx)?,
            '_' => return Err(md(cx.line, "_ is emphasis syntax outside the subset")),
            '[' => link(after, cx)?,
            ']' => return Err(md(cx.line, "a ] outside a link")),
            '{' if cx.mode == Mode::Template && after.starts_with('{') => slot(after, cx)?,
            '}' if cx.mode == Mode::Template && after.starts_with('}') => {
                return Err(ph(cx.line, "}} without an opening {{"));
            }
            _ => {
                text.push(c);
                (None, after)
            }
        };
        if let Some(n) = node {
            flush(&mut out, &mut text);
            out.push(n);
        }
        // The last character consumed: the node's closing delimiter or
        // the text character.
        prev = rest
            .get(..rest.len().saturating_sub(tail.len()))
            .and_then(|done| done.chars().next_back());
        rest = tail;
    }
    flush(&mut out, &mut text);
    Ok(out)
}

/// A code span after its opening backtick: its text and the rest.
fn code_span(after: &str, cx: Cx) -> Result<(&str, &str), GuideError> {
    let end = after
        .find('`')
        .ok_or_else(|| md(cx.line, "a code span is not closed on its line"))?;
    let (code, tail) = after
        .split_at_checked(end)
        .ok_or_else(|| md(cx.line, "a code span is not closed on its line"))?;
    let tail = tail.get(1..).unwrap_or("");
    if code.is_empty() || tail.starts_with('`') {
        return Err(md(
            cx.line,
            "a code span is delimited by more than one backtick",
        ));
    }
    if code.starts_with(' ') || code.ends_with(' ') {
        return Err(md(cx.line, "a code span starts or ends with a space"));
    }
    if cx.mode == Mode::Template && (code.contains("{{") || code.contains("}}")) {
        return Err(ph(cx.line, "a placeholder stands inside a code span"));
    }
    Ok((code, tail))
}

/// Strong emphasis after its first `*`.
fn strong(after: &str, prev: Option<char>, cx: Cx) -> Result<(Option<Inline>, &str), GuideError> {
    let Some(body) = after.strip_prefix('*') else {
        return Err(md(
            cx.line,
            "a single * is emphasis outside the subset; strong emphasis is written **text**",
        ));
    };
    if cx.in_strong {
        return Err(md(cx.line, "strong emphasis inside strong emphasis"));
    }
    if body.starts_with('*') {
        return Err(md(
            cx.line,
            "a run of three or more * is outside the subset",
        ));
    }
    let end = body
        .find("**")
        .ok_or_else(|| md(cx.line, "strong emphasis is not closed on its line"))?;
    let (content, tail) = body
        .split_at_checked(end)
        .ok_or_else(|| md(cx.line, "strong emphasis is not closed on its line"))?;
    let tail = tail.get(2..).unwrap_or("");
    if tail.starts_with('*') {
        return Err(md(
            cx.line,
            "a run of three or more * is outside the subset",
        ));
    }
    let (Some(first), Some(last)) = (content.chars().next(), content.chars().next_back()) else {
        return Err(md(cx.line, "strong emphasis holds no text"));
    };
    if first.is_whitespace() || last.is_whitespace() {
        return Err(md(cx.line, "strong emphasis starts or ends with a space"));
    }
    if (is_punct(first) && !friendly(prev)) || (is_punct(last) && !friendly(tail.chars().next())) {
        return Err(md(
            cx.line,
            "strong emphasis edged by punctuation needs a space, punctuation or the line edge outside it",
        ));
    }
    let inner = inlines(
        content,
        Cx {
            in_strong: true,
            ..cx
        },
    )?;
    Ok((Some(Inline::Strong(inner)), tail))
}

/// An inline link after its `[`.
fn link(after: &str, cx: Cx) -> Result<(Option<Inline>, &str), GuideError> {
    const NOT_LINK: &str = "a [ that does not open an inline link; reference links and task list items are outside the subset";
    if cx.in_link {
        return Err(md(cx.line, "a link inside a link"));
    }
    let close = after.find(']').ok_or_else(|| md(cx.line, NOT_LINK))?;
    let (label, tail) = after
        .split_at_checked(close)
        .ok_or_else(|| md(cx.line, NOT_LINK))?;
    let Some(tail) = tail.get(1..).and_then(|t| t.strip_prefix('(')) else {
        return Err(md(cx.line, NOT_LINK));
    };
    if label.is_empty() || label.contains('[') {
        return Err(md(cx.line, "a link text is empty or holds a ["));
    }
    let end = tail
        .find(')')
        .ok_or_else(|| md(cx.line, "a link address is not closed by )"))?;
    let (url, tail) = tail
        .split_at_checked(end)
        .ok_or_else(|| md(cx.line, "a link address is not closed by )"))?;
    let tail = tail.get(1..).unwrap_or("");
    if cx.mode == Mode::Template && (url.contains("{{") || url.contains("}}")) {
        return Err(ph(cx.line, "a placeholder stands inside a link address"));
    }
    let plain = url.starts_with("https://")
        && !url.bytes().any(|b| matches!(b, b'(' | b'"' | b'\'' | b'`'));
    let url = SafeUrl::new(url)
        .ok()
        .filter(|_| plain)
        .ok_or_else(|| md(cx.line, "a link address is not a plain https address"))?;
    let content = inlines(
        label,
        Cx {
            in_link: true,
            ..cx
        },
    )?;
    Ok((Some(Inline::Link { content, url }), tail))
}

/// A placeholder after its first `{`.
fn slot(after: &str, cx: Cx) -> Result<(Option<Inline>, &str), GuideError> {
    let body = after.get(1..).unwrap_or("");
    let n = body.bytes().take_while(|b| is_key_byte(*b)).count();
    let (name, tail) = body
        .split_at_checked(n)
        .ok_or_else(|| ph(cx.line, "a placeholder key is not a key"))?;
    if name.is_empty() {
        return Err(ph(
            cx.line,
            "a placeholder is empty, or its key holds a character other than a letter, a digit, ., _ or -",
        ));
    }
    let Some(tail) = tail.strip_prefix("}}") else {
        return Err(ph(cx.line, "a placeholder key is not followed by }}"));
    };
    let key = slot_key(cx.line, name)?;
    match key.resolver().shape {
        Shape::Block => {
            return Err(GuideError::Placement {
                key: key.name(),
                rule: BLOCK_ALONE,
            });
        }
        Shape::Link if cx.in_link => {
            return Err(GuideError::Placement {
                key: key.name(),
                rule: "a link placeholder stands inside a link",
            });
        }
        Shape::Inline | Shape::Link => {}
    }
    Ok((Some(Inline::Slot(key)), tail))
}

/// Every placeholder of `blocks`, one per occurrence, in document order.
pub(crate) fn slots(blocks: &[Block]) -> Vec<Key> {
    fn walk(inlines: &[Inline], out: &mut Vec<Key>) {
        for n in inlines {
            match n {
                Inline::Slot(k) => out.push(*k),
                Inline::Strong(c) | Inline::Link { content: c, .. } => walk(c, out),
                Inline::Text(_) | Inline::Code(_) => {}
            }
        }
    }
    let mut out = Vec::new();
    for b in blocks {
        match b {
            Block::Heading { content, .. } => walk(content, &mut out),
            Block::Paragraph(lines) | Block::Bullets(lines) | Block::Numbered(lines) => {
                lines.iter().for_each(|l| walk(l, &mut out));
            }
            Block::Table { head, rows } => {
                head.iter().for_each(|c| walk(c, &mut out));
                rows.iter().flatten().for_each(|c| walk(c, &mut out));
            }
            Block::Slot(k) => out.push(*k),
            Block::Rule => {}
        }
    }
    out
}

/// The canonical spelling of an inline run.
pub(crate) fn encode_inlines(inlines: &[Inline]) -> String {
    let mut out = String::new();
    push_inlines(&mut out, inlines);
    out
}

fn push_inlines(out: &mut String, inlines: &[Inline]) {
    for n in inlines {
        match n {
            Inline::Text(t) => out.push_str(t),
            Inline::Strong(c) => {
                out.push_str("**");
                push_inlines(out, c);
                out.push_str("**");
            }
            Inline::Code(c) => {
                out.push('`');
                out.push_str(c);
                out.push('`');
            }
            Inline::Link { content, url } => {
                out.push('[');
                push_inlines(out, content);
                out.push_str("](");
                out.push_str(url.as_str());
                out.push(')');
            }
            Inline::Slot(k) => {
                out.push_str("{{");
                out.push_str(k.resolver().key);
                out.push_str("}}");
            }
        }
    }
}

fn push_row(out: &mut String, cells: &[Vec<Inline>]) {
    out.push('|');
    for c in cells {
        out.push(' ');
        push_inlines(out, c);
        out.push_str(" |");
    }
    out.push('\n');
}

/// The canonical spelling of `blocks`: one blank line between blocks and
/// a line feed after each line.
pub(crate) fn encode(blocks: &[Block]) -> String {
    let mut out = String::new();
    for (i, b) in blocks.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        match b {
            Block::Heading { level, content } => {
                for _ in 0..*level {
                    out.push('#');
                }
                out.push(' ');
                push_inlines(&mut out, content);
                out.push('\n');
            }
            Block::Paragraph(lines) => {
                for l in lines {
                    push_inlines(&mut out, l);
                    out.push('\n');
                }
            }
            Block::Rule => out.push_str("---\n"),
            Block::Table { head, rows } => {
                push_row(&mut out, head);
                out.push('|');
                for _ in head {
                    out.push_str(" --- |");
                }
                out.push('\n');
                for r in rows {
                    push_row(&mut out, r);
                }
            }
            Block::Bullets(items) => {
                for item in items {
                    out.push_str("- ");
                    push_inlines(&mut out, item);
                    out.push('\n');
                }
            }
            Block::Numbered(items) => {
                for (n, item) in (1_usize..).zip(items) {
                    out.push_str(&n.to_string());
                    out.push_str(". ");
                    push_inlines(&mut out, item);
                    out.push('\n');
                }
            }
            Block::Slot(k) => {
                out.push_str("{{");
                out.push_str(k.resolver().key);
                out.push_str("}}\n");
            }
        }
    }
    out
}
