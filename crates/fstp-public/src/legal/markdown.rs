//! The Markdown subset of the `legal/` drafts (ADR-037 section 2).
//!
//! An in-house parser, fuzzed as `legal_markdown` from its first commit
//! (CLAUDE.md). It turns a draft into [`Block`]s of [`Inline`]s and never
//! produces markup: the page renderer writes every text through the
//! escaping writer of `fstp-html` (I-68).
//!
//! Blocks: ATX headings `#` to `######`, paragraphs (lines joined by one
//! space), flat lists (`- `, `* ` or `1. `, with indented continuation
//! lines), pipe tables (a second row of dashes makes the first a header),
//! and rules (`---`, `***`). A `> ` quote is read as a paragraph.
//!
//! Inlines: `**strong**`, `` `code` ``, the placeholder `{{name}}`, the
//! marker `TODO(legal)`, and `[NOT BUILT ...]`. Anything else is text,
//! including a `[text](target)` link, whose target is never followed.
//!
//! Every construct that does not close is plain text. Each search for a
//! closing delimiter that fails is not repeated for the rest of the
//! input, so the parser runs in time linear in its input, times the fixed
//! nesting depth of two.

/// The largest draft the parser accepts, in bytes.
pub const MAX_SOURCE_BYTES: usize = 256 * 1024;

/// The longest placeholder name, in bytes.
pub const MAX_PLACEHOLDER_BYTES: usize = 64;

/// Why a draft did not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkdownError {
    /// The draft is longer than [`MAX_SOURCE_BYTES`].
    TooLong,
}

impl std::fmt::Display for MarkdownError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MarkdownError::TooLong => f.write_str("the draft is too long"),
        }
    }
}

impl std::error::Error for MarkdownError {}

/// One inline part of a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inline {
    /// Plain text.
    Text(String),
    /// `**...**`.
    Strong(Vec<Inline>),
    /// `` `...` ``.
    Code(String),
    /// `{{name}}`: a value the page fills, or marks as not set.
    Placeholder(String),
    /// `TODO(legal)`: a point still pending legal review.
    Pending,
    /// `[NOT BUILT ...]`: a rule the code does not carry out yet, with the
    /// text after `NOT BUILT` and an optional colon.
    NotBuilt(Vec<Inline>),
}

/// One block of a draft.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    /// A heading of level 1 to 6.
    Heading(u8, Vec<Inline>),
    /// A paragraph.
    Paragraph(Vec<Inline>),
    /// A list: ordered or not, one inline run per item.
    List {
        /// Whether the items are numbered.
        ordered: bool,
        /// The items.
        items: Vec<Vec<Inline>>,
    },
    /// A table: its header row, if any, then its body rows.
    Table {
        /// The header cells.
        head: Option<Vec<Vec<Inline>>>,
        /// The body rows.
        rows: Vec<Vec<Vec<Inline>>>,
    },
    /// A thematic break.
    Rule,
}

/// Parses `src` into blocks.
///
/// # Errors
///
/// [`MarkdownError::TooLong`] for a draft over [`MAX_SOURCE_BYTES`].
pub fn parse(src: &str) -> Result<Vec<Block>, MarkdownError> {
    if src.len() > MAX_SOURCE_BYTES {
        return Err(MarkdownError::TooLong);
    }
    let mut p = BlockParser::default();
    for raw in src.split('\n') {
        p.line(raw.strip_suffix('\r').unwrap_or(raw));
    }
    p.flush();
    Ok(p.blocks)
}

/// The list item a line opens, if any: whether it is numbered, and the
/// item's text.
fn list_item(line: &str) -> Option<(bool, &str)> {
    if let Some(rest) = line.strip_prefix("- ").or_else(|| line.strip_prefix("* ")) {
        return Some((false, rest));
    }
    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    if (1..=9).contains(&digits) {
        let (_, rest) = line.split_at_checked(digits)?;
        return rest.strip_prefix(". ").map(|r| (true, r));
    }
    None
}

/// The level and text of a heading line, if it is one.
fn heading(line: &str) -> Option<(u8, &str)> {
    let hashes = line.bytes().take_while(|b| *b == b'#').count();
    if !(1..=6).contains(&hashes) {
        return None;
    }
    let (_, rest) = line.split_at_checked(hashes)?;
    let text = rest.strip_prefix(' ')?;
    u8::try_from(hashes).ok().map(|n| (n, text.trim()))
}

/// Whether `line` is a thematic break.
fn rule(line: &str) -> bool {
    let t = line.trim();
    t.len() >= 3 && (t.bytes().all(|b| b == b'-') || t.bytes().all(|b| b == b'*'))
}

/// The cells of a table row, trimmed, without the outer pipes.
fn cells(line: &str) -> Vec<&str> {
    let t = line.trim();
    let t = t.strip_prefix('|').unwrap_or(t);
    let t = t.strip_suffix('|').unwrap_or(t);
    t.split('|').map(str::trim).collect()
}

/// Whether a table row is the separator under a header.
fn separator(row: &[&str]) -> bool {
    !row.is_empty()
        && row
            .iter()
            .all(|c| c.contains('-') && c.bytes().all(|b| matches!(b, b'-' | b':' | b' ')))
}

#[derive(Default)]
struct BlockParser {
    blocks: Vec<Block>,
    para: Vec<String>,
    list: Option<(bool, Vec<String>)>,
    table: Vec<String>,
}

impl BlockParser {
    fn flush(&mut self) {
        if !self.para.is_empty() {
            let text = self.para.join(" ");
            self.para.clear();
            self.blocks.push(Block::Paragraph(inlines(&text)));
        }
        if let Some((ordered, items)) = self.list.take() {
            self.blocks.push(Block::List {
                ordered,
                items: items.iter().map(|i| inlines(i)).collect(),
            });
        }
        if !self.table.is_empty() {
            let rows: Vec<Vec<&str>> = self.table.iter().map(|l| cells(l)).collect();
            let parse_row = |r: &Vec<&str>| r.iter().map(|c| inlines(c)).collect::<Vec<_>>();
            let block = match rows.get(1) {
                Some(sep) if separator(sep) => Block::Table {
                    head: rows.first().map(parse_row),
                    rows: rows.iter().skip(2).map(parse_row).collect(),
                },
                _ => Block::Table {
                    head: None,
                    rows: rows.iter().map(parse_row).collect(),
                },
            };
            self.table.clear();
            self.blocks.push(block);
        }
    }

    fn line(&mut self, line: &str) {
        if line.trim().is_empty() {
            self.flush();
            return;
        }
        if line.trim_start().starts_with('|') {
            if self.table.is_empty() {
                self.flush();
            }
            self.table.push(line.to_owned());
            return;
        }
        if !self.table.is_empty() {
            self.flush();
        }
        if rule(line) {
            self.flush();
            self.blocks.push(Block::Rule);
            return;
        }
        if let Some((level, text)) = heading(line) {
            self.flush();
            self.blocks.push(Block::Heading(level, inlines(text)));
            return;
        }
        if let Some((ordered, text)) = list_item(line) {
            if !self.para.is_empty() || self.list.as_ref().is_some_and(|(o, _)| *o != ordered) {
                self.flush();
            }
            self.list
                .get_or_insert_with(|| (ordered, Vec::new()))
                .1
                .push(text.trim().to_owned());
            return;
        }
        if let Some((_, items)) = self.list.as_mut()
            && line.starts_with("  ")
            && let Some(last) = items.last_mut()
        {
            last.push(' ');
            last.push_str(line.trim());
            return;
        }
        if self.list.is_some() {
            self.flush();
        }
        let text = line.trim();
        let text = text.strip_prefix("> ").unwrap_or(text);
        self.para.push(text.to_owned());
    }
}

/// Whether `name` may be a placeholder name: 1 to
/// [`MAX_PLACEHOLDER_BYTES`] bytes of ASCII letters, digits and `. _ - *`.
/// Anything else between braces stays text, so its markers still show.
fn placeholder_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_PLACEHOLDER_BYTES
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'*'))
}

/// The closing delimiters whose search already failed, so a later,
/// shorter rest cannot hold them either.
#[derive(Default)]
struct Missing {
    code: bool,
    strong: bool,
    brace: bool,
    bracket: bool,
}

/// The inline parts of `text`.
fn inlines(text: &str) -> Vec<Inline> {
    run(text, 0, false)
}

/// The inline parts of `rest` at nesting `depth`. A strong run holds no
/// strong run, and a not-built run holds no not-built run.
fn run(mut rest: &str, depth: u8, in_strong: bool) -> Vec<Inline> {
    let mut out = Vec::new();
    let mut text = String::new();
    let mut missing = Missing::default();
    let flush = |text: &mut String, out: &mut Vec<Inline>| {
        if !text.is_empty() {
            out.push(Inline::Text(std::mem::take(text)));
        }
    };
    while !rest.is_empty() {
        if !missing.code
            && let Some(r) = rest.strip_prefix('`')
        {
            match r.split_once('`') {
                // A pending marker inside a code span still shows as a marker.
                Some((code, after)) if !code.contains("TODO(legal)") => {
                    flush(&mut text, &mut out);
                    out.push(Inline::Code(code.to_owned()));
                    rest = after;
                    continue;
                }
                Some(_) => {}
                None => missing.code = true,
            }
        }
        if !in_strong
            && !missing.strong
            && depth < 2
            && let Some(r) = rest.strip_prefix("**")
        {
            match r.split_once("**") {
                Some((inner, after)) if !inner.is_empty() => {
                    flush(&mut text, &mut out);
                    out.push(Inline::Strong(run(inner, depth.saturating_add(1), true)));
                    rest = after;
                    continue;
                }
                Some(_) => {}
                None => missing.strong = true,
            }
        }
        if !missing.brace
            && let Some(r) = rest.strip_prefix("{{")
        {
            match r.split_once("}}") {
                Some((name, after)) if placeholder_name(name.trim()) => {
                    flush(&mut text, &mut out);
                    out.push(Inline::Placeholder(name.trim().to_owned()));
                    rest = after;
                    continue;
                }
                Some(_) => {}
                None => missing.brace = true,
            }
        }
        if let Some(r) = rest.strip_prefix("TODO(legal)") {
            flush(&mut text, &mut out);
            out.push(Inline::Pending);
            rest = r;
            continue;
        }
        if depth < 2
            && !missing.bracket
            && let Some(r) = rest.strip_prefix("[NOT BUILT")
        {
            match r.split_once(']') {
                Some((inner, after)) => {
                    flush(&mut text, &mut out);
                    let inner = inner.strip_prefix(':').unwrap_or(inner).trim();
                    out.push(Inline::NotBuilt(run(inner, 2, in_strong)));
                    rest = after;
                    continue;
                }
                None => missing.bracket = true,
            }
        }
        let mut chars = rest.chars();
        if let Some(c) = chars.next() {
            text.push(c);
        }
        rest = chars.as_str();
    }
    flush(&mut text, &mut out);
    out
}

/// Every placeholder name in `blocks`, in document order.
pub fn placeholders(blocks: &[Block]) -> Vec<&str> {
    let mut out = Vec::new();
    for_each_inline(blocks, &mut |i| {
        if let Inline::Placeholder(n) = i {
            out.push(n.as_str());
        }
    });
    out
}

/// The number of pending points in `blocks`: each `TODO(legal)` and each
/// `[NOT BUILT ...]`.
pub fn pending_points(blocks: &[Block]) -> usize {
    let mut n: usize = 0;
    for_each_inline(blocks, &mut |i| {
        if matches!(i, Inline::Pending | Inline::NotBuilt(_)) {
            n = n.saturating_add(1);
        }
    });
    n
}

/// Calls `f` on every inline of `blocks`, depth first.
fn for_each_inline<'a>(blocks: &'a [Block], f: &mut impl FnMut(&'a Inline)) {
    fn walk<'a>(runs: &'a [Inline], f: &mut impl FnMut(&'a Inline)) {
        for i in runs {
            f(i);
            match i {
                Inline::Strong(inner) | Inline::NotBuilt(inner) => walk(inner, f),
                _ => {}
            }
        }
    }
    for b in blocks {
        match b {
            Block::Heading(_, r) | Block::Paragraph(r) => walk(r, f),
            Block::List { items, .. } => items.iter().for_each(|r| walk(r, f)),
            Block::Table { head, rows } => {
                for row in head.iter().chain(rows.iter()) {
                    row.iter().for_each(|r| walk(r, f));
                }
            }
            Block::Rule => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Inline {
        Inline::Text(s.to_owned())
    }

    /// ADR-037: the subset's blocks parse as the drafts use them.
    #[test]
    fn adr037_blocks_of_the_subset() {
        let src = "## 1. Who\n\nA line\nand more.\n\n- **One.** first\n  continued\n- two\n\n| A | B |\n| --- | --- |\n| x | y |\n\n---\n";
        let blocks = parse(src).unwrap_or_default();
        assert_eq!(blocks.len(), 5, "{blocks:?}");
        assert_eq!(blocks.first(), Some(&Block::Heading(2, vec![t("1. Who")])));
        assert_eq!(
            blocks.get(1),
            Some(&Block::Paragraph(vec![t("A line and more.")]))
        );
        assert_eq!(
            blocks.get(2),
            Some(&Block::List {
                ordered: false,
                items: vec![
                    vec![Inline::Strong(vec![t("One.")]), t(" first continued")],
                    vec![t("two")],
                ],
            })
        );
        assert!(
            matches!(blocks.get(3), Some(Block::Table { head: Some(h), rows }) if h.len() == 2 && rows.len() == 1)
        );
        assert_eq!(blocks.get(4), Some(&Block::Rule));
    }

    /// ADR-037: placeholders, pending markers and not-built runs are
    /// recognised; an unclosed construct stays text.
    #[test]
    fn adr037_inline_markers() {
        let r = inlines(
            "To {{tenant.legal_name}}: TODO(legal): x. [NOT BUILT: y `z`] `a` {{ }} {{open",
        );
        assert_eq!(
            r,
            vec![
                t("To "),
                Inline::Placeholder("tenant.legal_name".to_owned()),
                t(": "),
                Inline::Pending,
                t(": x. "),
                Inline::NotBuilt(vec![t("y "), Inline::Code("z".to_owned())]),
                t(" "),
                Inline::Code("a".to_owned()),
                t(" {{ }} {{open"),
            ]
        );
        assert_eq!(inlines("**open"), vec![t("**open")]);
        assert_eq!(inlines("`open"), vec![t("`open")]);
        assert_eq!(inlines("[NOT BUILT open"), vec![t("[NOT BUILT open")]);
        let blocks = parse("TODO(legal) a [NOT BUILT: b]\n").unwrap_or_default();
        assert_eq!(pending_points(&blocks), 2);
    }

    /// ADR-037: a draft over the limit is refused, and a long run of
    /// unclosed openers parses quickly as text.
    #[test]
    fn adr037_limits() {
        assert_eq!(
            parse(&"a".repeat(MAX_SOURCE_BYTES + 1)),
            Err(MarkdownError::TooLong)
        );
        let src = "[NOT BUILT**{{`".repeat(10_000);
        let blocks = parse(&src).unwrap_or_default();
        assert_eq!(blocks.len(), 1);
    }
}
