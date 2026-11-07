//! The Guide for Applicants as a tagged PDF (R-GA-02, M5 design section
//! 3.3).
//!
//! The PDF is rendered from the stored canonical document of
//! [`fstp_guide::RenderedGuide::canonical`], never from a new binding. So a
//! call published in M4 gets its PDF from the bytes its `GuidePublished`
//! digest covers, and re-rendering the same canonical document gives the
//! same bytes (I-53). The writer is `fstp-pdf`, which tags the structure.
//!
//! The canonical document is read line by line through `fstp-json`. Every
//! line must be one of the shapes the renderer writes; any other shape is
//! refused by line, never skipped. Fuzzed (`guide_pdf`).
//!
//! The mapping is interim, pending Daniel:
//!
//! - a level 1 heading is `/H1`, every deeper heading `/H2`;
//! - the lines of a paragraph join with a space;
//! - a list item is a paragraph led by a bullet or its number;
//! - a table is one paragraph per row, cells joined by ` | `;
//! - a link shows its text and then its address in brackets;
//! - a thematic break is dropped.
//!
//! The module lives here, on the shell side, and not in `fstp-guide`:
//! `fstp-pdf` hashes through `fstp-crypto` (aws-lc-rs), and `fstp-engine`
//! reaches `fstp-guide`, so the Guide crate stays free of both (M2
//! layering rule 1, M4 design section 1.3 rule A10).

use std::collections::BTreeMap;

use fstp_json::Value;
use fstp_pdf::{Block, BlockKind, Document, WriteError};

use fstp_guide::{GUIDE_LOCALE, MAX_GUIDE_BYTES, RenderedGuide};

/// The version line every canonical document starts with.
const VERSION_LINE: &str = "[\"fstp.guide\",1]";

/// Why a Guide PDF was not made. No variant holds Guide text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuidePdfError {
    /// The document is above [`MAX_GUIDE_BYTES`].
    TooLarge,
    /// The document is not UTF-8.
    NotUtf8,
    /// The first line is not the canonical version line.
    Version,
    /// Line `line` is not a shape the renderer writes.
    Line {
        /// The line, counted from 1.
        line: u32,
        /// The rule it breaks.
        rule: &'static str,
    },
    /// The PDF writer refused the content.
    Pdf(WriteError),
}

impl std::fmt::Display for GuidePdfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuidePdfError::TooLarge => write!(f, "the Guide is above {MAX_GUIDE_BYTES} bytes"),
            GuidePdfError::NotUtf8 => f.write_str("the Guide is not UTF-8"),
            GuidePdfError::Version => f.write_str("the Guide has no canonical version line"),
            GuidePdfError::Line { line, rule } => write!(f, "Guide line {line}: {rule}"),
            GuidePdfError::Pdf(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for GuidePdfError {}

/// The content of a stored Guide: its title, its blocks in reading order
/// and the plain text of each bound value by placeholder key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuideContent {
    title: String,
    blocks: Vec<Block>,
    values: BTreeMap<String, String>,
}

impl GuideContent {
    /// The title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// The blocks in reading order, the title first.
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    /// The plain text of the last value bound to `key`, if the Guide shows
    /// that placeholder.
    pub fn value(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    /// The level 2 headings, without their section numbers.
    pub fn sections(&self) -> Vec<&str> {
        self.blocks
            .iter()
            .filter(|b| b.kind == BlockKind::Heading2)
            .map(|b| unnumbered(&b.text))
            .collect()
    }

    /// The document for `fstp-pdf`, in the Guide's language.
    pub fn document(&self) -> Document {
        Document {
            title: self.title.clone(),
            lang: GUIDE_LOCALE.to_owned(),
            blocks: self.blocks.clone(),
            signature_fields: Vec::new(),
        }
    }
}

/// `title` without a leading section number `N. `.
fn unnumbered(title: &str) -> &str {
    let d = title.bytes().take_while(u8::is_ascii_digit).count();
    match title.get(d..).and_then(|r| r.strip_prefix(". ")) {
        Some(rest) if d > 0 => rest,
        _ => title,
    }
}

/// A refusal at the current line.
struct At(u32);

impl At {
    fn err(&self, rule: &'static str) -> GuidePdfError {
        GuidePdfError::Line { line: self.0, rule }
    }
}

/// The items of an array.
fn arr<'v>(v: &'v Value, at: &At, rule: &'static str) -> Result<&'v [Value], GuidePdfError> {
    v.as_array().map(|a| &a[..]).ok_or_else(|| at.err(rule))
}

/// A string.
fn string<'v>(v: Option<&'v Value>, at: &At, rule: &'static str) -> Result<&'v str, GuidePdfError> {
    v.and_then(Value::as_str).ok_or_else(|| at.err(rule))
}

/// The tag and the rest of a tagged array `["tag", ...]`.
fn tagged<'v>(v: &'v Value, at: &At) -> Result<(&'v str, &'v [Value]), GuidePdfError> {
    let items = arr(v, at, "a node is not an array")?;
    let (tag, rest) = items
        .split_first()
        .ok_or_else(|| at.err("a node is empty"))?;
    Ok((string(Some(tag), at, "a node tag is not a string")?, rest))
}

/// Text with every control character turned into a space.
fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// The reader of one canonical document.
struct Reader {
    blocks: Vec<Block>,
    values: BTreeMap<String, String>,
}

impl Reader {
    fn push(&mut self, kind: BlockKind, text: String) {
        let text = clean(&text);
        if !text.trim().is_empty() {
            self.blocks.push(Block { kind, text });
        }
    }

    /// The plain text of a list of inlines.
    fn inlines(&mut self, v: &Value, at: &At) -> Result<String, GuidePdfError> {
        let mut out = String::new();
        for n in arr(v, at, "inlines are not an array")? {
            let (tag, rest) = tagged(n, at)?;
            match tag {
                "t" | "code" => out.push_str(string(rest.first(), at, "text is not a string")?),
                "strong" => {
                    let inner = rest
                        .first()
                        .ok_or_else(|| at.err("strong has no content"))?;
                    out.push_str(&self.inlines(inner, at)?);
                }
                "a" => {
                    let url = string(rest.first(), at, "a link has no address")?;
                    let inner = rest.get(1).ok_or_else(|| at.err("a link has no content"))?;
                    let text = self.inlines(inner, at)?;
                    out.push_str(&text);
                    if text != url {
                        out.push_str(" (");
                        out.push_str(url);
                        out.push(')');
                    }
                }
                "v" => {
                    let (key, value) = self.slot(rest, at)?;
                    let text = match value {
                        Bound::Inline(t) => t,
                        Bound::Blocks(_) => return Err(at.err("a block value in an inline place")),
                    };
                    self.values.insert(key, text.clone());
                    out.push_str(&text);
                }
                _ => return Err(at.err("an unknown inline")),
            }
        }
        Ok(out)
    }

    /// The key and value of a bound value `"key", [kind, ...]`.
    fn slot(&mut self, rest: &[Value], at: &At) -> Result<(String, Bound), GuidePdfError> {
        let key = string(rest.first(), at, "a value has no key")?.to_owned();
        let v = rest.get(1).ok_or_else(|| at.err("a value is missing"))?;
        if rest.len() != 2 {
            return Err(at.err("a value has extra members"));
        }
        let (kind, args) = tagged(v, at)?;
        let strings = |v: Option<&Value>| -> Result<Vec<String>, GuidePdfError> {
            arr(
                v.unwrap_or(&Value::Null),
                at,
                "a value list is not an array",
            )?
            .iter()
            .map(|s| string(Some(s), at, "a value item is not a string").map(str::to_owned))
            .collect()
        };
        let bound = match kind {
            "text" | "link" => {
                Bound::Inline(string(args.first(), at, "a value is not a string")?.to_owned())
            }
            "paragraphs" => Bound::Blocks(
                strings(args.first())?
                    .into_iter()
                    .map(|t| (BlockKind::Paragraph, t))
                    .collect(),
            ),
            "list" => Bound::Blocks(
                strings(args.first())?
                    .into_iter()
                    .map(|t| (BlockKind::Paragraph, format!("\u{2022} {t}")))
                    .collect(),
            ),
            "table" => {
                let mut rows = vec![strings(args.first())?.join(" | ")];
                for r in arr(
                    args.get(1).unwrap_or(&Value::Null),
                    at,
                    "table rows are not an array",
                )? {
                    rows.push(strings(Some(r))?.join(" | "));
                }
                Bound::Blocks(
                    rows.into_iter()
                        .map(|t| (BlockKind::Paragraph, t))
                        .collect(),
                )
            }
            _ => return Err(at.err("an unknown value kind")),
        };
        Ok((key, bound))
    }

    /// One block line.
    fn block(&mut self, v: &Value, at: &At) -> Result<(), GuidePdfError> {
        let (tag, rest) = tagged(v, at)?;
        match tag {
            "h" => {
                let level = rest
                    .first()
                    .and_then(Value::as_u64)
                    .ok_or_else(|| at.err("a heading level is not a number"))?;
                let inner = rest
                    .get(1)
                    .ok_or_else(|| at.err("a heading has no content"))?;
                let text = self.inlines(inner, at)?;
                let kind = if level <= 1 {
                    BlockKind::Heading1
                } else {
                    BlockKind::Heading2
                };
                self.push(kind, text);
            }
            "p" => {
                let mut lines = Vec::new();
                for l in arr(
                    rest.first().unwrap_or(&Value::Null),
                    at,
                    "paragraph lines are not an array",
                )? {
                    lines.push(self.inlines(l, at)?);
                }
                self.push(BlockKind::Paragraph, lines.join(" "));
            }
            "hr" => {}
            "ul" | "ol" => {
                let items = arr(
                    rest.first().unwrap_or(&Value::Null),
                    at,
                    "list items are not an array",
                )?;
                for (i, item) in items.iter().enumerate() {
                    let text = self.inlines(item, at)?;
                    let lead = if tag == "ul" {
                        "\u{2022}".to_owned()
                    } else {
                        format!("{}.", i.saturating_add(1))
                    };
                    self.push(BlockKind::Paragraph, format!("{lead} {text}"));
                }
            }
            "table" => {
                let head = arr(
                    rest.first().unwrap_or(&Value::Null),
                    at,
                    "table head is not an array",
                )?;
                let mut cells = Vec::new();
                for c in head {
                    cells.push(self.inlines(c, at)?);
                }
                self.push(BlockKind::Paragraph, cells.join(" | "));
                for r in arr(
                    rest.get(1).unwrap_or(&Value::Null),
                    at,
                    "table rows are not an array",
                )? {
                    let mut cells = Vec::new();
                    for c in arr(r, at, "a table row is not an array")? {
                        cells.push(self.inlines(c, at)?);
                    }
                    self.push(BlockKind::Paragraph, cells.join(" | "));
                }
            }
            "v" => {
                let (key, value) = self.slot(rest, at)?;
                match value {
                    Bound::Blocks(blocks) => {
                        let plain: Vec<&str> = blocks.iter().map(|(_, t)| t.as_str()).collect();
                        self.values.insert(key, plain.join("\n"));
                        for (kind, text) in blocks {
                            self.push(kind, text);
                        }
                    }
                    Bound::Inline(_) => return Err(at.err("an inline value in a block place")),
                }
            }
            _ => return Err(at.err("an unknown block")),
        }
        Ok(())
    }
}

/// A bound value: inline text, or blocks.
enum Bound {
    Inline(String),
    Blocks(Vec<(BlockKind, String)>),
}

/// Reads the stored canonical document of a Guide (module documentation).
pub fn read_canonical(canonical: &[u8]) -> Result<GuideContent, GuidePdfError> {
    if canonical.len() > MAX_GUIDE_BYTES {
        return Err(GuidePdfError::TooLarge);
    }
    let text = std::str::from_utf8(canonical).map_err(|_| GuidePdfError::NotUtf8)?;
    let mut lines = text.split('\n');
    if lines.next() != Some(VERSION_LINE) {
        return Err(GuidePdfError::Version);
    }
    let mut reader = Reader {
        blocks: Vec::new(),
        values: BTreeMap::new(),
    };
    let mut title: Option<String> = None;
    let mut n: u32 = 1;
    for line in lines {
        n = n.saturating_add(1);
        let at = At(n);
        if line.is_empty() {
            continue;
        }
        let v = fstp_json::parse(line.as_bytes()).map_err(|_| at.err("a line is not JSON"))?;
        if title.is_none() {
            let (tag, rest) = tagged(&v, &at)?;
            if tag != "title" || rest.len() != 1 {
                return Err(at.err("the second line is not the title"));
            }
            let t = clean(string(rest.first(), &at, "the title is not a string")?);
            reader.push(BlockKind::Heading1, t.clone());
            title = Some(t);
            continue;
        }
        reader.block(&v, &at)?;
    }
    let title = title.ok_or(GuidePdfError::Line {
        line: 2,
        rule: "the Guide has no title",
    })?;
    Ok(GuideContent {
        title,
        blocks: reader.blocks,
        values: reader.values,
    })
}

/// The PDF of the stored canonical document `canonical`. Equal input gives
/// equal bytes (R-GA-02, I-53).
pub fn guide_pdf(canonical: &[u8]) -> Result<Vec<u8>, GuidePdfError> {
    let content = read_canonical(canonical)?;
    fstp_pdf::write(&content.document()).map_err(GuidePdfError::Pdf)
}

/// The PDF of a rendered Guide, from its canonical document
/// ([`guide_pdf`]).
///
/// # Errors
///
/// As [`guide_pdf`].
pub fn rendered_guide_pdf(guide: &RenderedGuide) -> Result<Vec<u8>, GuidePdfError> {
    guide_pdf(guide.canonical())
}
