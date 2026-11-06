//! The text preview of a Guide over a draft (R-PG-01, I-51; M4 design
//! sections 2.2 J1 and 3.2).
//!
//! The creator's review page shows the Guide a draft would publish as
//! text blocks, never as markup. [`preview_text`] walks the template body
//! and resolves each placeholder through its one resolver, as [`crate::bind`]
//! does. A placeholder that does not resolve is never filled with a
//! made-up value: it shows as a marker that names its key. The marker
//! says whether the value comes at publication (the call record, the
//! Guide version, the platform and data protection texts) or is missing
//! from the draft. Interim, pending Daniel.

use crate::markdown::{Block, Inline};
use crate::resolve::{Ctx, Key, Source, Value};
use crate::{GuideInputs, Template};

/// The kind of one preview block, as the creator page shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PreviewKind {
    /// A heading.
    Heading,
    /// A paragraph.
    Paragraph,
    /// One list item or table row.
    Item,
}

impl PreviewKind {
    /// The wire token of the kind: `heading`, `paragraph` or `item`.
    pub fn token(self) -> &'static str {
        match self {
            PreviewKind::Heading => "heading",
            PreviewKind::Paragraph => "paragraph",
            PreviewKind::Item => "item",
        }
    }
}

/// One block of a text preview: plain text, never markup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewBlock {
    /// The kind.
    pub kind: PreviewKind,
    /// The text.
    pub text: String,
}

/// The marker of a placeholder with no value (module documentation).
fn marker(key: Key) -> String {
    let r = key.resolver();
    match r.source {
        Source::CallRecord | Source::Other => {
            format!("[{}: set when the call is published]", r.key)
        }
        Source::Policy | Source::Artefacts => format!("[{}: not set in the draft]", r.key),
    }
}

struct Walk<'a> {
    ctx: Ctx<'a>,
    out: Vec<PreviewBlock>,
}

impl Walk<'_> {
    fn value(&self, key: Key) -> Result<Value, String> {
        self.ctx.resolve(key).map_err(|_| marker(key))
    }

    fn inlines(&self, list: &[Inline], out: &mut String) {
        for n in list {
            match n {
                Inline::Text(t) | Inline::Code(t) => out.push_str(t),
                Inline::Strong(c) => self.inlines(c, out),
                Inline::Link { content, .. } => self.inlines(content, out),
                Inline::Slot(k) => match self.value(*k) {
                    Ok(v) => out.push_str(&v.plain()),
                    Err(m) => out.push_str(&m),
                },
            }
        }
    }

    fn line(&self, list: &[Inline]) -> String {
        let mut s = String::new();
        self.inlines(list, &mut s);
        s
    }

    fn push(&mut self, kind: PreviewKind, text: String) {
        if !text.trim().is_empty() {
            self.out.push(PreviewBlock { kind, text });
        }
    }

    fn block(&mut self, b: &Block) {
        match b {
            Block::Heading { content, .. } => {
                let t = self.line(content);
                self.push(PreviewKind::Heading, t);
            }
            Block::Paragraph(lines) => {
                let t = lines
                    .iter()
                    .map(|l| self.line(l))
                    .collect::<Vec<_>>()
                    .join(" ");
                self.push(PreviewKind::Paragraph, t);
            }
            Block::Rule => {}
            Block::Table { head, rows } => {
                for r in std::iter::once(head).chain(rows) {
                    let t = r
                        .iter()
                        .map(|c| self.line(c))
                        .collect::<Vec<_>>()
                        .join(" | ");
                    self.push(PreviewKind::Item, t);
                }
            }
            Block::Bullets(items) | Block::Numbered(items) => {
                for i in items {
                    let t = self.line(i);
                    self.push(PreviewKind::Item, t);
                }
            }
            Block::Slot(k) => match self.value(*k) {
                Ok(Value::Paragraphs(p)) => {
                    for s in p {
                        self.push(PreviewKind::Paragraph, s);
                    }
                }
                Ok(Value::List(items)) => {
                    for s in items {
                        self.push(PreviewKind::Item, s);
                    }
                }
                Ok(Value::Table { head, rows }) => {
                    for r in std::iter::once(head).chain(rows) {
                        self.push(PreviewKind::Item, r.join(" | "));
                    }
                }
                Ok(v) => self.push(PreviewKind::Paragraph, v.plain()),
                Err(m) => self.push(PreviewKind::Paragraph, m),
            },
        }
    }
}

/// The text preview of `template` over `inputs` (module documentation):
/// one block per heading and paragraph, and one per list item or table
/// row, in document order. The template header is not shown.
pub fn preview_text(template: &Template, inputs: &GuideInputs<'_>) -> Vec<PreviewBlock> {
    let mut w = Walk {
        ctx: Ctx::new(inputs),
        out: Vec::new(),
    };
    for b in template.body() {
        w.block(b);
    }
    w.out
}
