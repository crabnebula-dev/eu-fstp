//! Stage 1: text extraction (M7 design section 3.2).
//!
//! Records and removes zero-width, bidi-control and tag characters with
//! their spans in the original text. The marks feed the deterministic
//! integrity scanner of stage 7 (TH-01). Fuzz target
//! `extract_unicode_marks`.
//!
//! Interim: no Unicode normalisation form is applied. NFC needs tables
//! that no allowlisted crate provides, as for `fstp-import`.

use crate::span::SpanMap;

/// The class of a removed character.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MarkKind {
    /// A zero-width character, such as U+200B or U+FEFF.
    ZeroWidth,
    /// A bidi control, such as U+202E.
    Bidi,
    /// A tag character, U+E0000 to U+E007F.
    Tag,
}

/// One removed character: its class and its span in the original text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mark {
    /// The class.
    pub kind: MarkKind,
    /// The first byte offset in the original text.
    pub start: usize,
    /// The byte offset just after it.
    pub end: usize,
}

/// The class of `c`, when stage 1 removes it.
pub fn mark_kind(c: char) -> Option<MarkKind> {
    match c {
        '\u{200b}'..='\u{200d}' | '\u{2060}'..='\u{2064}' | '\u{feff}' | '\u{180e}' => {
            Some(MarkKind::ZeroWidth)
        }
        '\u{200e}'
        | '\u{200f}'
        | '\u{061c}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2066}'..='\u{2069}' => Some(MarkKind::Bidi),
        '\u{e0000}'..='\u{e007f}' => Some(MarkKind::Tag),
        _ => None,
    }
}

/// Whether stage 1 removes `c`.
pub fn is_hidden(c: char) -> bool {
    mark_kind(c).is_some()
}

/// One extracted text: cleaned, with its marks and its map back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extracted {
    text: String,
    marks: Vec<Mark>,
    map: SpanMap,
}

impl Extracted {
    /// The cleaned text. Still untrusted data.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The removed characters, in order.
    pub fn marks(&self) -> &[Mark] {
        &self.marks
    }

    /// The map from cleaned offsets to original offsets.
    pub fn map(&self) -> &SpanMap {
        &self.map
    }
}

/// Removes and records every hidden character of `s`.
pub fn extract_text(s: &str) -> Extracted {
    let mut text = String::with_capacity(s.len());
    let mut marks = Vec::new();
    let mut map = SpanMap::new();
    let mut run = 0_usize;
    for (i, c) in s.char_indices() {
        let len = c.len_utf8();
        if let Some(kind) = mark_kind(c) {
            map.push_copy(run);
            run = 0;
            map.push_replace(len, 0);
            marks.push(Mark {
                kind,
                start: i,
                end: i.saturating_add(len),
            });
        } else {
            text.push(c);
            run = run.saturating_add(len);
        }
    }
    map.push_copy(run);
    Extracted { text, marks, map }
}
