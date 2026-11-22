//! The deterministic injection scan of submission text (ADR-035, TH-01,
//! TH-60).
//!
//! - [`scan`] runs every detector of ADR-035 over one text and returns
//!   typed [`Detection`]s: a closed [`Reason`] and a byte span of the
//!   text. It never returns text, so nothing it yields can carry
//!   submission content into a log (R-NF-02).
//! - [`neutralise`] removes every character of the hidden classes. It is
//!   idempotent, and its result is always the input with those characters
//!   left out. The original stays stored as submitted; the neutralised
//!   view is what models and agents receive.
//! - Phrase detectors run on a folded view: hidden characters removed,
//!   `fstp_unorm::fold_nfkc` per character (ADR-029), Cyrillic and Greek
//!   look-alike letters mapped to Latin, and white space collapsed. Each
//!   folded byte remembers its span in the original, so every detection
//!   points back into the text as submitted.
//!
//! The scan is pure: no I/O, no clock. Its time is linear in the text
//! times the fixed pattern tables, over at most [`MAX_SCAN_BYTES`], and it
//! keeps at most [`MAX_DETECTIONS`]. A detection is a flag for a human,
//! never a verdict: nothing here refuses a submission (I-10).
//!
//! The detector list and the benign controls are interim readings,
//! pending Daniel (ADR-035, "Detectors").

mod hidden;
mod markup;
mod phrases;
mod view;

use core::fmt;

pub use hidden::is_removed;

/// The most bytes of one text the scan reads. The rest is flagged
/// [`Reason::Truncated`].
pub const MAX_SCAN_BYTES: usize = 1 << 20;

/// The most detections one scan keeps. [`Scan::omitted`] counts the rest.
pub const MAX_DETECTIONS: usize = 64;

/// Why a span was flagged (ADR-035, "Detectors").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reason {
    /// Zero-width and other invisible characters.
    ZeroWidth,
    /// Bidirectional controls.
    Bidi,
    /// Unicode tag characters, U+E0000 to U+E007F.
    Tag,
    /// Runs of variation selectors, or a supplementary selector out of
    /// place.
    VariationRun,
    /// Other invisible format characters.
    Format,
    /// Markup that hides text: comments, invisible styles, off-page
    /// positions, white or tiny text.
    HiddenMarkup,
    /// Chat role markers and template tokens.
    RoleMarker,
    /// Requests to ignore or replace earlier instructions.
    Override,
    /// Text addressed to an AI reader.
    Addressed,
    /// Requests to set a score, a band or the findings.
    ScoreRequest,
    /// Requests to call tools, and tool-call payloads.
    ToolCall,
    /// JSON-schema-like or finding-shaped payloads.
    SchemaPayload,
    /// Links that could carry data out.
    ExfilLink,
    /// Long base64 or hex runs.
    EncodedBlob,
    /// Words that mix scripts or use full-width or mathematical letters.
    Confusable,
    /// The text was longer than [`MAX_SCAN_BYTES`].
    Truncated,
}

impl Reason {
    /// Every reason, in declaration order.
    pub const ALL: [Reason; 16] = [
        Reason::ZeroWidth,
        Reason::Bidi,
        Reason::Tag,
        Reason::VariationRun,
        Reason::Format,
        Reason::HiddenMarkup,
        Reason::RoleMarker,
        Reason::Override,
        Reason::Addressed,
        Reason::ScoreRequest,
        Reason::ToolCall,
        Reason::SchemaPayload,
        Reason::ExfilLink,
        Reason::EncodedBlob,
        Reason::Confusable,
        Reason::Truncated,
    ];

    /// The reason code, as records and read models spell it.
    pub const fn code(self) -> &'static str {
        match self {
            Reason::ZeroWidth => "zero_width",
            Reason::Bidi => "bidi",
            Reason::Tag => "tag",
            Reason::VariationRun => "variation_run",
            Reason::Format => "format",
            Reason::HiddenMarkup => "hidden_markup",
            Reason::RoleMarker => "role_marker",
            Reason::Override => "override",
            Reason::Addressed => "addressed",
            Reason::ScoreRequest => "score_request",
            Reason::ToolCall => "tool_call",
            Reason::SchemaPayload => "schema_payload",
            Reason::ExfilLink => "exfil_link",
            Reason::EncodedBlob => "encoded_blob",
            Reason::Confusable => "confusable",
            Reason::Truncated => "truncated",
        }
    }

    /// The reason of `code`, or `None`.
    pub fn parse(code: &str) -> Option<Reason> {
        Reason::ALL.into_iter().find(|r| r.code() == code)
    }

    /// Whether the reason is a class of hidden characters, which
    /// [`neutralise`] removes.
    pub const fn is_hidden(self) -> bool {
        matches!(
            self,
            Reason::ZeroWidth | Reason::Bidi | Reason::Tag | Reason::VariationRun | Reason::Format
        )
    }

    /// What was found, in plain words, for a finding statement. Fixed
    /// platform text that never quotes the scanned text.
    pub const fn words(self) -> &'static str {
        match self {
            Reason::ZeroWidth => "invisible zero-width characters",
            Reason::Bidi => "characters that reverse the reading direction",
            Reason::Tag => "invisible tag characters that can hide text",
            Reason::VariationRun => "runs of invisible variation selectors",
            Reason::Format => "invisible formatting characters",
            Reason::HiddenMarkup => "markup that hides text from a human reader",
            Reason::RoleMarker => "chat role markers aimed at an AI system",
            Reason::Override => "an instruction to ignore or replace earlier instructions",
            Reason::Addressed => "text addressed to an AI reader",
            Reason::ScoreRequest => "a request to set a score or the findings",
            Reason::ToolCall => "a request to call a tool, or a tool call",
            Reason::SchemaPayload => "a structured payload shaped like assessment output",
            Reason::ExfilLink => "a link that could carry data out",
            Reason::EncodedBlob => "a long encoded block of data",
            Reason::Confusable => "words written with look-alike letters",
            Reason::Truncated => "more text than the scan reads",
        }
    }
}

/// One detection: a reason and a byte span of the scanned text, end
/// exclusive, on character boundaries.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Detection {
    /// The first byte of the span.
    pub start: usize,
    /// The byte just after the span.
    pub end: usize,
    /// The reason.
    pub reason: Reason,
}

impl fmt::Debug for Detection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}..{}", self.reason.code(), self.start, self.end)
    }
}

/// The result of one scan. Its `Debug` form names reasons and offsets
/// only (R-NF-02).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Scan {
    detections: Vec<Detection>,
    omitted: usize,
}

impl Scan {
    /// The kept detections, by start, then reason.
    pub fn detections(&self) -> &[Detection] {
        &self.detections
    }

    /// How many detections were left out over [`MAX_DETECTIONS`].
    pub fn omitted(&self) -> usize {
        self.omitted
    }

    /// Whether anything was detected.
    pub fn flagged(&self) -> bool {
        !self.detections.is_empty()
    }

    /// The distinct reasons, in declaration order.
    pub fn reasons(&self) -> Vec<Reason> {
        let mut r: Vec<Reason> = self.detections.iter().map(|d| d.reason).collect();
        r.sort_unstable();
        r.dedup();
        r
    }
}

/// The text with every character of the hidden classes removed: the view
/// models and agents receive (ADR-035). Idempotent; never adds content.
pub fn neutralise(text: &str) -> String {
    text.chars().filter(|c| !is_removed(*c)).collect()
}

/// The largest character boundary of `s` at or below `n`.
fn floor_boundary(s: &str, n: usize) -> usize {
    let mut i = n.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i = i.saturating_sub(1);
    }
    i
}

/// Runs every detector of ADR-035 over `text`.
pub fn scan(text: &str) -> Scan {
    let limit = floor_boundary(text, MAX_SCAN_BYTES);
    let head = text.get(..limit).unwrap_or("");
    let mut found: Vec<Detection> = Vec::new();
    hidden::detect(head, &mut found);
    markup::blobs(head, &mut found);
    markup::confusables(head, &mut found);
    let folded = view::View::folded(head);
    let compact = folded.compact();
    phrases::detect(&folded, &mut found);
    markup::detect(&folded, &compact, &mut found);
    if limit < text.len() {
        found.push(Detection {
            start: limit,
            end: text.len(),
            reason: Reason::Truncated,
        });
    }
    finish(found)
}

/// Sorts, merges overlapping or touching spans of one reason, and caps.
fn finish(mut found: Vec<Detection>) -> Scan {
    found.sort_unstable_by_key(|d| (d.reason, d.start, d.end));
    let mut merged: Vec<Detection> = Vec::with_capacity(found.len());
    for d in found {
        match merged.last_mut() {
            Some(m) if m.reason == d.reason && d.start <= m.end => {
                m.end = m.end.max(d.end);
            }
            _ => merged.push(d),
        }
    }
    merged.sort_unstable_by_key(|d| (d.start, d.reason, d.end));
    let omitted = merged.len().saturating_sub(MAX_DETECTIONS);
    merged.truncate(MAX_DETECTIONS);
    Scan {
        detections: merged,
        omitted,
    }
}

/// The span of `detection` in Unicode scalar values of `text`: the start
/// and end as character counts, for read models that mark spans (ADR-035
/// "Marks"). `None` when the span is not on character boundaries.
pub fn char_span(text: &str, start: usize, end: usize) -> Option<(usize, usize)> {
    let a = text.get(..start)?.chars().count();
    let b = a.checked_add(text.get(start..end)?.chars().count())?;
    Some((a, b))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-035: every reason code parses back to its reason.
    #[test]
    fn adr035_reason_codes_round_trip() {
        for r in Reason::ALL {
            assert_eq!(Reason::parse(r.code()), Some(r));
            assert!(!r.words().is_empty());
        }
        assert_eq!(Reason::parse("other"), None);
    }

    /// ADR-035: the char span counts characters, not bytes.
    #[test]
    fn adr035_char_span_counts_scalars() {
        assert_eq!(char_span("aé b", 1, 3), Some((1, 2)));
        assert_eq!(char_span("aé b", 2, 3), None);
    }
}
