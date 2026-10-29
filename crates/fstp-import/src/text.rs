//! The text normaliser and evidence spans (TH-16, TH-47, T-FUZZ-UPLOAD).
//!
//! M4 imports UTF-8 `text/plain` and `text/markdown` only (Q24). Markdown
//! is not rendered or parsed into structure. Both media types go through
//! the same normaliser, so Markdown syntax, HTML and injection phrases stay
//! as data. Evidence spans are byte offsets into the normalised text.
//!
//! The normaliser, in order:
//!
//! 1. refuses input above the size limit, before reading it;
//! 2. refuses input that is not valid UTF-8 (strict: no overlong forms, no
//!    surrogates, nothing above U+10FFFF);
//! 3. drops every leading U+FEFF (byte order mark);
//! 4. turns CR LF and a lone CR into LF;
//! 5. replaces every other control character (Unicode category Cc, which
//!    is C0, DEL and C1) except TAB and LF with U+FFFD, so no NUL reaches
//!    storage or a terminal;
//! 6. refuses a result that is empty or above the size limit.
//!
//! Interim readings, pending Daniel:
//!
//! - Format controls such as U+200B and U+202E are kept. They are data, and
//!   the import review page must show them visibly (TH-47). Stripping them
//!   would change evidence a reader cannot see.
//! - No Unicode normalisation form is applied. NFC needs tables this
//!   in-house crate does not hold.
//! - The standard size limit is 1 MiB of text. Q24 names no figure.
//!
//! The output is its own fixed point: normalising it again gives the same
//! text, so spans into it stay valid.

use fstp_findings::text::UntrustedText;

use crate::error::ImportError;

/// The media types M4 imports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImportMedia {
    /// UTF-8 `text/plain`.
    TextPlain,
    /// UTF-8 `text/markdown`, normalised as text and never rendered.
    TextMarkdown,
}

impl ImportMedia {
    /// Every media type M4 imports.
    pub const ALL: [ImportMedia; 2] = [ImportMedia::TextPlain, ImportMedia::TextMarkdown];

    /// The media type name, as stored and as the upload names it.
    pub const fn mime(self) -> &'static str {
        match self {
            ImportMedia::TextPlain => "text/plain",
            ImportMedia::TextMarkdown => "text/markdown",
        }
    }

    /// The media type named exactly `name`. Parameters such as `charset`
    /// are the upload decoder's concern, not this lookup's.
    pub fn from_mime(name: &str) -> Option<ImportMedia> {
        ImportMedia::ALL.into_iter().find(|m| m.mime() == name)
    }
}

/// The largest size limit any import may have. Spans are `u32` offsets,
/// and this bound keeps every offset far inside that range.
pub const MAX_IMPORT_BYTES: usize = 16 << 20;

/// Limits on one import (Q24).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportLimits {
    max_bytes: usize,
}

impl ImportLimits {
    /// The standard limit, 1 MiB. Interim, pending Daniel (Q24).
    pub const STANDARD_BYTES: usize = 1 << 20;

    /// The standard limits.
    pub fn standard() -> Result<ImportLimits, ImportError> {
        ImportLimits::new(ImportLimits::STANDARD_BYTES)
    }

    /// Limits of `max_bytes` for both the upload and its normalised text.
    /// Refused outside `1..=MAX_IMPORT_BYTES`.
    pub fn new(max_bytes: usize) -> Result<ImportLimits, ImportError> {
        if (1..=MAX_IMPORT_BYTES).contains(&max_bytes) {
            Ok(ImportLimits { max_bytes })
        } else {
            Err(ImportError::InvalidLimits)
        }
    }

    /// The limit in bytes, for the upload and for its normalised text.
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }
}

/// An evidence span: byte offsets into the normalised text, end exclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Span {
    /// The first byte.
    pub start: u32,
    /// One past the last byte.
    pub end: u32,
}

impl Span {
    /// Whether the span is non-empty and ends at or before `len` bytes.
    pub fn fits(self, len: u32) -> bool {
        self.start < self.end && self.end <= len
    }
}

/// The most evidence spans one proposal may carry.
pub const MAX_SPANS: usize = 8;

/// Checks the shape of a proposal's evidence: 1 to [`MAX_SPANS`] spans,
/// each non-empty, in strictly ascending order, each ending at or before
/// `len` bytes.
pub(crate) fn check_evidence(spans: &[Span], len: u32) -> Result<(), ImportError> {
    if spans.is_empty() || spans.len() > MAX_SPANS {
        return Err(ImportError::EvidenceCount);
    }
    if !spans.iter().all(|s| s.fits(len)) || !spans.windows(2).all(|w| matches!(w, [a, b] if a < b))
    {
        return Err(ImportError::BadSpan);
    }
    Ok(())
}

/// Normalised document text. It is untrusted data. It has no `Display` and
/// no `Deref<Target = str>`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ExtractedText(UntrustedText);

impl ExtractedText {
    /// The text as untrusted data. Pass it only through a data channel.
    pub fn untrusted(&self) -> &UntrustedText {
        &self.0
    }

    /// The length of the text in bytes. It is at most
    /// [`MAX_IMPORT_BYTES`], so it always fits.
    pub fn byte_len(&self) -> u32 {
        u32::try_from(self.0.as_data().len()).unwrap_or(u32::MAX)
    }

    /// Checks one span: non-empty, inside the text and on character
    /// boundaries at both ends.
    pub fn check_span(&self, span: Span) -> Result<(), ImportError> {
        let text = self.0.as_data();
        let (Ok(start), Ok(end)) = (usize::try_from(span.start), usize::try_from(span.end)) else {
            return Err(ImportError::BadSpan);
        };
        if span.fits(self.byte_len()) && text.is_char_boundary(start) && text.is_char_boundary(end)
        {
            Ok(())
        } else {
            Err(ImportError::BadSpan)
        }
    }

    /// The text of one span, as untrusted data, if the span is valid.
    pub fn evidence(&self, span: Span) -> Option<UntrustedText> {
        self.check_span(span).ok()?;
        let start = usize::try_from(span.start).ok()?;
        let end = usize::try_from(span.end).ok()?;
        self.0
            .as_data()
            .get(start..end)
            .map(|s| UntrustedText::new(s.to_owned()))
    }

    /// Checks a proposal's evidence against this text: the shape rules of
    /// [`MAX_SPANS`] and every span on character boundaries.
    pub fn check_evidence(&self, spans: &[Span]) -> Result<(), ImportError> {
        check_evidence(spans, self.byte_len())?;
        spans.iter().try_for_each(|s| self.check_span(*s))
    }
}

impl core::fmt::Debug for ExtractedText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExtractedText")
            .field("bytes", &self.0.as_data().len())
            .finish()
    }
}

/// Validates and normalises an uploaded document. Fuzzed
/// (`import_text_decode`, T-FUZZ-IMPORT, T-FUZZ-UPLOAD).
///
/// Both media types follow the module's rules. The text is never
/// rendered, trimmed or interpreted.
pub fn normalise(
    bytes: &[u8],
    media: ImportMedia,
    limits: ImportLimits,
) -> Result<ExtractedText, ImportError> {
    // Markdown is normalised as text, exactly as plain text is.
    let _ = media;
    let limit = limits.max_bytes();
    if bytes.len() > limit {
        return Err(ImportError::TooLarge { limit });
    }
    let text = core::str::from_utf8(bytes).map_err(|e| ImportError::InvalidUtf8 {
        offset: e.valid_up_to(),
    })?;
    let body = text.trim_start_matches('\u{FEFF}');
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            '\n' | '\t' => out.push(c),
            c if c.is_control() => out.push('\u{FFFD}'),
            c => out.push(c),
        }
    }
    if out.is_empty() {
        return Err(ImportError::EmptyDocument);
    }
    if out.len() > limit {
        return Err(ImportError::TooLarge { limit });
    }
    Ok(ExtractedText(UntrustedText::new(out)))
}
