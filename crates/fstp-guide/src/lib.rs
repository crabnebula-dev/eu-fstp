//! The Guide for Applicants (M4 design section 3.10).
//!
//! The crate parses the Guide template, its `{{...}}` placeholders and the
//! Markdown subset the template uses. It binds placeholders to the draft
//! or frozen policy, the call record and the programme artefacts, checks
//! section completeness, renders HTML through `fstp-html` and builds the
//! canonical document the publication digest is taken over.
//!
//! - [`parse_markdown`] parses the subset of module `markdown` and refuses
//!   every other construct, never passing it through as text.
//! - [`parse_template`] parses the same subset with placeholders. Each key
//!   has exactly one row in [`RESOLVERS`]. An unknown key is refused by
//!   name.
//! - [`bind`] resolves every placeholder from [`GuideInputs`]. A key that
//!   does not resolve is refused by name, never rendered empty (I-51).
//! - [`render`] writes a bound template as a [`RenderedGuide`]: the HTML,
//!   the canonical document and one [`BoundText`] per placeholder
//!   occurrence. Parameter-bound text is never editable (I-51).
//! - [`missing_sections`] names the required sections a template lacks
//!   (I-52), and [`preview`] gathers everything the creator reports.
//! - [`corrigendum`] words one numbered entry of a published call's
//!   effective-limits record, and [`page_with_corrigenda`] serves the
//!   stored Guide page with its corrigenda after it (I-51, I-53, Q37 C).
//! - The renderer follows the block that describes the pre-check with
//!   the fixed [`PRECHECK_NOTE`] (Q38 C).
//! - [`preview_text`] shows a draft's Guide as text blocks, with a marker
//!   naming each placeholder that has no value yet.
//!
//! [`ShippedProfiles`] is the only production profile source. It compiles
//! in `crates/fstp-guide/profiles/**`. The synthetic legal-wording profile
//! lives in `fstp-api-testkit` and reaches this crate only through a
//! testkit implementation of [`ProfileSource`] (layering rule A9b).
//! [`FunderProfile`] has no public constructor, so a profile comes only
//! from a source.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

mod corrigendum;
mod markdown;
pub mod pdf;
mod preview;
mod profile;
mod publication;
mod render;
mod resolve;
mod sections;

use std::collections::BTreeMap;

pub use corrigendum::{Corrigendum, corrigendum, page_with_corrigenda};
pub use pdf::{GuideContent, GuidePdfError, guide_pdf, read_canonical};
pub use preview::{PreviewBlock, PreviewKind, preview_text};
pub use profile::{
    FunderProfile, HORIZON_EUROPE, LEGAL_MARKER, LEGAL_SECTIONS, LegalSection, MAX_GUIDE_BYTES,
    ProfileError, ProfileFiles, ProfileSource, ShippedProfiles, WordingStatus,
};
pub use publication::{GuideSource, PublicationError, publication_guide};
pub use render::{BoundText, GUIDE_LOCALE, GUIDE_TITLE, PRECHECK_NOTE, RenderedGuide};
pub use resolve::{
    GuideCall, GuideInputs, NoStoredTexts, RESOLVERS, Resolver, Shape, Source, StoredTexts,
};
pub use sections::{REQUIRED_SECTIONS, RequiredSection};

use markdown::{Block, Mode};
use resolve::{Key, Value};

/// The longest placeholder key, in bytes.
pub const MAX_KEY_BYTES: usize = 64;

/// A placeholder key named in an error: 1 to [`MAX_KEY_BYTES`] bytes of
/// ASCII letters, digits, `.`, `_` and `-`.
///
/// It is held by value, so [`GuideError`] stays `Copy`. Only the parser
/// and the resolvers build one, from a key they have checked.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyName {
    len: u8,
    bytes: [u8; MAX_KEY_BYTES],
}

impl KeyName {
    /// The key `key`, or `None` when it is not a key.
    pub fn new(key: &str) -> Option<KeyName> {
        if key.is_empty() || key.len() > MAX_KEY_BYTES || !key.bytes().all(is_key_byte) {
            return None;
        }
        let mut bytes = [0_u8; MAX_KEY_BYTES];
        for (slot, b) in bytes.iter_mut().zip(key.bytes()) {
            *slot = b;
        }
        Some(KeyName {
            len: u8::try_from(key.len()).ok()?,
            bytes,
        })
    }

    /// The key.
    pub fn as_str(&self) -> &str {
        self.bytes
            .get(..usize::from(self.len))
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("")
    }
}

impl std::fmt::Debug for KeyName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}

impl std::fmt::Display for KeyName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether `b` may stand in a placeholder key.
pub(crate) fn is_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
}

/// The name of a known key. Every row of [`RESOLVERS`] holds a valid key,
/// which a test checks, so the empty fallback is never reached.
pub(crate) fn known_name(key: &str) -> KeyName {
    KeyName::new(key).unwrap_or(KeyName {
        len: 0,
        bytes: [0; MAX_KEY_BYTES],
    })
}

/// Why a Guide operation failed. No variant holds template or input text
/// other than a checked placeholder key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuideError {
    /// The input is above [`MAX_GUIDE_BYTES`].
    TooLarge,
    /// The input is not UTF-8.
    NotUtf8,
    /// A construct outside the Markdown subset, at this line.
    Markdown {
        /// The line, counted from 1.
        line: u32,
        /// The rule it breaks.
        rule: &'static str,
    },
    /// A malformed placeholder, at this line.
    Placeholder {
        /// The line, counted from 1.
        line: u32,
        /// The rule it breaks.
        rule: &'static str,
    },
    /// A placeholder whose key has no resolver (I-51).
    UnknownPlaceholder(KeyName),
    /// A known placeholder at a place its value cannot stand.
    Placement {
        /// The key.
        key: KeyName,
        /// The rule it breaks.
        rule: &'static str,
    },
    /// A placeholder with no value from its source (I-51).
    Unresolved {
        /// The key.
        key: KeyName,
        /// Why it has no value.
        reason: &'static str,
    },
    /// The HTML writer refused the page. This signals a defect here.
    Html(&'static str),
}

impl std::fmt::Display for GuideError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuideError::TooLarge => write!(f, "the Guide text is above {MAX_GUIDE_BYTES} bytes"),
            GuideError::NotUtf8 => f.write_str("the Guide text is not UTF-8"),
            GuideError::Markdown { line, rule } => {
                write!(f, "line {line}: outside the Markdown subset: {rule}")
            }
            GuideError::Placeholder { line, rule } => {
                write!(f, "line {line}: malformed placeholder: {rule}")
            }
            GuideError::UnknownPlaceholder(key) => {
                write!(f, "unknown placeholder {{{{{key}}}}}: no resolver holds it")
            }
            GuideError::Placement { key, rule } => write!(f, "placeholder {{{{{key}}}}}: {rule}"),
            GuideError::Unresolved { key, reason } => {
                write!(f, "placeholder {{{{{key}}}}} does not resolve: {reason}")
            }
            GuideError::Html(rule) => write!(f, "the HTML writer refused the Guide: {rule}"),
        }
    }
}

impl std::error::Error for GuideError {}

/// The text of `bytes`, within the size bound.
fn text_of(bytes: &[u8]) -> Result<&str, GuideError> {
    if bytes.len() > MAX_GUIDE_BYTES {
        return Err(GuideError::TooLarge);
    }
    std::str::from_utf8(bytes).map_err(|_| GuideError::NotUtf8)
}

/// A parsed document of the Markdown subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkdownDoc {
    blocks: Vec<Block>,
}

impl MarkdownDoc {
    /// The number of blocks.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether the document holds no block.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// The document in the canonical spelling of the subset. Parsing it
    /// gives an equal document (fuzzed, `guide_markdown_parse`).
    pub fn to_markdown(&self) -> String {
        markdown::encode(&self.blocks)
    }
}

/// A parsed Guide template, unbound or bound to its inputs.
///
/// The template header is every block up to and including the first
/// thematic break. It addresses template authors, as the shipped
/// template's preamble does, so it holds no placeholder and is never
/// rendered. A template with no thematic break has no header. Interim,
/// pending Daniel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    blocks: Vec<Block>,
    header: usize,
    values: BTreeMap<Key, Value>,
}

impl Template {
    /// The placeholder keys, one per occurrence, in document order.
    pub fn placeholders(&self) -> Vec<&'static str> {
        markdown::slots(&self.blocks)
            .into_iter()
            .map(|k| k.resolver().key)
            .collect()
    }

    /// Whether [`bind`] has given every placeholder its value.
    pub fn is_bound(&self) -> bool {
        markdown::slots(self.body())
            .iter()
            .all(|k| self.values.contains_key(k))
    }

    /// The template in the canonical spelling of the subset, with each
    /// placeholder as `{{key}}`. Bound values are not part of it. Parsing
    /// the text of an unbound template gives an equal template (fuzzed,
    /// `guide_template_parse`).
    pub fn to_markdown(&self) -> String {
        markdown::encode(&self.blocks)
    }

    /// The blocks after the header.
    pub(crate) fn body(&self) -> &[Block] {
        self.blocks.get(self.header..).unwrap_or(&[])
    }

    /// The value bound to `key`, if any.
    pub(crate) fn value(&self, key: Key) -> Option<&Value> {
        self.values.get(&key)
    }
}

/// Parses a Guide template: the Markdown subset with `{{key}}`
/// placeholders. Unknown placeholders are refused by key. Fuzzed
/// (`guide_template_parse`).
pub fn parse_template(bytes: &[u8]) -> Result<Template, GuideError> {
    let blocks = markdown::parse(text_of(bytes)?, Mode::Template)?;
    let header = blocks
        .iter()
        .position(|b| *b == Block::Rule)
        .map_or(0, |at| at.saturating_add(1));
    if let Some(key) = markdown::slots(blocks.get(..header).unwrap_or(&[])).first() {
        return Err(GuideError::Placement {
            key: key.name(),
            rule: "a placeholder stands in the template header, before the first thematic break",
        });
    }
    Ok(Template {
        blocks,
        header,
        values: BTreeMap::new(),
    })
}

/// Parses the Markdown subset. Constructs outside the subset are refused,
/// never passed through. Fuzzed (`guide_markdown_parse`).
pub fn parse_markdown(bytes: &[u8]) -> Result<MarkdownDoc, GuideError> {
    let blocks = markdown::parse(text_of(bytes)?, Mode::Markdown)?;
    Ok(MarkdownDoc { blocks })
}

/// Binds every placeholder of the template body to its value from
/// `inputs` (I-51). The first key in document order that does not resolve
/// is refused by name.
pub fn bind(template: &Template, inputs: &GuideInputs<'_>) -> Result<Template, GuideError> {
    let ctx = resolve::Ctx::new(inputs);
    let mut values = BTreeMap::new();
    for key in markdown::slots(template.body()) {
        if values.contains_key(&key) {
            continue;
        }
        let v = ctx.resolve(key).map_err(|reason| GuideError::Unresolved {
            key: key.name(),
            reason,
        })?;
        values.insert(key, v);
    }
    Ok(Template {
        blocks: template.blocks.clone(),
        header: template.header,
        values,
    })
}

/// Renders a bound template as HTML, with its canonical document and its
/// bound texts. An unbound placeholder is refused by key. Fuzzed
/// (`guide_render`).
pub fn render(template: &Template) -> Result<RenderedGuide, GuideError> {
    render::render(template)
}

/// The names of the required sections of
/// `SPEC/02-domain/guide-for-applicants.md` the template lacks, in the
/// order of that table (I-52). Only the body counts: a heading in the
/// template header is never rendered, so its section is missing.
pub fn missing_sections(template: &Template) -> Vec<&'static str> {
    sections::missing(template.body())
}

/// What the creator reports about a Guide over a draft (design section
/// 3.2: `GuideSectionMissing`, `GuideBindingUnresolved`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuidePreview {
    /// The required sections the template lacks (I-52).
    pub missing_sections: Vec<&'static str>,
    /// One [`GuideError::Unresolved`] per placeholder key that does not
    /// resolve, in document order (I-51).
    pub unresolved: Vec<GuideError>,
    /// The rendered Guide, or the first reason it could not be rendered.
    pub guide: Result<RenderedGuide, GuideError>,
}

/// Previews the Guide of `template` over `inputs`: every missing section,
/// every placeholder that does not resolve, and the rendered Guide when
/// every placeholder resolves.
pub fn preview(template: &Template, inputs: &GuideInputs<'_>) -> GuidePreview {
    let ctx = resolve::Ctx::new(inputs);
    let mut unresolved = Vec::new();
    let mut seen = Vec::new();
    for key in markdown::slots(template.body()) {
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        if let Err(reason) = ctx.resolve(key) {
            unresolved.push(GuideError::Unresolved {
                key: key.name(),
                reason,
            });
        }
    }
    let guide = match unresolved.first() {
        Some(e) => Err(*e),
        None => bind(template, inputs).and_then(|t| render(&t)),
    };
    GuidePreview {
        missing_sections: missing_sections(template),
        unresolved,
        guide,
    }
}
