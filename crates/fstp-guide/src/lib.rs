//! The Guide for Applicants (M4 design section 3.10).
//!
//! The crate parses the Guide template, its `{{...}}` placeholders and the
//! Markdown subset the template uses. It binds placeholders to the draft
//! or frozen policy, checks section completeness and legal-wording status,
//! renders HTML and computes the content digest.
//!
//! [`ShippedProfiles`] is the only production profile source. It compiles
//! in `crates/fstp-guide/profiles/**`. The synthetic legal-wording profile
//! lives in `fstp-api-testkit` and reaches this crate only through a
//! testkit implementation of [`ProfileSource`] (layering rule A9b).
//! [`FunderProfile`] has no public constructor, so a profile comes only
//! from a source.
//!
//! Status: the profiles and their sources are built (module `profile`,
//! lane m4eng). The template parser, the Markdown parser and the renderer
//! are W0 stubs of lane W2c (L-GUIDE-PUBLIC). Each refuses with
//! [`GuideError::NotImplemented`].

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

mod profile;

pub use profile::{
    FunderProfile, HORIZON_EUROPE, LEGAL_MARKER, LEGAL_SECTIONS, LegalSection, MAX_GUIDE_BYTES,
    ProfileError, ProfileFiles, ProfileSource, ShippedProfiles, WordingStatus,
};

/// Why a Guide operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuideError {
    /// The W0 stub of the named operation refuses.
    NotImplemented(&'static str),
}

impl std::fmt::Display for GuideError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuideError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for GuideError {}

/// A parsed Guide template.
///
/// W0 placeholder with no fields. Lane W2c writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    _w0: (),
}

/// A parsed document of the Markdown subset.
///
/// W0 placeholder with no fields. Lane W2c writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkdownDoc {
    _w0: (),
}

/// A rendered Guide document.
///
/// W0 placeholder with no fields. Lane W2c writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedGuide {
    _w0: (),
}

/// Parses a Guide template. Unknown placeholders are rejected. Fuzzed
/// (`guide_template_parse`).
pub fn parse_template(bytes: &[u8]) -> Result<Template, GuideError> {
    let _ = bytes;
    Err(GuideError::NotImplemented("fstp_guide::parse_template"))
}

/// Parses the Markdown subset. Constructs outside the subset are refused,
/// never passed through. Fuzzed (`guide_markdown_parse`).
pub fn parse_markdown(bytes: &[u8]) -> Result<MarkdownDoc, GuideError> {
    let _ = bytes;
    Err(GuideError::NotImplemented("fstp_guide::parse_markdown"))
}

/// Renders a template to HTML. Fuzzed (`guide_render`).
pub fn render(template: &Template) -> Result<RenderedGuide, GuideError> {
    let _ = template;
    Err(GuideError::NotImplemented("fstp_guide::render"))
}
