//! Server-rendered HTML (M4 design section 1.1).
//!
//! The crate holds:
//!
//! - an escaping HTML writer with no raw-insertion API;
//! - the message catalogues for server-rendered text (R-NF-04);
//! - the `Label` and `ApprovedText` kinds (I-72 seam);
//! - a test sink that records every dynamic text node;
//! - the well-formedness checker that tests and fuzz targets use.
//!
//! Status: W0 stub. Lane W1d (L-HTML) owns this crate. Every operation
//! refuses with [`HtmlError::NotImplemented`].

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

/// Why an HTML operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HtmlError {
    /// The W0 stub of the named operation refuses.
    NotImplemented(&'static str),
}

impl std::fmt::Display for HtmlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HtmlError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for HtmlError {}

/// One parsed catalogue message.
///
/// W0 placeholder with no fields. Lane W1d writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageFormat {
    _w0: (),
}

/// A parsed `Accept-Language` header.
///
/// W0 placeholder with no fields. Lane W1d writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptLanguage {
    _w0: (),
}

/// Parses one catalogue message with its placeholders. Fuzzed
/// (`message_format_parse`).
pub fn parse_message_format(bytes: &[u8]) -> Result<MessageFormat, HtmlError> {
    let _ = bytes;
    Err(HtmlError::NotImplemented("fstp_html::parse_message_format"))
}

/// Parses an `Accept-Language` header value. Fuzzed
/// (`accept_language_parse`).
pub fn parse_accept_language(bytes: &[u8]) -> Result<AcceptLanguage, HtmlError> {
    let _ = bytes;
    Err(HtmlError::NotImplemented(
        "fstp_html::parse_accept_language",
    ))
}

/// Checks that `bytes` is a well-formed document of the writer's subset.
/// Fuzzed (`html_wellformed_check`).
pub fn check_wellformed(bytes: &[u8]) -> Result<(), HtmlError> {
    let _ = bytes;
    Err(HtmlError::NotImplemented("fstp_html::check_wellformed"))
}
