//! The one error type of the crate.

use std::fmt;

/// Why an HTML operation refused.
///
/// No variant carries a dynamic value the caller passed, so an error
/// message never copies tenant or applicant text into a log (R-NF-02). A
/// locale or message id appears only when it passed its own check, and a
/// message id only when the catalogue knows it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HtmlError {
    /// The bytes are not a document of the writer's subset.
    NotWellFormed {
        /// The byte offset where the checker stopped.
        at: usize,
        /// The rule the document breaks.
        rule: &'static str,
    },
    /// A catalogue message is outside the message grammar.
    MessageSyntax {
        /// The byte offset of the fault.
        at: usize,
        /// The rule the message breaks.
        rule: &'static str,
    },
    /// An `Accept-Language` value is outside the grammar or its bounds.
    AcceptLanguage {
        /// The rule the header breaks.
        rule: &'static str,
    },
    /// A URL is not a same-origin path or an `https:` URL.
    UnsafeUrl,
    /// A catalogue set or an override breaks a catalogue rule.
    Catalogue {
        /// The rule broken.
        rule: &'static str,
        /// The locale and message id concerned, when there is one.
        entry: String,
    },
    /// A message reference cannot be resolved with its arguments.
    Message {
        /// Why resolution refused.
        rule: &'static str,
        /// The message id when the catalogue knows it, or empty.
        id: String,
    },
    /// The locale has no catalogue, or is not a language tag.
    UnknownLocale,
    /// A page breaks a rule of the writer's subset.
    Page {
        /// The element concerned.
        element: &'static str,
        /// The rule broken.
        rule: &'static str,
    },
    /// An attribute is not allowed where the page puts it.
    Attribute {
        /// The element concerned.
        element: &'static str,
        /// The attribute concerned.
        attribute: &'static str,
        /// The rule broken.
        rule: &'static str,
    },
}

impl fmt::Display for HtmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HtmlError::NotWellFormed { at, rule } => {
                write!(f, "not a document of the subset at byte {at}: {rule}")
            }
            HtmlError::MessageSyntax { at, rule } => {
                write!(f, "catalogue message refused at byte {at}: {rule}")
            }
            HtmlError::AcceptLanguage { rule } => write!(f, "Accept-Language refused: {rule}"),
            HtmlError::UnsafeUrl => {
                f.write_str("URL refused: only same-origin paths and https URLs are allowed")
            }
            HtmlError::Catalogue { rule, entry } if entry.is_empty() => {
                write!(f, "catalogue refused: {rule}")
            }
            HtmlError::Catalogue { rule, entry } => {
                write!(f, "catalogue refused at {entry}: {rule}")
            }
            HtmlError::Message { rule, id } if id.is_empty() => {
                write!(f, "message refused: {rule}")
            }
            HtmlError::Message { rule, id } => write!(f, "message {id} refused: {rule}"),
            HtmlError::UnknownLocale => f.write_str("locale refused: no catalogue for it"),
            HtmlError::Page { element, rule } => write!(f, "page refused at <{element}>: {rule}"),
            HtmlError::Attribute {
                element,
                attribute,
                rule,
            } => write!(f, "page refused at <{element} {attribute}>: {rule}"),
        }
    }
}

impl std::error::Error for HtmlError {}
