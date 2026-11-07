//! Email messages for the dispatcher (M6 design section 5.3, lane L6-MAIL).
//!
//! - [`template`]: versioned default templates whose gaps come from the
//!   closed placeholder enum of [`placeholder`] (I-25, I-27).
//! - [`mime`]: an in-house RFC 5322 and MIME builder, deterministic and
//!   7-bit, and a strict parser for tests, the demo and T5 scans.
//! - [`encode`]: base64, quoted-printable and RFC 2047 encoded words.
//! - [`dkim`]: relaxed/relaxed canonicalisation in-house, signatures
//!   through aws-lc-rs by way of `fstp-crypto` (ADR-001). Signing is off
//!   unless [`MailConfig::dkim`] names a signer.
//!
//! [`compose`] ties them together. It is a pure function of its input, so
//! every attempt of one message gives the same bytes and the same
//! `Message-ID` (I-26).

pub mod address;
pub mod dkim;
pub mod encode;
pub mod mime;
pub mod placeholder;
pub mod template;

use std::fmt;

use fstp_domain::time::Timestamp;

pub use address::{DisplayName, Mailbox, Origin};
pub use dkim::{DkimKey, DkimPublicKey, DkimSigner, verify as dkim_verify};
pub use mime::{HeaderField, ParsedMessage, ParsedPart, parse};
pub use placeholder::{Bindings, LinkTarget, Moment, Slot, Value, ValueKind};
pub use template::{
    BANK_DETAILS_SENTENCE, Locale, Part, Rendered, TEMPLATES, Template, TemplateId,
};

/// Why a message could not be built, parsed or verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MailError {
    /// The template has this slot and the bindings do not fill it.
    MissingSlot(Slot),
    /// The bindings fill a slot the template does not have.
    UnexpectedSlot(Slot),
    /// The value for this slot has another kind.
    WrongKind(Slot),
    /// An instant outside the years 0000 to 9999, or an offset beyond 18 hours.
    DateOutOfRange,
    /// A PDF was given for a template that takes none.
    AttachmentNotAllowed,
    /// Not an acceptable mailbox.
    InvalidAddress,
    /// Not an acceptable display name.
    InvalidDisplayName,
    /// Not an acceptable origin.
    InvalidOrigin,
    /// Not an acceptable DKIM domain or selector.
    InvalidDkimName,
    /// `fstp-crypto` failed.
    Crypto,
    /// Input that does not parse, with the construct that failed.
    Malformed(&'static str),
    /// Input beyond a parser bound, with the bound.
    TooLarge(&'static str),
    /// No DKIM signature for the given domain and selector.
    DkimNoSignature,
    /// A DKIM signature uses an algorithm, version or canonicalisation
    /// other than the ones this crate writes.
    DkimUnsupported,
    /// The DKIM body hash does not match.
    DkimBodyHash,
    /// The DKIM signature does not verify.
    DkimSignature,
}

impl fmt::Display for MailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MailError::MissingSlot(s) => write!(f, "slot {} is not bound", s.code()),
            MailError::UnexpectedSlot(s) => write!(f, "slot {} is not in the template", s.code()),
            MailError::WrongKind(s) => write!(f, "slot {} has a value of another kind", s.code()),
            MailError::DateOutOfRange => f.write_str("date out of range"),
            MailError::AttachmentNotAllowed => f.write_str("template takes no attachment"),
            MailError::InvalidAddress => f.write_str("invalid mailbox"),
            MailError::InvalidDisplayName => f.write_str("invalid display name"),
            MailError::InvalidOrigin => f.write_str("invalid origin"),
            MailError::InvalidDkimName => f.write_str("invalid DKIM domain or selector"),
            MailError::Crypto => f.write_str("cryptographic operation failed"),
            MailError::Malformed(w) => write!(f, "malformed {w}"),
            MailError::TooLarge(w) => write!(f, "{w} over its bound"),
            MailError::DkimNoSignature => {
                f.write_str("no DKIM signature for this domain and selector")
            }
            MailError::DkimUnsupported => f.write_str("unsupported DKIM signature"),
            MailError::DkimBodyHash => f.write_str("DKIM body hash mismatch"),
            MailError::DkimSignature => f.write_str("DKIM signature does not verify"),
        }
    }
}

impl std::error::Error for MailError {}

/// The tenant's mail settings.
pub struct MailConfig {
    /// Where links point.
    pub origin: Origin,
    /// The sender. Its domain is the sending domain of `Message-ID`.
    pub from: Mailbox,
    /// The sender's display name, such as the fund's name.
    pub from_name: Option<DisplayName>,
    /// The DKIM signers. Empty means DKIM is off, which is the default
    /// until the flag is set (M6 design section 5.3).
    pub dkim: Vec<DkimSigner>,
}

/// One message to compose.
#[derive(Clone, Copy, Debug)]
pub struct Message<'a> {
    /// The template version.
    pub template: &'static Template,
    /// Its values.
    pub bindings: &'a Bindings,
    /// The recipient.
    pub to: &'a Mailbox,
    /// The idempotency key of M6 design section 3.1. `Message-ID` is built
    /// from it.
    pub idem: [u8; 32],
    /// The timeline event id, sent as `X-FSTP-Event`.
    pub event: [u8; 32],
    /// The `Date` header, the instant the event fired.
    pub date: Timestamp,
    /// The sealed notice PDF, for a template that allows one (P-48).
    pub pdf: Option<&'a [u8]>,
}

/// Renders, builds and, when the flag is on, signs one message.
///
/// # Errors
///
/// [`MailError::AttachmentNotAllowed`] for a PDF on a template without
/// one, any rendering error of [`Template::render`], and
/// [`MailError::Crypto`] when a signature fails.
pub fn compose(cfg: &MailConfig, msg: &Message<'_>) -> Result<Vec<u8>, MailError> {
    if msg.pdf.is_some() && !msg.template.allows_pdf() {
        return Err(MailError::AttachmentNotAllowed);
    }
    let rendered = msg.template.render(msg.bindings, &cfg.origin)?;
    let mut raw = mime::build(cfg, msg, &rendered)?;
    for signer in &cfg.dkim {
        raw = dkim::sign(&raw, signer)?;
    }
    Ok(raw)
}
