//! Untrusted text: a finding statement held as data (TH-01).
//!
//! A statement comes from a model that read submission content. It may hold
//! instructions aimed at the assessor, JSON fragments or any Unicode. The
//! type keeps the bytes unchanged and offers no implicit string view, so it
//! cannot be formatted or pasted into an instruction by accident
//! (`SPEC/04-llm-assessment/assessment.md`, design section 2.13).

use core::fmt;

/// Text that is data and never an instruction.
///
/// There is no `Display`, `Deref`, `AsRef<str>`, `Borrow<str>` or
/// `Into<String>`. The only reader is [`UntrustedText::as_data`], whose
/// name marks the data channel at every call site. `Debug` shows the
/// length only, so a log line never carries the content.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct UntrustedText(String);

impl UntrustedText {
    /// Wraps `text` unchanged. Nothing is trimmed, normalised or escaped.
    pub fn new(text: String) -> UntrustedText {
        UntrustedText(text)
    }

    /// The text as data, byte for byte as it was given.
    ///
    /// Pass it only through a data channel. Never concatenate it into an
    /// instruction for a model.
    pub fn as_data(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for UntrustedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UntrustedText")
            .field("bytes", &self.0.len())
            .finish()
    }
}
