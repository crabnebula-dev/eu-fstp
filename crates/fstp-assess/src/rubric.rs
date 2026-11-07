//! The pinned rubric (M7 design section 2, reading 1).
//!
//! Rubric v1 lists the closed required-element tags every proposal must
//! address. Its digest is an input of the `config_id` (I-11). Interim,
//! pending Daniel: the spec does not list a call's required elements.

use fstp_infer::ElementTag;

/// A pinned rubric: a version and its required-element tags, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rubric {
    version: &'static str,
    required: &'static [ElementTag],
}

/// Rubric v1: every tag of [`ElementTag::ALL`], in rubric order.
pub static RUBRIC_V1: Rubric = Rubric::new("v1", &ElementTag::ALL);

impl Rubric {
    /// A rubric of `version` with these required elements.
    pub const fn new(version: &'static str, required: &'static [ElementTag]) -> Rubric {
        Rubric { version, required }
    }

    /// The version.
    pub fn version(&self) -> &'static str {
        self.version
    }

    /// The required elements, in order.
    pub fn required(&self) -> &'static [ElementTag] {
        self.required
    }

    /// Whether `tag` is one of the rubric's elements.
    pub fn contains(&self, tag: ElementTag) -> bool {
        self.required.contains(&tag)
    }

    /// SHA-256 over the labelled version and tags.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = fstp_crypto::Sha256::new();
        h.update(b"fstp-assess/rubric\0");
        h.update(self.version.as_bytes());
        h.update(b"\0");
        for t in self.required {
            h.update(t.as_str().as_bytes());
            h.update(b"\0");
        }
        h.finish()
    }
}
