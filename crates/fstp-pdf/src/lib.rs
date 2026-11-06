//! PDF for contracts and the Guide (M5 design sections 3.1 to 3.4).
//!
//! The crate holds:
//!
//! - [`writer`]: the deterministic writer of revision 0 (R-CT-01, R-GA-02),
//!   tagged, with one embedded font and empty signature fields;
//! - [`font`]: the bounded TrueType reader for that font (ADR-017);
//! - [`object`] and [`file`]: the strict object parser and file reader;
//! - [`increment`]: the strict verifier of the signature increment that
//!   the browser's LibPDF prepares (ADR-016, I-30), the server-side
//!   preparation for seals, and the embedding of the CMS value.
//!
//! The crate creates no signature. It hashes through `fstp-crypto`
//! (aws-lc-rs). Each parser has a fuzz target in `fuzz/`.
//!
//! ```
//! use fstp_pdf::{Block, BlockKind, Document, SignatureField};
//!
//! let doc = Document {
//!     title: "Grant agreement".into(),
//!     lang: "en".into(),
//!     blocks: vec![Block { kind: BlockKind::Paragraph, text: "Synthetic clause.".into() }],
//!     signature_fields: vec![SignatureField { name: "lead".into(), label: "Lead applicant".into() }],
//! };
//! let rev0 = fstp_pdf::write(&doc)?;
//! let inc = fstp_pdf::prepare_increment(&rev0, "lead", 8192)?;
//! let ok = fstp_pdf::verify_increment(&rev0, &inc, "lead")?;
//! assert_eq!(ok.byte_range[0], 0);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod file;
pub mod font;
pub mod increment;
pub mod object;
pub mod writer;

pub use file::PdfFile;
pub use font::{FontError, TrueType, embedded_font};
pub use increment::{
    IncrementError, VerifiedIncrement, embed_signature, prepare_increment, verify_increment,
};
pub use object::{Object, ParseError, ParseErrorKind};
pub use writer::{Block, BlockKind, Document, SignatureField, WriteError, write};
