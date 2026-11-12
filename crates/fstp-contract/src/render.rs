//! The contract PDF, revision 0 (R-CT-01, M5 design section 3.1 step 1).
//!
//! The terms come from the template and the agreed plan version. This
//! module only lays them out through `fstp-pdf`, which renders the same
//! terms to the same bytes. The platform supplies no clause wording:
//! `TODO(legal)`: the clause texts come from the signed grant agreement
//! and legal review (`contracts.md`, I-49).

use fstp_pdf::{Block, BlockKind, Document, SignatureField, WriteError};

use crate::digest::Digest;

/// One block of the terms.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TermsBlock {
    /// A section heading.
    Heading(String),
    /// A clause.
    Clause(String),
}

/// The terms of one contract version, ready to render.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ContractTerms {
    /// The document title.
    pub title: String,
    /// The blocks, in order.
    pub blocks: Vec<TermsBlock>,
    /// One signature field per party: field name and visible label.
    pub parties: Vec<(String, String)>,
}

/// The values the sub-grant agreement layout shows, each already
/// formatted. The contract PDF passes a grant's values. The creator
/// preview passes visible markers for the values a draft cannot know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgreementValues<'a> {
    /// The proposal the agreement is for.
    pub proposal: &'a str,
    /// The currency code of the granted amount.
    pub currency: &'a str,
    /// The granted amount.
    pub amount: &'a str,
    /// The agreed plan version.
    pub plan: &'a str,
}

/// The clause that stands in for every clause text until legal review.
/// `TODO(legal)`: the clause texts come from the signed grant agreement
/// and legal review (`contracts.md`, I-49).
pub const CLAUSES_PENDING: &str = "Clause texts pending legal review.";

/// The heading of the sub-grant agreement for `proposal`.
#[must_use]
pub fn agreement_heading(proposal: &str) -> String {
    format!("Sub-grant agreement for proposal {proposal}")
}

/// The blocks of the sub-grant agreement: one layout for the contract
/// PDF and the creator's contract preview (R-CT-01, R-PG-01).
#[must_use]
pub fn agreement_blocks(v: &AgreementValues<'_>) -> Vec<TermsBlock> {
    vec![
        TermsBlock::Heading(agreement_heading(v.proposal)),
        TermsBlock::Clause(format!("Granted amount: {} {}.", v.currency, v.amount)),
        TermsBlock::Clause(format!("Agreed plan version: {}.", v.plan)),
        TermsBlock::Clause(CLAUSES_PENDING.to_owned()),
    ]
}

/// Why rendering failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenderError(pub WriteError);

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "contract rendering failed: {:?}", self.0)
    }
}

impl std::error::Error for RenderError {}

impl ContractTerms {
    /// The `fstp-pdf` document of these terms.
    #[must_use]
    pub fn document(&self) -> Document {
        Document {
            title: self.title.clone(),
            lang: "en".into(),
            blocks: self
                .blocks
                .iter()
                .map(|b| match b {
                    TermsBlock::Heading(t) => Block {
                        kind: BlockKind::Heading1,
                        text: t.clone(),
                    },
                    TermsBlock::Clause(t) => Block {
                        kind: BlockKind::Paragraph,
                        text: t.clone(),
                    },
                })
                .collect(),
            signature_fields: self
                .parties
                .iter()
                .map(|(name, label)| SignatureField {
                    name: name.clone(),
                    label: label.clone(),
                })
                .collect(),
        }
    }
}

/// Renders revision 0 of `terms`.
///
/// # Errors
///
/// A [`RenderError`] when `fstp-pdf` refuses the document.
pub fn render(terms: &ContractTerms) -> Result<Vec<u8>, RenderError> {
    fstp_pdf::write(&terms.document()).map_err(RenderError)
}

/// Renders revision 0 and returns it with its digest, the value
/// `ContractSent` records.
///
/// # Errors
///
/// A [`RenderError`] when `fstp-pdf` refuses the document.
pub fn render_with_digest(terms: &ContractTerms) -> Result<(Vec<u8>, Digest), RenderError> {
    let bytes = render(terms)?;
    let d = crate::digest::sha256(&bytes);
    Ok((bytes, d))
}
