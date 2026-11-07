//! The data part of a request (M7 design section 3.3, TH-01).

use fstp_findings::UntrustedText;

/// What a data part holds. Closed, so a label is never submission text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DataLabel {
    /// The proposal title.
    Title,
    /// The proposal summary.
    Summary,
    /// The proposal narrative.
    Narrative,
    /// The plan: tasks, rates and milestones, as text.
    Plan,
    /// One claim, for verification.
    Claim,
    /// A retrieved source under the applicant's control.
    SourceApplicant,
    /// A retrieved independent source.
    SourceIndependent,
}

impl DataLabel {
    /// Every label.
    pub const ALL: [DataLabel; 7] = [
        DataLabel::Title,
        DataLabel::Summary,
        DataLabel::Narrative,
        DataLabel::Plan,
        DataLabel::Claim,
        DataLabel::SourceApplicant,
        DataLabel::SourceIndependent,
    ];

    /// The label as the data message spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            DataLabel::Title => "title",
            DataLabel::Summary => "summary",
            DataLabel::Narrative => "narrative",
            DataLabel::Plan => "plan",
            DataLabel::Claim => "claim",
            DataLabel::SourceApplicant => "source_applicant",
            DataLabel::SourceIndependent => "source_independent",
        }
    }
}

/// One part of the data message: untrusted text under a closed label.
/// It is the only request type that accepts [`UntrustedText`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataPart {
    label: DataLabel,
    text: UntrustedText,
}

impl DataPart {
    /// A part holding `text` under `label`.
    pub fn new(label: DataLabel, text: UntrustedText) -> DataPart {
        DataPart { label, text }
    }

    /// The label.
    pub fn label(&self) -> DataLabel {
        self.label
    }

    /// The text, as data.
    pub fn text(&self) -> &UntrustedText {
        &self.text
    }
}
