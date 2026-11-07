//! The instruction part of a request (M7 design section 3.3, TH-01).

use fstp_domain::id::CriterionId;

use crate::prompt::Prompt;

/// A rubric element tag of the pinned v1 rubric (M7 design section 2,
/// reading 1). Closed: a tag is never read from submission content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ElementTag {
    /// The problem the proposal addresses.
    Problem,
    /// The technical approach.
    Approach,
    /// Relevance to the Open Internet Stack.
    OisRelevance,
    /// The team's experience.
    TeamExperience,
    /// The licence of the deliverables.
    DeliverablesLicence,
    /// The milestones.
    Milestones,
    /// The justification of the budget.
    BudgetJustification,
}

impl ElementTag {
    /// Every tag, in rubric order.
    pub const ALL: [ElementTag; 7] = [
        ElementTag::Problem,
        ElementTag::Approach,
        ElementTag::OisRelevance,
        ElementTag::TeamExperience,
        ElementTag::DeliverablesLicence,
        ElementTag::Milestones,
        ElementTag::BudgetJustification,
    ];

    /// The tag as the rubric and the output schema spell it.
    pub const fn as_str(self) -> &'static str {
        match self {
            ElementTag::Problem => "problem",
            ElementTag::Approach => "approach",
            ElementTag::OisRelevance => "ois_relevance",
            ElementTag::TeamExperience => "team_experience",
            ElementTag::DeliverablesLicence => "deliverables_licence",
            ElementTag::Milestones => "milestones",
            ElementTag::BudgetJustification => "budget_justification",
        }
    }

    /// The tag with this spelling.
    pub fn parse(s: &str) -> Option<ElementTag> {
        ElementTag::ALL.into_iter().find(|t| t.as_str() == s)
    }
}

/// The instruction of one request: a pinned prompt and closed parameters.
///
/// There is no constructor that takes a `String` or an
/// [`UntrustedText`](fstp_findings::UntrustedText). The criterion is an
/// id of the frozen P-01, rendered as hex, and element tags come from the
/// closed rubric.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    prompt: Prompt,
    criterion: Option<CriterionId>,
    elements: Vec<ElementTag>,
}

impl Instruction {
    /// The instruction of `prompt` with no parameters.
    pub fn new(prompt: Prompt) -> Instruction {
        Instruction {
            prompt,
            criterion: None,
            elements: Vec::new(),
        }
    }

    /// Names one P-01 criterion.
    #[must_use]
    pub fn criterion(mut self, c: CriterionId) -> Instruction {
        self.criterion = Some(c);
        self
    }

    /// Names rubric elements, in the given order.
    #[must_use]
    pub fn elements(mut self, tags: &[ElementTag]) -> Instruction {
        self.elements = tags.to_vec();
        self
    }

    /// The prompt.
    pub fn prompt(&self) -> Prompt {
        self.prompt
    }

    /// The criterion, if one is named.
    pub fn criterion_id(&self) -> Option<CriterionId> {
        self.criterion
    }

    /// The element tags.
    pub fn element_tags(&self) -> &[ElementTag] {
        &self.elements
    }

    /// The instruction text: the prompt file, then the parameter block.
    pub fn rendered(&self) -> String {
        let mut s = String::from(self.prompt.text());
        s.push_str("\nParameters:\nprompt: ");
        s.push_str(self.prompt.name());
        s.push('\n');
        if let Some(c) = self.criterion {
            s.push_str(&criterion_label(c));
            s.push('\n');
        }
        for e in &self.elements {
            s.push_str("element: ");
            s.push_str(e.as_str());
            s.push('\n');
        }
        s
    }
}

/// `criterion: c-<32 hex digits>`.
fn criterion_label(c: CriterionId) -> String {
    format!("criterion: {}", criterion_name(c))
}

/// `c-<32 hex digits>`, the criterion as the output schema spells it.
pub(crate) fn criterion_name(c: CriterionId) -> String {
    format!("c-{:032x}", c.raw())
}
