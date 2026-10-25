//! The finding as plain data (design section 2.13).
//!
//! The fields follow the finding schema outline of
//! `SPEC/04-llm-assessment/assessment.md`. A finding supports human
//! reviewers and never decides (I-10). Its `config` names the pinned
//! model, prompt and rubric that produced it (I-11, R-LA-05).

use fstp_domain::id::{CallId, CriterionId, LlmConfigId, ProposalId, TextRef};

use crate::text::UntrustedText;

macro_rules! id {
    ($($(#[$doc:meta])* $n:ident),* $(,)?) => { $(
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $n(u128);

        impl $n {
            /// The id with raw value `r`, as drawn by the shell.
            pub const fn from_raw(r: u128) -> Self {
                Self(r)
            }

            /// The raw value.
            pub const fn raw(self) -> u128 {
                self.0
            }
        }
    )* };
}

id!(
    /// A finding. The shell draws it, and the store never reuses one.
    FindingId,
    /// A retained assessment trace (`trace_id` in the schema outline).
    TraceRef,
);

/// The kind of a finding (`type` in the schema outline).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingKind {
    /// Completeness against the call's required elements.
    Completeness,
    /// Quality per criterion of P-01, against the pinned rubric.
    Quality,
    /// Accuracy of representation, from claim verification.
    Accuracy,
    /// Suspected instructions aimed at the assessor. Reviewers see them.
    Integrity,
}

/// The severity of a finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// For information.
    Info,
    /// A minor observation.
    Minor,
    /// A major observation.
    Major,
}

/// The model-reported confidence, in permille from 0 to 1000.
///
/// The crate holds no floats, so the value is an integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Confidence(u16);

impl Confidence {
    /// The largest confidence, 1000 permille.
    pub const FULL: Confidence = Confidence(1000);

    /// The confidence of `permille`, or `None` above 1000.
    pub const fn from_permille(permille: u16) -> Option<Confidence> {
        if permille <= Confidence::FULL.0 {
            Some(Confidence(permille))
        } else {
            None
        }
    }

    /// The confidence in permille.
    pub const fn permille(self) -> u16 {
        self.0
    }
}

/// A pointer into a submission span or a retrieved source (R-LA-02).
///
/// Evidence names text only by reference. The text itself stays outside
/// the finding (design section 5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceRef {
    /// The span from `start` to `end` of a submission text, end exclusive.
    /// A span with `start` after `end` is malformed. The store and the
    /// decoder refuse it.
    ///
    /// An empty span, with `start` equal to `end`, is a valid point
    /// pointer. It names a place in the text and covers no text. A
    /// completeness finding can use one to mark where a required element
    /// is missing. It counts as an evidence pointer under R-LA-02.
    Submission {
        /// The submission text.
        text: TextRef,
        /// The first offset of the span.
        start: u32,
        /// The offset just after the span.
        end: u32,
    },
    /// A source retrieved through the retrieval proxy.
    Retrieved {
        /// The retrieved source.
        source: TextRef,
    },
}

impl EvidenceRef {
    /// Whether the pointer is well formed: a submission span never ends
    /// before it starts. An empty span is a well-formed point pointer.
    pub const fn is_well_formed(&self) -> bool {
        match *self {
            EvidenceRef::Submission { start, end, .. } => start <= end,
            EvidenceRef::Retrieved { .. } => true,
        }
    }
}

/// One finding of the assessor (design section 2.13).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Finding {
    /// The finding.
    pub id: FindingId,
    /// The call that produced the finding. The finding stays with it (Q15).
    pub call: CallId,
    /// The assessed proposal.
    pub proposal: ProposalId,
    /// The configuration that produced it: model, prompt and rubric (I-11).
    pub config: LlmConfigId,
    /// The kind (`type` in the schema outline).
    pub kind: FindingKind,
    /// The P-01 criterion, where one applies.
    pub criterion: Option<CriterionId>,
    /// The severity.
    pub severity: Severity,
    /// The model-reported confidence.
    pub confidence: Confidence,
    /// The plain-language observation, held as untrusted data (TH-01).
    pub statement: UntrustedText,
    /// Pointers into submission spans or retrieved sources. A finding
    /// carries at least one (R-LA-02).
    pub evidence: Vec<EvidenceRef>,
    /// The retained trace.
    pub trace: TraceRef,
}

impl Finding {
    /// Whether the finding carries at least one evidence pointer and every
    /// pointer is well formed (R-LA-02).
    pub fn is_well_formed(&self) -> bool {
        !self.evidence.is_empty() && self.evidence.iter().all(EvidenceRef::is_well_formed)
    }
}

/// A reviewer's mark on a finding. Marks feed calibration and never a
/// decision (I-10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mark {
    /// The reviewer agrees with the finding.
    Agreed,
    /// The reviewer disputes the finding.
    Disputed,
}
