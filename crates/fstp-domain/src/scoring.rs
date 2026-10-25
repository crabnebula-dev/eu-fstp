//! Scores, quorum and the I-08 comparison (design section 2.9, I-07, I-08, I-09).
//!
//! Owned by lane L-SCORE (docs/handoff/m2-design.md section 10). Step W1c
//! declared the vocabulary the interface names and the checked constructor
//! of [`Criteria`], which crates outside this one need to build a policy.
//! Lane L-SCORE adds the `Quorum`, `Stage1Verdict` and `EffectiveScore`
//! witnesses and the exact score arithmetic.

use std::collections::BTreeSet;
use std::num::{NonZeroU8, NonZeroU16};

use crate::id::{AssignmentId, CriterionId, PlanVersionId};

/// One scoring criterion of P-01 with its positive integer weight.
///
/// Declared by W1c for the interface. Lane L-SCORE completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Criterion {
    /// The criterion.
    pub id: CriterionId,
    /// Its weight. Weights need no particular total (P-01 NOTE 6).
    pub weight: NonZeroU16,
}

/// The P-01 value: the criteria, their weights and the scale maximum N.
/// Each criterion is scored on the integer scale 0 to N (P-01 NOTE 6).
///
/// Fields are private so that only the checked [`Criteria::new`] builds one.
/// Declared by W1c for the interface, with that constructor, so that crates
/// outside this one can build a policy before lane L-SCORE lands. Lane
/// L-SCORE may tighten the checks but keeps the signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Criteria {
    scale_max: NonZeroU8,
    items: Vec<Criterion>,
}

impl Criteria {
    /// Checked P-01 criteria with the design section 2.4 bounds: 1 to 16
    /// criteria with unique ids, each weight at most 1000, and a scale maximum
    /// of at most 100. These keep the exact score arithmetic within `u128`.
    pub fn new(scale_max: NonZeroU8, items: Vec<Criterion>) -> Result<Criteria, CriteriaError> {
        if items.is_empty() {
            return Err(CriteriaError::Empty);
        }
        if items.len() > usize::from(Criteria::MAX_CRITERIA) {
            return Err(CriteriaError::TooMany);
        }
        if scale_max.get() > Criteria::MAX_SCALE {
            return Err(CriteriaError::ScaleTooLarge);
        }
        if items.iter().any(|c| c.weight.get() > Criteria::MAX_WEIGHT) {
            return Err(CriteriaError::WeightTooLarge);
        }
        let ids: BTreeSet<CriterionId> = items.iter().map(|c| c.id).collect();
        if ids.len() != items.len() {
            return Err(CriteriaError::DuplicateCriterion);
        }
        Ok(Criteria { scale_max, items })
    }

    /// The most criteria P-01 may hold.
    pub const MAX_CRITERIA: u8 = 16;
    /// The largest weight of one criterion.
    pub const MAX_WEIGHT: u16 = 1000;
    /// The largest scale maximum N.
    pub const MAX_SCALE: u8 = 100;

    /// The scale maximum N.
    pub fn scale_max(&self) -> NonZeroU8 {
        self.scale_max
    }

    /// The criteria in their P-01 order.
    pub fn items(&self) -> &[Criterion] {
        &self.items
    }
}

/// Why [`Criteria::new`] refused a P-01 value (design section 2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CriteriaError {
    /// No criterion.
    Empty,
    /// More than 16 criteria.
    TooMany,
    /// A weight above 1000.
    WeightTooLarge,
    /// A scale maximum above 100.
    ScaleTooLarge,
    /// Two criteria share an id.
    DuplicateCriterion,
}

impl core::fmt::Display for CriteriaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid P-01 criteria: {self:?}")
    }
}

impl std::error::Error for CriteriaError {}

/// Evaluation stage of a score.
///
/// Declared by W1c for the interface. Lane L-SCORE completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Stage {
    /// Stage 1 scoring.
    One,
    /// Stage 2 rescoring of a revised plan.
    Two,
}

/// The key of one current score: one assignment, one stage, one plan version.
///
/// Declared by W1c for the interface. Lane L-SCORE completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScoreKey {
    /// The assignment that scored.
    pub assignment: AssignmentId,
    /// The stage.
    pub stage: Stage,
    /// The plan version scored.
    pub plan: PlanVersionId,
}

/// One value per P-01 criterion, in P-01 order, each from 0 to N.
///
/// Declared by W1c for the interface. Lane L-SCORE checks it against P-01.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScoreVector(pub Vec<u8>);

/// Why a score stopped counting.
///
/// Declared by W1c for the interface. Lane L-SCORE completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VoidCause {
    /// The assignment was released before the stage closed (NOTE 3).
    AssignmentReleased,
    /// A conflict on the proposal was declared or detected (I-03).
    Conflict,
    /// A recorded complaint remedy reopened the stage (`SPEC/02-domain/complaints.md`).
    ComplaintRemedy,
}
