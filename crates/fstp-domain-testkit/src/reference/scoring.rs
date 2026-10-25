//! Independent reference for scoring, written from the spec text (design section 6.1).
//!
//! Owned by lane L-SCORE (docs/handoff/m2-design.md section 10).
//!
//! Sources:
//! - I-07, I-08 and I-09 in `SPEC/02-domain/invariants.md`;
//! - P-01 and P-02 NOTE 6 in `SPEC/02-domain/policy-parameters.md`;
//! - NOTE 3 and NOTE 4 in `SPEC/02-domain/state-machine.md`.
//!
//! The reference shares only id, record and value types with production.
//! It never calls production scoring code and never uses the order of
//! [`Ratio`]: every comparison is its own cross-multiplication in `u128`.
//!
//! - [`weighted_reference`] computes the score with one common denominator.
//!   It sums each criterion over reviewers first, then weights the totals.
//!   NOTE 6 defines it the other way round, reviewer by reviewer. With
//!   complete vectors the two agree (design section 2.9), so the reference
//!   takes the other route on purpose.
//! - [`valid_score_keys`], [`quorum_reference`] and
//!   [`stage1_close_reference`] are set computations over raw records
//!   (I-07, NOTE 3, NOTE 4, NOTE 8).
//! - [`effective_reference`] applies P-24 to an original plan and its
//!   revisions (I-09, NOTE 4).
//!
//! The `*_property` functions are the predicates of the pure tests. Each
//! takes the implementation under test as a plain function pointer, so a
//! teeth test can pass a deliberately broken one. Every failure message
//! starts with the property id and a colon, as `harness::teeth` expects.

use core::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::decision::Basis;
use fstp_domain::id::{AccountId, AssignmentId, CallId, PlanVersionId, ProposalId};
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::record::{Declared, Record};
use fstp_domain::scoring::{ScoreKey, ScoreVector, Stage};
use fstp_money::{Percent, Ratio};
use fstp_prop::Gen;

use crate::r#gen::scores::{
    EffectiveCase, QuorumCase, Stage1Case, TwoProgrammeCase, effective_case, quorum_case,
    record_name, stage1_case, two_programme_case,
};

// ---------------------------------------------------------------------------
// Exact fractions
// ---------------------------------------------------------------------------

/// An exact non-negative fraction, not reduced. The denominator is above zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exact {
    /// The numerator.
    pub num: u128,
    /// The denominator, above zero.
    pub den: u128,
}

impl Exact {
    /// The fraction of a ratio.
    pub fn of(r: Ratio) -> Exact {
        Exact {
            num: u128::from(r.num()),
            den: u128::from(r.den().get()),
        }
    }

    /// Compares two fractions by cross-multiplication. `None` on overflow,
    /// which the scoring bounds never reach.
    pub fn compare(self, other: Exact) -> Option<Ordering> {
        let lhs = self.num.checked_mul(other.den)?;
        let rhs = other.num.checked_mul(self.den)?;
        Some(lhs.cmp(&rhs))
    }

    /// Whether two fractions have the same value.
    pub fn same(self, other: Exact) -> Result<bool, String> {
        self.compare(other)
            .map(|o| o == Ordering::Equal)
            .ok_or_else(|| "overflow in an exact comparison".to_owned())
    }

    /// The fraction as a ratio, when both parts fit `u64`.
    pub fn to_ratio(self) -> Result<Ratio, String> {
        let num = u64::try_from(self.num).map_err(|_| "numerator above u64".to_owned())?;
        let den = u64::try_from(self.den)
            .ok()
            .and_then(NonZeroU64::new)
            .ok_or("denominator 0 or above u64")?;
        Ok(Ratio::new(num, den))
    }
}

impl core::fmt::Display for Exact {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}/{}", self.num, self.den)
    }
}

// ---------------------------------------------------------------------------
// I-08: the weighted score and the strict comparison
// ---------------------------------------------------------------------------

/// The P-01 score of complete reviewer vectors, as one exact fraction
/// (NOTE 6): `sum_i w_i * S_i` over `R * N * sum_i w_i`, where `S_i` is
/// the total of criterion `i` over the `R` reviewers.
///
/// Refuses an empty criterion list, a zero weight, a zero scale, no
/// reviewer, an incomplete vector and a value above N, which NOTE 6
/// excludes.
pub fn weighted_reference(
    scale_max: u8,
    weights: &[u16],
    vectors: &[Vec<u8>],
) -> Result<Exact, String> {
    if scale_max == 0 {
        return Err("P-01 scale maximum 0".to_owned());
    }
    if weights.is_empty() || weights.contains(&0) {
        return Err("P-01 needs positive weights".to_owned());
    }
    if vectors.is_empty() {
        return Err("no reviewer".to_owned());
    }
    let mut totals: Vec<u128> = vec![0; weights.len()];
    for v in vectors {
        if v.len() != weights.len() {
            return Err("an incomplete score vector".to_owned());
        }
        for (t, s) in totals.iter_mut().zip(v) {
            if *s > scale_max {
                return Err("a value above the scale maximum".to_owned());
            }
            *t = t.checked_add(u128::from(*s)).ok_or("overflow")?;
        }
    }
    let mut num: u128 = 0;
    let mut wsum: u128 = 0;
    for (w, t) in weights.iter().zip(&totals) {
        num = u128::from(*w)
            .checked_mul(*t)
            .and_then(|p| num.checked_add(p))
            .ok_or("overflow")?;
        wsum = wsum.checked_add(u128::from(*w)).ok_or("overflow")?;
    }
    let reviewers = u128::try_from(vectors.len()).map_err(|_| "too many reviewers".to_owned())?;
    let den = reviewers
        .checked_mul(u128::from(scale_max))
        .and_then(|d| d.checked_mul(wsum))
        .ok_or("overflow")?;
    Ok(Exact { num, den })
}

/// Whether `score` is strictly above P-02 (I-08, NOTE 6): exactly, with
/// no rounding, as `num * 10 000 > p02_bp * den`.
pub fn passes_reference(score: Exact, p02_bp: u16) -> Result<bool, String> {
    let lhs = score
        .num
        .checked_mul(u128::from(Percent::MAX_BP))
        .ok_or("overflow")?;
    let rhs = u128::from(p02_bp)
        .checked_mul(score.den)
        .ok_or("overflow")?;
    Ok(lhs > rhs)
}

/// The outcome a stage 1 scorer reports for a [`Stage1Case`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Judged {
    /// The weighted score as a fraction of the maximum.
    pub score: Ratio,
    /// Whether the proposal passes stage 1.
    pub passed: bool,
}

/// A stage 1 scorer under test: production through an adapter, the
/// reference, or a deliberately broken scorer in a teeth test.
pub type Stage1Scorer = fn(&Stage1Case) -> Result<Judged, String>;

/// The reference as a scorer. Teeth tests build their broken scorers on
/// it, and the control tests show that the predicates accept it.
pub fn exact_scorer(case: &Stage1Case) -> Result<Judged, String> {
    let exact = weighted_reference(case.scale_max, &case.weights, &case.vectors)?;
    Ok(Judged {
        score: exact.to_ratio()?,
        passed: passes_reference(exact, case.p02_bp)?,
    })
}

/// Checks one case against the reference: the exact score, and a pass
/// exactly when the score is strictly above P-02 (I-08).
pub fn check_stage1_case(case: &Stage1Case, scorer: Stage1Scorer) -> Result<Judged, String> {
    let exact = weighted_reference(case.scale_max, &case.weights, &case.vectors)
        .map_err(|e| format!("I-08: the generator drew an invalid case: {e}"))?;
    for e in case.earlier.iter().flatten() {
        weighted_reference(case.scale_max, &case.weights, core::slice::from_ref(e))
            .map_err(|err| format!("I-08: the generator drew an invalid earlier vector: {err}"))?;
    }
    let pass = passes_reference(exact, case.p02_bp).map_err(|e| format!("I-08: {e}"))?;
    let got = scorer(case).map_err(|e| format!("I-08: the scorer failed: {e}"))?;
    if !Exact::of(got.score)
        .same(exact)
        .map_err(|e| format!("I-08: {e}"))?
    {
        return Err(format!(
            "I-08: the score {} differs from the exact reference {exact}",
            Exact::of(got.score)
        ));
    }
    if got.passed != pass {
        return Err(format!(
            "I-08: the score {exact} against P-02 {} gave passed = {}, the strict reference gives {pass}",
            Percent::from_bp(case.p02_bp).map_or_else(|| "?".to_owned(), |p| p.to_string()),
            got.passed
        ));
    }
    Ok(got)
}

/// The I-08 property over one generated case, with its metamorphic checks:
///
/// - the score equals the exact reference over the current vectors, and
///   passes exactly when it is strictly above P-02. Some reviewers first
///   record an earlier vector and then correct it, so a superseded value
///   that enters the score is caught (NOTE 3);
/// - raising one value by one strictly raises the score, and never turns
///   a pass into a fail;
/// - permuting the reviewers changes nothing;
/// - multiplying every weight by the same factor changes nothing.
pub fn i08_property(g: &mut Gen, scorer: Stage1Scorer) -> Result<(), String> {
    let case = stage1_case(g);
    g.note("case", &case);
    let base = check_stage1_case(&case, scorer)?;

    // Monotone in each score.
    let mut raisable = Vec::new();
    for (r, v) in case.vectors.iter().enumerate() {
        for (i, s) in v.iter().enumerate() {
            if *s < case.scale_max {
                raisable.push((r, i));
            }
        }
    }
    if !raisable.is_empty() {
        let (r, i) = *g.pick(&raisable);
        let mut raised = case.clone();
        if let Some(s) = raised.vectors.get_mut(r).and_then(|v| v.get_mut(i)) {
            *s = s.saturating_add(1);
        }
        g.note("raised reviewer and criterion", &(r, i));
        let up = check_stage1_case(&raised, scorer)?;
        let order = Exact::of(up.score).compare(Exact::of(base.score));
        if order != Some(Ordering::Greater) {
            return Err(format!(
                "I-08: raising reviewer {r} criterion {i} did not raise the score ({:?} to {:?})",
                base.score, up.score
            ));
        }
        if base.passed && !up.passed {
            return Err("I-08: raising a score turned a pass into a fail".to_owned());
        }
    }

    // Invariant under reviewer permutation. Each reviewer keeps its
    // earlier, corrected vector.
    let mut permuted = case.clone();
    let mut pairs: Vec<(Vec<u8>, Option<Vec<u8>>)> = case
        .vectors
        .iter()
        .enumerate()
        .map(|(r, v)| (v.clone(), case.earlier.get(r).cloned().flatten()))
        .collect();
    g.shuffle(&mut pairs);
    (permuted.vectors, permuted.earlier) = pairs.into_iter().unzip();
    let p = check_stage1_case(&permuted, scorer)?;
    if p != base {
        return Err(format!(
            "I-08: permuting the reviewers changed the outcome from {base:?} to {p:?}"
        ));
    }

    // Invariant under scaling every weight.
    let max_w = case.weights.iter().copied().max().unwrap_or(1).max(1);
    let k_max = 1000_u16.checked_div(max_w).unwrap_or(1);
    if k_max >= 2 {
        let k = g.u16_in(2..=k_max);
        let mut scaled = case.clone();
        for w in &mut scaled.weights {
            *w = w.saturating_mul(k);
        }
        g.note("weight factor", &k);
        let s = check_stage1_case(&scaled, scorer)?;
        if s != base {
            return Err(format!(
                "I-08: multiplying every weight by {k} changed the outcome from {base:?} to {s:?}"
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// R-PC-01: two programmes, identical inputs
// ---------------------------------------------------------------------------

/// A scorer of both programmes of a [`TwoProgrammeCase`]: the scores of
/// programme A and programme B.
pub type TwoProgrammeScorer = fn(&TwoProgrammeCase) -> Result<(Ratio, Ratio), String>;

/// The reference as a two-programme scorer, for the control test.
pub fn exact_two_programme_scorer(case: &TwoProgrammeCase) -> Result<(Ratio, Ratio), String> {
    let a = weighted_reference(case.scale_max, &case.weights_a, &case.vectors)?;
    let b = weighted_reference(case.scale_max, &case.weights_b, &case.vectors)?;
    Ok((a.to_ratio()?, b.to_ratio()?))
}

/// The R-PC-01 property: two programmes with different P-01 weights give
/// different weighted scores for identical reviewer inputs, and each
/// score equals the reference.
pub fn r_pc_01_property(g: &mut Gen, scorer: TwoProgrammeScorer) -> Result<(), String> {
    let case = two_programme_case(g);
    g.note("case", &case);
    let ra = weighted_reference(case.scale_max, &case.weights_a, &case.vectors)
        .map_err(|e| format!("R-PC-01: invalid case: {e}"))?;
    let rb = weighted_reference(case.scale_max, &case.weights_b, &case.vectors)
        .map_err(|e| format!("R-PC-01: invalid case: {e}"))?;
    if ra.same(rb).map_err(|e| format!("R-PC-01: {e}"))? {
        return Err(format!(
            "R-PC-01: the generator drew inputs that do not discriminate the weights ({ra} and {rb})"
        ));
    }
    let (a, b) = scorer(&case).map_err(|e| format!("R-PC-01: the scorer failed: {e}"))?;
    if !Exact::of(a).same(ra).map_err(|e| format!("R-PC-01: {e}"))? {
        return Err(format!(
            "R-PC-01: programme A scored {a:?}, the reference gives {ra}"
        ));
    }
    if !Exact::of(b).same(rb).map_err(|e| format!("R-PC-01: {e}"))? {
        return Err(format!(
            "R-PC-01: programme B scored {b:?}, the reference gives {rb}"
        ));
    }
    if Exact::of(a)
        .same(Exact::of(b))
        .map_err(|e| format!("R-PC-01: {e}"))?
    {
        return Err(format!(
            "R-PC-01: both programmes scored {a:?} although their weights differ"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// I-07: valid scores and the quorum
// ---------------------------------------------------------------------------

/// The assignment, conflict and score facts of raw records for one proposal.
struct Facts {
    /// Every assignment: its proposal, call, account and kind.
    assignments: BTreeMap<AssignmentId, (ProposalId, CallId, AccountId, AssignmentKind)>,
    /// Assignments with a declaration of no conflict.
    declared_clear: BTreeSet<AssignmentId>,
    /// Assignments with a conflicted declaration.
    declared_conflicted: BTreeSet<AssignmentId>,
    /// Released assignments.
    released: BTreeSet<AssignmentId>,
    /// Accounts with a conflict fact on the proposal.
    conflicted: BTreeSet<AccountId>,
    /// The proposal's creation call, where stage 1 runs. Re-entry goes
    /// only to STAGE2 or IRC_REVIEW (NOTE 8).
    created: Option<CallId>,
    /// The proposal's current call: its creation call, or the call it last
    /// re-entered (NOTE 8).
    call: Option<CallId>,
    /// The origin of each plan version of the proposal.
    origins: BTreeMap<PlanVersionId, PlanOrigin>,
    /// Per score key, whether it has a current value.
    current: BTreeMap<ScoreKey, bool>,
}

/// The facts of `records` for `proposal`, in ledger order.
fn facts_of(records: &[Record], proposal: ProposalId) -> Facts {
    let mut f = Facts {
        assignments: BTreeMap::new(),
        declared_clear: BTreeSet::new(),
        declared_conflicted: BTreeSet::new(),
        released: BTreeSet::new(),
        conflicted: BTreeSet::new(),
        created: None,
        call: None,
        origins: BTreeMap::new(),
        current: BTreeMap::new(),
    };
    for r in records {
        match r {
            Record::ProposalCreated {
                proposal: p, call, ..
            } if *p == proposal => {
                f.created = Some(*call);
                f.call = Some(*call);
            }
            Record::PlanVersionRecorded(v) if v.proposal == proposal => {
                f.origins.insert(v.plan, v.origin);
            }
            Record::ReEntered {
                proposal: p,
                to_call,
                ..
            } if *p == proposal => f.call = Some(*to_call),
            Record::Assigned(a) => {
                f.assignments
                    .insert(a.assignment, (a.proposal, a.call, a.reviewer, a.kind));
            }
            Record::AssignmentReleased(a) => {
                f.released.insert(a.assignment);
            }
            Record::ConflictDeclared(d) => match d.subject {
                Declared::Assignment(a) => {
                    if d.conflicted {
                        f.declared_conflicted.insert(a);
                        if let Some((p, _, account, _)) = f.assignments.get(&a)
                            && *p == proposal
                        {
                            f.conflicted.insert(*account);
                        }
                    } else {
                        f.declared_clear.insert(a);
                    }
                }
                Declared::Proposal {
                    proposal: p,
                    account,
                } => {
                    if d.conflicted && p == proposal {
                        f.conflicted.insert(account);
                    }
                }
            },
            Record::ConflictDetected(d) if d.proposal == proposal => {
                f.conflicted.insert(d.account);
            }
            Record::ScoreRecorded(s) => {
                f.current.insert(s.key, true);
            }
            Record::ScoreVoided(v) => {
                f.current.insert(v.key, false);
            }
            _ => {}
        }
    }
    f
}

impl Facts {
    /// The call whose assignments score `stage`: the creation call for
    /// stage 1, the current call for stage 2 (NOTE 8).
    fn stage_call(&self, stage: Stage) -> Option<CallId> {
        match stage {
            Stage::One => self.created,
            Stage::Two => self.call,
        }
    }

    /// The account of `a` when it is a reviewer assignment to `proposal`,
    /// made in the call of `stage`, declared without conflict and not
    /// released (design section 2.7, NOTE 8).
    fn active_reviewer(
        &self,
        a: AssignmentId,
        proposal: ProposalId,
        stage: Stage,
    ) -> Option<AccountId> {
        let (p, call, account, kind) = self.assignments.get(&a)?;
        let active = *p == proposal
            && Some(*call) == self.stage_call(stage)
            && *kind == AssignmentKind::Reviewer
            && self.declared_clear.contains(&a)
            && !self.declared_conflicted.contains(&a)
            && !self.released.contains(&a);
        active.then_some(*account)
    }
}

/// The valid scores on `(stage, plan)` of `proposal`, read from raw records
/// in ledger order (NOTE 3, NOTE 4, NOTE 8, design sections 2.7 and 2.9):
///
/// - the key's current value is its latest `ScoreRecorded`, unless a later
///   `ScoreVoided` names it, so a correction replaces a value and never
///   adds one;
/// - the key's assignment is a reviewer assignment to `proposal`, made in
///   the stage's call, with a declaration of no conflict, and no
///   `AssignmentReleased` names it, so it is active now. The stage's call
///   is the creation call for stage 1, where stage 1 runs, and the current
///   call for stage 2;
/// - the assignee has no conflict fact on `proposal`: no conflicted
///   declaration on any of its assignments to `proposal`, no conflicted
///   declaration on the proposal, and no detected conflict.
pub fn valid_score_keys(
    records: &[Record],
    proposal: ProposalId,
    stage: Stage,
    plan: PlanVersionId,
) -> BTreeSet<ScoreKey> {
    let f = facts_of(records, proposal);
    f.current
        .iter()
        .filter(|(k, live)| **live && k.stage == stage && k.plan == plan)
        .map(|(k, _)| *k)
        .filter(|k| {
            f.active_reviewer(k.assignment, proposal, stage)
                .is_some_and(|account| !f.conflicted.contains(&account))
        })
        .collect()
}

/// The active reviewer assignments to `proposal` in the call of `stage`,
/// whatever their scores and conflict facts. Stage 1 closes only when each
/// of them has a valid score (NOTE 3).
pub fn active_reviewer_assignments(
    records: &[Record],
    proposal: ProposalId,
    stage: Stage,
) -> BTreeSet<AssignmentId> {
    let f = facts_of(records, proposal);
    f.assignments
        .keys()
        .copied()
        .filter(|a| f.active_reviewer(*a, proposal, stage).is_some())
        .collect()
}

/// Whether `stage` scores `plan` of `proposal`: stage 1 scores the
/// submitted plan, and stage 2 scores a stage 2 revision (NOTE 3, NOTE 4).
/// A quorum on any other plan is refused, not merely too small.
pub fn plan_scorable(
    records: &[Record],
    proposal: ProposalId,
    stage: Stage,
    plan: PlanVersionId,
) -> bool {
    let wanted = match stage {
        Stage::One => PlanOrigin::Submitted,
        Stage::Two => PlanOrigin::Stage2Revision,
    };
    facts_of(records, proposal).origins.get(&plan) == Some(&wanted)
}

/// The current value of `key`, read from raw records: its latest
/// `ScoreRecorded`, unless a later `ScoreVoided` names it.
pub fn current_values(records: &[Record], key: ScoreKey) -> Option<ScoreVector> {
    let mut out = None;
    for r in records {
        match r {
            Record::ScoreRecorded(s) if s.key == key => out = Some(s.values.clone()),
            Record::ScoreVoided(v) if v.key == key => out = None,
            _ => {}
        }
    }
    out
}

/// The reviewer accounts behind `keys`, read from raw records.
pub fn reviewers_of(records: &[Record], keys: &BTreeSet<ScoreKey>) -> BTreeSet<AccountId> {
    let wanted: BTreeSet<AssignmentId> = keys.iter().map(|k| k.assignment).collect();
    records
        .iter()
        .filter_map(|r| match r {
            Record::Assigned(a) if wanted.contains(&a.assignment) => Some(a.reviewer),
            _ => None,
        })
        .collect()
}

/// The I-07 quorum on `(stage, plan)`: the valid score keys when they come
/// from at least `p03` distinct reviewers, else `None`. In stage 2 this is
/// the NOTE 4 rule: at least P-03 valid stage 2 scores on the revised
/// plan. A plan that the stage does not score never has a quorum
/// ([`plan_scorable`]).
pub fn quorum_reference(
    records: &[Record],
    proposal: ProposalId,
    stage: Stage,
    plan: PlanVersionId,
    p03: u8,
) -> Option<BTreeSet<ScoreKey>> {
    if !plan_scorable(records, proposal, stage, plan) {
        return None;
    }
    let keys = valid_score_keys(records, proposal, stage, plan);
    let reviewers = reviewers_of(records, &keys);
    (reviewers.len() >= usize::from(p03) && reviewers.len() == keys.len()).then_some(keys)
}

/// A quorum under test: the counted keys, or `None` when the quorum is
/// refused for too few valid scores, or because the stage does not score
/// the plan ([`plan_scorable`]). Any other failure is an error.
pub type QuorumFn = fn(&QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String>;

/// The reference as a quorum function, for the control test.
pub fn reference_quorum(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    let records = case.script.records();
    Ok(quorum_reference(
        &records,
        case.fixture.proposal,
        case.stage,
        case.plan,
        case.fixture.p03,
    ))
}

/// The I-07 property: the quorum exists exactly when the reference finds
/// at least P-03 valid scores, and it counts exactly the reference's keys.
pub fn i07_property(g: &mut Gen, quorum: QuorumFn) -> Result<(), String> {
    let case = quorum_case(g).map_err(|e| format!("I-07: the generator failed: {e}"))?;
    let records = note_case(g, &case);
    let valid = valid_score_keys(&records, case.fixture.proposal, case.stage, case.plan);
    let expected = quorum_reference(
        &records,
        case.fixture.proposal,
        case.stage,
        case.plan,
        case.fixture.p03,
    );
    let scorable = plan_scorable(&records, case.fixture.proposal, case.stage, case.plan);
    let got = quorum(&case).map_err(|e| format!("I-07: the quorum failed: {e}"))?;
    match (expected, got) {
        (None, None) => Ok(()),
        (Some(e), Some(k)) if e == k => Ok(()),
        (Some(e), Some(k)) => Err(format!(
            "I-07: the quorum counted {k:?}, the valid scores are {e:?}"
        )),
        (None, Some(k)) if !scorable => Err(format!(
            "I-07: over-permission, a stage {:?} quorum of {k:?} on plan {:?}, which that stage does not score (NOTE 3, NOTE 4)",
            case.stage, case.plan
        )),
        (None, Some(k)) => Err(format!(
            "I-07: over-permission, a quorum of {} keys ({k:?}) where only {} valid scores exist and P-03 is {}",
            k.len(),
            valid.len(),
            case.fixture.p03
        )),
        (Some(e), None) => Err(format!(
            "I-07: over-denial, no quorum although {} valid scores exist ({e:?}) and P-03 is {}",
            e.len(),
            case.fixture.p03
        )),
    }
}

/// The stage 1 close on the submitted plan of `proposal` (NOTE 3): the
/// valid stage 1 score keys when the I-07 quorum exists and every active
/// reviewer assignment of the stage 1 call has one of them, else `None`.
pub fn stage1_close_reference(
    records: &[Record],
    proposal: ProposalId,
    plan: PlanVersionId,
    p03: u8,
) -> Option<BTreeSet<ScoreKey>> {
    let keys = quorum_reference(records, proposal, Stage::One, plan, p03)?;
    let scored: BTreeSet<AssignmentId> = keys.iter().map(|k| k.assignment).collect();
    active_reviewer_assignments(records, proposal, Stage::One)
        .is_subset(&scored)
        .then_some(keys)
}

/// A stage 1 close under test, asked on the submitted plan: the counted
/// keys when stage 1 may close, or `None` when it may not.
pub type CloseFn = fn(&QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String>;

/// The reference as a close function, for the control test.
pub fn reference_close(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    let records = case.script.records();
    Ok(stage1_close_reference(
        &records,
        case.fixture.proposal,
        case.fixture.plan,
        case.fixture.p03,
    ))
}

/// The I-07 and NOTE 3 close property on stage 1 of the submitted plan:
/// stage 1 may close exactly when at least P-03 valid scores exist and
/// every active reviewer assignment of the stage 1 call has a valid
/// score. The keys counted are exactly the reference's. Cases after a
/// re-entry check that stage 1 stays in the call it ran in (NOTE 8).
pub fn i07_close_property(g: &mut Gen, close: CloseFn) -> Result<(), String> {
    let mut case = quorum_case(g).map_err(|e| format!("I-07: the generator failed: {e}"))?;
    case.stage = Stage::One;
    case.plan = case.fixture.plan;
    let records = note_case(g, &case);
    let proposal = case.fixture.proposal;
    let expected = stage1_close_reference(&records, proposal, case.plan, case.fixture.p03);
    let got = close(&case).map_err(|e| format!("I-07: the close failed: {e}"))?;
    let active = active_reviewer_assignments(&records, proposal, Stage::One);
    match (expected, got) {
        (None, None) => Ok(()),
        (Some(e), Some(k)) if e == k => Ok(()),
        (Some(e), Some(k)) => Err(format!(
            "I-07: the close counted {k:?}, the valid scores are {e:?}"
        )),
        (None, Some(k)) => Err(format!(
            "I-07: over-permission, stage 1 closed on {k:?} although the reference refuses; active assignments {active:?}, P-03 {}",
            case.fixture.p03
        )),
        (Some(e), None) => Err(format!(
            "I-07: over-denial, stage 1 did not close although every active assignment {active:?} has a valid score ({e:?})"
        )),
    }
}

/// Notes the records of `case` for a failure report and returns them.
fn note_case(g: &mut Gen, case: &QuorumCase) -> Vec<Record> {
    let records = case.script.records();
    g.note_with(|| {
        let names: Vec<String> = case
            .script
            .entries()
            .iter()
            .map(|e| format!("{} {}", e.seq.raw(), record_name(&e.record)))
            .collect();
        format!(
            "P-03 {}, stage {:?}, plan {:?}, records: {}",
            case.fixture.p03,
            case.stage,
            case.plan,
            names.join(", ")
        )
    });
    g.note("records", &records);
    records
}

// ---------------------------------------------------------------------------
// I-09: the effective score after stage 2
// ---------------------------------------------------------------------------

/// The effective score an implementation reports for an [`EffectiveCase`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectiveOutcome {
    /// The one plan version named.
    pub plan: PlanVersionId,
    /// The effective score.
    pub value: Ratio,
    /// Whether the original or the revised plan carries forward.
    pub basis: Basis,
}

/// An effective score under test.
pub type EffectiveFn = fn(&EffectiveCase) -> Result<EffectiveOutcome, String>;

/// P-24, "higher of original and revised", with NOTE 4: the latest scored
/// revision counts, and on a tie the original plan carries forward. With
/// no scored revision the original carries forward.
pub fn effective_reference(case: &EffectiveCase) -> Result<EffectiveOutcome, String> {
    let (original, o_score) = case.original;
    let latest = case
        .revisions
        .iter()
        .rev()
        .find_map(|(p, s)| s.map(|s| (*p, s)));
    let Some((revised, r_score)) = latest else {
        return Ok(EffectiveOutcome {
            plan: original,
            value: o_score,
            basis: Basis::Original,
        });
    };
    match Exact::of(r_score).compare(Exact::of(o_score)) {
        Some(Ordering::Greater) => Ok(EffectiveOutcome {
            plan: revised,
            value: r_score,
            basis: Basis::Revised,
        }),
        Some(_) => Ok(EffectiveOutcome {
            plan: original,
            value: o_score,
            basis: Basis::Original,
        }),
        None => Err("overflow in an exact comparison".to_owned()),
    }
}

/// The I-09 property: the effective score names exactly one plan of the
/// proposal, the one P-24 picks, with the reference value and basis.
pub fn i09_property(g: &mut Gen, effective: EffectiveFn) -> Result<(), String> {
    let case = effective_case(g);
    g.note("case", &case);
    let expected = effective_reference(&case).map_err(|e| format!("I-09: {e}"))?;
    let got = effective(&case).map_err(|e| format!("I-09: the effective score failed: {e}"))?;
    let original = case.original.0;
    let known = got.plan == original || case.revisions.iter().any(|(p, _)| *p == got.plan);
    if !known {
        return Err(format!(
            "I-09: the effective score names {:?}, which is not a plan of the proposal",
            got.plan
        ));
    }
    let basis_matches = (got.basis == Basis::Original) == (got.plan == original);
    if !basis_matches {
        return Err(format!(
            "I-09: basis {:?} does not match the named plan {:?}",
            got.basis, got.plan
        ));
    }
    if got.plan != expected.plan || got.basis != expected.basis {
        return Err(format!(
            "I-09: named {:?} ({:?}), P-24 picks {:?} ({:?})",
            got.plan, got.basis, expected.plan, expected.basis
        ));
    }
    if !Exact::of(got.value)
        .same(Exact::of(expected.value))
        .map_err(|e| format!("I-09: {e}"))?
    {
        return Err(format!(
            "I-09: value {:?}, the reference maximum is {:?}",
            got.value, expected.value
        ));
    }
    Ok(())
}

/// The reference as an effective score, for the control test.
pub fn reference_effective(case: &EffectiveCase) -> Result<EffectiveOutcome, String> {
    effective_reference(case)
}
