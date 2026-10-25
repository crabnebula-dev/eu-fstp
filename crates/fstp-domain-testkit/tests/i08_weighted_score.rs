//! I-08 pure tests of the production weighted score and the strict P-02
//! comparison (`docs/handoff/m2-design.md` sections 2.9 and 6.2).
//!
//! I-08: a proposal passes stage 1 only if its weighted score is strictly
//! above P-02. P-01 and P-02 NOTE 6 fix the arithmetic: an integer scale
//! 0 to N, positive integer weights with no required total, and the mean
//! over reviewers of the weighted sums as a fraction of the maximum.
//!
//! The production side is reached only through [`production`]. It builds
//! a state from raw records with the public structural `apply`
//! ([`Script::fold`]), never through commands. Then it calls the design
//! section 2.9 API.
//!
//! API this file is written against, from the design:
//! - `fstp_domain::scoring::establish_quorum(&State, ProposalId, Stage,
//!   PlanVersionId, &FrozenPolicy, &Answers) -> Result<Quorum, Refusal>`;
//! - `fstp_domain::scoring::weighted_score(&Quorum, &State, &FrozenPolicy) -> Ratio`;
//! - `fstp_domain::scoring::judge_stage1(Quorum, &State, &FrozenPolicy)
//!   -> Result<Stage1Verdict, Refusal>`, refusing a stage 2 quorum with I-08;
//! - `Stage1Verdict::score(&self) -> Ratio` and `Stage1Verdict::passed(&self) -> bool`;
//! - `CallState::frozen(&self, CallId) -> Option<&FrozenPolicy>`, read
//!   through `State::calls()`. The design names the field
//!   `CallView::frozen` (section 2.5) but no accessor yet.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Actor;
use fstp_domain::id::PlanVersionId;
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::record::Record;
use fstp_domain::refusal::RuleRef;
use fstp_domain::rules::{Row, StateTag};
use fstp_domain::scoring::{ScoreKey, Stage, establish_quorum, judge_stage1, weighted_score};
use fstp_domain::state::State;
use fstp_domain_testkit::r#gen::scores::{COORDINATOR, Fixture, Script, Stage1Case, stage1_script};
use fstp_domain_testkit::reference::scoring::{Judged, check_stage1_case, i08_property};
use fstp_money::Ratio;
use fstp_prop::check;

/// Production stage 1 judgement of a case, through the design API.
fn production(case: &Stage1Case) -> Result<Judged, String> {
    let (fx, script) = stage1_script(case)?;
    let state = script.fold()?;
    judge(&state, &script, &fx)
}

/// The quorum, weighted score and verdict of the fixture's proposal on its
/// original plan in stage 1. The verdict's score must equal `weighted_score`.
fn judge(state: &State, script: &Script, fx: &Fixture) -> Result<Judged, String> {
    let policy = state
        .calls()
        .frozen(fx.call)
        .ok_or_else(|| "the call has no frozen policy".to_owned())?;
    let answers = script.no_conflict_answers(fx.proposal);
    let quorum = establish_quorum(state, fx.proposal, Stage::One, fx.plan, policy, &answers)
        .map_err(|r| format!("establish_quorum refused: {r}"))?;
    let score = weighted_score(&quorum, state, policy);
    let verdict =
        judge_stage1(quorum, state, policy).map_err(|r| format!("judge_stage1 refused: {r}"))?;
    if verdict.score() != score {
        return Err(format!(
            "the verdict holds {:?} but weighted_score gives {score:?}",
            verdict.score()
        ));
    }
    Ok(Judged {
        score: verdict.score(),
        passed: verdict.passed(),
    })
}

/// I-08, R-EV-03: the production score equals the common-denominator
/// reference, and passes exactly when it is strictly above P-02. The
/// generator favours scores equal to P-02. The property also checks that
/// the score is monotone in each value, and invariant under reviewer
/// permutation and under scaling every weight.
#[test]
fn i08_weighted_score_matches_exact_reference() {
    check("i08_weighted_score_matches_exact_reference", |g| {
        i08_property(g, production)
    });
}

/// The ratio `num / den`.
fn ratio(num: u64, den: u64) -> Ratio {
    Ratio::new(num, core::num::NonZeroU64::new(den).unwrap())
}

/// I-08, NOTE 6: weights 30/40/30, scale 0 to 4 and every score 3 give
/// exactly 75.00%, which does not pass a P-02 of 75.00%. The same holds
/// for weights (1, 1) at 50.00% and (3, 1) at 75.00% (design section 6.2).
#[test]
fn i08_equality_is_not_a_pass() {
    let cases = [
        (4, vec![30, 40, 30], vec![3, 3, 3], 7_500, ratio(3, 4)),
        (2, vec![1, 1], vec![1, 1], 5_000, ratio(1, 2)),
        (1, vec![3, 1], vec![1, 0], 7_500, ratio(3, 4)),
    ];
    for (scale_max, weights, vector, p02_bp, exact) in cases {
        for reviewers in [1, 2, 3] {
            let case = Stage1Case {
                scale_max,
                weights: weights.clone(),
                vectors: vec![vector.clone(); reviewers],
                earlier: Vec::new(),
                p02_bp,
            };
            let judged = production(&case).unwrap();
            assert_eq!(judged.score, exact, "{case:?}");
            assert!(!judged.passed, "equality passed stage 1: {case:?}");
            check_stage1_case(&case, production).unwrap();
        }
    }
}

/// I-08: the same 75.00% score passes a P-02 one basis point lower, so the
/// comparison is strict and not a refusal of every pass.
#[test]
fn i08_score_one_basis_point_above_p02_passes() {
    let case = Stage1Case {
        scale_max: 4,
        weights: vec![30, 40, 30],
        vectors: vec![vec![3, 3, 3]; 2],
        earlier: Vec::new(),
        p02_bp: 7_499,
    };
    let judged = production(&case).unwrap();
    assert_eq!(judged.score, ratio(3, 4));
    assert!(judged.passed, "75.00% did not pass a P-02 of 74.99%");
}

/// I-08, NOTE 3: a quorum of stage 2 scores on a revised plan never
/// becomes a stage 1 verdict. `judge_stage1` refuses it with I-08, so a
/// `Stage1Verdict` always judges the submitted plan.
#[test]
fn i08_judge_stage1_refuses_a_stage2_quorum() {
    let case = Stage1Case {
        scale_max: 4,
        weights: vec![30, 40, 30],
        vectors: vec![vec![3, 3, 3]],
        earlier: Vec::new(),
        p02_bp: 5_000,
    };
    let (fx, mut script) = stage1_script(&case).unwrap();
    let assignment = script
        .records()
        .iter()
        .find_map(|r| match r {
            Record::Assigned(a) => Some(a.assignment),
            _ => None,
        })
        .unwrap();
    script
        .transition(
            fx.proposal,
            StateTag::Stage1,
            StateTag::Stage2,
            Row::Stage1ToStage2,
            Actor::Account(COORDINATOR),
            None,
        )
        .unwrap();
    let revised = PlanVersionId::from_raw(script.fresh());
    script
        .plan(
            fx.proposal,
            revised,
            PlanOrigin::Stage2Revision,
            Some(fx.plan),
        )
        .unwrap();
    script
        .push(Record::RevisionSubmitted {
            proposal: fx.proposal,
            plan: revised,
        })
        .unwrap();
    let key = ScoreKey {
        assignment,
        stage: Stage::Two,
        plan: revised,
    };
    script.score(key, vec![4, 4, 4], None).unwrap();
    let state = script.fold().unwrap();
    let policy = state.calls().frozen(fx.call).unwrap();
    let answers = script.no_conflict_answers(fx.proposal);
    let quorum =
        establish_quorum(&state, fx.proposal, Stage::Two, revised, policy, &answers).unwrap();
    let refusal = judge_stage1(quorum, &state, policy).unwrap_err();
    assert_eq!(refusal.rule, RuleRef::I08, "{refusal}");
}

/// I-08, NOTE 3: a correction replaces the current value. Two reviewers
/// first record 0 everywhere and then correct to 3 everywhere. The score
/// is the corrected 75.00%, never the superseded 0%, and a correction
/// never adds a second value.
#[test]
fn i08_corrected_score_counts_its_current_value() {
    let case = Stage1Case {
        scale_max: 4,
        weights: vec![30, 40, 30],
        vectors: vec![vec![3, 3, 3]; 2],
        earlier: vec![Some(vec![0, 0, 0]); 2],
        p02_bp: 5_000,
    };
    let judged = production(&case).unwrap();
    assert_eq!(judged.score, ratio(3, 4));
    assert!(judged.passed, "the superseded 0% was scored");
    check_stage1_case(&case, production).unwrap();
}
