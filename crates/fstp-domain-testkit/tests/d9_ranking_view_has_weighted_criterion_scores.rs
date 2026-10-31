//! R-EV-08 and the Committee ranking view: each row holds the weighted score of every criterion (M4 design section 3.4, D9).
//!
//! `SPEC/02-domain/roles-and-sod.md` Committee ranking view lists
//! "weighted scores per criterion". D9: the mean over the assigned
//! reviewers whose scores count of weight times score, as an exact ratio,
//! from the effective score set after stage 2 (I-09). M2 returned an empty
//! list. The expected values come from
//! `reference::review::weighted_criterion_scores`, over the score vectors
//! each story records.
//!
//! P-01 here has weights (3, 1) on a scale of 0 to 2 and P-02 is 50.00.
//! Every story runs production commands from genesis through [`Story`].

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::id::CriterionId;
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::{ScoreKey, Stage};
use fstp_domain::visibility::{RankingRow, ranking_view};
use fstp_domain_testkit::r#gen::review::{L1, PR1, R1, R2, plan_of};
use fstp_domain_testkit::r#gen::roster::{Backend, call};
use fstp_domain_testkit::mc::life_model::{
    Story, life_judges, rank, revision_milestone, revision_of, revision_plan, score, story_setup,
    submit_revision,
};
use fstp_domain_testkit::reference::review::weighted_criterion_scores;

/// P-01 of these stories: criteria 1 and 2 with weights 3 and 1.
fn criteria() -> Vec<(CriterionId, u16)> {
    vec![(CriterionId::from_raw(1), 3), (CriterionId::from_raw(2), 1)]
}

fn story() -> Story {
    let mut setup = story_setup(vec![(L1, PR1, false)], life_judges());
    setup.weights = vec![3, 1];
    Story::new(&setup, Backend::Production, |_| {}).unwrap_or_else(|e| panic!("{e}"))
}

fn row(s: &Story) -> RankingRow {
    let rows = ranking_view(&s.world.rev.sod.state, call(1)).unwrap_or_else(|e| panic!("{e}"));
    rows.into_iter()
        .find(|r| r.proposal == PR1)
        .unwrap_or_else(|| panic!("no ranking row for PR1"))
}

/// D9, R-EV-08, I-09: ranked on the original plan by "no questions", the
/// row holds, per criterion, the mean of weight times score over R1 and R2
/// on their stage 1 scores: (3 * 2 + 3 * 1) / 2 and (1 * 1 + 1 * 1) / 2.
#[test]
fn d9_ranking_view_has_weighted_criterion_scores() {
    let mut s = story();
    let vectors = vec![vec![2, 1], vec![1, 1]];
    s.ranked(L1, PR1, &[R1, R2], &vectors)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Ranked));
    let want = weighted_criterion_scores(&criteria(), &vectors).unwrap();
    assert_eq!(
        want.iter()
            .map(|(_, r)| (r.num(), r.den().get()))
            .collect::<Vec<_>>(),
        vec![(9, 2), (1, 1)],
        "the reference of this story"
    );
    assert_eq!(row(&s).criterion_scores, want);
}

/// D9, I-09, P-24: when the revised plan carries forward, the weighted
/// scores come from the stage 2 scores of the revision, not from stage 1.
#[test]
fn d9_ranking_view_reads_the_effective_score_set_after_a_revision() {
    let mut s = story();
    s.closed(L1, PR1, &[R1, R2], &[vec![2, 0], vec![2, 0]])
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Stage2));
    let revised = revision_of(PR1, 1);
    let plan = revision_plan(
        L1,
        PR1,
        revised,
        Some(plan_of(PR1)),
        revision_milestone(PR1, 1),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    s.run(&plan).unwrap_or_else(|e| panic!("{e}"));
    s.run(&submit_revision(L1, PR1, revised))
        .unwrap_or_else(|e| panic!("{e}"));
    let vectors = vec![vec![2, 2], vec![2, 1]];
    for (r, v) in [R1, R2].into_iter().zip(&vectors) {
        let key = ScoreKey {
            assignment: s
                .world
                .assignment(r, PR1, Stage::Two, AssignmentKind::Reviewer)
                .unwrap_or_else(|| panic!("no stage 2 assignment of {r:?}")),
            stage: Stage::Two,
            plan: revised,
        };
        s.run(&score(r, key, v)).unwrap_or_else(|e| panic!("{e}"));
    }
    s.run(&rank(R1, PR1)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Ranked));
    let effective = fstp_domain::decision::effective_score(&s.world.rev.sod.state, PR1)
        .unwrap_or_else(|| panic!("no effective score"));
    assert_eq!(
        effective.plan(),
        revised,
        "P-24: the higher revised plan carries forward"
    );
    assert_eq!(
        row(&s).criterion_scores,
        weighted_criterion_scores(&criteria(), &vectors).unwrap(),
        "D9: the stage 2 scores of the revision"
    );
}
