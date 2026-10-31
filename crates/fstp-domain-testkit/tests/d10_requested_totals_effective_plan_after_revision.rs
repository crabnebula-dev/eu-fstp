//! I-09 and R-EV-08: the ranking view's requested amount totals the effective plan (M4 design section 3.4, D10).
//!
//! `SubmitRevision` exists since M2, so a stage 2 revision can change the
//! plan whose total the committee sees. D10: `requested` totals the
//! effective plan, the plan the effective score names after stage 2
//! (I-09). Without a revision that is the submitted plan.
//!
//! The submitted plan has one milestone of 1000.00 EUR. The revision has
//! two, so it totals 2000.00 EUR. P-01 has weights (3, 1) on a scale of 0
//! to 2 and P-02 is 50.00. Every story runs production commands from
//! genesis through [`Story`].

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::Command;
use fstp_domain::id::ContentDigest;
use fstp_domain::proposal::{PlanOrigin, Task};
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::{ScoreKey, Stage};
use fstp_domain::visibility::ranking_view;
use fstp_domain_testkit::r#gen::policy::eur;
use fstp_domain_testkit::r#gen::review::{L1, PR1, R1, R2, milestone, plan_of};
use fstp_domain_testkit::r#gen::roster::{Backend, call};
use fstp_domain_testkit::mc::life_model::{
    Story, by, life_judges, rank, revision_milestone, revision_of, score, story_setup,
    submit_revision,
};

fn story() -> Story {
    let mut setup = story_setup(vec![(L1, PR1, false)], life_judges());
    setup.weights = vec![3, 1];
    Story::new(&setup, Backend::Production, |_| {}).unwrap_or_else(|e| panic!("{e}"))
}

fn requested(s: &Story) -> fstp_money::NonNegAmount {
    ranking_view(&s.world.rev.sod.state, call(1))
        .unwrap_or_else(|e| panic!("{e}"))
        .into_iter()
        .find(|r| r.proposal == PR1)
        .unwrap_or_else(|| panic!("no ranking row for PR1"))
        .requested
}

/// D10, I-09: without a revision, the requested amount is the total of the
/// submitted plan, 1000.00 EUR.
#[test]
fn d10_requested_totals_the_submitted_plan_without_a_revision() {
    let mut s = story();
    s.ranked(L1, PR1, &[R1, R2], &[vec![2, 1], vec![2, 1]])
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(requested(&s), eur(100_000).unwrap());
}

/// D10, I-09, P-24: after a revision that carries forward, the requested
/// amount is the total of the revised plan, 2000.00 EUR, not the
/// submitted plan's 1000.00 EUR.
#[test]
fn d10_requested_totals_effective_plan_after_revision() {
    let mut s = story();
    s.closed(L1, PR1, &[R1, R2], &[vec![2, 0], vec![2, 0]])
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Stage2));
    let revised = revision_of(PR1, 1);
    let plan = by(
        L1,
        Command::RecordPlanVersion {
            plan: revised,
            proposal: PR1,
            origin: PlanOrigin::Stage2Revision,
            supersedes: Some(plan_of(PR1)),
            tasks: vec![Task {
                milestones: vec![
                    milestone(revision_milestone(PR1, 1)).unwrap(),
                    milestone(revision_milestone(PR1, 2)).unwrap(),
                ],
            }],
            content: ContentDigest::from_bytes([0x10; 32]),
        },
    );
    s.run(&plan).unwrap_or_else(|e| panic!("{e}"));
    s.run(&submit_revision(L1, PR1, revised))
        .unwrap_or_else(|e| panic!("{e}"));
    for r in [R1, R2] {
        let key = ScoreKey {
            assignment: s
                .world
                .assignment(r, PR1, Stage::Two, AssignmentKind::Reviewer)
                .unwrap_or_else(|| panic!("no stage 2 assignment of {r:?}")),
            stage: Stage::Two,
            plan: revised,
        };
        s.run(&score(r, key, &[2, 2]))
            .unwrap_or_else(|e| panic!("{e}"));
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
        requested(&s),
        eur(200_000).unwrap(),
        "D10: the revised plan's total"
    );
}
