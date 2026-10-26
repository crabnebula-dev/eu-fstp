//! R-EV-05 and O-50: "no questions" closes the stage 2 window at once only when every active assigned reviewer records it (NOTE 4).
//!
//! Each story runs production commands from genesis: PR1 by L1 reaches
//! STAGE2 with a stage 1 score of 75.00 from R1 and R2. Every step is also
//! compared with the lifecycle reference in both directions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::decision::Basis;
use fstp_domain::record::Record;
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::{ScoreKey, Stage};
use fstp_domain_testkit::r#gen::review::plan_of;
use fstp_domain_testkit::r#gen::review::{L1, PR1, R1, R2};
use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::mc::life_model::{
    Story, answer, ask, expire, life_judges, no_questions, rank, revision_milestone, revision_of,
    revision_plan, score, story_setup, submit_revision,
};

fn in_stage2(backend: Backend) -> Story {
    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let mut s = Story::new(&setup, backend, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.closed(L1, PR1, &[R1, R2], &[vec![2, 1], vec![2, 1]])
        .unwrap_or_else(|e| panic!("PR1 to STAGE2: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Stage2));
    s
}

fn asg(s: &Story, r: fstp_domain::id::AccountId) -> fstp_domain::id::AssignmentId {
    s.world
        .assignment(r, PR1, Stage::Two, AssignmentKind::Reviewer)
        .unwrap()
}

fn effective_basis(records: &[Record]) -> Option<Basis> {
    records.iter().find_map(|r| match r {
        Record::EffectiveScoreSet(e) => Some(e.basis()),
        _ => None,
    })
}

fn r_ev_05_every_reviewer_records_no_questions_on(b: Backend) {
    let mut s = in_stage2(b);
    let a1 = asg(&s, R1);
    s.run(&no_questions(R1, PR1, a1))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        s.state(PR1),
        Some(StateTag::Stage2),
        "O-50: one reviewer's \"no questions\" does not close the window"
    );
    let a2 = asg(&s, R2);
    let records = s
        .run(&no_questions(R2, PR1, a2))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        s.state(PR1),
        Some(StateTag::Ranked),
        "R-EV-05 AC: the last \"no questions\" reaches RANKED without waiting for P-07"
    );
    assert_eq!(
        effective_basis(&records),
        Some(Basis::Original),
        "I-09: with no revision the original plan carries forward"
    );
}

fn r_ev_05_a_question_keeps_the_window_open_on(b: Backend) {
    let mut s = in_stage2(b);
    let (a1, a2) = (asg(&s, R1), asg(&s, R2));
    s.run(&ask(R1, PR1, a1)).unwrap_or_else(|e| panic!("{e}"));
    s.run(&no_questions(R2, PR1, a2))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        s.state(PR1),
        Some(StateTag::Stage2),
        "NOTE 4: a question keeps the window open"
    );
    let refused = s
        .attempt(&no_questions(R1, PR1, a1))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        refused.is_none(),
        "NOTE 4: R1 asked and cannot record \"no questions\""
    );
    let end = s.world.life.window_end(PR1).unwrap();
    s.at(end);
    s.run(&expire(PR1)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        s.state(PR1),
        Some(StateTag::Deferred),
        "R-EV-07: P-07 elapsed without answers"
    );
}

fn r_ev_05_answers_or_a_scored_revision_conclude_stage2_on(b: Backend) {
    let mut s = in_stage2(b);
    let a1 = asg(&s, R1);
    s.run(&ask(R1, PR1, a1)).unwrap_or_else(|e| panic!("{e}"));
    s.run(&answer(L1, PR1)).unwrap_or_else(|e| panic!("{e}"));
    let early = s.attempt(&rank(R1, PR1)).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        early.is_none(),
        "NOTE 4: answers conclude stage 2 only once the window closed"
    );
    let plan = revision_of(PR1, 1);
    s.run(
        &revision_plan(
            L1,
            PR1,
            plan,
            Some(plan_of(PR1)),
            revision_milestone(PR1, 1),
        )
        .unwrap(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    s.run(&submit_revision(L1, PR1, plan))
        .unwrap_or_else(|e| panic!("{e}"));
    for r in [R1, R2] {
        let key = ScoreKey {
            assignment: asg(&s, r),
            stage: Stage::Two,
            plan,
        };
        s.run(&score(r, key, &[2, 2]))
            .unwrap_or_else(|e| panic!("{e}"));
    }
    let records = s.run(&rank(R2, PR1)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Ranked));
    assert_eq!(
        effective_basis(&records),
        Some(Basis::Revised),
        "I-09, P-24: the revision scores 100.00 against 75.00 and carries forward"
    );
}

/// R-EV-05 AC, NOTE 4, O-50: when every active assigned reviewer records
/// "no questions", the proposal reaches RANKED at once.
#[test]
fn r_ev_05_every_reviewer_records_no_questions() {
    r_ev_05_every_reviewer_records_no_questions_on(Backend::Production);
}

/// R-EV-05, O-50, R-EV-07: a question keeps the window open, and P-07 then runs.
#[test]
fn r_ev_05_a_question_keeps_the_window_open() {
    r_ev_05_a_question_keeps_the_window_open_on(Backend::Production);
}

/// R-EV-05, NOTE 4: a revised plan scored by P-03 reviewers concludes stage 2.
#[test]
fn r_ev_05_answers_or_a_scored_revision_conclude_stage2() {
    r_ev_05_answers_or_a_scored_revision_conclude_stage2_on(Backend::Production);
}

/// R-EV-05: the stories above pass on the references alone.
#[test]
fn r_ev_05_stories_pass_on_the_reference() {
    r_ev_05_every_reviewer_records_no_questions_on(Backend::Reference);
    r_ev_05_a_question_keeps_the_window_open_on(Backend::Reference);
    r_ev_05_answers_or_a_scored_revision_conclude_stage2_on(Backend::Reference);
}
