//! Reproducers from the independent review of lane L-LIFE (step W4b, model and test strength).
//!
//! Each test fails against the lane's code as reviewed and passes once the
//! defect it names is fixed. The final check of each test runs production
//! alone, so a fix in production does not depend on a reference change.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::Actor;
use fstp_domain::decision::Vote;
use fstp_domain::record::Record;
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::{ScoreKey, Stage};
use fstp_domain_testkit::r#gen::review::{IRC, L1, L2, PR1, PR2, R1, R2, R3, plan_of, tag};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, Step, Steps, call, publish};
use fstp_domain_testkit::mc::life_model::{
    IRC2, Story, assign_declared, ballots, cut_off, cut_off_decision, decline, expire, irc_review,
    life_judges, rank, revision_of, score, story_setup, submit_revision, system,
};
use fstp_domain_testkit::vault::Relation;

/// Whether `records` take `proposal` into `to`.
fn moves_to(records: &[Record], proposal: fstp_domain::id::ProposalId, to: StateTag) -> bool {
    records
        .iter()
        .any(|r| matches!(r, Record::Transitioned(t) if t.proposal == proposal && t.to == to))
}

/// Runs `step` on production alone. `Some` holds the records of an accepted step.
fn production(s: &mut Story, steps: &impl Steps) -> Option<Vec<Record>> {
    let mut out = Vec::new();
    for step in steps.as_steps() {
        match s.world.rev.exec(step) {
            Ok(Ok(records)) => out.extend(records),
            Ok(Err(_)) => return None,
            Err(e) => panic!("harness: {e}"),
        }
    }
    Some(out)
}

/// PR1 in IRC_REVIEW in call 1, with IRC and IRC2 assigned and declared.
fn in_irc_review() -> Story {
    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let mut s = Story::new(&setup, Backend::Production, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.ranked(L1, PR1, &[R1, R2], &[vec![2, 2], vec![2, 2]])
        .unwrap_or_else(|e| panic!("PR1 to RANKED: {e}"));
    s.run(&cut_off(
        R1,
        cut_off_decision(1),
        call(1),
        vec![PR1],
        1,
        false,
        ballots(&[R1, R2, R3], Vote::For),
    ))
    .unwrap_or_else(|e| panic!("PR1 to IRC_REVIEW: {e}"));
    for i in [IRC, IRC2] {
        for st in assign_declared(i, PR1, call(1), AssignmentKind::Irc) {
            s.run(&st).unwrap_or_else(|e| panic!("{e}"));
        }
    }
    s
}

/// NOTE 7, R-IR-02: a concern raised while no later call exists leaves
/// PR1 in IRC_REVIEW for the programme manager's decline. Once a later
/// call of the programme is published, the IRC_REVIEW to DEFERRED guard
/// holds ("concern raised; future call exists") and the decline guard
/// fails. Some command must then take the row, or PR1 is stuck for good.
#[test]
fn review_irc_concern_then_later_call_published_is_stuck() {
    let mut s = in_irc_review();
    let a1 = s
        .world
        .assignment(IRC, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap();
    let a2 = s
        .world
        .assignment(IRC2, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap();
    s.run(&irc_review(IRC, a1, false))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
    s.run(&publish(call(2))).unwrap_or_else(|e| panic!("{e}"));
    let mut candidates = vec![
        irc_review(IRC2, a2, false),
        irc_review(IRC, a1, false),
        decline(Actor::Account(STAFF_PM), PR1),
    ];
    let now = s.world.now();
    candidates.extend(
        fstp_domain::due(&s.world.rev.sod.state, now)
            .into_iter()
            .map(system),
    );
    let deferred = candidates.iter().any(|step| {
        let mut probe = s.clone();
        production(&mut probe, step).is_some_and(|r| moves_to(&r, PR1, StateTag::Deferred))
    });
    assert!(
        deferred,
        "NOTE 7: after the later call is published, no command takes PR1 from IRC_REVIEW to DEFERRED"
    );
}

/// O-50, NOTE 4, R-EV-07: R1 and R2 record "no questions", then R3's
/// assignment is released for a conflict found in the vault. Every active
/// assigned reviewer has then recorded "no questions", so the window has
/// closed with answers deemed complete. P-07 elapsing must not defer PR1.
#[test]
fn review_no_questions_complete_after_a_release_is_still_deferred() {
    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let mut s = Story::new(&setup, Backend::Production, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.closed(
        L1,
        PR1,
        &[R1, R2, R3],
        &[vec![2, 1], vec![2, 1], vec![2, 1]],
    )
    .unwrap_or_else(|e| panic!("PR1 to STAGE2: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Stage2));
    s.no_questions(PR1, &[R1, R2])
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Stage2));
    let reaction = s
        .vault(|t| t.relate(tag(R3), tag(L1), Relation::CoWorker))
        .unwrap_or_else(|e| panic!("the conflict reaction: {e}"));
    assert!(
        reaction
            .iter()
            .any(|r| matches!(r, Record::AssignmentReleased(_))),
        "the conflict releases R3's assignment: {reaction:?}"
    );
    let end = s.world.life.window_end(PR1).unwrap();
    s.at(end);
    let expired = production(&mut s, &expire(PR1));
    assert!(
        !expired.is_some_and(|r| moves_to(&r, PR1, StateTag::Deferred)),
        "O-50: every active assigned reviewer recorded \"no questions\", yet P-07 defers PR1"
    );
}

/// R-EV-08, design 3.7: the remaining budget the cut-off records is the
/// one the committee sees in the ranking view. PR1 carries forward a
/// revision of 2000.00 against a submitted plan of 1000.00 and enters
/// IRC_REVIEW. Round 2 of the cut-off then records one remaining budget
/// while `ranking_view` shows another.
#[test]
fn review_cut_off_budget_differs_from_ranking_view() {
    let setup = story_setup(vec![(L1, PR1, false), (L2, PR2, false)], life_judges());
    let mut s = Story::new(&setup, Backend::Production, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.submit(L2, PR2).unwrap_or_else(|e| panic!("{e}"));
    s.closed(L1, PR1, &[R1, R2], &[vec![2, 1], vec![2, 1]])
        .unwrap_or_else(|e| panic!("PR1 to STAGE2: {e}"));
    let plan = revision_of(PR1, 1);
    let tasks = fstp_domain_testkit::r#gen::review::tasks(&[
        fstp_domain_testkit::mc::life_model::revision_milestone(PR1, 1),
        fstp_domain_testkit::mc::life_model::revision_milestone(PR1, 2),
    ])
    .unwrap();
    let mut digest = [9u8; 32];
    let (head, _) = digest.split_at_mut(16);
    head.copy_from_slice(&plan.raw().to_be_bytes());
    s.run(&fstp_domain_testkit::mc::life_model::by(
        L1,
        fstp_domain::command::Command::RecordPlanVersion {
            plan,
            proposal: PR1,
            origin: fstp_domain::proposal::PlanOrigin::Stage2Revision,
            supersedes: Some(plan_of(PR1)),
            tasks,
            content: fstp_domain::id::ContentDigest::from_bytes(digest),
        },
    ))
    .unwrap_or_else(|e| panic!("the revision of 2000.00: {e}"));
    s.run(&submit_revision(L1, PR1, plan))
        .unwrap_or_else(|e| panic!("{e}"));
    for r in [R1, R2] {
        let key = ScoreKey {
            assignment: s
                .world
                .assignment(r, PR1, Stage::Two, AssignmentKind::Reviewer)
                .unwrap(),
            stage: Stage::Two,
            plan,
        };
        s.run(&score(r, key, &[2, 2]))
            .unwrap_or_else(|e| panic!("{e}"));
    }
    s.run(&rank(R1, PR1)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Ranked));
    s.run(&cut_off(
        R1,
        cut_off_decision(1),
        call(1),
        vec![PR1],
        1,
        false,
        ballots(&[R1, R2, R3], Vote::For),
    ))
    .unwrap_or_else(|e| panic!("round 1: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
    s.ranked(L2, PR2, &[R1, R2], &[vec![2, 1], vec![2, 1]])
        .unwrap_or_else(|e| panic!("PR2 to RANKED: {e}"));
    let shown = fstp_domain::visibility::ranking_view(&s.world.rev.sod.state, call(1))
        .unwrap()
        .first()
        .map(|row| row.remaining_budget);
    let records = production(
        &mut s,
        &cut_off(
            R1,
            cut_off_decision(2),
            call(1),
            vec![PR2],
            0,
            false,
            ballots(&[R1, R2, R3], Vote::For),
        ),
    )
    .unwrap_or_else(|| panic!("round 2 was refused"));
    let recorded = records.iter().find_map(|r| match r {
        Record::CutOffRecorded(c) => Some(c.remaining_budget),
        _ => None,
    });
    assert_eq!(
        recorded, shown,
        "R-EV-08: the recorded remaining budget differs from the ranking view the committee used"
    );
}

/// R-MC-05, P-77, NOTE 13, O-49: the lane makes IRC_REVIEW to DECLINED a
/// programme manager's decision. Under P-77 "draft only" a decision through
/// MCP must be refused, as the IRC review through MCP is. The decline
/// through MCP is accepted, because `DeclineAfterConcern` still counts as
/// a non-binding action.
#[test]
fn review_decline_after_concern_through_mcp_ignores_p77() {
    let mut s = in_irc_review();
    let a1 = s
        .world
        .assignment(IRC, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap();
    let a2 = s
        .world
        .assignment(IRC2, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap();
    let now = s.world.now();
    let through_mcp = |s: &Story, step: &Step| {
        let mut ctx = step.ctx(
            now,
            fstp_domain::id::CommandId::from_bytes(*b"review:life:mcp!"),
        );
        ctx.via = fstp_domain::command::Via::Mcp;
        let state = &s.world.rev.sod.state;
        let mut answers = fstp_domain::oracle::Answers::new();
        for q in fstp_domain::queries(state, &step.cmd, &ctx)? {
            let a = s.world.rev.answer(&q);
            answers.insert(q, a);
        }
        fstp_domain::decide(state, &step.cmd, &ctx, &answers)
    };
    let review = through_mcp(&s, &irc_review(IRC2, a2, true));
    assert!(
        matches!(&review, Err(r) if r.rule == fstp_domain::refusal::RuleRef::Param(fstp_domain::rules::ParamId::P77)),
        "the setup's P-77 is \"draft only\", so an IRC review through MCP is refused: {review:?}"
    );
    s.run(&irc_review(IRC, a1, false))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
    let declined = through_mcp(&s, &decline(Actor::Account(STAFF_PM), PR1));
    assert!(
        declined.is_err(),
        "P-77: the programme manager's decline is a decision, yet MCP records it: {declined:?}"
    );
}
