//! Independent review of lane L-LIFE (step W4b): spec fidelity reproducers.
//!
//! Each test fails against the lane's current code and passes once the
//! named defect is fixed. The stories run production commands from
//! genesis. The final probes run on production alone, so a fix does not
//! depend on the lifecycle reference.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command};
use fstp_domain::decision::Vote;
use fstp_domain::id::{AccountId, AssignmentId, ProposalId};
use fstp_domain::record::Record;
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::{ScoreKey, Stage};
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, IRC, L1, PR1, R1, R2, R3, plan_of, unassign,
};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, Step, call, publish};
use fstp_domain_testkit::mc::life_model::{
    IRC2, Story, assign_declared, ballots, cut_off, cut_off_decision, decline, irc_review,
    life_judges, no_questions, rank, revision_milestone, revision_of, revision_plan, score,
    story_setup, submit_revision,
};

/// Runs `step` on production alone. `Some(records)` when accepted.
fn production(s: &mut Story, step: &Step) -> Option<Vec<Record>> {
    match s.world.rev.exec(step) {
        Ok(Ok(records)) => Some(records),
        Ok(Err(_)) => None,
        Err(e) => panic!("harness failure on {:?}: {e}", step.cmd),
    }
}

fn moves(records: &[Record], proposal: ProposalId, to: StateTag) -> bool {
    records
        .iter()
        .any(|r| matches!(r, Record::Transitioned(t) if t.proposal == proposal && t.to == to))
}

fn asg(s: &Story, r: AccountId) -> AssignmentId {
    s.world
        .assignment(r, PR1, Stage::Two, AssignmentKind::Reviewer)
        .unwrap()
}

/// PR1 in IRC_REVIEW in call 1, with IRC and IRC2 assigned and declared,
/// and no later call published.
fn in_irc_review() -> Story {
    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let mut s = Story::new(&setup, Backend::Production, |_| {}).unwrap();
    s.ranked(L1, PR1, &[R1, R2], &[vec![2, 2], vec![2, 2]])
        .unwrap();
    s.run(&cut_off(
        R1,
        cut_off_decision(1),
        call(1),
        vec![PR1],
        1,
        false,
        ballots(&[R1, R2, R3], Vote::For),
    ))
    .unwrap();
    for i in [IRC, IRC2] {
        for st in assign_declared(i, PR1, call(1), AssignmentKind::Irc) {
            s.run(&st).unwrap();
        }
    }
    s
}

/// NOTE 7, R-IR-02, rows IRC_REVIEW to DEFERRED and to DECLINED: a concern
/// raised while no later call is published leaves PR1 in IRC_REVIEW. Once
/// a later call of the programme is published, the DECLINED row no longer
/// applies, but nothing can take the DEFERRED row either: the decline is
/// refused, a second concern is refused and `due` offers nothing. The
/// proposal is stuck in IRC_REVIEW with only withdrawal left.
#[test]
fn review_irc_concern_then_later_call_leaves_proposal_stuck() {
    let mut s = in_irc_review();
    let a = s
        .world
        .assignment(IRC, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap();
    s.run(&irc_review(IRC, a, false)).unwrap();
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
    s.run(&publish(call(2))).unwrap();

    let declined = production(&mut s.clone(), &decline(Actor::Account(STAFF_PM), PR1));
    let a2 = s
        .world
        .assignment(IRC2, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap();
    let deferred = production(&mut s.clone(), &irc_review(IRC2, a2, false));
    let due: Vec<Command> = fstp_domain::due(&s.world.rev.sod.state, s.world.now())
        .into_iter()
        .filter(|c| {
            matches!(c, Command::DeclineAfterConcern { proposal } | Command::ReEnter { proposal, .. }
                if *proposal == PR1)
        })
        .collect();
    assert!(
        declined.is_some_and(|r| moves(&r, PR1, StateTag::Declined))
            || deferred.is_some_and(|r| moves(&r, PR1, StateTag::Deferred))
            || !due.is_empty(),
        "NOTE 7: after a concern, PR1 must still leave IRC_REVIEW by the DEFERRED \
         or the DECLINED row once a later call is published"
    );
}

/// Rows STAGE2 to RANKED and STAGE2 to DEFERRED, NOTE 4, R-EV-07: the lead
/// submits a revised plan that P-03 assigned reviewers score, so stage 2
/// has concluded. No question was asked, so no `AnswersRecorded` exists.
/// When P-07 elapses, `due` still offers `ExpireStage2`, and the System
/// defers a proposal whose revised plan has its stage 2 quorum.
#[test]
fn review_scored_revision_is_offered_for_stage2_expiry() {
    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let mut s = Story::new(&setup, Backend::Production, |_| {}).unwrap();
    s.closed(L1, PR1, &[R1, R2], &[vec![2, 1], vec![2, 1]])
        .unwrap();
    assert_eq!(s.state(PR1), Some(StateTag::Stage2));
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
    .unwrap();
    s.run(&submit_revision(L1, PR1, plan)).unwrap();
    for r in [R1, R2] {
        let key = ScoreKey {
            assignment: asg(&s, r),
            stage: Stage::Two,
            plan,
        };
        s.run(&score(r, key, &[2, 2])).unwrap();
    }
    let end = s.world.life.window_end(PR1).unwrap();
    s.at(end);
    let ranks = production(&mut s.clone(), &rank(R1, PR1));
    assert!(
        ranks.is_some_and(|r| moves(&r, PR1, StateTag::Ranked)),
        "NOTE 4: the scored revision concludes stage 2"
    );
    let due = fstp_domain::due(&s.world.rev.sod.state, end);
    assert!(
        !due.contains(&Command::ExpireStage2 { proposal: PR1 }),
        "R-EV-07: a revised plan with P-03 valid stage 2 scores is not a proposal \
         without stage 2 answers, yet due offers {due:?}"
    );
}

/// NOTE 4, O-50: R1 and R2 record "no questions", then the coordinator
/// releases R3, the only active assigned reviewer who had not. Every
/// active assigned reviewer has now recorded "no questions", so the
/// window has closed with answers deemed complete. Production neither
/// ranks PR1 in the release batch nor accepts `RankAfterStage2`, and the
/// System later defers PR1 under P-07 instead.
#[test]
fn review_no_questions_by_every_remaining_reviewer_never_ranks() {
    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let mut s = Story::new(&setup, Backend::Production, |_| {}).unwrap();
    s.closed(
        L1,
        PR1,
        &[R1, R2, R3],
        &[vec![2, 1], vec![2, 1], vec![2, 1]],
    )
    .unwrap();
    assert_eq!(s.state(PR1), Some(StateTag::Stage2));
    for r in [R1, R2] {
        let id = asg(&s, r);
        s.run(&no_questions(r, PR1, id)).unwrap();
    }
    let a3 = asg(&s, R3);
    let released = production(&mut s, &unassign(COORDINATOR, a3)).unwrap();
    let ranked_now = moves(&released, PR1, StateTag::Ranked);
    let ranks = production(&mut s.clone(), &rank(R1, PR1));
    assert!(
        ranked_now || ranks.is_some_and(|r| moves(&r, PR1, StateTag::Ranked)),
        "O-50: every active assigned reviewer recorded \"no questions\", so \
         STAGE2 to RANKED applies"
    );
}

/// Runs `step` through MCP on production, with the vault's answers, and
/// returns the decision without committing it.
fn through_mcp(s: &Story, step: &Step) -> Result<Vec<Record>, fstp_domain::refusal::Refusal> {
    let mut ctx = step.ctx(
        s.world.now(),
        fstp_domain::id::CommandId::from_bytes(*b"review:w4life:mc"),
    );
    ctx.via = fstp_domain::command::Via::Mcp;
    let state = &s.world.rev.sod.state;
    let mut answers = fstp_domain::oracle::Answers::new();
    for q in fstp_domain::queries(state, &step.cmd, &ctx)? {
        let a = s.world.rev.answer(&q);
        answers.insert(q, a);
    }
    fstp_domain::decide(state, &step.cmd, &ctx, &answers)
}

/// R-MC-05, P-77, NOTE 13, O-49: the lane made `DeclineAfterConcern` a
/// decision the programme manager records. Under P-77 "draft only" every
/// binding action through MCP is refused, yet the decline still counts as
/// a non-binding System command. So a programme manager declines PR1
/// through MCP, while an IRC review through MCP is refused under P-77.
#[test]
fn review_decline_after_concern_through_mcp_bypasses_p77() {
    let mut s = in_irc_review();
    let a = s
        .world
        .assignment(IRC, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap();
    let a2 = s
        .world
        .assignment(IRC2, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap();
    let review = through_mcp(&s, &irc_review(IRC2, a2, true));
    assert!(
        matches!(&review, Err(r) if r.rule == fstp_domain::refusal::RuleRef::Param(
            fstp_domain::rules::ParamId::P77)),
        "the setup's P-77 is draft only: {review:?}"
    );
    s.run(&irc_review(IRC, a, false)).unwrap();
    let declined = through_mcp(&s, &decline(Actor::Account(STAFF_PM), PR1));
    assert!(
        declined.is_err(),
        "R-MC-05: the programme manager's decline is a binding decision and \
         P-77 \"draft only\" refuses it through MCP, yet it was accepted: {declined:?}"
    );
}
