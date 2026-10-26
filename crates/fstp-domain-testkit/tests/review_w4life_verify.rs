//! Adversarial verification of lane L-LIFE (step W4b) after fix round 1.
//!
//! Each test fails against the lane's current code and passes once the
//! named defect is fixed. The final probes run on production alone, so a
//! fix does not depend on the lifecycle reference.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Command;
use fstp_domain::record::Record;
use fstp_domain::refusal::RefusalReason;
use fstp_domain_testkit::r#gen::review::{COORDINATOR, L1, L2, PR1, PR2, R1, R2};
use fstp_domain_testkit::r#gen::roster::{Backend, Step};
use fstp_domain_testkit::mc::life_model::{Story, admit_decision, by, life_judges, story_setup};

/// Runs `step` on production alone: the records when accepted, or the refusal.
fn production(s: &mut Story, step: &Step) -> Result<Vec<Record>, fstp_domain::refusal::Refusal> {
    match s.world.rev.exec(step) {
        Ok(r) => r,
        Err(e) => panic!("harness failure on {:?}: {e}", step.cmd),
    }
}

/// R-AU-01, `UsedIds` ("decide refuses a reused id"): PR1 is admitted to
/// STAGE1 under decision D. PR2's admission then reuses D. `intake_basis`
/// checks the used decision ids, but no fold ever marks an admission's
/// decision id as taken. So the second admission is accepted and two
/// decisions share one id in the audit trail.
#[test]
fn review_admission_decision_id_can_be_reused() {
    let setup = story_setup(vec![(L1, PR1, false), (L2, PR2, false)], life_judges());
    let mut s = Story::new(&setup, Backend::Production, |_| {}).unwrap();
    s.submit(L2, PR2).unwrap();
    s.to_stage1(L1, PR1, &[R1, R2]).unwrap();
    s.checked(L2, PR2, &[R1, R2]).unwrap();
    let reused = by(
        COORDINATOR,
        Command::AdmitToStage1 {
            decision: admit_decision(PR1),
            proposal: PR2,
        },
    );
    let out = production(&mut s, &reused);
    assert!(
        matches!(&out, Err(r) if r.reason == RefusalReason::IdReused),
        "the admission decision id of PR1 is already taken, so PR2's admission \
         under the same id must be refused with IdReused: {out:?}"
    );
}

/// R-LA-03, NOTE 13, fix of finding 7: IRC_REVIEW to NEGOTIATION is a
/// decision of the IRC members, and NOTE 13 lists it among neither the
/// timer rows nor the date rows that the System records. With P-15 = 1,
/// IRC validates and the vault then finds a conflict for IRC2, the one
/// outstanding IRC member. The vault reaction releases IRC2's assignment,
/// and `decision::contribute` takes PR1 into NEGOTIATION in that batch
/// with the System as the actor. No named human records the decision.
#[test]
fn review_vault_release_enters_negotiation_with_system_actor() {
    use fstp_domain::assignment::AssignmentKind;
    use fstp_domain::command::Actor;
    use fstp_domain::decision::Vote;
    use fstp_domain::rules::StateTag;
    use fstp_domain::scoring::Stage;
    use fstp_domain_testkit::r#gen::review::{IRC, R3, tag};
    use fstp_domain_testkit::r#gen::roster::call;
    use fstp_domain_testkit::mc::life_model::{
        IRC2, assign_declared, ballots, cut_off, cut_off_decision, irc_review,
    };
    use fstp_domain_testkit::vault::Relation;

    let mut setup = story_setup(vec![(L1, PR1, false)], life_judges());
    setup.p15 = 1;
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
    let a1 = s
        .world
        .assignment(IRC, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap();
    s.run(&irc_review(IRC, a1, true)).unwrap();
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
    s.world
        .rev
        .sod
        .truth
        .relate(tag(IRC2), tag(L1), Relation::CoWorker);
    let reaction = s
        .world
        .rev
        .sync()
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("the vault reaction: {r}"));
    assert!(
        reaction
            .iter()
            .any(|r| matches!(r, Record::AssignmentReleased(_))),
        "the conflict releases IRC2's assignment: {reaction:?}"
    );
    let by_system = reaction.iter().any(|r| {
        matches!(r, Record::Transitioned(t)
            if t.proposal == PR1
                && t.to == StateTag::Negotiation
                && matches!(t.actor, Actor::System(_)))
    });
    assert!(
        !by_system,
        "R-LA-03, NOTE 13: IRC_REVIEW to NEGOTIATION is a decision, yet the vault \
         reaction records it with the System as actor: {reaction:?}"
    );
}
