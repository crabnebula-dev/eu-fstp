//! Review reproducers for the M2 final review (W7).
//!
//! Each test runs production commands from genesis and is compared with
//! the references in both directions. Each one failed before its fix.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{AccountId, ProposalId};
use fstp_domain::record::{OutboxEvent, Record};
use fstp_domain::refusal::RuleRef;
use fstp_domain_testkit::r#gen::review::{L1, L2, PR1, PR2, R1, R2, judge_binding};
use fstp_domain_testkit::r#gen::roster::{Backend, end};
use fstp_domain_testkit::mc::life_model::{Story, T_EVAL, life_judges, story_setup};
use fstp_domain_testkit::vault::IdentityTag;

/// The identity of the staff programme manager in the synthetic vault.
const STAFF_PM_IDENTITY: IdentityTag = IdentityTag::new(903);

fn notifiable(records: &[Record], account: AccountId, proposal: ProposalId) -> bool {
    let detected = records.iter().any(|r| {
        matches!(r, Record::ConflictDetected(d)
            if d.account == account && d.proposal == proposal && d.notifiable)
    });
    let drafted = records.iter().any(|r| {
        matches!(r, Record::OutboxEnqueued(OutboxEvent::NotifiableConflict { proposal: p })
            if *p == proposal)
    });
    detected && drafted
}

/// R-CF-04, I-06, Identity discovery: R1 and R2 score PR1 and stage 1
/// closes. The tenant admin then ends R1's committee binding, and the
/// vault merges R1 into the staff programme manager's identity. The ended
/// Judging binding is suspended as a conflict of interest, so the scores
/// R1 gave get a notifiable conflict and a notification draft.
#[test]
fn review_w7_coi_suspension_of_an_ended_judge_marks_its_scores_notifiable() {
    let setup = story_setup(vec![(L1, PR1, false), (L2, PR2, false)], life_judges());
    let mut s = Story::new(&setup, Backend::Production, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.closed(L1, PR1, &[R1, R2], &[vec![2, 1], vec![2, 1]])
        .unwrap_or_else(|e| panic!("PR1 through stage 1: {e}"));
    let t = T_EVAL;
    s.at(t);
    s.run(&end(judge_binding(1), t))
        .unwrap_or_else(|e| panic!("EndRole of R1's committee binding: {e}"));
    let records = s
        .vault(|t| t.set_identity(R1, STAFF_PM_IDENTITY))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    assert!(
        records
            .iter()
            .any(|r| matches!(r, Record::BindingSuspended(b)
            if b.binding == judge_binding(1) && b.rule == RuleRef::I06)),
        "Identity discovery: R1's ended committee binding is suspended under I-06: {records:?}"
    );
    assert!(
        notifiable(&records, R1, PR1),
        "R-CF-04: the scores of the suspended, ended judge R1 on PR1 are notifiable: {records:?}"
    );
}

/// SoD-10, I-34, I-35 (decided 2026-10-25): each committee binding records
/// the reviewer's organisation, and SoD-10 and I-34 count organisations
/// from that field. A `GrantRole` of a committee member without one is
/// refused, so no reviewer can switch off I-34 or I-35 by leaving it out.
/// The same grant with an organisation is accepted.
#[test]
fn review_w7_committee_grant_without_organisation_is_refused() {
    use fstp_domain::command::Command;
    use fstp_domain::id::BindingId;
    use fstp_domain::roles::Role;
    use fstp_domain_testkit::r#gen::review::{O1, R4, tag};
    use fstp_domain_testkit::r#gen::roster::{P1, grant};

    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let mut s = Story::new(&setup, Backend::Production, |t| {
        t.set_identity(R4, tag(R4));
        t.verify(R4);
    })
    .unwrap_or_else(|e| panic!("{e}"));
    s.at(T_EVAL);
    let mut g = grant(
        BindingId::from_raw(9_001),
        R4,
        P1,
        Role::CommitteeMember,
        T_EVAL,
    );
    if let Command::GrantRole { organisation, .. } = &mut g.cmd {
        *organisation = None;
    }
    let out = s
        .attempt(&g)
        .unwrap_or_else(|e| panic!("the grant without organisation: {e}"));
    assert!(
        out.is_none(),
        "SoD-10, I-34: a committee grant without organisation is refused: {out:?}"
    );
    if let Command::GrantRole { organisation, .. } = &mut g.cmd {
        *organisation = Some(O1);
    }
    s.run(&g)
        .unwrap_or_else(|e| panic!("the same grant with an organisation: {e}"));
}

/// The judges of the I-34 release stories: R1 and R3 of O1, R2 of O2.
fn two_org_judges() -> Vec<(
    AccountId,
    fstp_domain::roles::Role,
    Option<fstp_domain::id::OrganisationId>,
)> {
    use fstp_domain_testkit::r#gen::review::{O1, O2, R3};
    use fstp_domain_testkit::mc::life_model::R5;
    let mut judges = life_judges();
    for j in &mut judges {
        if j.0 == R3 {
            j.2 = Some(O1);
        }
    }
    judges.push((R5, fstp_domain::roles::Role::CommitteeMember, Some(O2)));
    judges
}

/// I-34, SoD-10: the assigned reviewers of a proposal belong to at least
/// P-39 distinct organisations. R1 and R3 (O1) and R2 (O2) admit PR1 with
/// P-39 = 2 and P-03 = 2. The coordinator then releases R2, the only O2
/// reviewer. R1 and R3 score, and the stage 1 close is refused, since
/// the scores would come from one organisation. A new O2 reviewer
/// restores the count, and the close is accepted once it scores.
#[test]
fn review_w7_i34_stage1_close_needs_p39_organisations_after_a_release() {
    use fstp_domain::assignment::AssignmentKind;
    use fstp_domain::command::Actor;
    use fstp_domain::rules::StateTag;
    use fstp_domain_testkit::r#gen::review::{COORDINATOR, R3, unassign};
    use fstp_domain_testkit::r#gen::roster::call;
    use fstp_domain_testkit::mc::life_model::{R5, assign_declared, assignment_of, close};

    let setup = story_setup(vec![(L1, PR1, false)], two_org_judges());
    let mut s = Story::new(&setup, Backend::Production, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.to_stage1(L1, PR1, &[R1, R2, R3])
        .unwrap_or_else(|e| panic!("PR1 to STAGE1 over O1 and O2: {e}"));
    let r2 = assignment_of(R2, PR1, call(1), AssignmentKind::Reviewer);
    s.run(&unassign(COORDINATOR, r2))
        .unwrap_or_else(|e| panic!("the release of R2: {e}"));
    s.score_stage1(PR1, &[R1, R3], &[vec![2, 1], vec![2, 1]])
        .unwrap_or_else(|e| panic!("R1 and R3 score: {e}"));
    let out = s
        .attempt(&close(Actor::Account(COORDINATOR), PR1))
        .unwrap_or_else(|e| panic!("the close over one organisation: {e}"));
    assert!(
        out.is_none(),
        "I-34: the stage 1 close over reviewers of one organisation is refused: {out:?}"
    );
    assert_eq!(s.state(PR1), Some(StateTag::Stage1));
    // A new O2 reviewer restores the count.
    for st in assign_declared(R5, PR1, call(1), AssignmentKind::Reviewer) {
        s.run(&st)
            .unwrap_or_else(|e| panic!("the assignment of R5 (O2): {e}"));
    }
    s.score_stage1(PR1, &[R5], &[vec![2, 1]])
        .unwrap_or_else(|e| panic!("R5 scores: {e}"));
    s.run(&close(Actor::Account(COORDINATOR), PR1))
        .unwrap_or_else(|e| panic!("the close over O1 and O2: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Stage2));
}

/// I-34, SoD-10, NOTE 4: the same release after the stage 1 close. R1,
/// R2 and R3 close stage 1 and PR1 enters STAGE2. The coordinator
/// releases R2, the only O2 reviewer. "No questions" by R1 and R3 then
/// ranks nothing, and `RankAfterStage2` is refused, since the ranking
/// would rest on one organisation. A new O2 reviewer's "no questions"
/// ranks PR1.
#[test]
fn review_w7_i34_stage2_ranking_needs_p39_organisations_after_a_release() {
    use fstp_domain::assignment::AssignmentKind;
    use fstp_domain::rules::StateTag;
    use fstp_domain_testkit::r#gen::review::{COORDINATOR, R3, unassign};
    use fstp_domain_testkit::r#gen::roster::call;
    use fstp_domain_testkit::mc::life_model::{R5, assign_declared, assignment_of, rank};

    let setup = story_setup(vec![(L1, PR1, false)], two_org_judges());
    let mut s = Story::new(&setup, Backend::Production, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.closed(
        L1,
        PR1,
        &[R1, R2, R3],
        &[vec![2, 1], vec![2, 1], vec![2, 1]],
    )
    .unwrap_or_else(|e| panic!("PR1 through stage 1: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Stage2));
    let r2 = assignment_of(R2, PR1, call(1), AssignmentKind::Reviewer);
    s.run(&unassign(COORDINATOR, r2))
        .unwrap_or_else(|e| panic!("the release of R2: {e}"));
    s.no_questions(PR1, &[R1, R3])
        .unwrap_or_else(|e| panic!("no questions by R1 and R3: {e}"));
    assert_eq!(
        s.state(PR1),
        Some(StateTag::Stage2),
        "I-34: no ranking over reviewers of one organisation"
    );
    let out = s
        .attempt(&rank(R1, PR1))
        .unwrap_or_else(|e| panic!("the ranking over one organisation: {e}"));
    assert!(
        out.is_none(),
        "I-34: RankAfterStage2 over reviewers of one organisation is refused: {out:?}"
    );
    for st in assign_declared(R5, PR1, call(1), AssignmentKind::Reviewer) {
        s.run(&st)
            .unwrap_or_else(|e| panic!("the assignment of R5 (O2): {e}"));
    }
    s.no_questions(PR1, &[R5])
        .unwrap_or_else(|e| panic!("no questions by R5: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Ranked));
}

/// R-IR-01, R-LA-03, I-03: IRC_REVIEW to NEGOTIATION is the IRC members'
/// row, computed by `RecordIrcReview` only, with a conflict-free actor.
/// With P-15 = 1, IRC validates PR1. IRC2 then declares a conflict on its
/// own IRC assignment, which releases it. That batch must not record the
/// entry into NEGOTIATION under IRC2, who just declared a conflict. PR1
/// stays in IRC_REVIEW, and IRC records the entry by repeating its
/// validation.
#[test]
fn review_w7_irc_entry_is_never_recorded_by_a_conflicted_releaser() {
    use fstp_domain::assignment::AssignmentKind;
    use fstp_domain::command::Actor;
    use fstp_domain::command::DeclarationSubject;
    use fstp_domain::decision::Vote;
    use fstp_domain::rules::{Row, StateTag};
    use fstp_domain::scoring::Stage;
    use fstp_domain_testkit::r#gen::review::{IRC, R3, declare};
    use fstp_domain_testkit::r#gen::roster::call;
    use fstp_domain_testkit::mc::life_model::{
        IRC2, assign_declared, ballots, cut_off, cut_off_decision, irc_review,
    };

    let mut setup = story_setup(vec![(L1, PR1, false)], life_judges());
    setup.p15 = 1;
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
    let irc = |s: &Story, who| {
        s.world
            .assignment(who, PR1, Stage::Two, AssignmentKind::Irc)
            .unwrap()
    };
    let a1 = irc(&s, IRC);
    let a2 = irc(&s, IRC2);
    s.run(&irc_review(IRC, a1, true))
        .unwrap_or_else(|e| panic!("IRC validates: {e}"));
    let records = s
        .world
        .rev
        .exec(&declare(
            IRC2,
            DeclarationSubject::Assignment(a2),
            true,
            false,
        ))
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("IRC2 declares a conflict: {r}"));
    assert!(
        !records.iter().any(|r| matches!(r, Record::Transitioned(t)
            if t.proposal == PR1 && t.row == Row::IrcReviewToNegotiation)),
        "R-LA-03, I-03: the conflicted IRC2 records no IRC review outcome: {records:?}"
    );
    let now = s.world.now();
    for r in &records {
        s.world
            .life
            .fold(r, now)
            .unwrap_or_else(|e| panic!("the lifecycle reference folds {r:?}: {e}"));
    }
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
    let entry = s
        .run(&irc_review(IRC, a1, true))
        .unwrap_or_else(|e| panic!("R-IR-01: IRC repeats its validation: {e}"));
    let t = entry
        .iter()
        .find_map(|r| match r {
            Record::Transitioned(t) if t.row == Row::IrcReviewToNegotiation => Some(*t),
            _ => None,
        })
        .unwrap_or_else(|| panic!("the repeat records the entry: {entry:?}"));
    assert_eq!(
        t.actor,
        Actor::Account(IRC),
        "R-LA-03: IRC records the entry"
    );
    assert_eq!(s.state(PR1), Some(StateTag::Negotiation));
}
