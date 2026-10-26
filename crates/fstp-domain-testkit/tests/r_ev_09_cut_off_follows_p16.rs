//! R-EV-09: committee cut-off decisions follow P-16 (policy-parameters NOTE 8, Conflict declarations).
//!
//! Each story runs production commands from genesis. PR1 by L1 and PR2 by
//! L2 are ranked with effective scores of 100.00 and 75.00, so the order is
//! PR1 then PR2. The committee is R1, R2, R3, R4, R5 and the chair. The
//! vault relates R3 and R5 to L2, so both recuse from the call's cut-off
//! vote. Four members may vote: R1, R2, R4 and the chair. A quorum is
//! more than half of them, so three. If recused members counted, it would
//! be four.
//!
//! Every attempt is also compared with the lifecycle reference in both
//! directions, so a test fails on any disagreement as well as on its own
//! assertion.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::decision::{Ballot, Vote};
use fstp_domain::id::AccountId;
use fstp_domain::record::Record;
use fstp_domain::roles::Role;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::review::{L1, L2, O1, O3, PR1, PR2, R1, R2, R3, R4, tag};
use fstp_domain_testkit::r#gen::roster::{Backend, call};
use fstp_domain_testkit::mc::life_model::{
    CHAIR, R5, Story, cut_off, cut_off_decision, life_judges, story_setup,
};
use fstp_domain_testkit::reference::lifecycle::p16_outcome;
use fstp_domain_testkit::vault::Relation;

fn story(backend: Backend) -> Story {
    let mut judges = life_judges();
    judges.push((R4, Role::CommitteeMember, Some(O3)));
    judges.push((R5, Role::CommitteeMember, Some(O1)));
    judges.push((CHAIR, Role::CommitteeChair, None));
    let setup = story_setup(vec![(L1, PR1, false), (L2, PR2, false)], judges);
    let mut s = Story::new(&setup, backend, |t| {
        t.relate(tag(R3), tag(L2), Relation::Relative);
        t.relate(tag(R5), tag(L2), Relation::CoWorker);
    })
    .unwrap_or_else(|e| panic!("story from genesis: {e}"));
    s.submit(L2, PR2).unwrap_or_else(|e| panic!("{e}"));
    s.ranked(L1, PR1, &[R1, R2], &[vec![2, 2], vec![2, 2]])
        .unwrap_or_else(|e| panic!("PR1 to RANKED: {e}"));
    s.ranked(L2, PR2, &[R1, R2], &[vec![2, 1], vec![2, 1]])
        .unwrap_or_else(|e| panic!("PR2 to RANKED: {e}"));
    s
}

fn own(voter: AccountId, vote: Vote) -> Ballot {
    Ballot {
        voter,
        vote,
        delegated_by: None,
    }
}

fn held(voter: AccountId, from: AccountId, vote: Vote) -> Ballot {
    Ballot {
        voter,
        vote,
        delegated_by: Some(from),
    }
}

/// The cut-off nominating PR1, under `ballots`: its records, or `None` when refused.
fn vote(backend: Backend, ballots: Vec<Ballot>) -> Option<Vec<Record>> {
    let mut s = story(backend);
    s.attempt(&cut_off(
        R1,
        cut_off_decision(1),
        call(1),
        vec![PR1, PR2],
        1,
        false,
        ballots,
    ))
    .unwrap_or_else(|e| panic!("{e}"))
}

fn adopted(b: Backend, ballots: Vec<Ballot>, why: &str) {
    match vote(b, ballots) {
        Some(_) => {}
        None => panic!("R-EV-09: {why}, but the cut-off was refused"),
    }
}

fn refused(b: Backend, ballots: Vec<Ballot>, why: &str) {
    if let Some(records) = vote(b, ballots) {
        panic!("R-EV-09: {why}, but the cut-off was recorded: {records:?}");
    }
}

/// R-EV-09, P-16 NOTE 8, Conflict declarations: a recused member's ballot
/// is refused, and recused members do not count towards the quorum. Three
/// of the four members who may vote form a quorum, and the record names
/// the recused members.
fn r_ev_09_recused_member_neither_votes_nor_counts_on(b: Backend) {
    refused(
        b,
        vec![
            own(R1, Vote::For),
            own(R2, Vote::For),
            own(R4, Vote::For),
            own(R5, Vote::For),
        ],
        "R5 is recused and may not vote",
    );
    let records = vote(
        b,
        vec![own(R1, Vote::For), own(R2, Vote::For), own(R4, Vote::For)],
    )
    .unwrap_or_else(|| panic!("R-EV-09: three of four members who may vote form a quorum"));
    let recused = records.iter().find_map(|r| match r {
        Record::CutOffRecorded(c) => Some(c.recused.clone()),
        _ => None,
    });
    assert_eq!(
        recused,
        Some([R3, R5].into_iter().collect()),
        "R-EV-09: the cut-off records R3 and R5 as recused"
    );
}

/// R-EV-09, P-16 NOTE 8: a quorum is more than half of the members who may
/// vote, and delegated votes count towards it.
fn r_ev_09_quorum_counts_delegated_votes_on(b: Backend) {
    refused(
        b,
        vec![own(R1, Vote::For), own(R2, Vote::For)],
        "two of four members are no quorum",
    );
    adopted(
        b,
        vec![
            own(R1, Vote::For),
            own(R2, Vote::For),
            held(R2, R4, Vote::For),
        ],
        "R2 holds R4's vote, so three of four take part",
    );
}

/// R-EV-09, P-16 NOTE 8: a decision needs a majority of the votes cast.
/// Test-author reading: abstentions are not votes cast.
fn r_ev_09_decision_needs_a_majority_of_votes_cast_on(b: Backend) {
    adopted(
        b,
        vec![
            own(R1, Vote::For),
            own(R2, Vote::For),
            own(R4, Vote::Against),
        ],
        "two votes for and one against are a majority",
    );
    refused(
        b,
        vec![
            own(R1, Vote::For),
            own(R2, Vote::Against),
            own(R4, Vote::Against),
        ],
        "one vote for and two against are no majority",
    );
    adopted(
        b,
        vec![
            own(R1, Vote::For),
            own(R2, Vote::Abstain),
            own(R4, Vote::Abstain),
        ],
        "one vote for and none against are a majority of the votes cast",
    );
}

/// R-EV-09, P-16 NOTE 8: a member holds at most one delegated vote.
fn r_ev_09_member_holds_at_most_one_delegated_vote_on(b: Backend) {
    refused(
        b,
        vec![
            own(R1, Vote::For),
            held(R1, R2, Vote::For),
            held(R1, R4, Vote::For),
        ],
        "R1 holds two delegated votes",
    );
    adopted(
        b,
        vec![
            own(R1, Vote::For),
            held(R1, R2, Vote::For),
            own(R4, Vote::For),
        ],
        "R1 holds one delegated vote",
    );
}

/// R-EV-09, Conflict declarations: no vote is delegated to or from a recused member.
fn r_ev_09_no_delegation_to_or_from_a_recused_member_on(b: Backend) {
    refused(
        b,
        vec![
            own(R1, Vote::For),
            own(R2, Vote::For),
            own(R4, Vote::For),
            held(R1, R5, Vote::For),
        ],
        "R5 is recused and may not delegate",
    );
    refused(
        b,
        vec![
            own(R1, Vote::For),
            own(R2, Vote::For),
            held(R3, R4, Vote::For),
        ],
        "R3 is recused and may not hold R4's vote",
    );
}

/// R-EV-09, P-16 NOTE 8: the committee chair has a casting vote on a tie.
fn r_ev_09_chair_casting_vote_breaks_a_tie_on(b: Backend) {
    adopted(
        b,
        vec![
            own(R1, Vote::For),
            own(R2, Vote::Against),
            own(R4, Vote::Against),
            own(CHAIR, Vote::For),
        ],
        "two to two, and the chair votes for",
    );
    refused(
        b,
        vec![
            own(R1, Vote::For),
            own(R2, Vote::For),
            own(R4, Vote::Against),
            own(CHAIR, Vote::Against),
        ],
        "two to two, and the chair votes against",
    );
}

/// R-EV-09: the stories above pass on the references alone.
#[test]
fn r_ev_09_stories_pass_on_the_reference() {
    let mut s = story(Backend::Reference);
    let records = s
        .run(&cut_off(
            R1,
            cut_off_decision(1),
            call(1),
            vec![PR1, PR2],
            1,
            false,
            vec![own(R1, Vote::For), own(R2, Vote::For), own(R4, Vote::For)],
        ))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        records
            .iter()
            .any(|r| matches!(r, Record::CutOffRecorded(_)))
    );
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
    assert_eq!(s.state(PR2), Some(StateTag::NotSelected));
}

/// R-EV-09: the reference P-16 rule on its own, over the committee of these stories.
#[test]
fn r_ev_09_reference_p16_rule() {
    let members = [R1, R2, R3, R4, R5, CHAIR].into_iter().collect();
    let recused = [R3, R5].into_iter().collect();
    let chairs = [CHAIR].into_iter().collect();
    let rule = |b: Vec<Ballot>| p16_outcome(&members, &recused, &chairs, &b);
    assert_eq!(
        rule(vec![
            own(R1, Vote::For),
            own(R2, Vote::For),
            own(R4, Vote::For)
        ]),
        Ok(true)
    );
    assert!(rule(vec![own(R1, Vote::For), own(R2, Vote::For)]).is_err());
    assert!(
        rule(vec![
            own(R5, Vote::For),
            own(R1, Vote::For),
            own(R2, Vote::For)
        ])
        .is_err()
    );
    assert_eq!(
        rule(vec![
            own(R1, Vote::For),
            own(R2, Vote::Against),
            own(R4, Vote::Against),
            own(CHAIR, Vote::For),
        ]),
        Ok(true)
    );
    assert_eq!(
        rule(vec![
            own(R1, Vote::Against),
            own(R2, Vote::For),
            own(R4, Vote::For),
            own(CHAIR, Vote::Against),
        ]),
        Ok(false)
    );
}

/// R-EV-09, P-16: see [`r_ev_09_recused_member_neither_votes_nor_counts_on`], over production.
#[test]
fn r_ev_09_recused_member_neither_votes_nor_counts() {
    r_ev_09_recused_member_neither_votes_nor_counts_on(Backend::Production);
}

/// R-EV-09, P-16: see [`r_ev_09_quorum_counts_delegated_votes_on`], over production.
#[test]
fn r_ev_09_quorum_counts_delegated_votes() {
    r_ev_09_quorum_counts_delegated_votes_on(Backend::Production);
}

/// R-EV-09, P-16: see [`r_ev_09_decision_needs_a_majority_of_votes_cast_on`], over production.
#[test]
fn r_ev_09_decision_needs_a_majority_of_votes_cast() {
    r_ev_09_decision_needs_a_majority_of_votes_cast_on(Backend::Production);
}

/// R-EV-09, P-16: see [`r_ev_09_member_holds_at_most_one_delegated_vote_on`], over production.
#[test]
fn r_ev_09_member_holds_at_most_one_delegated_vote() {
    r_ev_09_member_holds_at_most_one_delegated_vote_on(Backend::Production);
}

/// R-EV-09, P-16: see [`r_ev_09_no_delegation_to_or_from_a_recused_member_on`], over production.
#[test]
fn r_ev_09_no_delegation_to_or_from_a_recused_member() {
    r_ev_09_no_delegation_to_or_from_a_recused_member_on(Backend::Production);
}

/// R-EV-09, P-16: see [`r_ev_09_chair_casting_vote_breaks_a_tie_on`], over production.
#[test]
fn r_ev_09_chair_casting_vote_breaks_a_tie() {
    r_ev_09_chair_casting_vote_breaks_a_tie_on(Backend::Production);
}

/// R-EV-09, P-16: every ballot case above passes on the references alone.
#[test]
fn r_ev_09_ballot_cases_pass_on_the_reference() {
    r_ev_09_recused_member_neither_votes_nor_counts_on(Backend::Reference);
    r_ev_09_quorum_counts_delegated_votes_on(Backend::Reference);
    r_ev_09_decision_needs_a_majority_of_votes_cast_on(Backend::Reference);
    r_ev_09_member_holds_at_most_one_delegated_vote_on(Backend::Reference);
    r_ev_09_no_delegation_to_or_from_a_recused_member_on(Backend::Reference);
    r_ev_09_chair_casting_vote_breaks_a_tie_on(Backend::Reference);
}
