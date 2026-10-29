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
//! Since M4 change D5 (Q4 interim reading, pending Daniel), R1 opens a
//! round, each member casts or delegates their own ballot, and R1 records
//! the cut-off, which counts only the ballots cast. So an invalid ballot
//! is now refused when its member casts it, and the cut-off is refused
//! only when the ballots cast do not adopt it. The stories below run on
//! production directly after the start state, so they do not depend on
//! the lifecycle reference. Two stories run the whole cut-off through
//! [`Story`], which compares every step with the references in both
//! directions. D5 overturns the reference-mode run of the ballot cases,
//! because the M2 references judged ballots inside `RecordCutOff`, which
//! no longer carries them. M-BALLOT judges them now
//! (`r_ev_09_m_ballot.rs`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Command;
use fstp_domain::decision::{Ballot, Vote};
use fstp_domain::id::{AccountId, DecisionId};
use fstp_domain::record::{CutOffRecorded, Record};
use fstp_domain::refusal::{Refusal, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain::rules::StateTag;
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::{L1, L2, O1, O3, PR1, PR2, R1, R2, R3, R4, tag};
use fstp_domain_testkit::r#gen::roster::{Backend, Step, call};
use fstp_domain_testkit::mc::ballot_model::run_core;
use fstp_domain_testkit::mc::life_model::{
    CHAIR, R5, Story, cast, cut_off, cut_off_decision, delegate, life_judges, open_round,
    record_cut_off, story_setup,
};
use fstp_domain_testkit::reference::lifecycle::p16_outcome;
use fstp_domain_testkit::vault::{GroundTruth, Relation};

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

/// The round of every story.
fn round() -> DecisionId {
    cut_off_decision(1)
}

/// The production projection of the story with the round open, nominating
/// PR1 only. Every later command runs on production directly.
struct Round {
    core: State,
    truth: GroundTruth,
    now: Timestamp,
}

impl Round {
    fn open() -> Round {
        let s = story(Backend::Production);
        let mut r = Round {
            core: s.world.rev.sod.state.clone(),
            truth: s.world.rev.sod.truth.clone(),
            now: s.world.now(),
        };
        let step = open_round(R1, round(), call(1), vec![PR1, PR2], 1, false);
        r.must(&step);
        r
    }

    /// Runs `step` on production, committing it when accepted.
    fn act(&mut self, step: &Step) -> Result<Vec<Record>, Refusal> {
        let fstp_domain::command::Actor::Account(actor) = step.actor else {
            panic!("a System step in a ballot story");
        };
        let out = run_core(&self.core, &self.truth, self.now, actor, &step.cmd)
            .unwrap_or_else(|e| panic!("harness: {e}"));
        out.map(|(core, records)| {
            self.core = core;
            records
        })
    }

    fn must(&mut self, step: &Step) -> Vec<Record> {
        self.act(step)
            .unwrap_or_else(|r| panic!("{:?} by {:?} refused: {r}", step.cmd, step.actor))
    }

    fn refused(&mut self, step: &Step, why: &str) -> Refusal {
        match self.act(step) {
            Ok(records) => panic!(
                "R-EV-09: {why}, but {:?} was recorded: {records:?}",
                step.cmd
            ),
            Err(r) => r,
        }
    }

    fn cast(&mut self, member: AccountId, vote: Vote) {
        self.must(&cast(member, round(), vote));
    }

    fn record(&mut self) -> Result<CutOffRecorded, Refusal> {
        self.act(&record_cut_off(R1, round())).map(|records| {
            records
                .iter()
                .find_map(|r| match r {
                    Record::CutOffRecorded(c) => Some(c.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("a recorded cut-off without CutOffRecorded: {records:?}"))
        })
    }
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

/// The counted ballots of `c`, as a set for comparison.
fn counted(c: &CutOffRecorded) -> Vec<(AccountId, Option<AccountId>, bool)> {
    let mut out: Vec<(AccountId, Option<AccountId>, bool)> = c
        .ballots
        .iter()
        .map(|b| (b.voter, b.delegated_by, b.vote == Vote::For))
        .collect();
    out.sort();
    out
}

/// R-EV-09, P-16 NOTE 8, Conflict declarations: a recused member's ballot
/// and delegation are refused when the member casts them, and recused
/// members do not count towards the quorum. Three of the four members who
/// may vote form a quorum, and the record names the recused members.
#[test]
fn r_ev_09_recused_member_neither_votes_nor_counts() {
    let mut r = Round::open();
    let refusal = r.refused(
        &cast(R5, round(), Vote::For),
        "R5 is recused and may not vote",
    );
    assert_eq!(
        refusal.rule,
        RuleRef::I03,
        "the recused member is refused under I-03"
    );
    r.refused(
        &delegate(R5, round(), R1),
        "R5 is recused and may not delegate",
    );
    r.cast(R1, Vote::For);
    r.cast(R2, Vote::For);
    r.cast(R4, Vote::For);
    let c = r.record().unwrap_or_else(|e| {
        panic!("R-EV-09: three of four members who may vote form a quorum: {e}")
    });
    assert_eq!(
        c.recused,
        [R3, R5].into_iter().collect(),
        "R-EV-09: the cut-off records R3 and R5 as recused"
    );
    assert_eq!(
        counted(&c),
        vec![(R1, None, true), (R2, None, true), (R4, None, true)],
        "R-EV-09: the cut-off counts exactly the ballots cast"
    );
}

/// R-EV-09, P-16 NOTE 8: a quorum is more than half of the members who may
/// vote, and delegated votes count towards it.
#[test]
fn r_ev_09_quorum_counts_delegated_votes() {
    let mut r = Round::open();
    r.cast(R1, Vote::For);
    r.cast(R2, Vote::For);
    let refusal = r
        .record()
        .err()
        .unwrap_or_else(|| panic!("two of four members are no quorum"));
    assert_eq!(refusal.rule, RuleRef::Rev09, "the quorum is R-EV-09's");
    r.must(&delegate(R4, round(), R2));
    let c = r
        .record()
        .unwrap_or_else(|e| panic!("R2 holds R4's vote, so three of four take part: {e}"));
    assert_eq!(
        counted(&c),
        vec![(R1, None, true), (R2, None, true), (R2, Some(R4), true)],
        "R-EV-09: R4's delegated vote counts with R2's own ballot"
    );
}

/// R-EV-09, P-16 NOTE 8: a decision needs a majority of the votes cast.
/// Test-author reading: abstentions are not votes cast.
#[test]
fn r_ev_09_decision_needs_a_majority_of_votes_cast() {
    let cases: [([Vote; 3], bool, &str); 3] = [
        (
            [Vote::For, Vote::For, Vote::Against],
            true,
            "two votes for and one against are a majority",
        ),
        (
            [Vote::For, Vote::Against, Vote::Against],
            false,
            "one vote for and two against are no majority",
        ),
        (
            [Vote::For, Vote::Abstain, Vote::Abstain],
            true,
            "one vote for and none against are a majority of the votes cast",
        ),
    ];
    for (votes, adopted, why) in cases {
        let mut r = Round::open();
        for (m, v) in [R1, R2, R4].into_iter().zip(votes) {
            r.cast(m, v);
        }
        assert_eq!(r.record().is_ok(), adopted, "R-EV-09: {why}");
    }
}

/// R-EV-09, P-16 NOTE 8: a member holds at most one delegated vote.
#[test]
fn r_ev_09_member_holds_at_most_one_delegated_vote() {
    let mut r = Round::open();
    r.must(&delegate(R2, round(), R1));
    r.refused(
        &delegate(R4, round(), R1),
        "R1 would hold two delegated votes",
    );
    r.cast(R1, Vote::For);
    r.cast(R4, Vote::For);
    let c = r
        .record()
        .unwrap_or_else(|e| panic!("R1 holds one delegated vote: {e}"));
    assert_eq!(
        counted(&c),
        vec![(R1, None, true), (R1, Some(R2), true), (R4, None, true)],
        "R-EV-09: R2's vote counts once, with R1's ballot"
    );
}

/// R-EV-09, Conflict declarations: no vote is delegated to or from a recused member.
#[test]
fn r_ev_09_no_delegation_to_or_from_a_recused_member() {
    let mut r = Round::open();
    r.refused(
        &delegate(R5, round(), R1),
        "R5 is recused and may not delegate",
    );
    r.refused(
        &delegate(R4, round(), R3),
        "R3 is recused and may not hold R4's vote",
    );
    r.must(&delegate(R4, round(), R2));
}

/// R-EV-09, P-16 NOTE 8: the committee chair has a casting vote on a tie.
#[test]
fn r_ev_09_chair_casting_vote_breaks_a_tie() {
    let cases: [([Vote; 4], bool, &str); 2] = [
        (
            [Vote::For, Vote::Against, Vote::Against, Vote::For],
            true,
            "two to two, and the chair votes for",
        ),
        (
            [Vote::For, Vote::For, Vote::Against, Vote::Against],
            false,
            "two to two, and the chair votes against",
        ),
    ];
    for (votes, adopted, why) in cases {
        let mut r = Round::open();
        for (m, v) in [R1, R2, R4, CHAIR].into_iter().zip(votes) {
            r.cast(m, v);
        }
        assert_eq!(r.record().is_ok(), adopted, "R-EV-09: {why}");
    }
}

/// R-EV-09, D5: the whole cut-off through [`Story`], production and the
/// references agreeing on every step. PR1 reaches IRC_REVIEW and PR2
/// NOT_SELECTED, and the ballots counted are the ballots cast.
#[test]
fn r_ev_09_cut_off_through_the_story() {
    let mut s = story(Backend::Production);
    let records = s
        .run(&cut_off(
            R1,
            round(),
            call(1),
            vec![PR1, PR2],
            1,
            false,
            vec![
                own(R1, Vote::For),
                own(R2, Vote::For),
                held(R2, R4, Vote::For),
            ],
        ))
        .unwrap_or_else(|e| panic!("{e}"));
    let c = records
        .iter()
        .find_map(|r| match r {
            Record::CutOffRecorded(c) => Some(c.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no CutOffRecorded in {records:?}"));
    assert_eq!(
        counted(&c),
        vec![(R1, None, true), (R2, None, true), (R2, Some(R4), true)]
    );
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
    assert_eq!(s.state(PR2), Some(StateTag::NotSelected));
}

/// R-EV-09: the story above passes on the references alone.
#[test]
fn r_ev_09_stories_pass_on_the_reference() {
    let mut s = story(Backend::Reference);
    let records = s
        .run(&cut_off(
            R1,
            round(),
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

/// R-EV-09, D5: `RecordCutOff` names only its round. The pattern lists
/// every field, so a ballot field that came back would fail to compile
/// here: no member's session can state another member's vote.
#[test]
fn r_ev_09_record_cut_off_names_only_its_round() {
    let Command::RecordCutOff { round: named } = record_cut_off(R1, round()).cmd else {
        panic!("record_cut_off builds a RecordCutOff");
    };
    assert_eq!(named, round());
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
