//! R-EV-09: each committee member casts or delegates their own ballot (M4 design section 3.4, D5).
//!
//! Q4 interim reading, pending Daniel: under M2 one recorder entered every
//! member's ballot in `RecordCutOff`. Since D5 a member opens a round with
//! the order, the rank position, the rationale and the P-17 tie-break.
//! Each member who is not recused casts or delegates their own ballot,
//! and a member records the cut-off, which counts only the ballots cast.
//!
//! Every story starts from the M-BALLOT start state, built from genesis by
//! production commands: PR1 and PR2 RANKED in call 1, the committee R1,
//! R2, R4 and R5 with CHAIR, R5 recused, and the round opened by R1. Each
//! command runs on production `queries`, `decide` and `apply` directly.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::{Actor, Command};
use fstp_domain::decision::Vote;
use fstp_domain::id::{AccountId, DecisionId};
use fstp_domain::record::{Record, RulesVersion};
use fstp_domain::refusal::{Refusal, RuleRef};
use fstp_domain::rules::StateTag;
use fstp_domain::state::State;
use fstp_domain_testkit::r#gen::policy::text;
use fstp_domain_testkit::r#gen::review::{COORDINATOR, IRC, L1, PR1, PR2, R1, R2, R4};
use fstp_domain_testkit::r#gen::roster::{Step, call};
use fstp_domain_testkit::mc::ballot_model::{BallotModel, RECORDER, RECUSED, ROUND, run_core};
use fstp_domain_testkit::mc::life_model::{CHAIR, cast, delegate, open_round, record_cut_off};

/// The M-BALLOT start: the round open, nothing cast.
struct World {
    model: BallotModel,
    core: State,
}

impl World {
    fn new() -> World {
        let model = BallotModel::new().unwrap_or_else(|e| panic!("start from genesis: {e}"));
        let core = model.start.core.clone();
        World { model, core }
    }

    fn act(&mut self, step: &Step) -> Result<Vec<Record>, Refusal> {
        let Actor::Account(actor) = step.actor else {
            panic!("a System step in a ballot story");
        };
        run_core(
            &self.core,
            &self.model.truth,
            self.model.now,
            actor,
            &step.cmd,
        )
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .map(|(core, records)| {
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
            Ok(records) => panic!("R-EV-09: {why}, but production recorded {records:?}"),
            Err(r) => r,
        }
    }

    fn state(&self, p: fstp_domain::id::ProposalId) -> Option<StateTag> {
        fstp_domain::view::proposal_state(&self.core, p)
    }
}

/// R-EV-09, R-EV-08, D5: the opening records the round with the order, the
/// rank position, the rationale and its opener, and no ballot. No proposal
/// moves before the cut-off is recorded.
#[test]
fn r_ev_09_open_round_records_the_round_and_no_ballot() {
    let w = World::new();
    let opened = w.model.start.records.iter().any(|r| {
        *r == Record::CutOffRoundOpened {
            round: ROUND,
            call: call(1),
            order: vec![PR1, PR2],
            nominated: 1,
            rationale: text(85_000),
            tie_breaks: None,
            by: RECORDER,
        }
    });
    assert!(
        opened,
        "the opening records CutOffRoundOpened: {:?}",
        w.model.start.records
    );
    assert!(
        !w.model.start.records.iter().any(|r| matches!(
            r,
            Record::BallotCast { .. } | Record::CutOffRecorded(_) | Record::Transitioned(_)
        )),
        "the opening casts no ballot and moves no proposal"
    );
    assert_eq!(w.state(PR1), Some(StateTag::Ranked));
    assert_eq!(w.state(PR2), Some(StateTag::Ranked));
}

/// R-EV-09, Q4: a cast records the casting member's own ballot, and the
/// command names no voter, so it cannot state another member's vote.
#[test]
fn r_ev_09_cast_records_the_casting_member_only() {
    let mut w = World::new();
    let records = w.must(&cast(R2, ROUND, Vote::Against));
    let casts: Vec<&Record> = records
        .iter()
        .filter(|r| matches!(r, Record::BallotCast { .. }))
        .collect();
    assert_eq!(
        casts,
        vec![&Record::BallotCast {
            round: ROUND,
            voter: R2,
            vote: Vote::Against,
        }],
        "R-EV-09: the batch holds R2's own ballot and nothing else"
    );
    let Command::CastBallot { round, vote } = cast(R2, ROUND, Vote::For).cmd else {
        panic!("cast builds a CastBallot");
    };
    assert_eq!(
        (round, vote),
        (ROUND, Vote::For),
        "CastBallot names its round and vote only"
    );
}

/// R-EV-09, P-16 NOTE 8: a member casts once, does not cast after
/// delegating, and does not delegate after casting.
#[test]
fn r_ev_09_member_casts_or_delegates_once() {
    let mut w = World::new();
    w.must(&cast(R2, ROUND, Vote::For));
    w.refused(&cast(R2, ROUND, Vote::Against), "R2 already cast");
    w.refused(
        &delegate(R2, ROUND, R1),
        "R2 already cast, so R2 cannot delegate",
    );
    w.must(&delegate(R4, ROUND, R1));
    w.refused(
        &cast(R4, ROUND, Vote::For),
        "R4 delegated, so R4 cannot cast",
    );
    w.refused(&delegate(R4, ROUND, R2), "R4 already delegated");
    w.refused(&delegate(R1, ROUND, R1), "nobody delegates to themselves");
}

/// R-EV-09, Conflict declarations: the recused member neither casts nor
/// delegates, and nobody delegates to it. The refusal names I-03.
#[test]
fn r_ev_09_recused_member_cannot_take_part() {
    let mut w = World::new();
    let r = w.refused(&cast(RECUSED, ROUND, Vote::For), "R5 is recused");
    assert_eq!(r.rule, RuleRef::I03);
    w.refused(
        &delegate(RECUSED, ROUND, R1),
        "R5 is recused and may not delegate",
    );
    w.refused(
        &delegate(R1, ROUND, RECUSED),
        "R5 is recused and may not hold a vote",
    );
}

/// R-EV-09: only committee members and the chair cast. The coordinator, an
/// IRC member and a lead are refused.
#[test]
fn r_ev_09_non_member_cannot_cast() {
    let mut w = World::new();
    for a in [COORDINATOR, IRC, L1] {
        w.refused(&cast(a, ROUND, Vote::For), "a non-member casts");
    }
    w.must(&cast(CHAIR, ROUND, Vote::For));
}

/// R-EV-09, D5: nothing acts in a round that was never opened, and only
/// one round is open per call at a time. A recused member cannot open a
/// round, and the order must be the call's RANKED proposals by
/// non-increasing effective score (R-EV-08).
#[test]
fn r_ev_09_rounds_open_once_and_in_order() {
    let mut w = World::new();
    let other = DecisionId::from_raw(9_399);
    w.refused(&cast(R2, other, Vote::For), "no round 9399 was opened");
    w.refused(&record_cut_off(R1, other), "no round 9399 was opened");
    w.refused(
        &open_round(R2, other, call(1), vec![PR1, PR2], 1, false),
        "a round of call 1 is already open",
    );
    w.refused(
        &open_round(RECUSED, other, call(1), vec![PR1, PR2], 1, false),
        "a recused member opens a round",
    );
    let mut closed = World::new();
    closed.must(&cast(R1, ROUND, Vote::For));
    closed.must(&cast(R2, ROUND, Vote::For));
    closed.must(&cast(R4, ROUND, Vote::For));
    closed.must(&record_cut_off(R1, ROUND));
    closed.refused(
        &open_round(R2, other, call(1), vec![PR2, PR1], 1, false),
        "no proposal of call 1 is RANKED any more",
    );
}

/// R-EV-09, R-LA-03, D5: the recorded cut-off names the round as its
/// decision, its recorder and the M4 rules version. Each transition names
/// the round as its decision. After it the round is closed: no cast, no
/// delegation and no second record.
#[test]
fn r_ev_09_recorded_round_closes() {
    let mut w = World::new();
    w.must(&cast(R1, ROUND, Vote::For));
    w.must(&cast(R2, ROUND, Vote::For));
    w.must(&cast(R4, ROUND, Vote::Against));
    let records = w.must(&record_cut_off(R2, ROUND));
    let c = records
        .iter()
        .find_map(|r| match r {
            Record::CutOffRecorded(c) => Some(c.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no CutOffRecorded in {records:?}"));
    assert_eq!(c.decision, ROUND);
    assert_eq!(c.recorder, R2, "R-LA-03: the member who records is named");
    assert_eq!(
        c.rules,
        RulesVersion::M4,
        "D7: a D5 cut-off carries the M4 rules version"
    );
    for r in &records {
        if let Record::Transitioned(t) = r {
            assert_eq!(t.decision, Some(ROUND), "the transition names the round");
            assert_eq!(t.actor, Actor::Account(R2));
        }
    }
    assert_eq!(w.state(PR1), Some(StateTag::IrcReview));
    assert_eq!(w.state(PR2), Some(StateTag::NotSelected));
    w.refused(&cast(CHAIR, ROUND, Vote::For), "the round is closed");
    w.refused(&delegate(CHAIR, ROUND, R1), "the round is closed");
    w.refused(&record_cut_off(R1, ROUND), "the round is closed");
}

/// R-EV-09: the opener need not vote, and the vote of a member who has not
/// cast counts for nobody.
#[test]
fn r_ev_09_uncast_votes_count_for_nobody() {
    let mut w = World::new();
    w.must(&delegate(R4, ROUND, R2));
    w.must(&cast(R2, ROUND, Vote::For));
    w.must(&cast(CHAIR, ROUND, Vote::For));
    let records = w.must(&record_cut_off(R1, ROUND));
    let voters: Vec<(AccountId, Option<AccountId>)> = records
        .iter()
        .find_map(|r| match r {
            Record::CutOffRecorded(c) => {
                let mut v: Vec<(AccountId, Option<AccountId>)> = c
                    .ballots
                    .iter()
                    .map(|b| (b.voter, b.delegated_by))
                    .collect();
                v.sort();
                Some(v)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("no CutOffRecorded in {records:?}"));
    assert_eq!(
        voters,
        vec![(R2, None), (R2, Some(R4)), (CHAIR, None)],
        "R1 opened and recorded the round without voting, so no ballot of R1 counts"
    );
}
