//! I-27, Q5 (Daniel, 2026-11-23; ADR-036 section 7): every outcome of a
//! proposal enqueues its outcome notice, `OutboxEnqueued(ProposalOutcome)`,
//! in the batch of its transition. Until 2026-11-23 only INELIGIBLE did.
//!
//! - NOT_SELECTED, from the stage 1 close below P-02 and from the cut-off.
//! - NEGOTIATION (selected), from the IRC validation that completes.
//! - DECLINED, from the decline after an IRC concern and from the
//!   programme manager's decline of a negotiation.
//!
//! The notice names the proposal and the state it reached, nothing else:
//! the email it fires carries ids, time and a link only (I-27). A move
//! that is no outcome (STAGE1 to STAGE2, RANKED to IRC_REVIEW) enqueues
//! none.
//!
//! The lifecycle stories run production commands from genesis and compare
//! every step with the lifecycle reference in both directions, and pass
//! on the references alone too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::Actor;
use fstp_domain::decision::Vote;
use fstp_domain::id::ProposalId;
use fstp_domain::record::{OutboxEvent, Record};
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::Stage;
use fstp_domain_testkit::r#gen::money::{MoneySetup, MoneyStory, PC, decline_negotiation};
use fstp_domain_testkit::r#gen::review::{IRC, L1, L2, PR1, PR2, R1, R2, R3};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, call};
use fstp_domain_testkit::mc::life_model::{
    IRC2, Story, assign_declared, ballots, cut_off, cut_off_decision, decline, irc_review,
    life_judges, story_setup,
};

/// The outcome notices of `records`, as (proposal, state).
fn notices(records: &[Record]) -> Vec<(ProposalId, StateTag)> {
    records
        .iter()
        .filter_map(|r| match r {
            Record::OutboxEnqueued(OutboxEvent::ProposalOutcome { proposal, state }) => {
                Some((*proposal, *state))
            }
            _ => None,
        })
        .collect()
}

/// The (proposal, target) of every transition of `records`.
fn moves(records: &[Record]) -> Vec<(ProposalId, StateTag)> {
    records
        .iter()
        .filter_map(|r| match r {
            Record::Transitioned(t) => Some((t.proposal, t.to)),
            _ => None,
        })
        .collect()
}

/// PR1 and PR2 of leads L1 and L2, both submitted.
fn two(b: Backend) -> Story {
    let setup = story_setup(vec![(L1, PR1, false), (L2, PR2, false)], life_judges());
    let mut s = Story::new(&setup, b, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.submit(L2, PR2).unwrap_or_else(|e| panic!("{e}"));
    s
}

/// PR1 ranked and nominated into IRC_REVIEW, with IRC and IRC2 assigned
/// and declared. Returns the cut-off's records.
fn in_irc_review(s: &mut Story) -> Vec<Record> {
    s.ranked(L1, PR1, &[R1, R2], &[vec![2, 2], vec![2, 2]])
        .unwrap_or_else(|e| panic!("PR1 to RANKED: {e}"));
    let records = s
        .run(&cut_off(
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
    records
}

fn stage1_not_selected_on(b: Backend) {
    let mut s = two(b);
    let records = s
        .closed(L1, PR1, &[R1, R2], &[vec![0, 0], vec![0, 0]])
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(moves(&records), vec![(PR1, StateTag::NotSelected)]);
    assert_eq!(
        notices(&records),
        vec![(PR1, StateTag::NotSelected)],
        "I-27, Q5: the stage 1 close below P-02 enqueues the NOT_SELECTED notice: {records:?}"
    );
    let mut s = two(b);
    let records = s
        .closed(L1, PR1, &[R1, R2], &[vec![2, 2], vec![2, 2]])
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(moves(&records), vec![(PR1, StateTag::Stage2)]);
    assert!(
        notices(&records).is_empty(),
        "STAGE2 is no outcome, so no notice: {records:?}"
    );
}

fn cut_off_not_selected_on(b: Backend) {
    let mut s = two(b);
    s.ranked(L1, PR1, &[R1, R2], &[vec![2, 2], vec![2, 2]])
        .unwrap_or_else(|e| panic!("{e}"));
    s.ranked(L2, PR2, &[R1, R2], &[vec![2, 1], vec![2, 1]])
        .unwrap_or_else(|e| panic!("{e}"));
    let records = s
        .run(&cut_off(
            R2,
            cut_off_decision(7),
            call(1),
            vec![PR1, PR2],
            1,
            false,
            ballots(&[R1, R2, R3], Vote::For),
        ))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        notices(&records),
        vec![(PR2, StateTag::NotSelected)],
        "I-27, Q5: PR2 below the cut-off gets its notice, PR1 in IRC_REVIEW none: {records:?}"
    );
}

fn negotiation_on(b: Backend) {
    let mut s = two(b);
    let cut = in_irc_review(&mut s);
    assert!(
        notices(&cut).is_empty(),
        "IRC_REVIEW is no outcome: {cut:?}"
    );
    let mut records = Vec::new();
    for member in [IRC, IRC2] {
        let a = s
            .world
            .assignment(member, PR1, Stage::Two, AssignmentKind::Irc)
            .unwrap_or_else(|| panic!("no IRC assignment of {member:?}"));
        records.extend(
            s.run(&irc_review(member, a, true))
                .unwrap_or_else(|e| panic!("{member:?} validates: {e}")),
        );
    }
    assert_eq!(s.state(PR1), Some(StateTag::Negotiation));
    assert_eq!(
        notices(&records),
        vec![(PR1, StateTag::Negotiation)],
        "I-27, Q5: the entry into NEGOTIATION enqueues the selected notice once: {records:?}"
    );
}

fn declined_after_concern_on(b: Backend) {
    let mut s = two(b);
    in_irc_review(&mut s);
    let a = s
        .world
        .assignment(IRC, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap_or_else(|| panic!("no IRC assignment"));
    let concern = s
        .run(&irc_review(IRC, a, false))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        notices(&concern).is_empty(),
        "the concern itself is no outcome: {concern:?}"
    );
    let records = s
        .run(&decline(Actor::Account(STAFF_PM), PR1))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(moves(&records), vec![(PR1, StateTag::Declined)]);
    assert_eq!(
        notices(&records),
        vec![(PR1, StateTag::Declined)],
        "I-27, Q5: IRC_REVIEW to DECLINED enqueues the declined notice: {records:?}"
    );
}

/// I-27, Q5: the stage 1 close below P-02 enqueues the NOT_SELECTED notice.
#[test]
fn i27_q5_stage1_not_selected_enqueues_its_notice() {
    stage1_not_selected_on(Backend::Production);
}

/// I-27, Q5: a proposal below the cut-off gets the NOT_SELECTED notice.
#[test]
fn i27_q5_cut_off_not_selected_enqueues_its_notice() {
    cut_off_not_selected_on(Backend::Production);
}

/// I-27, Q5: the entry into NEGOTIATION enqueues the selected notice.
#[test]
fn i27_q5_negotiation_enqueues_the_selected_notice() {
    negotiation_on(Backend::Production);
}

/// I-27, Q5: the decline after an IRC concern enqueues the DECLINED notice.
#[test]
fn i27_q5_decline_after_concern_enqueues_its_notice() {
    declined_after_concern_on(Backend::Production);
}

/// I-27, Q5: the stories above pass on the references alone.
#[test]
fn i27_q5_outcome_notice_stories_pass_on_the_reference() {
    stage1_not_selected_on(Backend::Reference);
    cut_off_not_selected_on(Backend::Reference);
    negotiation_on(Backend::Reference);
    declined_after_concern_on(Backend::Reference);
}

fn negotiation_declined_on(b: Backend) {
    let mut s = MoneyStory::new(&MoneySetup::sybil([400, 300, 100]), b)
        .unwrap_or_else(|e| panic!("three proposals to NEGOTIATION from genesis: {e}"));
    let records = s
        .run(&decline_negotiation(Actor::Account(STAFF_PM), PC))
        .unwrap_or_else(|e| panic!("NOTE 9: the programme manager records the decline: {e}"));
    assert_eq!(
        notices(&records),
        vec![(PC, StateTag::Declined)],
        "I-27, Q5: NEGOTIATION to DECLINED enqueues the declined notice: {records:?}"
    );
}

/// I-27, Q5: the programme manager's decline of a negotiation enqueues
/// the DECLINED notice, in production and on the references alone.
#[test]
fn i27_q5_negotiation_declined_enqueues_its_notice() {
    negotiation_declined_on(Backend::Production);
    negotiation_declined_on(Backend::Reference);
}
