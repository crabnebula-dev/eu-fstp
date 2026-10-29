//! R-IR-01, R-LA-03: a release never records the IRC review outcome. A
//! validated IRC member records the entry into NEGOTIATION.
//!
//! The stories run production commands from genesis and compare every step
//! but the release with the lifecycle reference in both directions. PR1 is
//! ranked, nominated and in IRC_REVIEW of call 1, with IRC and IRC2
//! assigned and declared.
//! IRC validates, and the coordinator then releases IRC2's assignment.
//!
//! - With P-15 = 1, IRC is every reviewing IRC member. The release batch
//!   still records no entry, since IRC_REVIEW to NEGOTIATION is the IRC
//!   members' row, computed by `RecordIrcReview` only. IRC then repeats
//!   its validation, which records the entry under IRC.
//! - With P-15 = 2, one active IRC assignment is fewer than P-15, so PR1
//!   stays in IRC_REVIEW.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::Actor;
use fstp_domain::decision::Vote;
use fstp_domain::record::Record;
use fstp_domain::rules::{Row, StateTag};
use fstp_domain::scoring::Stage;
use fstp_domain_testkit::r#gen::review::{COORDINATOR, IRC, L1, PR1, R1, R2, R3, unassign};
use fstp_domain_testkit::r#gen::roster::{Backend, call};
use fstp_domain_testkit::mc::life_model::{
    IRC2, Story, assign_declared, ballots, cut_off, cut_off_decision, irc_review, life_judges,
    story_setup,
};

/// PR1 in IRC_REVIEW under `p15`, with IRC and IRC2 assigned, IRC validated
/// and IRC2's assignment then released. Returns the release's records.
fn released(backend: Backend, p15: u8) -> (Story, Vec<Record>) {
    let mut setup = story_setup(vec![(L1, PR1, false)], life_judges());
    setup.p15 = p15;
    let mut s = Story::new(&setup, backend, |_| {}).unwrap_or_else(|e| panic!("{e}"));
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
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
    // The L-REV reference expects an `Unassign` batch to hold its own
    // records only, so the release runs on production, and the lifecycle
    // reference folds its records.
    let records = s
        .world
        .rev
        .exec(&unassign(COORDINATOR, a2))
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("IRC2's assignment is released: {r}"));
    let now = s.world.now();
    for r in &records {
        s.world
            .life
            .fold(r, now)
            .unwrap_or_else(|e| panic!("the lifecycle reference folds {r:?}: {e}"));
    }
    (s, records)
}

fn entered_negotiation(records: &[Record]) -> bool {
    records.iter().any(|r| {
        matches!(r, Record::Transitioned(t)
            if t.proposal == PR1
                && t.to == StateTag::Negotiation
                && t.row == Row::IrcReviewToNegotiation
                && t.decision.is_none())
    })
}

fn r_ir_01_release_leaves_the_entry_to_a_validated_member_on(b: Backend) {
    let (mut s, records) = released(b, 1);
    assert!(
        !entered_negotiation(&records),
        "R-LA-03: the coordinator's release records no IRC review outcome: {records:?}"
    );
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
    let a1 = s
        .world
        .assignment(IRC, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap();
    let entry = s
        .run(&irc_review(IRC, a1, true))
        .unwrap_or_else(|e| panic!("R-IR-01: IRC repeats its validation: {e}"));
    let t = entry
        .iter()
        .find_map(|r| match r {
            Record::Transitioned(t) if t.row == Row::IrcReviewToNegotiation => Some(*t),
            _ => None,
        })
        .unwrap_or_else(|| panic!("R-IR-01: the repeat records the entry: {entry:?}"));
    assert_eq!(
        t.actor,
        Actor::Account(IRC),
        "R-LA-03: the validated IRC member records the entry"
    );
    assert_eq!(s.state(PR1), Some(StateTag::Negotiation));
}

fn r_ir_01_release_below_p15_keeps_the_review_open_on(b: Backend) {
    let (s, records) = released(b, 2);
    assert!(
        !entered_negotiation(&records),
        "R-IR-01: one validated IRC assignment is fewer than P-15 = 2: {records:?}"
    );
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
}

/// R-IR-01, R-LA-03, I-03: IRC_REVIEW to NEGOTIATION is the IRC members'
/// row. A release that leaves only validated IRC assignments, at least
/// P-15, records no entry. A validated IRC member records it by repeating
/// the validation.
#[test]
fn r_ir_01_release_leaves_the_entry_to_a_validated_member() {
    r_ir_01_release_leaves_the_entry_to_a_validated_member_on(Backend::Production);
}

/// R-IR-01, P-15: a release that leaves fewer than P-15 IRC assignments
/// keeps the review open.
#[test]
fn r_ir_01_release_below_p15_keeps_the_review_open() {
    r_ir_01_release_below_p15_keeps_the_review_open_on(Backend::Production);
}
