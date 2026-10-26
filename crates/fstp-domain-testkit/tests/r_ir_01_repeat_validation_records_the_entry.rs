//! R-IR-01, R-LA-03, NOTE 13, I-18: a named human records every entry into NEGOTIATION.
//!
//! The stories run production commands from genesis and compare every step
//! with the lifecycle reference in both directions. PR1 is ranked,
//! nominated and in IRC_REVIEW of call 1 under P-15 = 1.
//!
//! - A vault conflict releases IRC2, the one IRC member not yet validated.
//!   The vault reaction is the System's, so PR1 stays in IRC_REVIEW. IRC,
//!   who validated, then repeats the validation and records the entry.
//! - On a minor's proposal the repeat is refused until the vault holds a
//!   verified guardian consent, and then it records the entry.
//! - An IRC assignment awaiting its declaration is outstanding, so IRC's
//!   validation alone keeps PR1 in IRC_REVIEW (design 3.2).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, DeclarationSubject};
use fstp_domain::decision::Vote;
use fstp_domain::record::Record;
use fstp_domain::rules::{Row, StateTag};
use fstp_domain::scoring::Stage;
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, IRC, L1, PR1, R1, R2, R3, assign, declare, handle, tag,
};
use fstp_domain_testkit::r#gen::roster::{Backend, call};
use fstp_domain_testkit::mc::life_model::{
    IRC2, Story, assign_declared, assignment_of, ballots, cut_off, cut_off_decision, irc_review,
    life_judges, story_setup,
};
use fstp_domain_testkit::reference::lifecycle::check_recorded_by_human;
use fstp_domain_testkit::vault::Relation;

/// PR1 of a `minor` lead in IRC_REVIEW under P-15 = 1, with IRC assigned
/// and declared. IRC2 is assigned, and declared too when `declared`.
fn in_irc_review(backend: Backend, minor: bool, declared: bool) -> Story {
    let mut setup = story_setup(vec![(L1, PR1, minor)], life_judges());
    setup.p15 = 1;
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
    for st in assign_declared(IRC, PR1, call(1), AssignmentKind::Irc) {
        s.run(&st).unwrap_or_else(|e| panic!("{e}"));
    }
    if declared {
        for st in assign_declared(IRC2, PR1, call(1), AssignmentKind::Irc) {
            s.run(&st).unwrap_or_else(|e| panic!("{e}"));
        }
    } else {
        let id = assignment_of(IRC2, PR1, call(1), AssignmentKind::Irc);
        s.run(&assign(
            COORDINATOR,
            id,
            PR1,
            IRC2,
            AssignmentKind::Irc,
            Some(handle(id.raw())),
        ))
        .unwrap_or_else(|e| panic!("IRC2 is assigned: {e}"));
    }
    s
}

/// The IRC assignment of `member` on PR1.
fn irc_of(s: &Story, member: fstp_domain::id::AccountId) -> fstp_domain::id::AssignmentId {
    s.world
        .assignment(member, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap_or_else(|| panic!("no IRC assignment of {member:?}"))
}

/// IRC validates, and a vault conflict then releases IRC2's assignment.
fn validated_then_released(s: &mut Story) {
    let a1 = irc_of(s, IRC);
    s.run(&irc_review(IRC, a1, true))
        .unwrap_or_else(|e| panic!("IRC validates: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
    let reaction = s
        .vault(|t| t.relate(tag(IRC2), tag(L1), Relation::CoWorker))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    assert!(
        reaction
            .iter()
            .any(|r| matches!(r, Record::AssignmentReleased(_))),
        "the conflict releases IRC2's assignment: {reaction:?}"
    );
}

/// Whether `records` take PR1 into NEGOTIATION with IRC as the actor.
fn entered_by_irc(records: &[Record]) -> bool {
    records.iter().any(|r| {
        matches!(r, Record::Transitioned(t)
            if t.proposal == PR1
                && t.row == Row::IrcReviewToNegotiation
                && t.actor == Actor::Account(IRC)
                && t.decision.is_none())
    })
}

fn after_a_system_release_on(b: Backend) {
    let mut s = in_irc_review(b, false, true);
    validated_then_released(&mut s);
    assert_eq!(
        s.state(PR1),
        Some(StateTag::IrcReview),
        "R-LA-03, NOTE 13: the System records no entry into NEGOTIATION"
    );
    check_recorded_by_human(&s.world.life).unwrap_or_else(|e| panic!("{e}"));
    let a1 = irc_of(&s, IRC);
    let records = s
        .run(&irc_review(IRC, a1, true))
        .unwrap_or_else(|e| panic!("IRC repeats the validation: {e}"));
    assert!(
        entered_by_irc(&records),
        "R-IR-01: IRC records the entry into NEGOTIATION: {records:?}"
    );
    assert!(
        !records
            .iter()
            .any(|r| matches!(r, Record::IrcReviewRecorded { .. })),
        "the repeat records no second review: {records:?}"
    );
    assert_eq!(s.state(PR1), Some(StateTag::Negotiation));
}

fn minor_after_consent_on(b: Backend) {
    let mut s = in_irc_review(b, true, true);
    validated_then_released(&mut s);
    let a1 = irc_of(&s, IRC);
    let refused = s
        .attempt(&irc_review(IRC, a1, true))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        refused.is_none(),
        "I-18: no guardian consent, so the repeat is refused: {refused:?}"
    );
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
    s.vault(|t| t.consent(PR1))
        .unwrap_or_else(|e| panic!("the consent is verified: {e}"));
    let records = s
        .run(&irc_review(IRC, a1, true))
        .unwrap_or_else(|e| panic!("IRC repeats the validation with a consent: {e}"));
    assert!(
        entered_by_irc(&records),
        "R-IR-01, I-18: with the consent IRC records the entry: {records:?}"
    );
    assert_eq!(s.state(PR1), Some(StateTag::Negotiation));
}

fn undeclared_keeps_the_review_open_on(b: Backend) {
    let mut s = in_irc_review(b, false, false);
    let a1 = irc_of(&s, IRC);
    let records = s
        .run(&irc_review(IRC, a1, true))
        .unwrap_or_else(|e| panic!("IRC validates: {e}"));
    assert!(
        !entered_by_irc(&records),
        "design 3.2: IRC2's assignment awaits its declaration: {records:?}"
    );
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
    let a2 = assignment_of(IRC2, PR1, call(1), AssignmentKind::Irc);
    s.run(&declare(
        IRC2,
        DeclarationSubject::Assignment(a2),
        false,
        false,
    ))
    .unwrap_or_else(|e| panic!("IRC2 declares no conflict: {e}"));
    let records = s
        .run(&irc_review(IRC2, a2, true))
        .unwrap_or_else(|e| panic!("IRC2 validates: {e}"));
    assert!(
        records.iter().any(|r| matches!(r, Record::Transitioned(t)
            if t.proposal == PR1 && t.row == Row::IrcReviewToNegotiation
                && t.actor == Actor::Account(IRC2))),
        "R-IR-01: every reviewing IRC member validated: {records:?}"
    );
    assert_eq!(s.state(PR1), Some(StateTag::Negotiation));
}

/// R-IR-01, R-LA-03, NOTE 13: after a vault release a validated IRC
/// member records the entry into NEGOTIATION by repeating the validation.
#[test]
fn r_ir_01_repeat_validation_records_the_entry_after_a_system_release() {
    after_a_system_release_on(Backend::Production);
}

/// R-IR-01, I-18, R-NG-02: on a minor's proposal the repeat waits for a
/// verified guardian consent.
#[test]
fn r_ir_01_repeat_validation_waits_for_the_guardian_consent() {
    minor_after_consent_on(Backend::Production);
}

/// R-IR-01, design 3.2: an IRC assignment awaiting its declaration keeps
/// the IRC review open.
#[test]
fn r_ir_01_undeclared_irc_assignment_keeps_the_review_open() {
    undeclared_keeps_the_review_open_on(Backend::Production);
}
