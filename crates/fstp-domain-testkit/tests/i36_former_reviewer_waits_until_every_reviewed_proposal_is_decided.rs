//! I-36, decided 2026-10-25: a former reviewer waits until every proposal they reviewed is decided (roles-and-sod.md, Reviewer assignment, data placement NOTE).
//!
//! A person who reviewed a proposal takes no Receiving role in any later
//! call of the programme until every proposal they reviewed is terminal,
//! or GRANTED or later. This holds whatever P-12 says. The setup has
//! P-12 = 0, so SoD-05 alone would let a former committee member apply to
//! every call published after its binding ended.
//!
//! The property drives production from genesis. Rows that lane L-LIFE
//! does not record yet are folded through the public structural fold, as
//! the teeth helpers do. The reference-backed run checks the property and
//! the reference against each other before production lands.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{BindingId, ProposalId};
use fstp_domain::record::Record;
use fstp_domain::refusal::RuleRef;
use fstp_domain::rules::{Row, StateTag};
use fstp_domain_testkit::r#gen::review::{
    I36_OTHER_CALL, IRC, L4, PR1, PR2, R1, ReviewWorld, i36_fold_path, i36_property, i36_world,
};
use fstp_domain_testkit::r#gen::roster::{Backend, Step, add_member, call, draft};
use fstp_domain_testkit::reference::review::{check_i36, check_i36_held};
use fstp_domain_testkit::reference::sod::Verdict;
use fstp_prop::{Config, check_with, run};

/// Cases per run of the property.
const CASES: u32 = 96;

/// I-36: generated reviews, lifecycle rows, withdrawals, drafts and team
/// roles never let a former reviewer take a Receiving role in a call of
/// the programme while a proposal it reviewed is undecided. Once all are
/// decided, the bar lifts. Production is compared with the reference in
/// both directions, and the refusal names RuleRef::I36.
#[test]
fn i36_former_reviewer_waits_until_every_reviewed_proposal_is_decided() {
    check_with(
        "i36_former_reviewer_waits_until_every_reviewed_proposal_is_decided",
        Config::default().with_cases(CASES),
        |g| i36_property(g, Backend::Production, false),
    );
}

/// I-36: the same property with the references as their own engine
/// passes, so a failure of the production run is production's.
#[test]
fn i36_property_agrees_with_its_reference() {
    let outcome = run(
        "i36_property_agrees_with_its_reference",
        Config::default().with_cases(CASES),
        |g| i36_property(g, Backend::Reference, false),
    );
    if let Some(f) = outcome.failure() {
        panic!("the reference-backed I-36 property failed: {}", f.message);
    }
}

const STAGE1: [(StateTag, StateTag, Row); 1] = [(
    StateTag::Submitted,
    StateTag::Stage1,
    Row::SubmittedToStage1,
)];

const INELIGIBLE: [(StateTag, StateTag, Row); 1] = [(
    StateTag::Submitted,
    StateTag::Ineligible,
    Row::SubmittedToIneligible,
)];

/// SUBMITTED to NEGOTIATION through the stage, ranking and IRC rows.
const TO_NEGOTIATION: [(StateTag, StateTag, Row); 5] = [
    (
        StateTag::Submitted,
        StateTag::Stage1,
        Row::SubmittedToStage1,
    ),
    (StateTag::Stage1, StateTag::Stage2, Row::Stage1ToStage2),
    (StateTag::Stage2, StateTag::Ranked, Row::Stage2ToRanked),
    (
        StateTag::Ranked,
        StateTag::IrcReview,
        Row::RankedToIrcReview,
    ),
    (
        StateTag::IrcReview,
        StateTag::Negotiation,
        Row::IrcReviewToNegotiation,
    ),
];

const GRANT: [(StateTag, StateTag, Row); 1] = [(
    StateTag::Negotiation,
    StateTag::Granted,
    Row::NegotiationToGranted,
)];

fn apply(n: u128, c: u128) -> Step {
    draft(
        R1,
        ProposalId::from_raw(n),
        call(c),
        BindingId::from_raw(n),
        false,
    )
}

/// Runs `step` and asserts that it is refused under I-36, and that the
/// reference agrees.
fn barred(w: &mut ReviewWorld, step: &Step, why: &str) {
    assert_eq!(
        w.verdict(step),
        Verdict::Refuse("I-36".to_owned()),
        "the reference bars {why}"
    );
    match w.exec(step).unwrap_or_else(|e| panic!("harness: {e}")) {
        Err(r) => assert_eq!(r.rule, RuleRef::I36, "{why}: {r}"),
        Ok(records) => panic!("I-36: {why} was granted: {records:?}"),
    }
}

/// Runs `step` and asserts that it is accepted, and that the reference agrees.
fn granted(w: &mut ReviewWorld, step: &Step, why: &str) -> Vec<Record> {
    assert_eq!(
        w.verdict(step),
        Verdict::Accept,
        "the reference accepts {why}"
    );
    w.exec(step)
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("{why} refused: {r}"))
}

/// I-36: R1 reviewed PR1 and PR2. While either is undecided, R1 is refused
/// a draft in calls 2 and 3 and a team role on another applicant's draft,
/// although neither proposal is under evaluation there. Once PR1 is
/// NOT_SELECTED and PR2 is GRANTED, R1 applies.
#[test]
fn i36_waits_for_the_last_reviewed_proposal_then_lifts() {
    let mut w = i36_world(Backend::Production, &[(R1, PR1), (R1, PR2)])
        .unwrap_or_else(|e| panic!("I-36 setup: {e}"));
    i36_fold_path(&mut w, PR1, &STAGE1).unwrap();
    barred(
        &mut w,
        &apply(9_501, 2),
        "R1's draft in call 2 while PR1 and PR2 are undecided",
    );
    barred(
        &mut w,
        &apply(9_502, 3),
        "R1's draft in call 3 while PR1 and PR2 are undecided",
    );
    let other = ProposalId::from_raw(9_503);
    granted(
        &mut w,
        &draft(L4, other, call(2), BindingId::from_raw(9_503), false),
        "L4's draft in call 2",
    );
    let join = add_member(L4, other, R1, BindingId::from_raw(9_504), false);
    barred(
        &mut w,
        &join,
        "R1's team role in call 2 while PR1 and PR2 are undecided",
    );

    i36_fold_path(
        &mut w,
        PR1,
        &[(
            StateTag::Stage1,
            StateTag::NotSelected,
            Row::Stage1ToNotSelected,
        )],
    )
    .unwrap();
    barred(
        &mut w,
        &apply(9_505, 2),
        "R1's draft in call 2 while PR2 is undecided",
    );

    i36_fold_path(&mut w, PR2, &TO_NEGOTIATION).unwrap();
    barred(
        &mut w,
        &apply(9_506, 2),
        "R1's draft in call 2 while PR2 is in NEGOTIATION",
    );
    i36_fold_path(&mut w, PR2, &GRANT).unwrap();
    granted(
        &mut w,
        &apply(9_507, 2),
        "R1's draft in call 2 once PR1 and PR2 are decided",
    );
    granted(&mut w, &join, "R1's team role once PR1 and PR2 are decided");
    check_i36_held(&w.sod.view, &w.view).unwrap();
    check_i36(&w.view).unwrap();
}

/// I-36: a terminal state decides a reviewed proposal at once. R1 reviewed
/// PR1 only, PR1 becomes INELIGIBLE from SUBMITTED, and R1 drafts in
/// call 2. Before that, R1 is refused, and the call of the other
/// programme stays open to R1 throughout.
#[test]
fn i36_terminal_state_decides_at_once() {
    let mut w =
        i36_world(Backend::Production, &[(R1, PR1)]).unwrap_or_else(|e| panic!("I-36 setup: {e}"));
    barred(
        &mut w,
        &apply(9_601, 2),
        "R1's draft in call 2 while PR1 is SUBMITTED",
    );
    granted(
        &mut w,
        &draft(
            R1,
            ProposalId::from_raw(9_602),
            I36_OTHER_CALL,
            BindingId::from_raw(9_602),
            false,
        ),
        "R1's draft in the other programme's call",
    );
    i36_fold_path(&mut w, PR1, &INELIGIBLE).unwrap();
    granted(
        &mut w,
        &apply(9_603, 2),
        "R1's draft in call 2 once PR1 is INELIGIBLE",
    );
}

/// I-36: an IRC assignment is a review. The IRC member reviewed PR1 in
/// IRC_REVIEW, and its IRC binding ended, so SoD-01 no longer bars it.
/// While PR1 is in IRC_REVIEW, the IRC member is refused a draft in
/// call 2. Once PR1 is DECLINED, the IRC member drafts there.
#[test]
fn i36_irc_review_bars_until_decided() {
    let mut w =
        i36_world(Backend::Production, &[(IRC, PR1)]).unwrap_or_else(|e| panic!("I-36 setup: {e}"));
    assert_eq!(
        w.view.proposals.get(&PR1).map(|l| l.state),
        Some(StateTag::IrcReview),
        "the setup folds PR1 to IRC_REVIEW"
    );
    assert!(
        w.view.reviewed.contains(&(IRC, PR1)),
        "the setup records the IRC assignment on PR1"
    );
    let irc_draft = |n: u128| {
        draft(
            IRC,
            ProposalId::from_raw(n),
            call(2),
            BindingId::from_raw(n),
            false,
        )
    };
    barred(
        &mut w,
        &irc_draft(9_701),
        "the IRC member's draft in call 2 while PR1 is in IRC_REVIEW",
    );
    i36_fold_path(
        &mut w,
        PR1,
        &[(
            StateTag::IrcReview,
            StateTag::Declined,
            Row::IrcReviewToDeclined,
        )],
    )
    .unwrap();
    granted(
        &mut w,
        &irc_draft(9_702),
        "the IRC member's draft in call 2 once PR1 is DECLINED",
    );
}

/// I-36: `AddGuardian` is a Receiving role. R1 reviewed PR1, and L4 drafts
/// a minor's proposal in call 2. While PR1 is SUBMITTED, R1 is refused as
/// its guardian. Once PR1 is INELIGIBLE, R1 becomes the guardian.
#[test]
fn i36_guardian_role_is_barred_until_decided() {
    let mut w =
        i36_world(Backend::Production, &[(R1, PR1)]).unwrap_or_else(|e| panic!("I-36 setup: {e}"));
    let minor = ProposalId::from_raw(9_801);
    granted(
        &mut w,
        &draft(L4, minor, call(2), BindingId::from_raw(9_801), true),
        "L4's minor draft in call 2",
    );
    let guard = add_member(L4, minor, R1, BindingId::from_raw(9_802), true);
    barred(
        &mut w,
        &guard,
        "R1 as guardian in call 2 while PR1 is SUBMITTED",
    );
    i36_fold_path(&mut w, PR1, &INELIGIBLE).unwrap();
    granted(
        &mut w,
        &guard,
        "R1 as guardian in call 2 once PR1 is INELIGIBLE",
    );
    check_i36_held(&w.sod.view, &w.view).unwrap();
    check_i36(&w.view).unwrap();
}
