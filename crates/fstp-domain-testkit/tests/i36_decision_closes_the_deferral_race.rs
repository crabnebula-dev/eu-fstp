//! I-36, decided 2026-10-25: the decision closes the race between a former reviewer's draft and a later deferral (roles-and-sod.md, Reviewer assignment, data placement NOTE).
//!
//! The race under the narrower check: R1 scores PR1 in call 1. Call 2 is
//! published, and R1 drafts there, which the narrower check allows
//! because PR1 is not under evaluation in call 2 yet. PR1 is then
//! deferred, so it is under evaluation in call 2 (Q12), and R1 holds a
//! Receiving role there. I-36 is broken, although the check was right
//! when it ran. Under the decision, the draft itself is refused while PR1
//! is undecided, so the deferral finds no former reviewer in call 2.
//!
//! The stage rows are folded through the public structural fold, as the
//! teeth helpers do, until lane L-LIFE records them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{BindingId, ProposalId};
use fstp_domain::refusal::RuleRef;
use fstp_domain::rules::{Row, StateTag};
use fstp_domain_testkit::r#gen::review::{
    PR1, R1, R2, i36_core, i36_exec_current_call_only, i36_fold_path, i36_world,
};
use fstp_domain_testkit::r#gen::roster::{Backend, Step, call, draft};
use fstp_domain_testkit::harness::teeth::names_property;
use fstp_domain_testkit::reference::review::{check_i36, check_i36_held};

const TO_STAGE2: [(StateTag, StateTag, Row); 2] = [
    (
        StateTag::Submitted,
        StateTag::Stage1,
        Row::SubmittedToStage1,
    ),
    (StateTag::Stage1, StateTag::Stage2, Row::Stage1ToStage2),
];

const DEFER: [(StateTag, StateTag, Row); 1] =
    [(StateTag::Stage2, StateTag::Deferred, Row::Stage2ToDeferred)];

fn apply(who: fstp_domain::id::AccountId, n: u128) -> Step {
    draft(
        who,
        ProposalId::from_raw(n),
        call(2),
        BindingId::from_raw(n),
        false,
    )
}

/// I-36: R1 reviewed PR1, which is in STAGE2 of call 1, and call 2 is
/// published. R1's draft in call 2 is refused with RuleRef::I36 before
/// PR1 is deferred, so the deferral leaves no former reviewer holding a
/// Receiving role in call 2. R2, who reviewed nothing, drafts in call 2
/// and keeps the draft through the deferral.
#[test]
fn i36_decision_closes_the_deferral_race() {
    let mut w =
        i36_world(Backend::Production, &[(R1, PR1)]).unwrap_or_else(|e| panic!("I-36 setup: {e}"));
    i36_fold_path(&mut w, PR1, &TO_STAGE2).unwrap();
    match w
        .exec(&apply(R1, 9_701))
        .unwrap_or_else(|e| panic!("harness: {e}"))
    {
        Err(r) => assert_eq!(r.rule, RuleRef::I36, "R1's draft in call 2: {r}"),
        Ok(records) => panic!(
            "I-36: R1 drafted in call 2 while PR1, which it reviewed, is undecided: {records:?}"
        ),
    }
    if let Err(e) = i36_core(&mut w, &apply(R2, 9_702), false) {
        panic!("{e}");
    }
    i36_fold_path(&mut w, PR1, &DEFER).unwrap();
    if let Err(e) = check_i36_held(&w.sod.view, &w.view) {
        panic!("{e}");
    }
    if let Err(e) = check_i36(&w.view) {
        panic!("{e}");
    }
    match w
        .exec(&apply(R1, 9_703))
        .unwrap_or_else(|e| panic!("harness: {e}"))
    {
        Err(r) => assert_eq!(r.rule, RuleRef::I36, "R1's draft after the deferral: {r}"),
        Ok(records) => panic!("I-36: R1 drafted in call 2 after PR1's deferral: {records:?}"),
    }
}

/// I-36 teeth: under the narrower check, injected as the faulty engine on
/// the references, R1's draft in call 2 is granted while PR1 is in
/// STAGE2. Once PR1 is deferred, the state predicate reports R1's
/// Receiving binding in call 2, and the grant predicate reports the grant.
#[test]
fn i36_teeth_race_under_the_current_call_check_is_caught() {
    let mut w =
        i36_world(Backend::Reference, &[(R1, PR1)]).unwrap_or_else(|e| panic!("I-36 setup: {e}"));
    i36_fold_path(&mut w, PR1, &TO_STAGE2).unwrap();
    let granted = i36_exec_current_call_only(&mut w, &apply(R1, 9_801))
        .unwrap_or_else(|e| panic!("harness: {e}"));
    assert!(
        granted.is_ok(),
        "the faulty engine grants R1's draft in call 2: {granted:?}"
    );
    assert!(
        check_i36_held(&w.sod.view, &w.view).is_ok(),
        "before the deferral, R1's binding sits in no call evaluating PR1"
    );
    i36_fold_path(&mut w, PR1, &DEFER).unwrap();
    match check_i36_held(&w.sod.view, &w.view) {
        Err(e) => assert!(names_property(&e, "I-36"), "{e}"),
        Ok(()) => panic!("teeth: the deferral race went undetected by the state predicate"),
    }
    match check_i36(&w.view) {
        Err(e) => assert!(names_property(&e, "I-36"), "{e}"),
        Ok(()) => panic!("teeth: the grant under the narrower check went undetected"),
    }
}
