//! I-36, decided 2026-10-25: the bar reaches only former reviewers, and only the calls of a programme where they reviewed (roles-and-sod.md, Reviewer assignment, data placement NOTE).
//!
//! The bar must not over-deny. A committee member who reviewed nothing
//! applies to the later calls of the programme like anyone else once
//! SoD-05 allows it. A former reviewer applies to a call of another
//! programme, where they reviewed nothing, while their reviewed proposal
//! is still undecided. Every command is compared with the reference too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{AccountId, BindingId, CallId, ProposalId};
use fstp_domain::rules::{Row, StateTag};
use fstp_domain_testkit::r#gen::review::{
    I36_OTHER_CALL, L4, PR1, R1, R2, R3, ReviewWorld, i36_core, i36_fold_path, i36_world,
};
use fstp_domain_testkit::r#gen::roster::{Backend, Step, add_member, call, draft};
use fstp_domain_testkit::reference::review::{check_i36, check_i36_held};
use fstp_domain_testkit::reference::sod::Verdict;

fn apply(who: AccountId, n: u128, c: CallId) -> Step {
    draft(
        who,
        ProposalId::from_raw(n),
        c,
        BindingId::from_raw(n),
        false,
    )
}

/// Runs `step`, which both the reference and production must accept.
fn accepted(w: &mut ReviewWorld, step: &Step, why: &str) {
    assert_eq!(
        w.verdict(step),
        Verdict::Accept,
        "the reference accepts {why}"
    );
    let before = w.view.receiving.len();
    if let Err(e) = i36_core(w, step, false) {
        panic!("{why}: {e}");
    }
    assert!(
        w.view.receiving.len() > before,
        "{why}: production granted the Receiving binding"
    );
}

/// I-36: R1 reviewed PR1, which is in STAGE1 of call 1 and undecided. R2
/// and R3, committee members who reviewed nothing, draft in call 2 and
/// join a draft in call 3. R1 drafts in the call of the other programme
/// and joins L4's draft there. Nothing of this is barred.
#[test]
fn i36_unreviewed_and_other_programme_calls_are_unaffected() {
    let mut w =
        i36_world(Backend::Production, &[(R1, PR1)]).unwrap_or_else(|e| panic!("I-36 setup: {e}"));
    i36_fold_path(
        &mut w,
        PR1,
        &[(
            StateTag::Submitted,
            StateTag::Stage1,
            Row::SubmittedToStage1,
        )],
    )
    .unwrap();
    accepted(&mut w, &apply(R2, 9_901, call(2)), "R2's draft in call 2");
    let l4 = ProposalId::from_raw(9_902);
    accepted(
        &mut w,
        &draft(L4, l4, call(3), BindingId::from_raw(9_902), false),
        "L4's draft in call 3",
    );
    accepted(
        &mut w,
        &add_member(L4, l4, R3, BindingId::from_raw(9_903), false),
        "R3's team role in call 3",
    );
    accepted(
        &mut w,
        &apply(R1, 9_904, I36_OTHER_CALL),
        "R1's draft in the other programme's call",
    );
    let other = ProposalId::from_raw(9_905);
    accepted(
        &mut w,
        &draft(L4, other, I36_OTHER_CALL, BindingId::from_raw(9_905), false),
        "L4's draft in the other programme's call",
    );
    accepted(
        &mut w,
        &add_member(L4, other, R1, BindingId::from_raw(9_906), false),
        "R1's team role in the other programme's call",
    );
    check_i36_held(&w.sod.view, &w.view).unwrap();
    check_i36(&w.view).unwrap();
}
