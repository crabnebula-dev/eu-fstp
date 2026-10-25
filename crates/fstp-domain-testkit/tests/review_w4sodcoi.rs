//! Review reproducers for lane w4-sodcoi (step W4, conflict-of-interest suspension).
//!
//! Each test fails against the lane's current code and passes once the
//! named defect is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::BindingId;
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::roster::{
    A, Backend, C, Facts, ID_AB, ID_C, P1, SodSetup, SodWorld, Step, T0, call, end, grant,
    reinstate, sod_truth,
};
use fstp_domain_testkit::reference::sod::{Verdict, check_i02, verdict};

/// Runs `step`, which the reference does not refuse and production must accept.
fn accept(w: &mut SodWorld, step: &Step, what: &str) {
    if let Verdict::Refuse(why) = verdict(&w.view, &w.truth, &step.ask(w.now)) {
        panic!("{what}: the reference refuses ({why}), so the story is wrong");
    }
    w.exec(step, Facts::Effective)
        .unwrap_or_else(|e| panic!("{what}: harness: {e}"))
        .unwrap_or_else(|r| panic!("{what} refused: {r}"));
}

/// Processes the newer vault epoch.
fn react(w: &mut SodWorld) {
    w.sync(Facts::Effective)
        .unwrap_or_else(|e| panic!("reaction: harness: {e}"))
        .unwrap_or_else(|r| panic!("the reaction was refused: {r}"));
}

/// I-02, SoD-02, Identity discovery (decided 2026-10-25): reinstating a
/// conflict-of-interest suspension must not leave an I-02 break behind.
///
/// Story at P-12 = 1: a is programme manager and c committee member. The
/// vault merges c into a's identity, so c's committee binding is suspended
/// as a conflict of interest. The vault splits them again. c is granted IRC
/// member, which SoD-02 lets through because the suspended binding does
/// not count as held. c's IRC binding ends. c's committee binding is then
/// reinstated: production accepts, and so does the reference verdict.
///
/// Counted again, the committee binding overlapped c's IRC binding. The
/// reference I-02 check, run by `SodMachine` after every step under the
/// I06 focus (IRC member is among its roles), then reports a break. Either
/// the reinstatement must be refused, as the I-01 own-account check
/// already does for a Drafting binding held during the suspension, or the
/// check must not count the suspension period as held.
#[test]
fn review_i02_reinstated_conflict_suspension_overlaps_an_irc_binding() {
    let mut setup = SodSetup::one(1, &[1, 2, 3]);
    setup.published = vec![call(1)];
    let mut w = SodWorld::from_setup(Backend::Production, sod_truth(), &setup)
        .unwrap_or_else(|e| panic!("setup: {e}"));
    let drafting = BindingId::from_raw(301);
    let judging = BindingId::from_raw(302);
    let irc = BindingId::from_raw(303);

    accept(
        &mut w,
        &grant(drafting, A, P1, Role::ProgrammeManager, T0),
        "a's grant",
    );
    accept(
        &mut w,
        &grant(judging, C, P1, Role::CommitteeMember, T0),
        "c's grant",
    );
    w.truth.set_identity(C, ID_AB);
    react(&mut w);
    assert!(
        w.view.bindings[&judging].conflict_of_interest,
        "the merge suspends c's committee binding as a conflict of interest"
    );
    w.truth.set_identity(C, ID_C);
    react(&mut w);

    accept(
        &mut w,
        &grant(irc, C, P1, Role::IrcMember, T0),
        "c's IRC grant while the committee binding is suspended",
    );
    accept(&mut w, &end(irc, T0), "the end of c's IRC binding");

    let step = reinstate(judging);
    let reference = verdict(&w.view, &w.truth, &step.ask(w.now));
    let result = w
        .exec(&step, Facts::Effective)
        .unwrap_or_else(|e| panic!("reinstatement: harness: {e}"));
    if result.is_ok()
        && let Err(e) = check_i02(&w.view)
    {
        panic!(
            "the reinstatement was accepted (reference verdict {reference:?}), and then the reference I-02 check fails: {e}"
        );
    }
}
