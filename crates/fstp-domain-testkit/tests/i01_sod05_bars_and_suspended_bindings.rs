//! I-01, SoD-01 and SoD-05 edge cases that the machines rarely draw (design 2.6 and 6.2).
//!
//! - The bar of an account and group is the largest bar pinned, even when a
//!   later end pins a smaller one because P-12 was lowered in between.
//! - A suspended binding is inactive for every action, but it still counts
//!   as held for the account rules (enforcement points, NOTE on suspension).
//!
//! Suspensions are injected as records, as the teeth tests inject faults,
//! because no M2 command suspends a Receiving binding.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{BindingId, PolicyVersionId, ProposalId};
use fstp_domain::record::{BindingSuspended, Record};
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::{CoolingOff, Group, Role};
use fstp_domain_testkit::r#gen::roster::{
    Backend, C, Facts, P1, SodSetup, SodWorld, T0, add_member, call, draft, edit_policy, end,
    grant, publish, sod_truth,
};
use fstp_domain_testkit::reference::sod::verdict;

/// The world of these tests: P-12 = `p12`, calls 1 to 3, call 1 published.
fn world(p12: u8) -> (SodSetup, SodWorld) {
    let mut setup = SodSetup::one(p12, &[1, 2, 3]);
    setup.published = vec![call(1)];
    let w = SodWorld::from_setup(Backend::Production, sod_truth(), &setup)
        .unwrap_or_else(|e| panic!("setup: {e}"));
    (setup, w)
}

/// Runs `step`, which must be accepted.
fn accept(w: &mut SodWorld, step: &fstp_domain_testkit::r#gen::roster::Step, what: &str) {
    w.exec(step, Facts::Effective)
        .unwrap_or_else(|e| panic!("{what}: harness: {e}"))
        .unwrap_or_else(|r| panic!("{what} refused: {r}"));
}

/// Suspends `binding` by injecting the record enforcement point 3 writes.
fn suspend(w: &mut SodWorld, binding: BindingId) {
    let epoch = w.epoch();
    w.commit(&[Record::BindingSuspended(BindingSuspended {
        binding,
        rule: RuleRef::I06,
        epoch,
    })])
    .unwrap_or_else(|e| panic!("suspension of {binding:?}: {e}"));
}

/// SoD-05, I-01: c ends a Drafting binding at P-12 = 2 (bar 3). P-12 is
/// lowered to 0, and c ends a second Drafting binding (bar 1). Call 2 is
/// then inside the first bar and outside the second. The largest bar
/// counts, so c's draft in call 2 is refused.
#[test]
fn i01_sod05_largest_bar_counts_after_p12_is_lowered() {
    let (setup, mut w) = world(2);
    let first = BindingId::from_raw(301);
    accept(
        &mut w,
        &grant(first, C, P1, Role::ProgrammeManager, T0),
        "first grant",
    );
    accept(&mut w, &end(first, T0), "first end");
    let head = setup.version(P1).unwrap_or_else(|e| panic!("head: {e}"));
    let lower = edit_policy(&head, PolicyVersionId::from_raw(2), |v| {
        v.live.p12 = CoolingOff(0);
    });
    accept(&mut w, &lower, "P-12 edit");
    let second = BindingId::from_raw(302);
    accept(
        &mut w,
        &grant(second, C, P1, Role::CallDrafter, T0),
        "second grant",
    );
    accept(&mut w, &end(second, T0), "second end");
    assert_eq!(w.state.roster().bar(P1, C, Group::Drafting), Some(3));
    accept(&mut w, &publish(call(2)), "publication of call 2");

    let step = draft(
        C,
        ProposalId::from_raw(1),
        call(2),
        BindingId::from_raw(201),
        false,
    );
    assert!(
        !verdict(&w.view, &w.truth, &step.ask(w.now)).accepts(),
        "the reference must refuse the draft inside the first bar"
    );
    match w.exec(&step, Facts::Effective).unwrap() {
        Ok(records) => panic!("SoD-05: the draft in call 2 inside bar 3 was accepted: {records:?}"),
        Err(r) => assert_eq!(r.rule, RuleRef::Sod05, "refused for {r}"),
    }
}

/// SoD-01, I-01: a suspended committee binding still counts as held, so a
/// Drafting grant to the same account is refused, as the reference says.
#[test]
fn i01_sod01_suspended_binding_still_counts_as_held() {
    let (_, mut w) = world(1);
    let committee = BindingId::from_raw(301);
    accept(
        &mut w,
        &grant(committee, C, P1, Role::CommitteeMember, T0),
        "committee grant",
    );
    suspend(&mut w, committee);

    let step = grant(BindingId::from_raw(302), C, P1, Role::ProgrammeManager, T0);
    assert!(
        !verdict(&w.view, &w.truth, &step.ask(w.now)).accepts(),
        "the reference must refuse the grant"
    );
    match w.exec(&step, Facts::Effective).unwrap() {
        Ok(records) => panic!("SoD-01: a suspended binding was taken as not held: {records:?}"),
        Err(r) => assert_eq!(r.rule, RuleRef::Sod01, "refused for {r}"),
    }
}

/// I-01, enforcement point 2: a suspended binding is inactive for every
/// action, so a lead whose Applicant binding is suspended adds no member.
#[test]
fn i01_suspended_lead_binding_is_inactive_for_adding_members() {
    let (_, mut w) = world(1);
    let proposal = ProposalId::from_raw(1);
    let lead = BindingId::from_raw(201);
    accept(&mut w, &draft(C, proposal, call(1), lead, false), "draft");
    suspend(&mut w, lead);

    let step = add_member(
        C,
        proposal,
        fstp_domain_testkit::r#gen::roster::A,
        BindingId::from_raw(202),
        false,
    );
    assert!(
        !verdict(&w.view, &w.truth, &step.ask(w.now)).accepts(),
        "the reference must refuse the addition"
    );
    if let Ok(records) = w.exec(&step, Facts::Effective).unwrap() {
        panic!("a lead with a suspended Applicant binding added a member: {records:?}");
    }
}
