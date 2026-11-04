//! SoD-10, I-34: a reviewer has one organisation per programme (decided 2026-10-28).
//!
//! `SPEC/02-domain/roles-and-sod.md`, Reviewer assignment NOTE: a
//! committee binding that records a different organisation from the
//! account's active committee binding in the programme is refused. So the
//! count of organisations for I-34 can never depend on which of two
//! bindings is read.
//!
//! Each test runs production commands from genesis and compares every
//! step with the roles reference verdict in both directions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::command::Command;
use fstp_domain::id::{AccountId, BindingId, OrganisationId, ProgrammeId};
use fstp_domain::record::{BindingGranted, Record};
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::BindingScope;
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::roster::{
    Backend, C, Facts, P1, P2, SodSetup, SodWorld, Step, T0, call, end, grant, sod_truth,
};
use fstp_domain_testkit::reference::review::{RevView, check_one_organisation};
use fstp_domain_testkit::reference::sod::{Verdict, View, verdict};

const O1: OrganisationId = OrganisationId::from_raw(71);
const O2: OrganisationId = OrganisationId::from_raw(72);

fn world(setup: &SodSetup) -> SodWorld {
    SodWorld::from_setup(Backend::Production, sod_truth(), setup)
        .unwrap_or_else(|e| panic!("setup: {e}"))
}

/// A committee member grant of `binding` to c in `programme`, recording `org`.
fn committee(binding: u128, programme: ProgrammeId, org: OrganisationId) -> Step {
    let mut g = grant(
        BindingId::from_raw(binding),
        C,
        programme,
        Role::CommitteeMember,
        T0,
    );
    if let Command::GrantRole { organisation, .. } = &mut g.cmd {
        *organisation = Some(org);
    }
    g
}

/// Runs `step` on production and checks it against the reference verdict.
/// Returns whether production accepted it.
fn judged(w: &mut SodWorld, step: &Step, what: &str) -> Result<bool, RuleRef> {
    let v = verdict(&w.view, &w.truth, &step.ask(w.now));
    let out = w
        .exec(step, Facts::Effective)
        .unwrap_or_else(|e| panic!("{what}: harness: {e}"));
    match (&v, &out) {
        (Verdict::Accept, Err(r)) => {
            panic!("{what}: over-denial, the reference accepts, production refuses with {r}")
        }
        (Verdict::Refuse(why), Ok(records)) => panic!(
            "{what}: over-permission, the reference refuses ({why}), production accepts with {records:?}"
        ),
        _ => {}
    }
    out.map(|_| true).map_err(|r| r.rule)
}

/// SoD-10, I-34 (decided 2026-10-28): c holds a committee binding of O1 in
/// programme 1. A second committee binding of c in programme 1 recording
/// O2 is refused under SoD-10.
#[test]
fn sod10_second_committee_binding_with_another_organisation_is_refused() {
    let mut w = world(&SodSetup::one(1, &[1]));
    judged(&mut w, &committee(301, P1, O1), "the O1 grant")
        .unwrap_or_else(|r| panic!("the O1 grant is refused with {r:?}"));
    let out = judged(&mut w, &committee(302, P1, O2), "the O2 grant");
    assert_eq!(
        out,
        Err(RuleRef::Sod10),
        "SoD-10: a second committee binding of another organisation is refused"
    );
}

/// SoD-10: a second committee binding recording the same organisation
/// keeps one organisation per reviewer, so SoD-10 does not refuse it.
/// Daniel's answer of 2026-10-31 (M4 design section 15.0) refuses a
/// re-grant of a role while the account holds that binding, and allows it
/// once the binding ends. So the second O1 grant is refused with `Input`
/// while the first is held, and accepted after its end.
#[test]
fn sod10_second_committee_binding_with_the_same_organisation_is_accepted_after_the_end() {
    let mut w = world(&SodSetup::one(1, &[1]));
    judged(&mut w, &committee(301, P1, O1), "the first O1 grant")
        .unwrap_or_else(|r| panic!("the first O1 grant is refused with {r:?}"));
    assert_eq!(
        judged(
            &mut w,
            &committee(302, P1, O1),
            "the O1 re-grant while held"
        ),
        Err(RuleRef::Input),
        "a re-grant of the committee role is refused while c holds it"
    );
    judged(&mut w, &end(BindingId::from_raw(301), T0), "the end")
        .unwrap_or_else(|r| panic!("the end is refused with {r:?}"));
    judged(
        &mut w,
        &committee(303, P1, O1),
        "the O1 grant after the end",
    )
    .unwrap_or_else(|r| panic!("the O1 grant after the end is refused with {r:?}"));
}

/// SoD-10: the rule reads the active committee binding. Once c's O1
/// binding has ended, a committee binding recording O2 is accepted.
#[test]
fn sod10_another_organisation_after_the_binding_ended_is_accepted() {
    let mut w = world(&SodSetup::one(1, &[1]));
    judged(&mut w, &committee(301, P1, O1), "the O1 grant")
        .unwrap_or_else(|r| panic!("the O1 grant is refused with {r:?}"));
    judged(&mut w, &end(BindingId::from_raw(301), T0), "the end")
        .unwrap_or_else(|r| panic!("the end is refused with {r:?}"));
    judged(&mut w, &committee(302, P1, O2), "the O2 grant")
        .unwrap_or_else(|r| panic!("the O2 grant after the end is refused with {r:?}"));
}

/// `T0` plus `n` seconds.
fn t(n: i64) -> fstp_domain::time::Timestamp {
    fstp_domain::time::Timestamp::from_micros(
        T0.micros().saturating_add(n.saturating_mul(1_000_000)),
    )
}

/// A committee member grant of `binding` to c in programme 1 from `start`,
/// recording `org`.
fn committee_from(binding: u128, start: fstp_domain::time::Timestamp, org: OrganisationId) -> Step {
    let mut g = committee(binding, P1, org);
    if let Command::GrantRole { start: s, .. } = &mut g.cmd {
        *s = start;
    }
    g
}

/// SoD-10 (decided 2026-10-28: "one organisation per programme"; "a
/// different organisation from the account's active committee binding"):
/// c's O1 binding has its end scheduled for `t(10)`, so it is active and
/// held until then. A committee binding recording O2 is refused while
/// it is held, even one that starts at `t(10)`. Once the System records
/// the end at `t(10)`, the O2 grant is accepted.
///
/// W7 fix round 2 overturned the round 1 reading, which accepted an O2
/// binding from `t(10)` ahead of the end. That let assignments made
/// under O1 survive the end under O2, unchecked by I-35
/// (`review_w7v2_sod10_switch.rs`).
#[test]
fn sod10_another_organisation_after_a_scheduled_end_is_accepted() {
    let mut w = world(&SodSetup::one(1, &[1]));
    judged(&mut w, &committee(301, P1, O1), "the O1 grant")
        .unwrap_or_else(|r| panic!("the O1 grant is refused with {r:?}"));
    judged(
        &mut w,
        &end(BindingId::from_raw(301), t(10)),
        "the scheduled end",
    )
    .unwrap_or_else(|r| panic!("the scheduled end is refused with {r:?}"));
    for (id, start) in [(302, t(9)), (303, t(10))] {
        let ahead = judged(
            &mut w,
            &committee_from(id, start, O2),
            "an O2 grant ahead of the end",
        );
        assert_eq!(
            ahead,
            Err(RuleRef::Sod10),
            "SoD-10: an O2 binding from {start:?} is refused while the O1 binding is held"
        );
    }
    w.arrive(t(10))
        .unwrap_or_else(|e| panic!("the System end at t(10): harness: {e}"))
        .unwrap_or_else(|r| panic!("the System end at t(10) is refused: {r}"));
    judged(
        &mut w,
        &committee_from(304, t(10), O2),
        "the O2 grant after the end",
    )
    .unwrap_or_else(|r| {
        panic!("SoD-10: an O2 binding after the recorded end is refused with {r:?}")
    });
}

/// SoD-10 (decided 2026-10-28): a reinstated committee binding never stands
/// beside a committee binding of c that records another organisation (W7
/// fix round 1). Here c's O1 binding is suspended as a conflict of
/// interest. Daniel's answer of 2026-10-31 (M4 design section 15.0)
/// refuses a grant of the same role while that binding has not ended, so
/// the O2 grant meanwhile is refused with `Input`. The reinstatement is
/// then accepted, and c's committee bindings on P1 record O1 alone.
/// `plan_reinstate` keeps its SoD-10 check as a second line of defence,
/// which no command sequence reaches since the 15.0 guard.
#[test]
fn sod10_reinstatement_beside_another_organisation_is_refused() {
    use fstp_domain_testkit::r#gen::roster::{A, ID_AB, ID_C, reinstate};
    let mut w = world(&SodSetup::one(1, &[1]));
    judged(
        &mut w,
        &grant(BindingId::from_raw(321), A, P1, Role::CallDrafter, T0),
        "a's call drafter grant",
    )
    .unwrap_or_else(|r| panic!("a's call drafter grant is refused with {r:?}"));
    judged(&mut w, &committee(301, P1, O1), "the O1 grant")
        .unwrap_or_else(|r| panic!("the O1 grant is refused with {r:?}"));
    w.truth.set_identity(C, ID_AB);
    w.sync(Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("the merge reaction is refused: {r}"));
    w.truth.set_identity(C, ID_C);
    w.sync(Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .unwrap_or_else(|r| panic!("the split reaction is refused: {r}"));
    assert_eq!(
        judged(&mut w, &committee(302, P1, O2), "the O2 grant"),
        Err(RuleRef::Input),
        "M4 design 15.0: the O2 grant beside a binding that has not ended is refused"
    );
    judged(
        &mut w,
        &reinstate(BindingId::from_raw(301)),
        "the reinstatement",
    )
    .unwrap_or_else(|r| panic!("the reinstatement is refused with {r:?}"));
    let organisations: BTreeSet<Option<OrganisationId>> = w
        .state
        .roster()
        .bindings()
        .filter(|(_, b)| b.account == C && b.programme == P1 && b.role == Role::CommitteeMember)
        .map(|(_, b)| b.organisation)
        .collect();
    assert_eq!(
        organisations,
        BTreeSet::from([Some(O1)]),
        "SoD-10: after the reinstatement c reviews for one organisation on P1"
    );
}

/// SoD-10: one organisation per programme. c may be a reviewer of O1 in
/// programme 1 and of O2 in programme 2.
#[test]
fn sod10_each_programme_keeps_its_own_organisation() {
    let setup = SodSetup {
        programmes: vec![P1, P2],
        p12: 1,
        p13: BTreeSet::new(),
        calls: vec![(P1, call(1)), (P2, call(21))],
        published: Vec::new(),
    };
    let mut w = world(&setup);
    judged(
        &mut w,
        &committee(301, P1, O1),
        "the O1 grant in programme 1",
    )
    .unwrap_or_else(|r| panic!("the O1 grant is refused with {r:?}"));
    judged(
        &mut w,
        &committee(302, P2, O2),
        "the O2 grant in programme 2",
    )
    .unwrap_or_else(|r| panic!("the O2 grant in another programme is refused with {r:?}"));
}

/// A committee binding of `account` in programme 1 recording `org`, as a
/// broken engine might record it.
fn forged(binding: u128, account: AccountId, org: OrganisationId) -> Record {
    Record::BindingGranted(BindingGranted {
        binding: BindingId::from_raw(binding),
        account,
        programme: P1,
        role: Role::CommitteeMember,
        scope: BindingScope::Programme,
        start: T0,
        granted_by: fstp_domain_testkit::r#gen::roster::ADMIN,
        second_admin: None,
        confidentiality: None,
        organisation: Some(org),
        verified_epoch: None,
    })
}

/// SoD-10 teeth (design 6.1): a ledger in which c holds committee bindings
/// of O1 and O2 in one programme is caught by the predicate, and the same
/// ledger with one organisation is not.
#[test]
fn sod10_teeth_two_organisations_of_one_reviewer_are_caught() {
    let broken = [forged(301, C, O1), forged(302, C, O2)];
    let view = View::of(broken.iter()).unwrap_or_else(|e| panic!("{e}"));
    let rev = RevView::of(broken.iter()).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        check_one_organisation(&view, &rev).is_err(),
        "SoD-10: the predicate catches two organisations of one reviewer"
    );
    let sound = [forged(301, C, O1), forged(302, C, O1)];
    let view = View::of(sound.iter()).unwrap_or_else(|e| panic!("{e}"));
    let rev = RevView::of(sound.iter()).unwrap_or_else(|e| panic!("{e}"));
    check_one_organisation(&view, &rev).unwrap_or_else(|e| panic!("one organisation: {e}"));
}
