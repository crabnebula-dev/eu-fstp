//! I-06 reactions to vault changes that the machines rarely draw (Identity discovery, enforcement point 3).
//!
//! - The vault links a candidate to a Receiving holder: the reaction must
//!   ask again when a candidate changed, not only the holder.
//! - An ended Receiving binding counts through its bar, so a discovery
//!   voids it when it breaks I-01 with the other account's binding, and
//!   keeps it otherwise.
//! - A suspended Receiving binding still counts as held, so a discovery voids it.
//! - A Drafting and a Judging binding found to share a verified identity:
//!   only a later identity merge reaches this. The reaction suspends the
//!   Judging binding as a conflict of interest, held or ended, and the
//!   Drafting binding stays (Identity discovery, decided 2026-10-25). The
//!   suspension restores I-06.
//!
//! Each reaction is also checked against the reference's expected voids
//! and conflict-of-interest suspensions, in both directions. Ended
//! Receiving bindings are injected as the `BindingEnded` that lane L-SOD
//! writes at a terminal state, because the `Transitioned` fold is lane
//! L-LIFE's.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{AccountId, BindingId, ProposalId};
use fstp_domain::record::{BindingEnded, BindingSuspended, Record};
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::{BindingStatus, CoolingOff, Group, Role};
use fstp_domain_testkit::r#gen::roster::{
    A, B, Backend, C, Facts, ID_AB, P1, SodSetup, SodWorld, Step, T0, call, draft, end, grant,
    publish, sod_truth,
};
use fstp_domain_testkit::reference::sod::{
    check_i06, check_suspensions, check_voids, expected_suspensions, expected_voids,
};
use fstp_domain_testkit::vault::{GroundTruth, IdentityTag};

/// Account d: its own verified identity.
const D: AccountId = AccountId::from_raw(104);
/// The identity behind d.
const ID_D: IdentityTag = IdentityTag::new(1004);

/// The world of these tests over `truth`: P-12 = `p12`, calls 1 to 3, call 1 published.
fn world(p12: u8, truth: GroundTruth) -> SodWorld {
    let mut setup = SodSetup::one(p12, &[1, 2, 3]);
    setup.published = vec![call(1)];
    SodWorld::from_setup(Backend::Production, truth, &setup)
        .unwrap_or_else(|e| panic!("setup: {e}"))
}

/// Runs `step`, which must be accepted.
fn accept(w: &mut SodWorld, step: &Step, what: &str) {
    w.exec(step, Facts::Effective)
        .unwrap_or_else(|e| panic!("{what}: harness: {e}"))
        .unwrap_or_else(|r| panic!("{what} refused: {r}"));
}

/// Ends the Receiving binding `binding` as a terminal state does, with
/// the latest published sequence `latest` and P-12 `p12`.
fn end_receiving(w: &mut SodWorld, binding: BindingId, latest: u32, p12: u8) {
    w.commit(&[Record::BindingEnded(BindingEnded {
        binding,
        at: T0,
        barred_through: latest.saturating_add(u32::from(p12)),
        p12: CoolingOff(p12),
    })])
    .unwrap_or_else(|e| panic!("terminal end of {binding:?}: {e}"));
}

/// Processes the newer vault epoch and checks its voids and its
/// conflict-of-interest suspensions against the reference. Returns the
/// reaction's records.
fn react(w: &mut SodWorld) -> Vec<Record> {
    let expected = expected_voids(&w.view, &w.truth);
    let suspensions = expected_suspensions(&w.view, &w.truth);
    let records = w
        .sync(Facts::Effective)
        .unwrap_or_else(|e| panic!("reaction: harness: {e}"))
        .unwrap_or_else(|r| panic!("the reaction was refused: {r}"));
    if let Err(e) = check_voids("reaction", &expected, &records) {
        panic!("{e}");
    }
    if let Err(e) = check_suspensions("reaction", &suspensions, &records) {
        panic!("{e}");
    }
    records
}

/// Whether `records` void `binding` under I-06.
fn voided_under_i06(records: &[Record], binding: BindingId) -> bool {
    records.iter().any(
        |r| matches!(r, Record::BindingVoided(v) if v.binding == binding && v.rule == RuleRef::I06),
    )
}

/// I-06, Identity discovery: d holds an Applicant binding and c a committee
/// binding, with distinct identities. The vault then links c to d's
/// identity and lists only c as changed. The reaction must ask again for
/// d, whose candidate changed, and void d's binding.
#[test]
fn i06_identity_merge_with_a_candidate_voids_the_receiving_holder() {
    let mut truth = sod_truth();
    truth.set_identity(D, ID_D);
    truth.verify(D);
    let mut w = world(1, truth);
    accept(
        &mut w,
        &grant(BindingId::from_raw(301), C, P1, Role::CommitteeMember, T0),
        "c's committee grant",
    );
    let applicant = BindingId::from_raw(201);
    accept(
        &mut w,
        &draft(D, ProposalId::from_raw(1), call(1), applicant, false),
        "d's draft",
    );

    w.truth.set_identity(C, ID_D);
    let records = react(&mut w);
    assert!(
        voided_under_i06(&records, applicant),
        "d shares c's verified identity now, but the reaction left d bound: {records:?}"
    );
    if let Err(e) = check_i06(&w.view, &w.truth) {
        panic!("{e}");
    }
}

/// Whether `records` suspend `binding` under I-06, the conflict-of-interest marker.
fn suspended_under_i06(records: &[Record], binding: BindingId) -> bool {
    records.iter().any(|r| {
        matches!(
            r,
            Record::BindingSuspended(BindingSuspended { binding: b, rule: RuleRef::I06, .. })
                if *b == binding
        )
    })
}

/// Whether `records` suspend `binding` under any rule.
fn suspended_at_all(records: &[Record], binding: BindingId) -> bool {
    records
        .iter()
        .any(|r| matches!(r, Record::BindingSuspended(s) if s.binding == binding))
}

/// I-06, Identity discovery (last paragraph, decided 2026-10-25),
/// enforcement point 3: a holds a Drafting binding and c a Judging one.
/// The vault merges c into a's identity, which SoD-09 would have refused at
/// binding time. In the same step the reaction suspends c's Judging binding
/// as a conflict of interest, under I-06. a's Drafting binding stays,
/// active and unsuspended. The suspension restores I-06.
#[test]
fn i06_identity_merge_suspends_the_judging_binding_as_a_conflict() {
    let mut w = world(1, sod_truth());
    let drafting = BindingId::from_raw(301);
    let judging = BindingId::from_raw(302);
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
    let records = react(&mut w);
    assert!(
        suspended_under_i06(&records, judging),
        "c's Judging binding shares a verified identity with a's Drafting binding and must be suspended as a conflict of interest: {records:?}"
    );
    assert!(
        !suspended_at_all(&records, drafting),
        "the Drafting binding stays: a's binding must not be suspended: {records:?}"
    );
    let roster = w.state.roster();
    let d = roster.binding(drafting).expect("a's binding");
    assert_eq!(d.status, BindingStatus::Active, "a's Drafting binding");
    let j = roster.binding(judging).expect("c's binding");
    assert_eq!(
        j.status,
        BindingStatus::Suspended(RuleRef::I06),
        "c's Judging binding"
    );
    assert!(
        !j.held(),
        "a conflict-of-interest suspension never counts as held"
    );
    if let Err(e) = check_i06(&w.view, &w.truth) {
        panic!("the conflict-of-interest suspension must restore I-06: {e}");
    }
}

/// I-06, Identity discovery (last paragraph, decided 2026-10-25): c ends a
/// Judging binding at P-12 = 1 (bar 2), and a then gets a Drafting binding
/// while the latest call is 1, inside that bar. The vault merges c into a's
/// identity. c's ended Judging binding still counts through its bar, so
/// the reaction suspends it as a conflict of interest. Its bar then never
/// counts. a's Drafting binding stays (test-author reading for an ended
/// Judging binding, see `reference::sod`).
#[test]
fn i06_identity_merge_suspends_an_ended_judging_binding_inside_its_bar() {
    let mut w = world(1, sod_truth());
    let judging = BindingId::from_raw(302);
    let drafting = BindingId::from_raw(301);
    accept(
        &mut w,
        &grant(judging, C, P1, Role::CommitteeMember, T0),
        "c's grant",
    );
    accept(&mut w, &end(judging, T0), "c's end");
    assert_eq!(w.state.roster().bar(P1, C, Group::Judging), Some(2));
    accept(
        &mut w,
        &grant(drafting, A, P1, Role::ProgrammeManager, T0),
        "a's grant",
    );

    w.truth.set_identity(C, ID_AB);
    let records = react(&mut w);
    assert!(
        suspended_under_i06(&records, judging),
        "c's ended Judging binding breaks I-01 with a's Drafting binding through its bar and must be suspended: {records:?}"
    );
    assert!(
        !suspended_at_all(&records, drafting),
        "the Drafting binding stays: {records:?}"
    );
    assert_eq!(
        w.state.roster().bar(P1, C, Group::Judging),
        None,
        "a conflict-of-interest suspension pins no cooling-off bar"
    );
    if let Err(e) = check_i06(&w.view, &w.truth) {
        panic!("the conflict-of-interest suspension must restore I-06: {e}");
    }
}

/// I-06, Identity discovery: b, unverified, ends a call 1 binding at
/// P-12 = 0 (bar 1). a gets a committee binding while the latest call is 1,
/// inside that bar. Calls 2 and 3 are published, so the bar no longer bars
/// anything new. The pair still breaks I-01 once b is verified, so the
/// reaction voids b's ended binding.
#[test]
fn i06_discovery_voids_an_ended_receiving_binding_after_its_bar_expired() {
    let mut w = world(0, sod_truth());
    let ended = BindingId::from_raw(201);
    accept(
        &mut w,
        &draft(B, ProposalId::from_raw(1), call(1), ended, false),
        "b's draft",
    );
    end_receiving(&mut w, ended, 1, 0);
    accept(
        &mut w,
        &grant(BindingId::from_raw(301), A, P1, Role::CommitteeMember, T0),
        "a's committee grant",
    );
    accept(&mut w, &publish(call(2)), "publication of call 2");
    accept(&mut w, &publish(call(3)), "publication of call 3");

    w.truth.verify(B);
    let records = react(&mut w);
    assert!(
        voided_under_i06(&records, ended),
        "b's ended binding breaks I-01 with a's committee binding: {records:?}"
    );
    if let Err(e) = check_i06(&w.view, &w.truth) {
        panic!("{e}");
    }
}

/// I-06, Identity discovery: b ends a call 1 binding at P-12 = 0 (bar 1).
/// Call 2 is published before a gets a committee binding, so the two never
/// break I-01 together. The reaction to b's verification keeps b's ended
/// binding, which must not be voided.
#[test]
fn i06_discovery_keeps_an_ended_receiving_binding_outside_its_bar() {
    let mut w = world(0, sod_truth());
    let ended = BindingId::from_raw(201);
    accept(
        &mut w,
        &draft(B, ProposalId::from_raw(1), call(1), ended, false),
        "b's draft",
    );
    end_receiving(&mut w, ended, 1, 0);
    accept(&mut w, &publish(call(2)), "publication of call 2");
    accept(
        &mut w,
        &grant(BindingId::from_raw(301), A, P1, Role::CommitteeMember, T0),
        "a's committee grant",
    );

    w.truth.verify(B);
    let records = react(&mut w);
    assert!(
        !records
            .iter()
            .any(|r| matches!(r, Record::BindingVoided(v) if v.binding == ended)),
        "b's ended binding is outside every bar and must stay: {records:?}"
    );
}

/// I-06, Identity discovery: a suspended Receiving binding still counts as
/// held, so b's verification voids it although it is suspended.
#[test]
fn i06_reaction_voids_a_suspended_receiving_binding() {
    let mut w = world(1, sod_truth());
    accept(
        &mut w,
        &grant(BindingId::from_raw(301), A, P1, Role::CommitteeMember, T0),
        "a's committee grant",
    );
    let applicant = BindingId::from_raw(201);
    accept(
        &mut w,
        &draft(B, ProposalId::from_raw(1), call(1), applicant, false),
        "b's draft",
    );
    let epoch = w.epoch();
    w.commit(&[Record::BindingSuspended(BindingSuspended {
        binding: applicant,
        rule: RuleRef::I06,
        epoch,
    })])
    .unwrap_or_else(|e| panic!("suspension: {e}"));

    w.truth.verify(B);
    let records = react(&mut w);
    assert!(
        voided_under_i06(&records, applicant),
        "a suspended binding still counts as held and must be voided: {records:?}"
    );
    if let Err(e) = check_i06(&w.view, &w.truth) {
        panic!("{e}");
    }
}
