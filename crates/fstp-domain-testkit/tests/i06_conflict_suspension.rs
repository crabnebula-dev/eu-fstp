//! I-06 conflict-of-interest suspensions after an identity merge (Identity discovery, last paragraph).
//!
//! Daniel decided on 2026-10-25: when the vault finds that accounts holding
//! Drafting and Judging bindings share one verified identity, the platform
//! suspends the Judging binding as a conflict of interest. That suspension
//! restores I-06 (`SPEC/02-domain/roles-and-sod.md`, Identity discovery and
//! the NOTE under Enforcement points):
//!
//! - the suspended Judging binding never counts as held, including as a
//!   past binding within the cooling-off period, and it pins no bar;
//! - so it is not in the candidate set of a later SoD-09 question;
//! - its reinstatement is refused while the identity clash lasts.
//!
//! The marker is a `BindingSuspended` with rule I-06 on a Judging binding.
//! Every other suspension still counts as held (see
//! `i01_sod05_bars_and_suspended_bindings`).
//!
//! In each story a holds a programme manager binding and c a committee
//! binding, with distinct identities. The vault then merges c into the
//! identity of a and b. The reaction's records are checked by
//! `i06_identity_merge_suspends_the_judging_binding_as_a_conflict`. These
//! tests check what the suspension means afterwards. Each refusal or
//! acceptance is compared with the reference verdict too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{BindingId, PolicyVersionId, ProposalId};
use fstp_domain::record::{BindingSuspended, Record};
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::{BindingStatus, CoolingOff, Group, IdentityDiscovery, Role};
use fstp_domain_testkit::r#gen::roster::{
    A, B, Backend, C, Facts, ID_AB, ID_C, P1, SodSetup, SodWorld, Step, T0, call, draft,
    edit_policy, end, grant, publish, reinstate, sod_truth,
};
use fstp_domain_testkit::reference::sod::{Verdict, check_i01, check_i06, verdict};

/// a's programme manager binding.
const DRAFTING: BindingId = BindingId::from_raw(301);
/// c's committee binding, suspended as a conflict of interest after the merge.
const JUDGING: BindingId = BindingId::from_raw(302);

/// The world of these tests: P-12 = `p12`, calls 1 to 3, call 1 published.
fn world(p12: u8) -> (SodSetup, SodWorld) {
    let mut setup = SodSetup::one(p12, &[1, 2, 3]);
    setup.published = vec![call(1)];
    let w = SodWorld::from_setup(Backend::Production, sod_truth(), &setup)
        .unwrap_or_else(|e| panic!("setup: {e}"));
    (setup, w)
}

/// Runs `step`, which the reference does not refuse and production must accept.
fn accept(w: &mut SodWorld, step: &Step, what: &str) {
    if let Verdict::Refuse(why) = verdict(&w.view, &w.truth, &step.ask(w.now)) {
        panic!("{what}: the reference refuses ({why}), so the story is wrong");
    }
    w.exec(step, Facts::Effective)
        .unwrap_or_else(|e| panic!("{what}: harness: {e}"))
        .unwrap_or_else(|r| panic!("{what} refused: {r}"));
}

/// Processes the newer vault epoch. The records are checked by the scenario
/// test of the reaction, not here.
fn react(w: &mut SodWorld) {
    w.sync(Facts::Effective)
        .unwrap_or_else(|e| panic!("reaction: harness: {e}"))
        .unwrap_or_else(|r| panic!("the reaction was refused: {r}"));
}

/// a's Drafting and c's Judging grants, then the merge of c into the
/// identity of a and b, with its reaction.
fn merged(w: &mut SodWorld) {
    accept(
        w,
        &grant(DRAFTING, A, P1, Role::ProgrammeManager, T0),
        "a's grant",
    );
    accept(
        w,
        &grant(JUDGING, C, P1, Role::CommitteeMember, T0),
        "c's grant",
    );
    w.truth.set_identity(C, ID_AB);
    react(w);
}

/// I-06, I-01, SoD-05, Identity discovery (decided 2026-10-25): c's
/// Judging binding under a conflict-of-interest suspension never counts as
/// held, and its end pins no bar that counts.
///
/// Story at P-12 = 0: after the merge, a's binding ends (bar 1). P-12 is
/// raised to 2, and c's suspended binding ends (bar 3 if it counted). Call
/// 2 is published. c then drafts in call 2, which is outside a's bar and
/// inside the bar c's binding would pin. Only a binding that never counts
/// lets the draft through.
#[test]
fn i06_conflict_suspension_is_not_held_and_pins_no_bar() {
    let (setup, mut w) = world(0);
    merged(&mut w);

    let j = w.state.roster().binding(JUDGING).expect("c's binding");
    assert_eq!(
        j.status,
        BindingStatus::Suspended(RuleRef::I06),
        "c's Judging binding must be under a conflict-of-interest suspension"
    );
    assert!(
        !j.held(),
        "a conflict-of-interest suspension never counts as held (Identity discovery)"
    );
    assert!(
        !w.view.bindings[&JUDGING].held(),
        "the reference must not count it as held"
    );

    accept(&mut w, &end(DRAFTING, T0), "a's end");
    let head = setup.version(P1).unwrap_or_else(|e| panic!("head: {e}"));
    let raise = edit_policy(&head, PolicyVersionId::from_raw(2), |v| {
        v.live.p12 = CoolingOff(2);
    });
    accept(&mut w, &raise, "P-12 edit");
    // Test-author reading: an open binding under a conflict-of-interest
    // suspension can still end. The bar its end pins never counts.
    accept(
        &mut w,
        &end(JUDGING, T0),
        "the end of c's suspended binding",
    );
    assert_eq!(
        w.state.roster().bar(P1, C, Group::Judging),
        None,
        "a conflict-of-interest suspension pins no cooling-off bar"
    );
    let live = w
        .state
        .roster()
        .ended()
        .find(|(id, _)| *id == JUDGING)
        .map(|(_, e)| e.live_bar());
    assert_eq!(
        live,
        Some(None),
        "c's ended binding is kept and pins no live bar"
    );

    accept(&mut w, &publish(call(2)), "publication of call 2");
    let step = draft(
        C,
        ProposalId::from_raw(1),
        call(2),
        BindingId::from_raw(201),
        false,
    );
    assert_eq!(
        verdict(&w.view, &w.truth, &step.ask(w.now)),
        Verdict::Accept,
        "the reference accepts c's draft in call 2"
    );
    match w.exec(&step, Facts::Effective).unwrap() {
        Ok(_) => {}
        Err(r) => panic!(
            "I-06: c's draft in call 2 was refused with {r}, so the conflict-of-interest suspension still counted"
        ),
    }
    if let Err(e) = check_i01(&w.view) {
        panic!("{e}");
    }
    if let Err(e) = check_i06(&w.view, &w.truth) {
        panic!("{e}");
    }
}

/// I-06, SoD-09, Identity discovery (decided 2026-10-25): a binding under a
/// conflict-of-interest suspension is not in the candidate set of a later
/// SoD-09 question. After the merge, the vault verifies b, of the same
/// identity, and b is granted call drafter. The only binding of another
/// group behind that identity is c's suspended committee binding, so the
/// grant must pass.
#[test]
fn i06_conflict_suspension_leaves_the_sod09_candidate_set() {
    let (_, mut w) = world(1);
    merged(&mut w);
    w.truth.verify(B);
    react(&mut w);

    let step = grant(BindingId::from_raw(303), B, P1, Role::CallDrafter, T0);
    assert_eq!(
        verdict(&w.view, &w.truth, &step.ask(w.now)),
        Verdict::Accept,
        "the reference accepts b's grant"
    );
    match w.exec(&step, Facts::Effective).unwrap() {
        Ok(_) => {}
        Err(r) => panic!(
            "SoD-09: b's call drafter grant was refused with {r}, so the suspended Judging binding stayed in the candidate set"
        ),
    }
    if let Err(e) = check_i06(&w.view, &w.truth) {
        panic!("{e}");
    }
}

/// I-06, Identity discovery (decided 2026-10-25): the reinstatement of a
/// conflict-of-interest suspension is refused while the identity clash
/// lasts. Once the vault splits c from the identity of a again, the clash
/// is over and the reinstatement goes through.
#[test]
fn i06_conflict_suspension_cannot_be_reinstated_while_the_clash_lasts() {
    let (_, mut w) = world(1);
    merged(&mut w);

    let step = reinstate(JUDGING);
    assert!(
        matches!(
            verdict(&w.view, &w.truth, &step.ask(w.now)),
            Verdict::Refuse(_)
        ),
        "the reference refuses the reinstatement while the clash lasts"
    );
    match w.exec(&step, Facts::Effective).unwrap() {
        Ok(records) => panic!(
            "I-06: c's Judging binding was reinstated while c shares a's verified identity: {records:?}"
        ),
        Err(r) => assert_eq!(r.rule, RuleRef::I06, "refused for {r}"),
    }
    assert_eq!(
        w.state.roster().binding(JUDGING).map(|b| b.status),
        Some(BindingStatus::Suspended(RuleRef::I06)),
        "a refused reinstatement leaves the suspension in place"
    );

    w.truth.set_identity(C, ID_C);
    react(&mut w);
    accept(
        &mut w,
        &reinstate(JUDGING),
        "the reinstatement after the split",
    );
    let j = w.state.roster().binding(JUDGING).expect("c's binding");
    assert_eq!(
        j.status,
        BindingStatus::Active,
        "c's binding after reinstatement"
    );
    if let Err(e) = check_i06(&w.view, &w.truth) {
        panic!("{e}");
    }
}

/// Suspends `binding` by injecting the record enforcement point 3 writes
/// for a new violation other than the conflict of interest.
fn suspend_ordinarily(w: &mut SodWorld, binding: BindingId) {
    let epoch = w.epoch();
    w.commit(&[Record::BindingSuspended(BindingSuspended {
        binding,
        rule: RuleRef::I01,
        epoch,
    })])
    .unwrap_or_else(|e| panic!("ordinary suspension of {binding:?}: {e}"));
}

/// The split of c from the identity of a, its reaction, and the
/// reinstatement of c's binding, which must now be accepted.
fn split_and_reinstate(w: &mut SodWorld) {
    w.truth.set_identity(C, ID_C);
    react(w);
    accept(w, &reinstate(JUDGING), "the reinstatement after the split");
}

/// I-06, enforcement point 3, Identity discovery (decided 2026-10-25): a
/// conflict-of-interest suspension that lands on a binding already under
/// an ordinary suspension keeps that suspension. Reinstating the conflict
/// of interest after the split falls back to the ordinary suspension,
/// which is still pending resolution. It does not make the binding active.
#[test]
fn i06_conflict_suspension_keeps_an_earlier_ordinary_suspension() {
    let (_, mut w) = world(1);
    accept(
        &mut w,
        &grant(DRAFTING, A, P1, Role::ProgrammeManager, T0),
        "a's grant",
    );
    accept(
        &mut w,
        &grant(JUDGING, C, P1, Role::CommitteeMember, T0),
        "c's grant",
    );
    suspend_ordinarily(&mut w, JUDGING);
    w.truth.set_identity(C, ID_AB);
    react(&mut w);
    let j = w.state.roster().binding(JUDGING).expect("c's binding");
    assert!(
        j.conflict_of_interest() && !j.held(),
        "the merge must put c's binding under a conflict-of-interest suspension, got {:?}",
        j.status
    );

    split_and_reinstate(&mut w);
    let j = w.state.roster().binding(JUDGING).expect("c's binding");
    assert_eq!(
        j.status,
        BindingStatus::Suspended(RuleRef::I01),
        "enforcement point 3: reinstating the conflict of interest dropped the earlier suspension"
    );
    assert!(
        j.held() && !j.active_at(w.now),
        "the earlier suspension counts as held and stays inactive"
    );
    let r = &w.view.bindings[&JUDGING];
    assert!(
        r.held() && r.suspended && !r.conflict_of_interest,
        "the reference keeps the earlier suspension too"
    );

    accept(&mut w, &reinstate(JUDGING), "the second reinstatement");
    let j = w.state.roster().binding(JUDGING).expect("c's binding");
    assert_eq!(
        j.status,
        BindingStatus::Active,
        "the second reinstatement lifts the earlier suspension"
    );
    if let Err(e) = check_i06(&w.view, &w.truth) {
        panic!("{e}");
    }
}

/// I-06, enforcement point 3, Identity discovery (decided 2026-10-25): an
/// ordinary suspension for another violation folds onto a binding under a
/// conflict-of-interest suspension. The binding stays out of the held
/// set. Reinstating the conflict of interest after the split leaves the
/// ordinary suspension in place.
#[test]
fn i06_ordinary_suspension_folds_beneath_a_conflict_suspension() {
    let (_, mut w) = world(1);
    merged(&mut w);
    suspend_ordinarily(&mut w, JUDGING);
    let j = w.state.roster().binding(JUDGING).expect("c's binding");
    assert!(
        j.conflict_of_interest() && !j.held(),
        "I-06: an ordinary suspension must not lift the conflict of interest, got {:?}",
        j.status
    );
    assert!(
        !w.view.bindings[&JUDGING].held(),
        "the reference must not count it as held"
    );
    if let Err(e) = check_i06(&w.view, &w.truth) {
        panic!("{e}");
    }

    split_and_reinstate(&mut w);
    let j = w.state.roster().binding(JUDGING).expect("c's binding");
    assert_eq!(
        j.status,
        BindingStatus::Suspended(RuleRef::I01),
        "enforcement point 3: the ordinary suspension must survive the reinstatement of the conflict of interest"
    );
    assert!(
        w.view.bindings[&JUDGING].suspended,
        "the reference keeps the ordinary suspension"
    );
}

/// I-06, R-CF-04, Identity discovery (decided 2026-10-25): the roster keeps
/// the conflict-of-interest discovery, with the epoch of its record, after
/// the suspension is reinstated. Lane L-REV can then still record the
/// notifiable conflicts on scores c already gave, in a later command.
#[test]
fn i06_r_cf_04_conflict_discovery_survives_reinstatement() {
    let (_, mut w) = world(1);
    merged(&mut w);
    let at = w.state.epoch();
    let expected = IdentityDiscovery::ConflictOfInterest {
        binding: JUDGING,
        account: C,
        programme: P1,
        role: Role::CommitteeMember,
        epoch: at,
    };
    let found: Vec<IdentityDiscovery> = w.state.roster().identity_discoveries().collect();
    assert_eq!(found, vec![expected], "the discovery after the merge");

    split_and_reinstate(&mut w);
    assert_eq!(
        w.state.roster().binding(JUDGING).map(|b| b.status),
        Some(BindingStatus::Active),
        "c's binding after reinstatement"
    );
    let found: Vec<IdentityDiscovery> = w.state.roster().identity_discoveries().collect();
    assert_eq!(
        found,
        vec![expected],
        "R-CF-04: the reinstatement erased the conflict-of-interest discovery"
    );
    assert_eq!(found[0].epoch(), at, "the discovery keeps its epoch");
}

/// c's IRC binding in the I-02 stories.
const IRC: BindingId = BindingId::from_raw(303);

/// I-02, SoD-02, Identity discovery (decided 2026-10-25): counted again, a
/// reinstated conflict-of-interest suspension counts over its suspension
/// period. So it is refused under I-02 when an IRC binding of its own
/// account was held beside it, even one that has ended since.
///
/// Story at P-12 = 1: after the merge, the vault splits c from a again. c
/// is granted IRC member while the committee binding does not count, and
/// that IRC binding ends. Reinstating the committee binding would show c
/// holding both at the same time, so production and the reference refuse.
#[test]
fn i06_i02_reinstatement_refused_after_an_irc_binding_held_beside_it() {
    let (_, mut w) = world(1);
    merged(&mut w);
    w.truth.set_identity(C, ID_C);
    react(&mut w);
    accept(
        &mut w,
        &grant(IRC, C, P1, Role::IrcMember, T0),
        "c's IRC grant while the committee binding does not count",
    );
    accept(&mut w, &end(IRC, T0), "the end of c's IRC binding");

    let step = reinstate(JUDGING);
    let reference = verdict(&w.view, &w.truth, &step.ask(w.now));
    assert!(
        matches!(&reference, Verdict::Refuse(why) if why.contains("I-02")),
        "the reference refuses under I-02, got {reference:?}"
    );
    match w.exec(&step, Facts::Effective).unwrap() {
        Ok(records) => panic!(
            "I-02: c's committee binding was reinstated over an IRC binding held beside it: {records:?}"
        ),
        Err(r) => assert_eq!(r.rule, RuleRef::I02, "refused for {r}"),
    }
}

/// I-02, SoD-02 NOTE 4, Identity discovery (decided 2026-10-25): an IRC
/// binding that ended before the committee grant was never held beside
/// it. A past Judging binding never bars, so the reinstatement after the
/// split goes through. At P-12 = 0, with call 2 published before the
/// merge, the IRC bar (1) does not reach a's opening (2). So the merge
/// leaves the ended IRC binding counted, and the test has teeth.
#[test]
fn i06_i02_reinstatement_ignores_an_irc_binding_ended_before_the_grant() {
    let (_, mut w) = world(0);
    accept(
        &mut w,
        &grant(IRC, C, P1, Role::IrcMember, T0),
        "c's IRC grant",
    );
    accept(&mut w, &end(IRC, T0), "the end of c's IRC binding");
    accept(&mut w, &publish(call(2)), "publication of call 2");
    merged(&mut w);
    assert!(
        w.view.bindings[&IRC].counts(),
        "the ended IRC binding must still count, or the story proves nothing"
    );
    w.truth.set_identity(C, ID_C);
    react(&mut w);
    split_reinstated(&mut w);
}

/// Accepts the reinstatement of c's committee binding and checks that it
/// is active again.
fn split_reinstated(w: &mut SodWorld) {
    accept(w, &reinstate(JUDGING), "the reinstatement after the split");
    assert_eq!(
        w.state.roster().binding(JUDGING).map(|b| b.status),
        Some(BindingStatus::Active),
        "c's binding after reinstatement"
    );
}

/// Suspends `binding` under `rule`, as enforcement point 3 would for a new
/// violation other than the conflict of interest.
fn suspend_under(w: &mut SodWorld, binding: BindingId, rule: RuleRef) {
    let epoch = w.epoch();
    w.commit(&[Record::BindingSuspended(BindingSuspended {
        binding,
        rule,
        epoch,
    })])
    .unwrap_or_else(|e| panic!("ordinary suspension of {binding:?} under {rule:?}: {e}"));
}

/// I-06, enforcement point 3, Identity discovery (decided 2026-10-25): a
/// second ordinary suspension folds under a conflict-of-interest
/// suspension, as the reference does. The latest rule is kept beneath the
/// marker, and the binding stays out of the held set.
#[test]
fn i06_second_ordinary_suspension_folds_beneath_a_conflict_suspension() {
    let (_, mut w) = world(1);
    merged(&mut w);
    suspend_ordinarily(&mut w, JUDGING);
    suspend_under(&mut w, JUDGING, RuleRef::I04);
    let j = w.state.roster().binding(JUDGING).expect("c's binding");
    assert!(
        j.conflict_of_interest() && !j.held(),
        "I-06: a further ordinary suspension must not lift the conflict of interest, got {:?}",
        j.status
    );
    if let Err(e) = check_i06(&w.view, &w.truth) {
        panic!("{e}");
    }
    split_and_reinstate(&mut w);
    assert_eq!(
        w.state.roster().binding(JUDGING).map(|b| b.status),
        Some(BindingStatus::Suspended(RuleRef::I04)),
        "enforcement point 3: the latest ordinary suspension survives the reinstatement"
    );
}

/// I-06, enforcement point 3, Identity discovery (decided 2026-10-25): an
/// ordinary suspension folds onto an ended binding under a
/// conflict-of-interest suspension. It stays out of the held set and still
/// pins no bar.
#[test]
fn i06_ordinary_suspension_folds_onto_an_ended_conflict_suspension() {
    let (_, mut w) = world(1);
    merged(&mut w);
    accept(
        &mut w,
        &end(JUDGING, T0),
        "the end of c's suspended binding",
    );
    suspend_ordinarily(&mut w, JUDGING);
    let (_, e) = w
        .state
        .roster()
        .ended()
        .find(|(id, _)| *id == JUDGING)
        .expect("c's ended binding");
    assert!(
        e.binding.conflict_of_interest() && e.live_bar().is_none(),
        "I-06: the ended conflict-of-interest suspension must still pin no bar, got {:?}",
        e.binding.status
    );
    assert_eq!(
        w.state.roster().bar(P1, C, Group::Judging),
        None,
        "I-06: no Judging bar counts for c"
    );
    if let Err(e) = check_i06(&w.view, &w.truth) {
        panic!("{e}");
    }
}

/// I-04, I-06, enforcement point 3: a second ordinary suspension of an
/// ordinarily suspended binding folds and keeps the latest rule. The
/// binding still counts as held. One reinstatement lifts it, as in the
/// reference.
#[test]
fn i06_second_ordinary_suspension_of_a_suspended_binding_folds() {
    let (_, mut w) = world(1);
    accept(
        &mut w,
        &grant(JUDGING, C, P1, Role::CommitteeMember, T0),
        "c's grant",
    );
    suspend_ordinarily(&mut w, JUDGING);
    suspend_under(&mut w, JUDGING, RuleRef::I02);
    let j = w.state.roster().binding(JUDGING).expect("c's binding");
    assert_eq!(j.status, BindingStatus::Suspended(RuleRef::I02));
    assert!(j.held(), "an ordinary suspension still counts as held");
    accept(&mut w, &reinstate(JUDGING), "the reinstatement");
    assert_eq!(
        w.state.roster().binding(JUDGING).map(|b| b.status),
        Some(BindingStatus::Active),
        "one reinstatement lifts the ordinary suspension, as in the reference"
    );
    assert!(!w.view.bindings[&JUDGING].suspended);
}
