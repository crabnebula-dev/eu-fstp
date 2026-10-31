//! I-77, I-79, m3-base re-derivation 2: `RosterView::from_roster` over a
//! real M2 roster, folded by the M2 deciders through the domain testkit.
//!
//! The holdings rule of design section 8.2 counts active, scheduled and
//! suspended bindings of the Drafting, Judging and Operations groups. It
//! drops voided bindings. A scheduled end counts until its instant. The
//! M2 roster's `Binding::held` drops a Judging binding under a
//! conflict-of-interest suspension (rule I-06), so the holdings rule must
//! not reuse it.
//!
//! Story, synthetic accounts only:
//!
//! - a holds a programme manager binding (Drafting).
//! - c holds a committee binding (Judging). The vault then merges c into
//!   a's identity, and the reaction suspends c's binding under I-06.
//! - e holds a programme manager binding whose end is scheduled.
//! - f holds a committee binding. d drafts a proposal (Receiving). The
//!   vault then gives f d's identity, and the reaction voids d's binding.
//!
//! Lane W2b, fix round 1.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use fstp_auth::{RosterView, TenantView, holds_management};
use fstp_domain::id::{AccountId, BindingId, ProposalId};
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::{BindingStatus, Role};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{
    A, Backend, C, Facts, ID_AB, P1, SodSetup, SodWorld, Step, T0, call, draft, grant, grant_until,
    sod_truth,
};
use fstp_domain_testkit::vault::IdentityTag;

/// Account d: an applicant with its own verified identity.
const D: AccountId = AccountId::from_raw(104);
/// Account e: a programme manager whose end is scheduled.
const E: AccountId = AccountId::from_raw(105);
/// Account f: a committee member.
const F: AccountId = AccountId::from_raw(106);

const ID_D: IdentityTag = IdentityTag::new(1004);
const ID_E: IdentityTag = IdentityTag::new(1005);
const ID_F: IdentityTag = IdentityTag::new(1006);

/// a's programme manager binding.
const A_PM: BindingId = BindingId::from_raw(301);
/// c's committee binding, suspended under I-06 after the merge.
const C_JUDGING: BindingId = BindingId::from_raw(302);
/// e's programme manager binding, with a scheduled end.
const E_PM: BindingId = BindingId::from_raw(303);
/// f's committee binding.
const F_JUDGING: BindingId = BindingId::from_raw(304);
/// d's applicant binding, voided after f takes d's identity.
const D_APPLICANT: BindingId = BindingId::from_raw(201);

/// The scheduled end of e's binding: ten seconds after `T0`.
const E_END: Timestamp = Timestamp::from_micros(T0.micros() + 10_000_000);

/// Runs `step`, which the M2 deciders must accept.
fn accept(w: &mut SodWorld, step: &Step, what: &str) {
    w.exec(step, Facts::Effective)
        .unwrap_or_else(|e| panic!("{what}: harness: {e}"))
        .unwrap_or_else(|r| panic!("{what} refused: {r}"));
}

/// Processes the newer vault epoch, which must be accepted.
fn react(w: &mut SodWorld, what: &str) {
    w.sync(Facts::Effective)
        .unwrap_or_else(|e| panic!("{what}: harness: {e}"))
        .unwrap_or_else(|r| panic!("{what} refused: {r}"));
}

/// The roster of the story, folded by production.
fn story() -> SodWorld {
    let mut truth = sod_truth();
    for (account, id) in [(D, ID_D), (E, ID_E), (F, ID_F)] {
        truth.set_identity(account, id);
        truth.verify(account);
    }
    let mut setup = SodSetup::one(1, &[1, 2, 3]);
    setup.published = vec![call(1)];
    let mut w = SodWorld::from_setup(Backend::Production, truth, &setup)
        .unwrap_or_else(|e| panic!("setup: {e}"));
    accept(&mut w, &grant(A_PM, A, P1, Role::ProgrammeManager, T0), "a");
    accept(
        &mut w,
        &grant(C_JUDGING, C, P1, Role::CommitteeMember, T0),
        "c",
    );
    let scheduled = grant_until(E_PM, E, P1, Role::ProgrammeManager, T0, E_END)
        .unwrap_or_else(|e| panic!("{e}"));
    accept(&mut w, &scheduled, "e with a scheduled end");
    accept(
        &mut w,
        &grant(F_JUDGING, F, P1, Role::CommitteeMember, T0),
        "f",
    );
    accept(
        &mut w,
        &draft(D, ProposalId::from_raw(1), call(1), D_APPLICANT, false),
        "d's draft",
    );
    w.truth.set_identity(C, ID_AB);
    react(&mut w, "the merge of c into a's identity");
    w.truth.set_identity(F, ID_D);
    react(&mut w, "f taking d's identity");
    w
}

/// I-77, I-79, design section 8.2: over a real M2 roster, the holdings
/// count the I-06 suspended Judging binding that `Binding::held` drops,
/// count a scheduled end until its instant and not at it, and drop the
/// voided binding.
#[test]
fn i77_holdings_from_m2_roster_count_suspended_and_scheduled_bindings() {
    let w = story();
    let roster = w.state.roster();

    let c = roster.binding(C_JUDGING).expect("c's binding");
    assert_eq!(c.status, BindingStatus::Suspended(RuleRef::I06));
    assert!(
        !c.held(),
        "the story needs the binding that Binding::held drops"
    );
    let d = roster.binding(D_APPLICANT).expect("d's binding");
    assert!(matches!(d.status, BindingStatus::Voided(_)), "{d:?}");
    let e = roster.binding(E_PM).expect("e's binding");
    assert_eq!(e.scheduled_end, Some(E_END));

    let facts = RosterView::facts(roster);
    let fact = |b: BindingId| {
        let binding = roster.binding(b).expect("binding");
        facts
            .iter()
            .find(|f| f.account == binding.account && f.role == binding.role)
            .copied()
            .expect("fact")
    };
    assert!(fact(C_JUDGING).suspended && !fact(C_JUDGING).voided);
    assert!(fact(D_APPLICANT).voided);
    assert_eq!(fact(E_PM).end, Some(E_END));

    let before = RosterView::from_roster(roster, T0);
    for who in [A, C, E, F] {
        assert!(before.management.contains(&who), "{who:?}: {before:?}");
    }
    assert!(!before.management.contains(&D), "{before:?}");
    assert_eq!(
        holds_management(&before, &TenantView::default(), C, T0),
        Ok(true)
    );

    let just_before = Timestamp::from_micros(E_END.micros() - 1);
    assert!(
        RosterView::from_roster(roster, just_before)
            .management
            .contains(&E)
    );
    let at_end = RosterView::from_roster(roster, E_END);
    assert!(!at_end.management.contains(&E), "{at_end:?}");
    for who in [A, C, F] {
        assert!(at_end.management.contains(&who), "{who:?}: {at_end:?}");
    }
}
