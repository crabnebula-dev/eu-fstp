//! Review reproducers for lane L-SOD, spec fidelity lens (step W3b).
//!
//! Each test fails against the lane's current code and passes once the
//! named defect is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{BindingId, ProposalId};
use fstp_domain::record::{BindingEnded, Record};
use fstp_domain::roles::{CoolingOff, Group, Role};
use fstp_domain_testkit::r#gen::roster::{
    A, B, Backend, Facts, P1, SodSetup, SodWorld, T0, call, draft, grant, publish, sod_truth,
};
use fstp_domain_testkit::reference::sod::check_i06;

/// I-06 and Identity discovery (`roles-and-sod.md`): when the vault
/// verifies b, every Receiving binding of b is voided, past bindings
/// within the cooling-off bar included, so that they pin no bar.
///
/// Story, P-12 = 2: b (unverified, same identity as a) leads a proposal in
/// call 1. The proposal reaches a terminal state, so b's binding ends with
/// bar 1 + 2 = 3. The end record is the one `terminal_ends` writes; it is
/// folded directly because lane L-LIFE's `Transitioned` fold is a stub.
/// Then a, verified, gets a committee binding while the latest call is 1.
/// The identity query over {b} answers false, since b is unverified. Call 2
/// is published and b leads a second proposal. The vault then verifies b.
///
/// The reaction voids b's call 2 binding, but b's ended call 1 binding
/// keeps its bar 3, and a's committee binding was granted inside it. One
/// verified identity now holds a Judging role and a past Receiving binding
/// within the cooling-off period: I-06 is broken after the reaction.
#[test]
fn review_i06_discovery_leaves_past_receiving_bar_of_discovered_account() {
    let mut setup = SodSetup::one(2, &[1, 2]);
    setup.published = vec![call(1)];
    let mut w = SodWorld::from_setup(Backend::Production, sod_truth(), &setup)
        .unwrap_or_else(|e| panic!("setup: {e}"));

    let first = BindingId::from_raw(201);
    let step = draft(B, ProposalId::from_raw(1), call(1), first, false);
    w.exec(&step, Facts::Effective)
        .unwrap()
        .unwrap_or_else(|r| panic!("b's first draft refused: {r}"));

    // The end that `terminal_ends` records when proposal 1 reaches a
    // terminal state: latest published seq 1 plus P-12 2.
    w.commit(&[Record::BindingEnded(BindingEnded {
        binding: first,
        at: T0,
        barred_through: 3,
        p12: CoolingOff(2),
    })])
    .unwrap_or_else(|e| panic!("terminal end: {e}"));
    assert_eq!(w.state.roster().bar(P1, B, Group::Receiving), Some(3));

    let committee = grant(BindingId::from_raw(301), A, P1, Role::CommitteeMember, T0);
    w.exec(&committee, Facts::Effective)
        .unwrap()
        .unwrap_or_else(|r| panic!("a's committee grant refused: {r}"));
    w.exec(&publish(call(2)), Facts::Effective)
        .unwrap()
        .unwrap_or_else(|r| panic!("call 2 publication refused: {r}"));
    let second = draft(
        B,
        ProposalId::from_raw(2),
        call(2),
        BindingId::from_raw(202),
        false,
    );
    w.exec(&second, Facts::Effective)
        .unwrap()
        .unwrap_or_else(|r| panic!("b's second draft refused: {r}"));
    assert!(
        check_i06(&w.view, &w.truth).is_ok(),
        "b is still unverified"
    );

    w.truth.verify(B);
    w.sync(Facts::Effective)
        .unwrap()
        .unwrap_or_else(|r| panic!("the reaction was refused: {r}"));

    if let Err(e) = check_i06(&w.view, &w.truth) {
        panic!("I-06 broken after the identity discovery reaction: {e}");
    }
}
