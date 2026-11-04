//! Review finding (lane m4glue, lens INVARIANTS): the re-grant guard of
//! Daniel's answer of 2026-10-31 (M4 design section 15.0) and a binding
//! under a conflict-of-interest suspension.
//!
//! Section 15.0 reads: "A domain guard in `GrantRole` refuses a grant
//! while the account holds a binding of the same role on the programme
//! that has not ended." A binding under a conflict-of-interest suspension
//! (I-06, Identity discovery) has not ended. It stays in the roster, and
//! `ReinstateBinding` makes it active again once the clash is over. So a
//! grant beside it, then its reinstatement, leaves the account with two
//! active bindings of one role on one programme. The guard exists to
//! prevent exactly that state.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::BindingId;
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::{BindingStatus, Role};
use fstp_domain_testkit::r#gen::roster::{
    A, Backend, C, Facts, ID_AB, ID_C, P1, SodSetup, SodWorld, Step, T0, call, grant, reinstate,
    sod_truth,
};

/// a's programme manager binding.
const DRAFTING: BindingId = BindingId::from_raw(301);
/// c's committee binding, suspended as a conflict of interest after the merge.
const JUDGING: BindingId = BindingId::from_raw(302);
/// The second committee binding of c that the grant beside the suspended
/// binding would create.
const SECOND: BindingId = BindingId::from_raw(304);

fn world() -> SodWorld {
    let mut setup = SodSetup::one(1, &[1, 2, 3]);
    setup.published = vec![call(1)];
    SodWorld::from_setup(Backend::Production, sod_truth(), &setup)
        .unwrap_or_else(|e| panic!("setup: {e}"))
}

fn accept(w: &mut SodWorld, step: &Step, what: &str) {
    w.exec(step, Facts::Effective)
        .unwrap_or_else(|e| panic!("{what}: harness: {e}"))
        .unwrap_or_else(|r| panic!("{what} refused: {r}"));
}

fn react(w: &mut SodWorld) {
    w.sync(Facts::Effective)
        .unwrap_or_else(|e| panic!("reaction: harness: {e}"))
        .unwrap_or_else(|r| panic!("the reaction was refused: {r}"));
}

/// Re-granting a role, M4 design section 15.0 (Daniel, 2026-10-31), with
/// I-06 Identity discovery: while c's committee binding is under a
/// conflict-of-interest suspension it has not ended, so a second committee
/// grant to c on the same programme must be refused. Otherwise the
/// reinstatement of the first leaves c with two active committee bindings.
#[test]
fn review_invariants_regrant_refused_beside_a_conflict_of_interest_suspension() {
    let mut w = world();
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
    // The vault merges c into a's identity: c's binding is suspended as a
    // conflict of interest. It is not ended.
    w.truth.set_identity(C, ID_AB);
    react(&mut w);
    assert_eq!(
        w.state.roster().binding(JUDGING).map(|b| b.status),
        Some(BindingStatus::Suspended(RuleRef::I06)),
        "story: c's binding is under a conflict-of-interest suspension"
    );
    // The vault splits c again. The clash is over, the binding still open.
    w.truth.set_identity(C, ID_C);
    react(&mut w);

    let regrant = grant(SECOND, C, P1, Role::CommitteeMember, T0);
    let got = w
        .exec(&regrant, Facts::Effective)
        .unwrap_or_else(|e| panic!("harness: {e}"));
    if got.is_ok() {
        // Show the state the guard is meant to prevent.
        let reinstated = w
            .exec(&reinstate(JUDGING), Facts::Effective)
            .unwrap_or_else(|e| panic!("harness: {e}"));
        let active: Vec<BindingId> = w
            .state
            .roster()
            .bindings()
            .filter(|(_, b)| {
                b.account == C
                    && b.programme == P1
                    && b.role == Role::CommitteeMember
                    && b.status == BindingStatus::Active
            })
            .map(|(id, _)| id)
            .collect();
        panic!(
            "M4 design 15.0: a committee grant to c was accepted while c's binding {JUDGING:?} \
             had not ended (conflict-of-interest suspension). Reinstating it then gave \
             {reinstated:?}, and c holds these active committee bindings on P1: {active:?}"
        );
    }
}
