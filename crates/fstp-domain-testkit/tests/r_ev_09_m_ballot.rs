//! R-EV-09 and P-16 NOTE 8 on M-BALLOT (M4 design sections 3.4 D5 and 8.5).
//!
//! Four committee members and a chair, one of them recused, one delegation
//! and one round, from genesis by production commands. Properties:
//! `always("two-way")`, the counted ballots were cast by their voters or
//! their single delegates, the recused member neither votes nor counts,
//! the outcome follows P-16 NOTE 8, and each member acts only for
//! themselves. A new round supersedes the round only after its vote
//! failed. Witnesses: a decided round, a tie broken by the chair's casting
//! vote, a counted delegated vote, and a new round after a failed vote.
//! The run is exhaustive, and
//! its state count must equal the count computed from the reference.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::ballot_model::{
    BallotModel, TRIPWIRE, ballot_properties, member_acts_only_for_themselves,
};

/// R-EV-09, P-16 NOTE 8 (D5, Q4 interim reading): over every order of
/// casts and the delegation, each counted ballot was cast by its voter or
/// its single delegate, recused members neither vote nor count, and the
/// recorded outcome is the P-16 outcome of the ballots cast.
#[test]
fn r_ev_09_m_ballot() {
    let model = BallotModel::new().unwrap_or_else(|e| panic!("M-BALLOT start from genesis: {e}"));
    let mut properties = ballot_properties::<BallotModel>();
    properties.push(member_acts_only_for_themselves());
    let outcome = check_exhaustive(&model, &properties, TRIPWIRE).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        outcome.stats.states, TRIPWIRE,
        "M-BALLOT: production reaches exactly the ballot states the reference admits"
    );
}
