//! R-EV-09 teeth on M-BALLOT (M4 design sections 6.1 "Teeth", 8.1 and 8.5).
//!
//! The fault: a broken engine records a cut-off that counts a ballot of the
//! recused member, which nobody cast. The property
//! `R-EV-09: counted ballots were cast` must report it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_domain_testkit::mc::ballot_model::{
    BallotModel, TRIPWIRE, ballot_properties, fault_uncast_ballot_counted,
};
use fstp_mc::check;

/// R-EV-09, D5: a counted ballot that its voter never cast is caught.
#[test]
fn r_ev_09_teeth_uncast_ballot_counted_is_caught() {
    let model = BallotModel::new().unwrap_or_else(|e| panic!("M-BALLOT start from genesis: {e}"));
    let mutant = Injecting::new(&model, fault_uncast_ballot_counted);
    let properties = ballot_properties::<Injecting<'_, BallotModel, _>>();
    let outcome = check(&mutant, &properties, &tripwire(TRIPWIRE.saturating_mul(2)));
    if let Err(e) = expect_violation(&outcome, "R-EV-09: counted ballots were cast") {
        panic!("{e}");
    }
}
