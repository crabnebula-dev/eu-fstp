//! I-02 teeth on M-SOD (design 6.1 "Teeth" and 6.2).
//!
//! The fault is an IRC binding granted beside a held committee binding of
//! the same account. Assignments belong to lane L-REV, so the assignment
//! half of this fault, an IRC member with a reviewer assignment, joins in
//! step W4. The `I-02` property must report the binding half.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_domain_testkit::mc::sod_model::{
    M_SOD_I02_STATES, SodModel, fault_irc_beside_committee, i02_config, i02_properties,
};
use fstp_mc::check;

fn caught(backend: Backend) {
    let model = SodModel::new(i02_config(), backend)
        .unwrap_or_else(|e| panic!("M-SOD start from genesis: {e}"));
    let mutant = Injecting::new(&model, fault_irc_beside_committee);
    let properties = i02_properties::<Injecting<'_, SodModel, _>>();
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(M_SOD_I02_STATES.saturating_mul(4)),
    );
    if let Err(e) = expect_violation(&outcome, "I-02") {
        panic!("{e}");
    }
}

/// I-02: an IRC member who also holds a committee binding is caught.
#[test]
fn i02_teeth_irc_with_assignment_is_caught() {
    caught(Backend::Production);
}

/// I-02: the same fault is caught on the reference alone.
#[test]
fn i02_teeth_irc_with_assignment_is_caught_on_the_reference() {
    caught(Backend::Reference);
}
