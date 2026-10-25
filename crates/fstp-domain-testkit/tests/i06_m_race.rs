//! I-06 on M-RACE, with and without the verification commit protocol (design 4.3 and 6.3).
//!
//! A grant request to a races the vault's verification of b, the Sybil of
//! a holding an Applicant binding. With the protocol of
//! `SPEC/03-architecture/overview.md` NOTE 4, no state breaks I-06 over the
//! vault's effective facts. Without it, a grant asked before the change and
//! committed before the reaction leaves both accounts bound, which the
//! second test asserts is reachable. That documents the M3 need.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::{check_exhaustive, tripwire};
use fstp_domain_testkit::harness::teeth::expect_violation;
use fstp_domain_testkit::mc::race_model::{
    M_RACE_NO_PROTOCOL_STATES, M_RACE_PROTOCOL_STATES, RaceModel, race_properties,
};
use fstp_mc::check;

fn with_protocol(backend: Backend) {
    let model =
        RaceModel::new(true, backend).unwrap_or_else(|e| panic!("M-RACE start from genesis: {e}"));
    let properties = race_properties::<RaceModel>();
    if let Err(e) = check_exhaustive(&model, &properties, M_RACE_PROTOCOL_STATES) {
        panic!("{e}");
    }
}

fn without_protocol(backend: Backend) {
    let model =
        RaceModel::new(false, backend).unwrap_or_else(|e| panic!("M-RACE start from genesis: {e}"));
    let properties = race_properties::<RaceModel>();
    let outcome = check(&model, &properties, &tripwire(M_RACE_NO_PROTOCOL_STATES));
    assert!(
        outcome.exhaustive,
        "M-RACE without the protocol is not exhaustive\n{outcome}"
    );
    if let Err(e) = expect_violation(&outcome, "I-06") {
        panic!("{e}");
    }
    let two_way = outcome.verdict("two-way").is_some_and(|v| v.is_pass());
    assert!(
        two_way,
        "production and the reference disagree in M-RACE\n{outcome}"
    );
}

/// I-06, overview NOTE 4: with the verification commit protocol, a grant
/// racing a verification never breaks I-06 at any instant.
#[test]
fn i06_m_race_with_protocol() {
    with_protocol(Backend::Production);
}

/// I-06, overview NOTE 4: without the protocol, a state that breaks I-06 is
/// reachable, which is why M3 needs the protocol.
#[test]
fn i06_m_race_without_protocol_reaches_violation() {
    without_protocol(Backend::Production);
}

/// I-06: M-RACE with the protocol passes on the reference alone.
#[test]
fn i06_m_race_with_protocol_reference() {
    with_protocol(Backend::Reference);
}

/// I-06: M-RACE without the protocol reaches the violation on the reference alone.
#[test]
fn i06_m_race_without_protocol_reaches_violation_reference() {
    without_protocol(Backend::Reference);
}
