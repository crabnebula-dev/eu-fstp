//! I-39, M-LICENCE (design section 14.2): no licence state, refresh
//! outcome or tick around the grace end blocks evaluation, payments,
//! notifications or export.
//!
//! Lane W1g wrote these runs before the production code. The run over
//! production is red until `fstp_release::licence` (lane W2j) lands with
//! a `GateKind` row per class. The runs over the reference and the teeth
//! are red until lane W4 records the M-LICENCE count in
//! `fstp_celltest::mc::tripwires`;
//! `i39_m_licence_tripwire_records_the_measured_count` prints it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_celltest::mc::licence_model::{
    LicenceBackend, LicenceDefect, LicenceModel, Mutant, Production, Reference, ids, properties,
};
use fstp_celltest::mc::tripwires::{M_LICENCE, NOT_MEASURED, tripwire};
use fstp_domain_testkit::harness::teeth::expect_violation;
use fstp_mc::{Config, check, explore};

/// The bound of every M-LICENCE run: twice the recorded count (design
/// section 14.1). A count not yet recorded fails here, by name.
fn bound() -> Config {
    assert_ne!(
        M_LICENCE, NOT_MEASURED,
        "the M-LICENCE tripwire is not recorded yet (lane W4); \
         i39_m_licence_tripwire_records_the_measured_count gives the count"
    );
    Config::default()
        .with_stop_when_decided(false)
        .with_max_states(tripwire(M_LICENCE))
}

fn model<B: LicenceBackend>(backend: B) -> LicenceModel<B> {
    LicenceModel::new(backend).unwrap_or_else(|e| panic!("M-LICENCE fixtures: {e}"))
}

/// Runs M-LICENCE over `backend` and asserts every property passed
/// exhaustively.
fn passes<B: LicenceBackend>(backend: B) {
    let m = model(backend);
    let props = properties(&m);
    let outcome = check(&m, &props, &bound());
    assert!(
        outcome.exhaustive,
        "M-LICENCE did not finish under its tripwire:\n{outcome}"
    );
    if let Err(e) = outcome.require_all_passed() {
        panic!("{e}\n{outcome}");
    }
}

/// Runs M-LICENCE over `backend` and asserts that property `id` is
/// violated, and not by a stub.
fn caught<B: LicenceBackend>(backend: B, id: &str) {
    let m = model(backend);
    let props = properties(&m);
    let outcome = check(&m, &props, &bound().with_stop_when_decided(true));
    if let Err(e) = expect_violation(&outcome, id) {
        panic!("{e}\n{outcome}");
    }
    let message = match outcome.verdict(id).and_then(|v| v.violation()) {
        Some(v) => format!("{v:?}"),
        None => String::new(),
    };
    assert!(
        !message.contains("NotImplemented"),
        "teeth: {id} failed on a stub, not on the seeded defect: {message}"
    );
}

/// I-39, M-LICENCE over production: `fstp_release::licence` import,
/// verification, state and gate.
#[test]
fn i39_m_licence() {
    let backend = Production::new()
        .unwrap_or_else(|e| panic!("M-LICENCE production backend: {e} (NotImplemented)"));
    passes(backend);
}

/// I-39, M-LICENCE over the reference: every property and witness holds.
#[test]
fn i39_m_licence_on_the_reference() {
    passes(Reference);
}

/// I-39, design section 14.1: the recorded tripwire count is the measured
/// state count of M-LICENCE over the reference.
#[test]
fn i39_m_licence_tripwire_records_the_measured_count() {
    let space = explore(&model(Reference), &Config::default());
    assert!(
        space.exhaustive,
        "M-LICENCE over the reference did not finish"
    );
    assert_eq!(
        M_LICENCE,
        space.len(),
        "record the measured M-LICENCE count {} in fstp_celltest::mc::tripwires (lane W4)",
        space.len()
    );
}

/// I-39 teeth (design sections 14.2 and 20): a gate that refuses
/// `ReleasePayment` outside a valid licence fails `always("I-39")`.
#[test]
fn i39_teeth_gate_on_release_payment_is_caught() {
    caught(
        Mutant::new(Reference, LicenceDefect::GateOnReleasePayment),
        ids::I39,
    );
}

/// P-43 teeth (design section 14.1 "Reduced clock"): a grace period that
/// includes its end instant fails the two-way check at the grace end tick.
#[test]
fn i39_teeth_grace_end_off_by_one_is_caught() {
    caught(
        Mutant::new(Reference, LicenceDefect::GraceEndInclusive),
        ids::TWO_WAY,
    );
}

/// I-39 teeth (design section 10.2, refresh): a refresh that adopts any
/// validly signed token, without checking its licence id or its age,
/// stores the replayed T1 over T2 or the foreign token. That fails
/// `always("garbage-never-adopted")`.
#[test]
fn i39_teeth_refresh_adopts_replayed_or_foreign_token_is_caught() {
    caught(
        Mutant::new(Reference, LicenceDefect::RefreshSkipsLicenceAndAge),
        ids::GARBAGE,
    );
}
