//! I-23 and NOTE 4: M-DRIVER (design section 14.2), `DriverCore` over a
//! store and a vault with a crash after append, a lost acknowledgement and
//! a stale head.
//!
//! Lane W1c wrote these tests before the production code. M-DRIVER over
//! production is red until lane W2c lands `DriverCore`, the lead adds the
//! `fstp-ledger` dependency of `mc::driver_model::LEDGER_SEAM`, and lane
//! W4 records the tripwire.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_celltest::mc::driver_model::{
    DriverBackend, DriverDefect, DriverModel, Mutant, Production, Reference, ids, properties,
};
use fstp_celltest::mc::tripwires::{M_DRIVER, NOT_MEASURED, tripwire};
use fstp_domain_testkit::harness::teeth::expect_violation;
use fstp_mc::{Config, check, explore};

fn bound() -> Config {
    assert_ne!(
        M_DRIVER, NOT_MEASURED,
        "the M-DRIVER tripwire is not recorded yet (lane W4); \
         seam_m_driver_i23_tripwire_records_the_measured_count gives the count"
    );
    Config::default()
        .with_stop_when_decided(false)
        .with_max_states(tripwire(M_DRIVER))
}

fn passes<B: DriverBackend>(backend: B)
where
    B::Run: 'static,
{
    let model = DriverModel::new(backend);
    let props = properties(&model);
    let outcome = check(&model, &props, &bound());
    assert!(
        outcome.exhaustive,
        "M-DRIVER did not finish under its tripwire:\n{outcome}"
    );
    if let Err(e) = outcome.require_all_passed() {
        panic!("{e}\n{outcome}");
    }
}

/// I-23, NOTE 4: M-DRIVER over production `DriverCore`.
#[test]
fn seam_m_driver_i23() {
    let backend = Production::new().unwrap_or_else(|e| panic!("M-DRIVER production backend: {e}"));
    passes(backend);
}

/// I-23, NOTE 4: M-DRIVER over the reference driver. Every property and
/// witness holds.
#[test]
fn seam_m_driver_i23_on_the_reference() {
    passes(Reference);
}

/// I-23, design section 14.1: the recorded tripwire count is the measured
/// state count of M-DRIVER over the reference.
#[test]
fn seam_m_driver_i23_tripwire_records_the_measured_count() {
    let space = explore(&DriverModel::new(Reference), &Config::default());
    assert!(
        space.exhaustive,
        "M-DRIVER over the reference did not finish"
    );
    assert_eq!(
        M_DRIVER,
        space.len(),
        "record the measured M-DRIVER count {} in fstp_celltest::mc::tripwires (lane W4)",
        space.len()
    );
}

/// I-23 teeth (design section 14.2, M-DRIVER row): a crash retry under a
/// fresh command id applies the command twice.
#[test]
fn seam_m_driver_i23_teeth_retry_with_fresh_command_id_is_caught() {
    let model = DriverModel::new(Mutant {
        defect: DriverDefect::RetryWithFreshId,
    });
    let props = properties(&model);
    let outcome = check(&model, &props, &bound().with_stop_when_decided(true));
    if let Err(e) = expect_violation(&outcome, ids::I23_ONCE) {
        panic!("{e}\n{outcome}");
    }
}

/// I-23, design section 5.2: the reference driver refuses a caller command
/// whose id has the reserved reaction prefix `fstp:vc:`, before any need,
/// so it never appends under a reaction's id.
///
/// Gap: the production twin, `seam_driver_core_refuses_reserved_command_id`,
/// waits on the caller command id of `Admitted` or `DriverCore::start`
/// (`mc::driver_model::COMMAND_ID_SEAM`, an API request to lane W2c).
#[test]
fn seam_i23_reference_driver_refuses_reserved_command_id() {
    use fstp_celltest::mc::driver_model::{DDone, DNeed, RefDriver};
    use fstp_celltest::reference::vault::reaction_command_id;
    for epoch in [0u64, 1, u64::MAX] {
        let mut run = RefDriver::new(reaction_command_id(epoch));
        let first = run.next(None);
        assert!(
            matches!(first, DNeed::Done(DDone::Refused(_))),
            "I-23: the reference driver took a caller command under the reserved id of epoch {epoch}: {first:?}"
        );
    }
}
