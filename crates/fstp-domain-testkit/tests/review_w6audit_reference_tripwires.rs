//! Review reproducers for lane w6-audit (tripwires of the reference twins).
//!
//! Design 6.1: `max_states` is a tripwire at twice the measured count, so
//! growth fails visibly. Step W6 set every shared `*_STATES` constant to the
//! production count. Where production stores more states, a reference twin
//! under that constant stopped only near three times its own count. The
//! twins now run under their own `*_REFERENCE_STATES` constants. Each test
//! runs one reference twin under that constant and fails while its tripwire
//! exceeds twice the count it stores.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::{check_exhaustive, tripwire};
use fstp_domain_testkit::mc::findings_model::{
    M_FIND_REFERENCE_STATES, m_find_model, m_find_properties,
};
use fstp_domain_testkit::mc::sod_model::{
    M_SOD_I02_REFERENCE_STATES, SodModel, i02_config, i02_properties,
};

fn bounded(name: &str, stored: usize, measured: usize) {
    let bound = tripwire(measured).max_states;
    assert!(
        bound <= stored.saturating_mul(2),
        "{name}: the reference twin stores {stored} states but runs under a tripwire of {bound}, \
         more than twice its count (design 6.1)"
    );
}

/// Design 6.1, I-11: the M-FIND reference twin stops at twice its own count.
#[test]
fn review_m_find_reference_twin_tripwire_is_twice_its_count() {
    let model = m_find_model(Backend::Reference).unwrap();
    let outcome =
        check_exhaustive(&model, &m_find_properties(&model), M_FIND_REFERENCE_STATES).unwrap();
    bounded("M-FIND", outcome.stats.states, M_FIND_REFERENCE_STATES);
}

/// Design 6.1, I-02: the M-SOD I-02 reference twin stops at twice its own count.
#[test]
fn review_m_sod_i02_reference_twin_tripwire_is_twice_its_count() {
    let model = SodModel::new(i02_config(), Backend::Reference).unwrap();
    let properties = i02_properties::<SodModel>();
    let outcome = check_exhaustive(&model, &properties, M_SOD_I02_REFERENCE_STATES).unwrap();
    bounded(
        "M-SOD I-02",
        outcome.stats.states,
        M_SOD_I02_REFERENCE_STATES,
    );
}
