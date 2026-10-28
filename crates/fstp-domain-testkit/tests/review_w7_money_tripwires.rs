//! Review reproducers for the M2 final review (W7): money model tripwires.
//!
//! Design 6.1: `max_states` is a tripwire at twice the measured count. The
//! exit audit rule is that each shared `*_STATES` constant holds the
//! production count, and each reference twin runs under its own
//! `*_REFERENCE_STATES` constant. After the NOTE 9 decline change,
//! production stores fewer states than the references in M-RACE
//! reservation, the I-15 repeat model and the after-negotiation model.
//! Each test fails while a constant holds a count its backend does not
//! store.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::money_model::{
    M_AFTER_REFERENCE_STATES, M_AFTER_STATES, M_MONEY_REPEAT_REFERENCE_STATES,
    M_MONEY_REPEAT_STATES, M_RACE_RESERVATION_REFERENCE_STATES, M_RACE_RESERVATION_STATES,
    McConfig, MoneyMc, after, after_properties, race, race_properties, repeat, repeat_properties,
};
use fstp_mc::Property;

fn stored(config: McConfig, properties: &[Property<'_, MoneyMc>], backend: Backend) -> usize {
    let model = MoneyMc::new(config, backend).unwrap_or_else(|e| panic!("start: {e}"));
    // The bound here is generous, so the count itself is what the test
    // compares.
    check_exhaustive(&model, properties, 1_000_000)
        .unwrap_or_else(|e| panic!("{e}"))
        .stats
        .states
}

fn holds(
    name: &str,
    config: fn() -> McConfig,
    properties: &[Property<'_, MoneyMc>],
    c: [usize; 2],
) {
    for (backend, constant) in [(Backend::Production, c[0]), (Backend::Reference, c[1])] {
        let n = stored(config(), properties, backend);
        assert_eq!(
            n, constant,
            "{name}: the constant of {backend:?} must be the count it stores, measured {n}"
        );
    }
}

/// I-14, design 6.1: the M-RACE reservation constants hold the counts.
#[test]
fn review_w7_m_race_reservation_tripwires_hold_the_counts() {
    holds(
        "M-RACE reservation",
        race,
        &race_properties::<MoneyMc>(),
        [
            M_RACE_RESERVATION_STATES,
            M_RACE_RESERVATION_REFERENCE_STATES,
        ],
    );
}

/// I-15, design 6.1: the I-15 repeat model constants hold the counts.
#[test]
fn review_w7_m_money_repeat_tripwires_hold_the_counts() {
    holds(
        "I-15 repeat",
        repeat,
        &repeat_properties::<MoneyMc>(),
        [M_MONEY_REPEAT_STATES, M_MONEY_REPEAT_REFERENCE_STATES],
    );
}

/// Design 6.4, design 6.1: the after-negotiation model constants hold the counts.
#[test]
fn review_w7_m_after_tripwires_hold_the_counts() {
    holds(
        "after negotiation",
        after,
        &after_properties::<MoneyMc>(),
        [M_AFTER_STATES, M_AFTER_REFERENCE_STATES],
    );
}
