//! I-14 on the reservation part of M-RACE (design 2.11, 6.2 and 6.3).
//!
//! Leads a and b share one identity. Both proposals reach NEGOTIATION
//! from genesis by production commands, each with a plan of 4.00, under
//! P-04 = [3.00, 4.00] and P-05 = 6.00. Lead b starts unverified, so the
//! vault groups b alone, and the vault change of M-RACE verifies b at any
//! point. The model interleaves the amount determinations, the three grant
//! facts, the decline and the withdrawal of both negotiations one command
//! at a time. Because the determination reserves cap headroom, and the
//! grant asks the cap again, two concurrent negotiations cannot both pass:
//! `always("I-14")` over granted plus reserved per identity, each
//! reservation counted under the identity the vault knew when it opened,
//! and never both granted. Witnesses: each one granted, the second
//! reservation blocked by the cap, two reservations merged above P-05 by
//! the verification, GRANTED then disabled, the decline for no amount
//! within the cap, and a grant once the blocked completing fact is sent
//! again.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::money_model::{
    M_RACE_RESERVATION_REFERENCE_STATES, M_RACE_RESERVATION_STATES, MoneyMc, race, race_properties,
};

fn model(backend: Backend, measured: usize) {
    let model =
        MoneyMc::new(race(), backend).unwrap_or_else(|e| panic!("M-RACE start from genesis: {e}"));
    match check_exhaustive(&model, &race_properties::<MoneyMc>(), measured) {
        Ok(o) => eprintln!("M-RACE reservation: {} states", o.stats.states),
        Err(e) => panic!("{e}"),
    }
}

/// I-14, design 2.11: two concurrent negotiations of one identity cannot both pass the cap.
#[test]
fn i14_m_race_reservation() {
    model(Backend::Production, M_RACE_RESERVATION_STATES);
}

/// I-14: the reservation race passes on the references alone.
#[test]
fn i14_m_race_reservation_reference() {
    model(Backend::Reference, M_RACE_RESERVATION_REFERENCE_STATES);
}
