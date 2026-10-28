//! Conformance: every proposal state after NEGOTIATION is reachable (design 6.4, NOTES 9, 11, 12 and 13).
//!
//! One proposal of lead c reaches NEGOTIATION from genesis by production
//! commands, with a plan of two milestones of 2.00. The lead is a minor
//! with a verified guardian consent, which the vault may withdraw. The
//! model runs the amount and the three grant facts. It records NEGOTIATION
//! to DECLINED by the programme manager and to WITHDRAWN by the lead. It
//! starts execution at the earliest milestone start date, pays a
//! milestone, closes the milestones and completes the grant. It also
//! terminates from GRANTED and from IN_EXECUTION. Every
//! command is compared with the references in both directions, and I-13,
//! I-14 and I-64 hold in every state.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::money_model::{
    M_AFTER_REFERENCE_STATES, M_AFTER_STATES, MoneyMc, after, after_properties,
};

fn model(backend: Backend, measured: usize) {
    let model = MoneyMc::new(after(), backend)
        .unwrap_or_else(|e| panic!("after-negotiation start from genesis: {e}"));
    match check_exhaustive(&model, &after_properties::<MoneyMc>(), measured) {
        Ok(o) => eprintln!("after negotiation: {} states", o.stats.states),
        Err(e) => panic!("{e}"),
    }
}

/// Conformance, R-AU-01, I-64: GRANTED, IN_EXECUTION, COMPLETED,
/// TERMINATED, DECLINED and WITHDRAWN are reachable after NEGOTIATION.
#[test]
fn lifecycle_after_negotiation_states_reachable() {
    model(Backend::Production, M_AFTER_STATES);
}

/// Conformance, R-AU-01, I-64: the after-negotiation model passes on the references alone.
#[test]
fn lifecycle_after_negotiation_states_reachable_reference() {
    model(Backend::Reference, M_AFTER_REFERENCE_STATES);
}
