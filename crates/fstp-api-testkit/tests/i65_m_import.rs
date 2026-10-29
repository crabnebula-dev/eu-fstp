//! I-65 on M-IMPORT (M4 design sections 8.4 and 8.5).
//!
//! Universe: one draft with the synthetic P-58 of 300000.00, programme
//! managers M1 and M2, tenant admin t (TB in the model); one document
//! with two proposals from the truthful or the havoc proposer; two
//! resolutions, one binding end and up to two activation attempts.
//!
//! Properties: `always("I-65")` (`check_i65` over the raw records, and
//! the draft holds only the values people chose), `transition("I-65")`
//! (only a resolution imports a value, into its own field, with its own
//! value), `replay(ledger) == state` and two-way agreement. Witnesses: a
//! confirmed value reaches the active policy; an edited value is active
//! and differs from its proposal; refusals of a tenant admin, of an ended
//! binding, of a stale `shown` value and of an unacknowledged conflict.
//!
//! The production run is red until lanes W2a, W2b and W2e land. The
//! `_on_the_reference` twin runs the reference alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::import_model::{
    Backend, ImportModel, REFERENCE_STATES, TRIPWIRE, i65_properties,
};
use fstp_domain_testkit::harness::mc::check_exhaustive;

fn run(backend: Backend, measured: usize) {
    let model =
        ImportModel::new(backend).unwrap_or_else(|e| panic!("M-IMPORT start from genesis: {e}"));
    let properties = i65_properties::<ImportModel>();
    if let Err(e) = check_exhaustive(&model, &properties, measured) {
        panic!("{e}");
    }
}

/// I-65, R-PG-02: M-IMPORT on production.
#[test]
fn i65_m_import() {
    run(Backend::Production, TRIPWIRE);
}

/// I-65: M-IMPORT passes on the reference alone.
#[test]
fn i65_m_import_on_the_reference() {
    run(Backend::Reference, REFERENCE_STATES);
}
