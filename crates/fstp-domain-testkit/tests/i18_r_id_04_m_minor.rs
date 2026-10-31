//! M-MINOR: the NEGOTIATION gate derives the minor flag from the vault alone (R-ID-04, I-18, state-machine NOTE 14).
//!
//! The model starts with PR1 in IRC_REVIEW, built from genesis, and the
//! vault holding neither an over-18 attestation of its lead nor a guardian
//! consent. It validates, attests and consents in every order. One
//! instance sends the actor's `CreateDraft` field clear, and one sends it
//! set. Both must pass the same properties with both admission paths
//! reachable, which shows the field neither sets nor clears the flag.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::minor_model::{
    M_MINOR_FIELD_CLEAR_REFERENCE_STATES, M_MINOR_FIELD_CLEAR_STATES,
    M_MINOR_FIELD_SET_REFERENCE_STATES, M_MINOR_FIELD_SET_STATES, MinorModel, minor_properties,
};

fn model(field: bool, backend: Backend, measured: usize) {
    let model = MinorModel::new(field, backend)
        .unwrap_or_else(|e| panic!("M-MINOR start from genesis: {e}"));
    if let Err(e) = check_exhaustive(&model, &minor_properties::<MinorModel>(), measured) {
        panic!("{e}");
    }
}

/// R-ID-04, I-18, NOTE 14: with the actor's field clear, PR1 enters
/// NEGOTIATION only on the lead's attestation at the deadline or on a
/// guardian consent, and both paths are reachable.
#[test]
fn i18_r_id_04_m_minor_field_clear() {
    model(false, Backend::Production, M_MINOR_FIELD_CLEAR_STATES);
}

/// R-ID-04, I-18: the field-clear instance on the references alone.
#[test]
fn i18_r_id_04_m_minor_field_clear_reference() {
    model(
        false,
        Backend::Reference,
        M_MINOR_FIELD_CLEAR_REFERENCE_STATES,
    );
}

/// R-ID-04, I-18, NOTE 14: with the actor's field set, the gate admits on
/// the same vault facts, and both paths are reachable.
#[test]
fn i18_r_id_04_m_minor_field_set() {
    model(true, Backend::Production, M_MINOR_FIELD_SET_STATES);
}

/// R-ID-04, I-18: the field-set instance on the references alone.
#[test]
fn i18_r_id_04_m_minor_field_set_reference() {
    model(true, Backend::Reference, M_MINOR_FIELD_SET_REFERENCE_STATES);
}
