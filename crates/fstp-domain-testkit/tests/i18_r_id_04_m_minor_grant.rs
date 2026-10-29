//! M-MINOR-GRANT: the guard into GRANTED derives the minor flag again (R-ID-04, I-18, state-machine NOTE 14, decided 2026-10-29).
//!
//! The model starts with PC in NEGOTIATION, admitted on its lead's
//! attestation or on a guardian consent, with only the contract fact
//! missing. It records and withdraws the attestation, records a
//! conflicting under-18 verification, records and withdraws a consent and
//! resolves the conflict by a manual check, in every order. It sends the
//! completing fact and the programme manager's decline after each change.
//! Production must agree with the references on every step. PC must enter
//! GRANTED only on a vault answer that NOTE 14 admits, and DECLINED only
//! when that answer leaves the consent missing (NOTE 9).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::minor_grant_model::{
    M_MINOR_GRANT_REFERENCE_STATES, M_MINOR_GRANT_STATES, MinorGrantModel, minor_grant_properties,
};

fn model(backend: Backend, measured: usize) {
    let model = MinorGrantModel::new(backend)
        .unwrap_or_else(|e| panic!("M-MINOR-GRANT start from genesis: {e}"));
    let o = check_exhaustive(
        &model,
        &minor_grant_properties::<MinorGrantModel>(),
        measured,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        o.stats.states, measured,
        "the tripwire constant must be the {backend:?} count, measured {} states \
         and {} transitions",
        o.stats.states, o.stats.transitions
    );
}

/// R-ID-04, I-18, NOTE 9, NOTE 14 (decided 2026-10-29): PC enters GRANTED
/// only when the vault answers about LC's attestation and the answer is
/// yes or PC has a consent. It enters DECLINED only when that answer
/// leaves the consent missing, and every way to GRANTED is reachable.
#[test]
fn i18_r_id_04_m_minor_grant() {
    model(Backend::Production, M_MINOR_GRANT_STATES);
}

/// R-ID-04, I-18: M-MINOR-GRANT on the references alone.
#[test]
fn i18_r_id_04_m_minor_grant_reference() {
    model(Backend::Reference, M_MINOR_GRANT_REFERENCE_STATES);
}
