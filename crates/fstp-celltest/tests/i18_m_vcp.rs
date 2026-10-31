//! I-18, I-04, I-06 and NOTE 4: M-VCP (design sections 14.2 and 14.4).
//!
//! Lane W1c wrote these tests before the production code. M-VCP runs over
//! `fstp_vault_core` and is red until lane W2d lands it and lane W4
//! records the tripwire. The reference run and the teeth runs use the
//! reference vault, so each seeded defect is shown to fail its property
//! once the tripwire is recorded.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_celltest::mc::tripwires::{M_VCP, NOT_MEASURED, tripwire};
use fstp_celltest::mc::vcp_model::{
    CellDefect, Mutant, Production, Reference, VaultDefect, VcpModel, VcpVault, genesis, ids,
    properties,
};
use fstp_domain_testkit::harness::teeth::expect_violation;
use fstp_mc::{Config, check, explore};

/// The bound of every M-VCP run: twice the recorded count (design
/// section 14.1). A count not yet recorded fails here, by name.
fn bound() -> Config {
    assert_ne!(
        M_VCP, NOT_MEASURED,
        "the M-VCP tripwire is not recorded yet (lane W4); \
         i18_m_vcp_tripwire_records_the_measured_count gives the count"
    );
    Config::default()
        .with_stop_when_decided(false)
        .with_max_states(tripwire(M_VCP))
}

fn passes<V: VcpVault>(model: VcpModel<V>) {
    if let Some(op) = genesis(model.vault()).halted {
        panic!("M-VCP: the backend did not answer at genesis: {op} (NotImplemented)");
    }
    let props = properties(&model);
    let outcome = check(&model, &props, &bound());
    assert!(
        outcome.exhaustive,
        "M-VCP did not finish under its tripwire:\n{outcome}"
    );
    if let Err(e) = outcome.require_all_passed() {
        panic!("{e}\n{outcome}");
    }
}

fn caught<V: VcpVault>(model: VcpModel<V>, id: &str) {
    let props = properties(&model);
    let outcome = check(&model, &props, &bound().with_stop_when_decided(true));
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

/// I-18, I-04, I-06, NOTE 4: M-VCP over production, `fstp_vault_core`.
#[test]
fn i18_m_vcp() {
    passes(VcpModel::new(Production));
}

/// I-18, I-04, I-06, NOTE 4: M-VCP over the reference vault. Every
/// property and witness holds.
#[test]
fn i18_m_vcp_on_the_reference() {
    passes(VcpModel::new(Reference));
}

/// I-18, design section 14.1: the recorded tripwire count is the measured
/// state count of M-VCP over the reference.
#[test]
fn i18_m_vcp_tripwire_records_the_measured_count() {
    let space = explore(&VcpModel::new(Reference), &Config::default());
    assert!(space.exhaustive, "M-VCP over the reference did not finish");
    assert_eq!(
        M_VCP,
        space.len(),
        "record the measured M-VCP count {} in fstp_celltest::mc::tripwires (lane W4)",
        space.len()
    );
}

/// I-18 teeth (design section 14.4): a vault that counts a provisional
/// consent lets the minor-flagged PR1 into NEGOTIATION early.
#[test]
fn i18_teeth_provisional_consent_counted_is_caught() {
    caught(
        VcpModel::new(Mutant {
            defect: VaultDefect::ProvisionalConsentCounted,
        }),
        ids::I18,
    );
}

/// NOTE 4 and I-06 teeth (design section 14.2, M-VCP row): a vault that
/// answers a non-reaction query while a provisional fact touches it.
#[test]
fn i18_m_vcp_note4_teeth_vault_answers_while_provisional_is_caught() {
    caught(
        VcpModel::new(Mutant {
            defect: VaultDefect::AnswersWhileProvisional,
        }),
        ids::NOTE4,
    );
}

/// NOTE 4 teeth (design section 14.2, M-VCP row): a driver that
/// acknowledges its reaction before the reaction commits.
#[test]
fn i18_m_vcp_note4_teeth_driver_acks_before_reaction_commits_is_caught() {
    caught(
        VcpModel::with_cell_defect(Reference, CellDefect::AckBeforeReaction),
        ids::NOTE4,
    );
}

/// NOTE 4 teeth (design section 14.2, M-VCP row): a fact that becomes
/// effective with no acknowledgement.
#[test]
fn i18_m_vcp_note4_teeth_fact_effective_without_ack_is_caught() {
    caught(
        VcpModel::new(Mutant {
            defect: VaultDefect::EffectiveWithoutAck,
        }),
        ids::NOTE4,
    );
}

/// I-06 teeth: a vault that makes a fact effective with no
/// acknowledgement leaves B's Receiving binding standing beside A's
/// Judging binding of the same effective person.
#[test]
fn i18_m_vcp_i06_teeth_fact_effective_without_ack_is_caught() {
    caught(
        VcpModel::new(Mutant {
            defect: VaultDefect::EffectiveWithoutAck,
        }),
        ids::I06,
    );
}

/// I-04 teeth: a driver that acknowledges before its reaction commits
/// leaves C's Receiving binding standing beside its effective excluded
/// affiliation.
#[test]
fn i18_m_vcp_i04_teeth_driver_acks_before_reaction_commits_is_caught() {
    caught(
        VcpModel::with_cell_defect(Reference, CellDefect::AckBeforeReaction),
        ids::I04,
    );
}
