//! I-03 and R-CF-02 on M-CONFLICT, truthful and havoc vault (design 6.2 and 6.3).
//!
//! The start state comes from genesis through production commands: three
//! committee members of three organisations, the FSTP coordinator and one
//! submitted proposal, with P-03 = 2. Properties: `always("two-way")`,
//! `always("I-03")`, `transition("I-03 act")` and `transition("R-CF-02")`.
//! Witnesses: content is read after a no-conflict declaration; reassignment
//! restores P-03 after a declared conflict; a detected conflict releases
//! the assignment; a reviewer is assigned once the vault no longer finds a
//! conflict. The havoc instance
//! also reaches a silent conflict on a cleared reader, which only the
//! fresh check at the current epoch can bar.
//!
//! The two-proposal instance checks that a conflict on one proposal
//! leaves acts on the other as they were. The staged instance folds the
//! stage rows, so assigned reviewers read and write ranking summaries, a
//! conflict found after reading is declared, and the production cut-off
//! recusal predicate is compared with the reference after every step.
//!
//! Each production run is exhaustive under a tripwire at twice the
//! measured count. The `_reference` twins run the same model on the
//! references alone, which must pass every property.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::conflict_model::{
    ConflictConfig, ConflictModel, M_CONFLICT_HAVOC_STATES, M_CONFLICT_STAGED_STATES,
    M_CONFLICT_TRUTHFUL_STATES, M_CONFLICT_TWO_PROPOSAL_STATES, havoc_config, havoc_properties,
    staged_config, staged_properties, truthful_config, truthful_properties, two_proposal_config,
    two_proposal_properties,
};
use fstp_mc::Property;

fn run(
    config: ConflictConfig,
    backend: Backend,
    properties: &[Property<'_, ConflictModel>],
    measured: usize,
) {
    let model = ConflictModel::new(config, backend)
        .unwrap_or_else(|e| panic!("M-CONFLICT start from genesis: {e}"));
    if let Err(e) = check_exhaustive(&model, properties, measured) {
        panic!("{e}");
    }
}

fn truthful(backend: Backend) {
    run(
        truthful_config(),
        backend,
        &truthful_properties::<ConflictModel>(),
        M_CONFLICT_TRUTHFUL_STATES,
    );
}

fn havoc(backend: Backend) {
    run(
        havoc_config(),
        backend,
        &havoc_properties::<ConflictModel>(),
        M_CONFLICT_HAVOC_STATES,
    );
}

fn two_proposals(backend: Backend) {
    run(
        two_proposal_config(),
        backend,
        &two_proposal_properties::<ConflictModel>(),
        M_CONFLICT_TWO_PROPOSAL_STATES,
    );
}

fn staged(backend: Backend) {
    run(
        staged_config(),
        backend,
        &staged_properties::<ConflictModel>(),
        M_CONFLICT_STAGED_STATES,
    );
}

/// I-03, R-CF-02 over a truthful vault: relations and mentoring added
/// mid-run bar reads and acts, and declared conflicts trigger reassignment.
#[test]
fn i03_m_conflict_truthful() {
    truthful(Backend::Production);
}

/// I-03, R-CF-02 over a havoc vault: the domain obeys every answer, and a
/// change query that lists nobody still cannot open a read.
#[test]
fn i03_m_conflict_havoc() {
    havoc(Backend::Production);
}

/// I-03: the truthful instance passes on the references alone.
#[test]
fn i03_m_conflict_truthful_reference() {
    truthful(Backend::Reference);
}

/// I-03: the havoc instance passes on the references alone.
#[test]
fn i03_m_conflict_havoc_reference() {
    havoc(Backend::Reference);
}

/// I-03, R-CF-02 over two proposals (design 6.3): a conflict fact or a
/// declaration on one proposal never opens or bars an act on the other.
#[test]
fn i03_m_conflict_two_proposals() {
    two_proposals(Backend::Production);
}

/// I-03: the two-proposal instance passes on the references alone.
#[test]
fn i03_m_conflict_two_proposals_reference() {
    two_proposals(Backend::Reference);
}

/// I-03, R-CF-02, R-AC-01 and the cut-off recusal of the Conflict
/// declarations section: assigned reviewers read and write ranking
/// summaries in stages 1 and 2, a conflict found after reading is
/// declared and releases the assignment, and the production recusal
/// predicate matches the reference in RANKED.
#[test]
fn i03_m_conflict_staged() {
    staged(Backend::Production);
}

/// I-03: the staged instance passes on the references alone.
#[test]
fn i03_m_conflict_staged_reference() {
    staged(Backend::Reference);
}
