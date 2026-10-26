//! I-09 on M-LIFE-S2 (design 6.2 and 6.3).
//!
//! The model is split in two, so each part stays small (design 6.3).
//!
//! - The stage 2 part starts in STAGE2 from genesis, with a stage 1 score
//!   of 75.00 under weights (1, 1) and P-02 50.00. Actions: questions,
//!   "no questions", answers, one revision, stage 2 scores of 50.00, 75.00
//!   and 100.00, the ranking, the reduced clock, the expiry, publication of
//!   the next call, re-entry with fresh assignments, one vault conflict
//!   that releases R2 in STAGE2 (O-50), and withdrawal.
//! - The after-ranking part starts in RANKED from genesis, on the revised
//!   or on the original plan. Actions: the cut-off, IRC assignment and
//!   review, concerns that defer or decline, publication, re-entry and
//!   withdrawal.
//!
//! Properties: `always("I-09")` in every state after stage 2, including
//! NOT_SELECTED, DECLINED, WITHDRAWN, DEFERRED and NEGOTIATION, and
//! `transition("I-09")`: entering RANKED sets exactly one effective score
//! per P-24 on one plan. Also two-way, I-07, I-08 and sealed scores.
//! Witnesses: both bases, a tie keeping the original plan (R-EV-06 AC),
//! and I-09 in each later state. Production runs are exhaustive under a
//! tripwire at twice the count measured on the references.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::life_model::{
    LifeConfig, LifeModel, M_LIFE_S2_AFTER_STATES, M_LIFE_S2_STATES, s2_after_config,
    s2_after_properties, s2_config, s2_properties,
};

fn stage2(backend: Backend) {
    let model = LifeModel::new(s2_config(), backend)
        .unwrap_or_else(|e| panic!("M-LIFE-S2 start from genesis: {e}"));
    if let Err(e) = check_exhaustive(&model, &s2_properties::<LifeModel>(), M_LIFE_S2_STATES) {
        panic!("{e}");
    }
}

fn after(config: LifeConfig, backend: Backend) {
    let model = LifeModel::new(config, backend)
        .unwrap_or_else(|e| panic!("M-LIFE-S2 start in RANKED from genesis: {e}"));
    if let Err(e) = check_exhaustive(
        &model,
        &s2_after_properties::<LifeModel>(),
        M_LIFE_S2_AFTER_STATES,
    ) {
        panic!("{e}");
    }
}

/// I-09, R-EV-05, R-EV-06, NOTE 4: M-LIFE-S2 from STAGE2 to RANKED.
#[test]
fn i09_m_life_s2() {
    stage2(Backend::Production);
}

/// I-09, NOTE 1: the effective score on the revised plan survives every later state.
#[test]
fn i09_m_life_s2_after_ranking_on_the_revised_plan() {
    after(s2_after_config(true), Backend::Production);
}

/// I-09, NOTE 1: the effective score on the original plan survives every later state.
#[test]
fn i09_m_life_s2_after_ranking_on_the_original_plan() {
    after(s2_after_config(false), Backend::Production);
}

/// I-09: the stage 2 part passes on the references alone.
#[test]
fn i09_m_life_s2_reference() {
    stage2(Backend::Reference);
}

/// I-09: the after-ranking part on the revised plan passes on the references alone.
#[test]
fn i09_m_life_s2_after_ranking_on_the_revised_plan_reference() {
    after(s2_after_config(true), Backend::Reference);
}

/// I-09: the after-ranking part on the original plan passes on the references alone.
#[test]
fn i09_m_life_s2_after_ranking_on_the_original_plan_reference() {
    after(s2_after_config(false), Backend::Reference);
}
