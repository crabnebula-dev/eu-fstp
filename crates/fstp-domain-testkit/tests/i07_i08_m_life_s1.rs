//! I-07 and I-08 on M-LIFE-S1 (design 6.2 and 6.3).
//!
//! The start state comes from genesis through production commands: one
//! proposal admitted to STAGE1 with three reviewers assigned and
//! declared, two criteria on a scale of 0 to 2, and P-03 = 2. Actions:
//! stage 1 scores, one correction, one conflict found in the vault, the
//! close by the FSTP coordinator, by another account and by the System,
//! withdrawal, and a tail that expires stage 2, publishes the next call
//! and re-enters. Properties: `always("two-way")`, `always("I-07")`,
//! `always("I-08")` for every proposal in STAGE2 or later, also after
//! re-entry, `always("NOTE 3")` for sealed scores, `transition("I-07")`,
//! `transition("I-08")` in both directions, and `transition("I-08 close")`:
//! only `CloseStage1` leaves STAGE1 by score. Witnesses: a score exactly at
//! P-02 ends NOT_SELECTED, both exits are reachable, and STAGE2 is reached
//! after re-entry.
//!
//! Instances: weights (1, 1) at P-02 50.00 and weights (3, 1) at 75.00.
//! Both reach equality. Each production run is exhaustive under a tripwire
//! at twice the count measured on the references. The `_reference` twins
//! run the same model on the references alone and must pass now.
//!
//! The I-10 part of this model (findings offered beside every action)
//! comes with lane L-FIND-B.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::life_model::{
    LifeConfig, LifeModel, M_LIFE_S1_EVEN_STATES, M_LIFE_S1_WEIGHTED_STATES, s1_even,
    s1_properties, s1_weighted,
};

fn run(config: LifeConfig, backend: Backend, measured: usize) {
    let model = LifeModel::new(config, backend)
        .unwrap_or_else(|e| panic!("M-LIFE-S1 start from genesis: {e}"));
    if let Err(e) = check_exhaustive(&model, &s1_properties::<LifeModel>(), measured) {
        panic!("{e}");
    }
}

/// I-07, I-08, R-EV-02, R-EV-03, NOTE 3: M-LIFE-S1 with weights (1, 1) at P-02 50.00.
#[test]
fn i07_i08_m_life_s1() {
    run(s1_even(), Backend::Production, M_LIFE_S1_EVEN_STATES);
}

/// I-07, I-08: M-LIFE-S1 with weights (3, 1) at P-02 75.00.
#[test]
fn i07_i08_m_life_s1_weighted() {
    run(
        s1_weighted(),
        Backend::Production,
        M_LIFE_S1_WEIGHTED_STATES,
    );
}

/// I-07, I-08: the weights (1, 1) instance passes on the references alone.
#[test]
fn i07_i08_m_life_s1_reference() {
    run(s1_even(), Backend::Reference, M_LIFE_S1_EVEN_STATES);
}

/// I-07, I-08: the weights (3, 1) instance passes on the references alone.
#[test]
fn i07_i08_m_life_s1_weighted_reference() {
    run(s1_weighted(), Backend::Reference, M_LIFE_S1_WEIGHTED_STATES);
}
