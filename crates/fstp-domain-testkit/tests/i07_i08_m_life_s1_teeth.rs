//! I-07 and I-08 teeth on M-LIFE-S1 (design 6.1 "Teeth" and 6.2).
//!
//! Each fault folds the records a broken engine would emit through the
//! public structural `apply`, beside the model's own actions:
//!
//! - I-07: an engine that counts a superseded score. Once a correction
//!   leaves a single valid score, it closes stage 1 as if P-03 scores
//!   existed. `always("I-07")` must report it.
//! - I-08: an engine that compares with `>=`. A score exactly at P-02
//!   passes to STAGE2. `always("I-08")` must report it.
//!
//! Each run checks the target property and one witness, and stops once
//! both are decided, because the mutant's state space has no fixed size.
//! The `_on_the_reference` twins inject the same faults into the
//! reference-only model and must pass now.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_domain_testkit::mc::life_model::{
    LifeModel, LifeState, M_LIFE_S1_EVEN_STATES, fault_ge_instead_of_gt, fault_superseded_counted,
    in_state, s1_even,
};
use fstp_domain_testkit::reference::lifecycle::{check_i07, check_i08};
use fstp_mc::{Property, check};

fn caught(
    backend: Backend,
    fault: fn(&LifeState) -> Option<LifeState>,
    id: &str,
    pred: fn(&LifeState) -> Result<(), String>,
) {
    let model = LifeModel::new(s1_even(), backend)
        .unwrap_or_else(|e| panic!("M-LIFE-S1 start from genesis: {e}"));
    let mutant = Injecting::new(&model, fault);
    let properties = vec![
        Property::<Injecting<'_, LifeModel, _>>::always_with(id, pred),
        Property::<Injecting<'_, LifeModel, _>>::reachable(
            "I-07 witness: STAGE1 to STAGE2",
            |s: &LifeState| in_state(s, StateTag::Stage2),
        ),
    ];
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(M_LIFE_S1_EVEN_STATES.saturating_mul(4)).with_stop_when_decided(true),
    );
    if let Err(e) = expect_violation(&outcome, id) {
        panic!("{e}");
    }
}

fn i07(s: &LifeState) -> Result<(), String> {
    check_i07(&s.world.life)
}

fn i08(s: &LifeState) -> Result<(), String> {
    check_i08(&s.world.life)
}

/// I-07: a stage 1 close that counts a superseded score is caught.
#[test]
fn i07_teeth_superseded_score_counted_is_caught() {
    caught(Backend::Production, fault_superseded_counted, "I-07", i07);
}

/// I-08: a stage 1 close that passes a score exactly at P-02 is caught.
#[test]
fn i08_teeth_ge_instead_of_gt_is_caught() {
    caught(Backend::Production, fault_ge_instead_of_gt, "I-08", i08);
}

/// I-07: the same fault is caught on the references alone.
#[test]
fn i07_teeth_superseded_score_counted_is_caught_on_the_reference() {
    caught(Backend::Reference, fault_superseded_counted, "I-07", i07);
}

/// I-08: the same fault is caught on the references alone.
#[test]
fn i08_teeth_ge_instead_of_gt_is_caught_on_the_reference() {
    caught(Backend::Reference, fault_ge_instead_of_gt, "I-08", i08);
}
