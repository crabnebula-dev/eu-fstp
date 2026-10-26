//! I-09 teeth on M-LIFE-S2 (design 6.1 "Teeth" and 6.2).
//!
//! The fault is an engine that clears the effective score. It takes STAGE2
//! to RANKED and leaves no effective score. Where the structural fold
//! needs one, it leaves an effective score of 0 that names the original
//! plan as the revised one. Both records are folded through the public structural
//! `apply`. `always("I-09")` must report it. The run stops once the
//! property and one witness are decided. The `_on_the_reference` twin
//! injects the same fault into the reference-only model and must pass now.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::decision::Basis;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_domain_testkit::mc::life_model::{
    LifeModel, LifeState, M_LIFE_S2_STATES, fault_effective_cleared, ranked_with, s2_config,
};
use fstp_domain_testkit::reference::lifecycle::check_i09;
use fstp_mc::{Property, check};

fn caught(backend: Backend) {
    let model = LifeModel::new(s2_config(), backend)
        .unwrap_or_else(|e| panic!("M-LIFE-S2 start from genesis: {e}"));
    let mutant = Injecting::new(&model, fault_effective_cleared);
    let properties = vec![
        Property::<Injecting<'_, LifeModel, _>>::always_with("I-09", |s: &LifeState| {
            check_i09(&s.world.life)
        }),
        Property::<Injecting<'_, LifeModel, _>>::reachable(
            "I-09 witness: RANKED on the original plan",
            |s: &LifeState| ranked_with(s, Basis::Original, StateTag::Ranked),
        ),
    ];
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(M_LIFE_S2_STATES.saturating_mul(4)).with_stop_when_decided(true),
    );
    if let Err(e) = expect_violation(&outcome, "I-09") {
        panic!("{e}");
    }
}

/// I-09: an engine that ranks without keeping an effective score is caught.
#[test]
fn i09_teeth_effective_cleared_is_caught() {
    caught(Backend::Production);
}

/// I-09: the same fault is caught on the references alone.
#[test]
fn i09_teeth_effective_cleared_is_caught_on_the_reference() {
    caught(Backend::Reference);
}
