//! I-11 teeth on M-FIND (design 6.1 "Teeth" and 6.2).
//!
//! The fault stores a finding of PR1's current call under a configuration
//! no call pinned, as a broken engine would. On production it folds the
//! finding record into the store with `FindingStore::apply`, past the
//! engine's check against the published pin. On the references it
//! forces the finding into the reference store.
//! `always("I-11")` must report it, naming the injected finding.
//!
//! The run checks the target property and one witness, and stops once
//! both are decided, because the mutant's state space has no fixed size.
//! The `_on_the_reference` twin must pass now.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_domain_testkit::mc::findings_model::{
    FOREIGN_FINDING, M_FIND_STATES, fault_foreign_config, m_find_core_properties, m_find_model,
};
use fstp_domain_testkit::mc::life_model::{LifeModel, LifeState};
use fstp_findings::FindingId;
use fstp_mc::{Verdict, check};

fn caught(backend: Backend) {
    let model = m_find_model(backend).unwrap_or_else(|e| panic!("M-FIND start from genesis: {e}"));
    let mutant = Injecting::new(
        &model,
        fault_foreign_config as fn(&LifeState) -> Option<LifeState>,
    );
    let properties = m_find_core_properties::<Injecting<'_, LifeModel, _>>();
    let outcome = check(
        &mutant,
        &properties,
        &tripwire(M_FIND_STATES.saturating_mul(8)).with_stop_when_decided(true),
    );
    if let Err(e) = expect_violation(&outcome, "I-11") {
        panic!("{e}");
    }
    // The violation must name the injected finding. A violation for any
    // other reason, such as the L-FIND-B seam, is not this fault caught.
    let foreign = format!("{:?}", FindingId::from_raw(FOREIGN_FINDING));
    match outcome.verdict("I-11") {
        Some(Verdict::Violated(v)) => {
            let detail = v.detail.as_deref().unwrap_or_default();
            assert!(
                detail.contains(&foreign),
                "teeth: I-11 was violated, but not by the injected {foreign}: {detail}"
            );
        }
        other => panic!("teeth: I-11 is {:?}", other.map(|v| v.label())),
    }
}

/// I-11: a finding stored under a foreign configuration is caught.
#[test]
fn i11_teeth_foreign_config_is_caught() {
    caught(Backend::Production);
}

/// I-11: the same fault is caught on the references alone.
#[test]
fn i11_teeth_foreign_config_is_caught_on_the_reference() {
    caught(Backend::Reference);
}
