//! Conformance: every proposal state up to NEGOTIATION is reachable on M-LIFECYCLE (design 6.3 and 6.4).
//!
//! The model runs from DRAFT, built from genesis by production commands,
//! with two calls, a havoc vault and coarse scores. It must reach DRAFT,
//! SUBMITTED, INELIGIBLE, STAGE1, NOT_SELECTED, STAGE2, RANKED, IRC_REVIEW,
//! DEFERRED, DECLINED, NEGOTIATION and WITHDRAWN, with every command
//! compared with the references in both directions. GRANTED, IN_EXECUTION,
//! COMPLETED and TERMINATED, and NEGOTIATION to DECLINED, come with lane
//! L-MONEY, which extends this model. The design's
//! `lifecycle_all_sixteen_states_reachable` waits for that lane.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::life_model::LifeModel;
use fstp_domain_testkit::mc::lifecycle_model::{
    M_LIFECYCLE_STATES, lifecycle_config, reachability_properties,
};

fn model(backend: Backend) {
    let model = LifeModel::new(lifecycle_config(), backend)
        .unwrap_or_else(|e| panic!("M-LIFECYCLE start from genesis: {e}"));
    if let Err(e) = check_exhaustive(
        &model,
        &reachability_properties::<LifeModel>(),
        M_LIFECYCLE_STATES,
    ) {
        panic!("{e}");
    }
}

/// Conformance, R-AU-01: every state up to NEGOTIATION is reachable, each
/// transition recorded with its row and actor.
#[test]
fn lifecycle_states_reachable_up_to_negotiation() {
    model(Backend::Production);
}

/// Conformance: the model passes on the references alone.
#[test]
fn lifecycle_states_reachable_up_to_negotiation_reference() {
    model(Backend::Reference);
}
