//! I-12 teeth on M-POLICY (design 6.1 "Teeth" and 6.2).
//!
//! - A guard that read the programme head instead of the call's frozen
//!   policy breaks I-12 by construction point 3 (design 2.4). The teeth
//!   test swaps the frozen read for one that returns the head, and the
//!   `I-12` property must report it.
//! - Over-denial: a model that drops every edit can no longer reach the
//!   witness of an edit between publications.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::{Dropping, expect_unreachable, expect_violation};
use fstp_domain_testkit::mc::policy_model::{
    M_POLICY_STATES, PolicyAction, PolicyModel, head_instead_of_snapshot, m_policy_properties,
    m_policy_start, production_read,
};
use fstp_mc::check;

/// I-12: reading the programme head instead of the publication snapshot is caught.
#[test]
fn i12_teeth_head_instead_of_snapshot_is_caught() {
    let start = m_policy_start().unwrap_or_else(|e| panic!("{e}"));
    let model = PolicyModel { start };
    let properties = m_policy_properties::<PolicyModel>(head_instead_of_snapshot);
    let outcome = check(&model, &properties, &tripwire(M_POLICY_STATES));
    if let Err(e) = expect_violation(&outcome, "I-12") {
        panic!("{e}\n{outcome}");
    }
}

/// I-12: an engine that refuses every edit loses the witness of an edit
/// between publications, so the witness guards against over-denial.
#[test]
fn i12_teeth_dropped_edits_hide_the_edit_witness() {
    let start = m_policy_start().unwrap_or_else(|e| panic!("{e}"));
    let model = PolicyModel { start };
    let mutant = Dropping::new(&model, |a: &PolicyAction| {
        matches!(a, PolicyAction::Edit { .. })
    });
    let properties = m_policy_properties::<Dropping<'_, PolicyModel, _>>(production_read);
    let outcome = check(&mutant, &properties, &tripwire(M_POLICY_STATES));
    if let Err(e) = expect_unreachable(&outcome, "I-12 witness: an edit between publications") {
        panic!("{e}\n{outcome}");
    }
}
