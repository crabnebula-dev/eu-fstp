//! I-12 on M-POLICY at the policy level (design 6.2 and 6.3).
//!
//! Two calls of one programme, P-02 in {50.00, 75.00}, P-03 in {1, 2} and
//! at most two edits. The start state comes from genesis through production
//! commands. Properties: `always("two-way")`, `always("I-12")`,
//! `transition("I-12 edit")`, `transition("R-PC-02")`, `transition("I-23")`,
//! and witnesses of an edit between publications and of both calls on one
//! version.
//!
//! The run must store exactly [`M_POLICY_STATES`] states. A smaller count
//! means production refused steps the reference accepts, so shrinkage fails
//! as visibly as growth.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::policy_model::{
    M_POLICY_STATES, PolicyModel, m_policy_properties, m_policy_start, production_read,
};

/// I-12: on M-POLICY no edit changes a published frozen policy, each
/// published call reads back its publication copy, and a call published
/// after an edit uses the new values.
#[test]
fn i12_m_policy() {
    let start = m_policy_start().unwrap_or_else(|e| panic!("{e}"));
    let model = PolicyModel { start };
    let properties = m_policy_properties::<PolicyModel>(production_read);
    let outcome = match check_exhaustive(&model, &properties, M_POLICY_STATES) {
        Ok(o) => o,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(
        outcome.stats.states, M_POLICY_STATES,
        "M-POLICY stored another number of states than the hand count\n{outcome}"
    );
}
