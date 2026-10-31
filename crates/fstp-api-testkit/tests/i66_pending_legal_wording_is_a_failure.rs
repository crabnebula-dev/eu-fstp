//! I-66 with Q6: pending legal wording is a validation failure (M4 design
//! sections 3.2 `LegalWordingPending` and 8.4, "Pure").
//!
//! `guide-for-applicants.md` Rules require approved wording for statements
//! on grant agreement obligations. While the profile's wording is pending
//! (`TODO(legal)`), the report shows `LegalWordingPending` with severity
//! Failure and activation is refused. The synthetic wording profile of the
//! testkit, loaded only by the end-to-end cell, clears it. Q6 is answered
//! with its recommendation as an interim reading, pending Daniel.
//!
//! The production test is red until lanes W2c (the synthetic wording
//! profile) and W2a (the creator) land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::{Backend, attempt};
use fstp_api_testkit::reference::creator::{
    Attempt, RefCheck, RefRefusal, StepVerdict, clean_plan,
};
use fstp_prop::{Gen, check, prop_assert_eq};

fn property(backend: Backend) -> impl Fn(&mut Gen) -> Result<(), String> {
    move |g| {
        let pending = g.bool();
        let roster = g.bool();
        g.note("wording pending", &pending);
        g.note("with RosterShort", &roster);
        let mut plan = clean_plan();
        plan.stat.wording_pending = pending;
        if roster {
            plan.seeds.insert(RefCheck::RosterShort);
        }
        let got = attempt(backend, &Attempt::by_second_admin(plan))?;
        prop_assert_eq!(
            got.report_at_approval
                .contains_key(&RefCheck::LegalWordingPending),
            pending,
            "the report"
        );
        let want = if pending {
            StepVerdict::Refused(RefRefusal::Failed(RefCheck::LegalWordingPending))
        } else {
            StepVerdict::Accepted
        };
        prop_assert_eq!(got.verdict, want, "I-66, Q6");
        Ok(())
    }
}

/// I-66, Q6: on production.
#[test]
fn i66_pending_legal_wording_is_a_failure() {
    check(
        "i66_pending_legal_wording_is_a_failure",
        property(Backend::Production),
    );
}

/// I-66, Q6: on the reference alone.
#[test]
fn i66_pending_legal_wording_is_a_failure_on_the_reference() {
    check(
        "i66_pending_legal_wording_is_a_failure_on_the_reference",
        property(Backend::Reference),
    );
}
