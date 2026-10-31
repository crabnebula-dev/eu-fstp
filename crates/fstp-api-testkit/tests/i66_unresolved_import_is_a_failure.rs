//! I-66 with Q30: an unresolved import proposal is a validation failure
//! (M4 design sections 3.2 `ImportUnresolved` and 8.4, "Pure").
//!
//! The engine passes the count of proposals neither confirmed, edited nor
//! dismissed in `CreatorInputs::unresolved_imports`. Any count above zero
//! shows `ImportUnresolved` with severity Failure and blocks activation.
//! A proposal that arrives after the request still blocks it, because
//! the report is recomputed at approval. Q30 is answered with its
//! recommendation as an interim reading, pending Daniel.
//!
//! The production test is red until lane W2a lands the creator.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::{Backend, attempt};
use fstp_api_testkit::reference::creator::{
    Attempt, RefCheck, RefRefusal, RefSeverity, StepVerdict, clean_plan,
};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

fn property(backend: Backend) -> impl Fn(&mut Gen) -> Result<(), String> {
    move |g| {
        let at_request = g.u32_in(0..=3);
        let at_approval = if g.bool() {
            at_request
        } else {
            g.u32_in(0..=3)
        };
        g.note("unresolved at the request", &at_request);
        g.note("unresolved at the approval", &at_approval);
        let mut plan = clean_plan();
        plan.env.unresolved_imports = at_request;
        let mut a = Attempt::by_second_admin(plan);
        a.approval_env.unresolved_imports = at_approval;
        let got = attempt(backend, &a)?;
        prop_assert_eq!(
            got.report_at_request
                .contains_key(&RefCheck::ImportUnresolved),
            at_request > 0,
            "the request-time report"
        );
        prop_assert_eq!(
            RefCheck::ImportUnresolved.severity(),
            RefSeverity::Failure,
            "Q30"
        );
        if at_approval > 0 {
            prop_assert!(
                got.report_at_approval
                    .contains_key(&RefCheck::ImportUnresolved),
                "the approval report must show the unresolved proposals"
            );
            prop_assert_eq!(
                got.verdict,
                StepVerdict::Refused(RefRefusal::Failed(RefCheck::ImportUnresolved)),
                "I-66: an unresolved import proposal must block activation"
            );
        } else {
            prop_assert_eq!(got.verdict, StepVerdict::Accepted, "no proposal is pending");
        }
        Ok(())
    }
}

/// I-66, Q30: on production.
#[test]
fn i66_unresolved_import_is_a_failure() {
    check(
        "i66_unresolved_import_is_a_failure",
        property(Backend::Production),
    );
}

/// I-66, Q30: on the reference alone.
#[test]
fn i66_unresolved_import_is_a_failure_on_the_reference() {
    check(
        "i66_unresolved_import_is_a_failure_on_the_reference",
        property(Backend::Reference),
    );
}
