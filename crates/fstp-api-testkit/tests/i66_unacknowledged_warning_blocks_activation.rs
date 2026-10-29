//! I-66: a warning without a live acknowledgement blocks activation (M4
//! design section 8.4, "Machine"; `programme-creator.md` Validation:
//! "Warnings need a recorded acknowledgement").
//!
//! The machine runs random sequences of grants, edits, acknowledgements,
//! requests, approvals and environment changes, weighted towards
//! acknowledgements and approvals. Every command is two-way against the
//! reference, a refusal for a warning names an unacknowledged warning the
//! report shows, and `check_i66` and `check_i67` hold over the records
//! after every command. The attempt property adds a direct case: every
//! warning of the catalogue, seeded alone, blocks activation until it is
//! acknowledged.
//!
//! The production tests are red until lane W2a lands the creator.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::{ActivationMachine, Backend, Focus, attempt};
use fstp_api_testkit::reference::creator::{
    Attempt, RefCheck, RefRefusal, StepVerdict, seeded_plan,
};
use fstp_prop::{Gen, check, check_machine, prop_assert, prop_assert_eq};

fn warning_property(backend: Backend) -> impl Fn(&mut Gen) -> Result<(), String> {
    move |g| {
        let warnings = RefCheck::warnings();
        let w = *g.pick(&warnings);
        let acknowledge = g.bool();
        g.note("warning", &w);
        g.note("acknowledge", &acknowledge);
        let mut a = Attempt::by_second_admin(seeded_plan(w));
        a.acknowledge = acknowledge;
        let got = attempt(backend, &a)?;
        prop_assert!(
            got.report_at_approval.contains_key(&w),
            "the report does not show the seeded warning {}: {:?}",
            w.name(),
            got.report_at_approval
        );
        if acknowledge {
            prop_assert_eq!(
                got.verdict,
                StepVerdict::Accepted,
                "an acknowledged warning"
            );
        } else {
            prop_assert_eq!(
                got.verdict,
                StepVerdict::Refused(RefRefusal::Unacknowledged(w)),
                "I-66: an unacknowledged warning must block activation and be named"
            );
        }
        Ok(())
    }
}

/// I-66: random command sequences on production agree with the reference
/// and never activate past an unacknowledged warning.
#[test]
fn i66_unacknowledged_warning_blocks_activation() {
    check_machine(
        "i66_unacknowledged_warning_blocks_activation",
        &ActivationMachine {
            backend: Backend::Production,
            focus: Focus::Acknowledgement,
        },
    );
}

/// I-66: the machine passes on the reference alone, which checks
/// `decide` against the independent predicates.
#[test]
fn i66_unacknowledged_warning_blocks_activation_on_the_reference() {
    check_machine(
        "i66_unacknowledged_warning_blocks_activation_on_the_reference",
        &ActivationMachine {
            backend: Backend::Reference,
            focus: Focus::Acknowledgement,
        },
    );
}

/// I-66: each catalogue warning, seeded alone, blocks activation until it
/// is acknowledged, on production.
#[test]
fn i66_unacknowledged_warning_blocks_activation_for_every_warning() {
    check(
        "i66_unacknowledged_warning_blocks_activation_for_every_warning",
        warning_property(Backend::Production),
    );
}

/// I-66: the same on the reference alone.
#[test]
fn i66_unacknowledged_warning_blocks_activation_for_every_warning_on_the_reference() {
    check(
        "i66_unacknowledged_warning_blocks_activation_for_every_warning_on_the_reference",
        warning_property(Backend::Reference),
    );
}
