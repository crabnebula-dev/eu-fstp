//! I-67 with Q2 B: unverified builders and approvers (M4 design section
//! 8.4, "Property").
//!
//! `SameIdentityAsAny` means something only between verified accounts, so
//! the vault must answer `IsVerified` for the approver and every builder.
//! Three cases: an unverified second account of M1's person, made a
//! tenant admin, approves; an unverified admin of another person
//! approves; the opener A1 is unverified. The first two are refused. The
//! third shows `BuilderUnverified` as a failure and is refused with it.
//! Q2 B is an interim reading, pending Daniel.
//!
//! The production test is red until lane W2a lands the creator.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::{Backend, attempt};
use fstp_api_testkit::reference::creator::{
    Attempt, M1, RefCheck, RefRefusal, SYBIL, StepVerdict, TA, TB, clean_plan,
};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

fn property(backend: Backend) -> impl Fn(&mut Gen) -> Result<(), String> {
    move |g| {
        let case = g.u8_in(0..=2);
        g.note("case", &case);
        let mut plan = clean_plan();
        let mut approver = TB;
        match case {
            0 => {
                let m1 = plan.stat.vault.person(M1).unwrap_or(0);
                plan.stat.vault = plan.stat.vault.clone().with(SYBIL, m1, false);
                plan.stat.admins.insert(SYBIL);
                approver = SYBIL;
            }
            1 => {
                let tb = plan.stat.vault.person(TB).unwrap_or(0);
                plan.stat.vault = plan.stat.vault.clone().with(TB, tb, false);
            }
            _ => {
                let ta = plan.stat.vault.person(TA).unwrap_or(0);
                plan.stat.vault = plan.stat.vault.clone().with(TA, ta, false);
            }
        }
        let mut a = Attempt::by_second_admin(plan);
        a.approver = approver;
        let got = attempt(backend, &a)?;
        prop_assert!(
            !got.verdict.accepted(),
            "I-67: case {case} activated with an unverified approver or builder"
        );
        if case == 2 {
            prop_assert!(
                got.report_at_approval
                    .contains_key(&RefCheck::BuilderUnverified),
                "the report must show BuilderUnverified: {:?}",
                got.report_at_approval
            );
            prop_assert_eq!(
                got.verdict,
                StepVerdict::Refused(RefRefusal::Failed(RefCheck::BuilderUnverified)),
                "I-67, Q2: an unverified builder"
            );
        }
        Ok(())
    }
}

/// I-67, Q2 B: on production.
#[test]
fn i67_unverified_builder_or_approver_refused() {
    check(
        "i67_unverified_builder_or_approver_refused",
        property(Backend::Production),
    );
}

/// I-67, Q2 B: on the reference alone.
#[test]
fn i67_unverified_builder_or_approver_refused_on_the_reference() {
    check(
        "i67_unverified_builder_or_approver_refused_on_the_reference",
        property(Backend::Reference),
    );
}
