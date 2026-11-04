//! I-66: a draft with a seeded failure never activates (M4 design section
//! 8.4, "Property").
//!
//! Each case seeds one check of severity Failure from the catalogue,
//! through the facts it reads (`seeded_plan`), and may add a warning and a
//! second programme manager as background. M1 acknowledges every warning
//! and requests; A2 approves. The approval is refused, the report
//! recomputed at approval shows the seeded check, and wherever the
//! reference names the seeded check the production refusal names it too.
//! The `for_every_failure` tests walk the whole catalogue in order.
//!
//! `CapAboveCeiling` is refused at save (I-50 timing, Daniel's answer of
//! 2026-10-31, M4 design section 15.0), so no draft can hold it. For that
//! check the case asserts the stronger outcome: the setup save of the cap
//! is refused, so the draft never exists to be activated.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::{Backend, CapOutcome, attempt, cap_attempt};
use fstp_api_testkit::reference::creator::{
    Attempt, CheckFeed, M2, RefCheck, RefRefusal, StepVerdict, run_attempt, seeded_plan,
};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

fn one(backend: Backend, failure: RefCheck, roster: bool, second: bool) -> Result<(), String> {
    let mut plan = seeded_plan(failure);
    if failure.feed() == CheckFeed::Cap {
        let got = cap_attempt(backend, plan.stat.cap.p05_minor, plan.stat.cap.p58_minor)?;
        prop_assert!(
            matches!(got, CapOutcome::RefusedAtSave { .. }),
            "I-50 at save, I-66: the save of P-05 above P-58 must be refused, so no draft holds it: {got:?}"
        );
        return Ok(());
    }
    if roster {
        plan.seeds.insert(RefCheck::RosterShort);
    }
    if second {
        plan.managers.push(M2);
    }
    let a = Attempt::by_second_admin(plan);
    let want = run_attempt(&a).map_err(|e| format!("the reference setup: {e:?}"))?;
    let got = attempt(backend, &a)?;
    prop_assert!(
        !got.verdict.accepted(),
        "I-66: the draft seeded with {} was activated",
        failure.name()
    );
    prop_assert!(
        got.report_at_approval.contains_key(&failure),
        "I-66: the report at approval does not show the seeded failure {}: {:?}",
        failure.name(),
        got.report_at_approval
    );
    if want.verdict == StepVerdict::Refused(RefRefusal::Failed(failure)) {
        prop_assert_eq!(
            got.verdict,
            want.verdict,
            "I-66: the refusal must name the seeded check {}",
            failure.name()
        );
    }
    Ok(())
}

fn property(backend: Backend) -> impl Fn(&mut Gen) -> Result<(), String> {
    move |g| {
        let failures = RefCheck::failures();
        let failure = *g.pick(&failures);
        let roster = g.bool();
        let second = g.bool();
        g.note("seeded failure", &failure);
        g.note("with RosterShort", &roster);
        g.note("with M2", &second);
        one(backend, failure, roster, second)
    }
}

fn every(backend: Backend) {
    let mut errors = Vec::new();
    for failure in RefCheck::failures() {
        if let Err(e) = one(backend, failure, false, false) {
            errors.push(format!("{}: {e}", failure.name()));
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// I-66, R-PG-03: generated drafts with a seeded failure never activate on
/// production, and the refusal names the check.
#[test]
fn i66_seeded_failure_never_activates() {
    check(
        "i66_seeded_failure_never_activates",
        property(Backend::Production),
    );
}

/// I-66: the same on the reference alone.
#[test]
fn i66_seeded_failure_never_activates_on_the_reference() {
    check(
        "i66_seeded_failure_never_activates_on_the_reference",
        property(Backend::Reference),
    );
}

/// I-66: every Failure check of the catalogue, seeded alone, blocks
/// activation on production.
#[test]
fn i66_seeded_failure_never_activates_for_every_failure() {
    every(Backend::Production);
}

/// I-66: the same on the reference alone.
#[test]
fn i66_seeded_failure_never_activates_for_every_failure_on_the_reference() {
    every(Backend::Reference);
}
