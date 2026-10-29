//! I-66: probes run at approval (M4 design sections 3.2 "Fresh probes"
//! and 8.4).
//!
//! The report at approval is recomputed over the probe results of the
//! approval request, never over the stored request-time report. A probe
//! that passes at the request and fails, or has no prober (Q5 A), at the
//! approval blocks activation and is named. A probe that fails at the
//! request and passes at the approval does not block it.
//!
//! The production test is red until lane W2a lands the creator.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::{Backend, attempt, env_with};
use fstp_api_testkit::reference::creator::{
    Attempt, RefProbe, RefProbeOutcome, RefRefusal, RefSeverity, StepVerdict, clean_plan,
};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

fn property(backend: Backend) -> impl Fn(&mut Gen) -> Result<(), String> {
    move |g| {
        let probe = *g.pick(&RefProbe::ALL);
        let bad = *g.pick(&[RefProbeOutcome::Fail, RefProbeOutcome::Absent]);
        let flips_to_bad = g.bool();
        g.note("probe", &probe);
        g.note("bad outcome", &bad);
        g.note("passes at the request, then fails", &flips_to_bad);
        let mut plan = clean_plan();
        let a = if flips_to_bad {
            let approval_env = env_with(&plan, probe, bad);
            Attempt {
                approval_env,
                ..Attempt::by_second_admin(plan)
            }
        } else {
            plan.env = env_with(&plan, probe, bad);
            let approval_env = env_with(&plan, probe, RefProbeOutcome::Pass);
            Attempt {
                approval_env,
                ..Attempt::by_second_admin(plan)
            }
        };
        let got = attempt(backend, &a)?;
        let check = probe.check();
        if flips_to_bad {
            prop_assert!(
                !got.report_at_request.contains_key(&check),
                "the probe passed at the request: {:?}",
                got.report_at_request
            );
            let want = match check.severity() {
                RefSeverity::Failure => RefRefusal::Failed(check),
                RefSeverity::Warning => RefRefusal::Unacknowledged(check),
            };
            prop_assert_eq!(
                got.verdict,
                StepVerdict::Refused(want),
                "I-66: a probe that fails at approval must block activation"
            );
        } else {
            prop_assert!(
                got.report_at_request.contains_key(&check),
                "the probe failed at the request: {:?}",
                got.report_at_request
            );
            prop_assert_eq!(
                got.verdict,
                StepVerdict::Accepted,
                "the approval must use fresh probe results, not the stored report"
            );
        }
        Ok(())
    }
}

/// I-66: probe results come from the approval request, on production.
#[test]
fn i66_probes_run_at_approval() {
    check("i66_probes_run_at_approval", property(Backend::Production));
}

/// I-66: the same on the reference alone.
#[test]
fn i66_probes_run_at_approval_on_the_reference() {
    check(
        "i66_probes_run_at_approval_on_the_reference",
        property(Backend::Reference),
    );
}
