//! I-85 and R-MC-05 on M-PREP (M4 design sections 8.4 and 8.5).
//!
//! The model runs exhaustively under its tripwire. On production it
//! drives dispatch on a fake cell and checks every step against the
//! reference. No high-risk or draft-only binding operation completes
//! except by a web confirmation of the same account. Each pending action
//! executes at most once. The executed request equals the stored one.
//! The `_reference` twin runs the reference alone and must pass now.
//!
//! The teeth test injects a confirmation without the digest check: on
//! production, an alternative adapter replaces a wrong shown digest with
//! the stored one; on the reference, the reference admits it. Each must
//! be caught.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    reason = "R-NF-02 print ban: test-only code that never ships, so it may print"
)]

use fstp_api_testkit::mc::prep_model::{
    Backend, Fault, PrepAction, PrepModel, Shown, TRIPWIRE, prep_properties,
};
use fstp_domain_testkit::harness::mc::{check_exhaustive, tripwire};
use fstp_domain_testkit::harness::teeth::expect_violation;
use fstp_mc::{Config, Verdict, check};

fn model(backend: Backend) {
    let model = PrepModel::new(backend).unwrap_or_else(|e| panic!("M-PREP: {e}"));
    if TRIPWIRE == 0 {
        let outcome = check(
            &model,
            &prep_properties(),
            &Config::default()
                .with_stop_when_decided(false)
                .with_max_depth(usize::MAX)
                .with_max_states(1_000_000),
        );
        panic!(
            "M-PREP TRIPWIRE is 0: record the measured count. This run explored {} states \
             (exhaustive: {})\n{outcome}",
            outcome.stats.states, outcome.exhaustive
        );
    }
    match check_exhaustive(&model, &prep_properties(), TRIPWIRE) {
        Ok(o) => eprintln!("M-PREP ({backend:?}): {} states", o.stats.states),
        Err(e) => panic!("{e}"),
    }
}

/// I-85, R-MC-05, R-MC-03: M-PREP on production dispatch. No high-risk or
/// draft-only binding operation completes except by a web confirmation of
/// the same account with a fresh step-up for its digest where high-risk;
/// each pending action executes at most once; the executed request equals
/// the stored one.
#[test]
fn i85_m_prep() {
    model(Backend::Production);
}

/// I-85, R-MC-05: M-PREP passes on the reference alone.
#[test]
fn i85_m_prep_reference() {
    model(Backend::Reference);
}

fn caught(backend: Backend) {
    let model = PrepModel::with_fault(backend, Fault::ForgeShownDigest)
        .unwrap_or_else(|e| panic!("M-PREP: {e}"));
    let bound = TRIPWIRE.max(1).saturating_mul(4);
    let outcome = check(
        &model,
        &prep_properties(),
        &tripwire(bound).with_stop_when_decided(true),
    );
    let id = match backend {
        Backend::Production => "I-85",
        Backend::Reference => "I-85 publication",
    };
    if let Err(e) = expect_violation(&outcome, id) {
        panic!("{e}\n{outcome}");
    }
    let Some(Verdict::Violated(v)) = outcome.verdict(id) else {
        panic!("{id} has no violation");
    };
    let last = v.trace.actions().last().copied();
    assert!(
        matches!(last, Some(PrepAction::Confirm(_, _, Shown::Wrong))),
        "the first violation of {id} is not the forged confirmation but {last:?}\n{outcome}"
    );
}

/// I-85 teeth: a confirmation that skips the digest check is caught on
/// production.
#[test]
fn i85_teeth_confirm_without_digest_check_is_caught() {
    caught(Backend::Production);
}

/// I-85 teeth: the same fault is caught on the reference alone.
#[test]
fn i85_teeth_confirm_without_digest_check_is_caught_on_the_reference() {
    caught(Backend::Reference);
}
