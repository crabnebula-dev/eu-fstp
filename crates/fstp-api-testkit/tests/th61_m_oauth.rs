//! TH-61 (T-MC-TOKEN), ADR-013, P-72 and R-MC-03 on M-OAUTH (M4 design
//! section 8.5).
//!
//! The model runs exhaustively under its tripwire. One client and one
//! account authorise, exchange, refresh, reuse, revoke, end the agent and
//! move the clock. The backend is replayed along each trace and checked
//! against the abstract machine after every step. Properties: no token
//! after revocation; reuse revokes the family; no code is used twice; no
//! code is redeemed at 60 seconds or later; no token outlives its family
//! (P-72). Witnesses: a rotation, a reuse detection and a token dead only
//! by the P-72 cap. The `_reference` twin runs the reference alone and
//! must pass now.
//!
//! The teeth test injects an adapter that accepts reuse: it sends the
//! family's current refresh token in place of a rotated one. It must be
//! caught on both backends.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    reason = "R-NF-02 print ban: test-only code that never ships, so it may print"
)]

use fstp_api_testkit::mc::oauth_model::{
    Backend, Fault, OauthAction, OauthModel, TRIPWIRE, oauth_properties,
};
use fstp_domain_testkit::harness::mc::{check_exhaustive, tripwire};
use fstp_domain_testkit::harness::teeth::expect_violation;
use fstp_mc::{Config, Verdict, check};

fn model(backend: Backend) {
    let model = OauthModel::new(backend).unwrap_or_else(|e| panic!("M-OAUTH: {e}"));
    if TRIPWIRE == 0 {
        let outcome = check(
            &model,
            &oauth_properties(),
            &Config::default()
                .with_stop_when_decided(false)
                .with_max_depth(usize::MAX)
                .with_max_states(2_000_000),
        );
        panic!(
            "M-OAUTH TRIPWIRE is 0: record the measured count. This run explored {} states \
             (exhaustive: {})\n{outcome}",
            outcome.stats.states, outcome.exhaustive
        );
    }
    match check_exhaustive(&model, &oauth_properties(), TRIPWIRE) {
        Ok(o) => eprintln!("M-OAUTH ({backend:?}): {} states", o.stats.states),
        Err(e) => panic!("{e}"),
    }
}

/// TH-61, ADR-013, P-72, R-MC-03: M-OAUTH on `fstp-oauth`. No token after
/// revocation; reuse revokes the family; no code used twice or after 60
/// seconds; no token outlives its family.
#[test]
fn th61_m_oauth() {
    model(Backend::Production);
}

/// TH-61, ADR-013, P-72, R-MC-03: M-OAUTH passes on the reference alone.
#[test]
fn th61_m_oauth_reference() {
    model(Backend::Reference);
}

fn caught(backend: Backend) {
    let model = OauthModel::with_fault(backend, Fault::AcceptReuse)
        .unwrap_or_else(|e| panic!("M-OAUTH: {e}"));
    let bound = TRIPWIRE.max(1).saturating_mul(4);
    let outcome = check(
        &model,
        &oauth_properties(),
        &tripwire(bound).with_stop_when_decided(true),
    );
    if let Err(e) = expect_violation(&outcome, "TH-61") {
        panic!("{e}\n{outcome}");
    }
    let Some(Verdict::Violated(v)) = outcome.verdict("TH-61") else {
        panic!("TH-61 has no violation");
    };
    let last = v.trace.actions().last().copied();
    assert!(
        matches!(last, Some(OauthAction::Refresh(_))),
        "the first violation of TH-61 is not the reused refresh but {last:?}\n{outcome}"
    );
}

/// TH-61 teeth: an adapter that accepts a reused refresh token is caught
/// on `fstp-oauth`.
#[test]
fn th61_teeth_reuse_accepted_is_caught() {
    caught(Backend::Production);
}

/// TH-61 teeth: the same fault is caught on the reference alone.
#[test]
fn th61_teeth_reuse_accepted_is_caught_on_the_reference() {
    caught(Backend::Reference);
}
