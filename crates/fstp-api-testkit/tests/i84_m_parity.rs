//! I-84 on M-PARITY (M4 design sections 8.4 and 8.5).
//!
//! The model runs exhaustively under its tripwire. On production every
//! MCP call goes through the MCP server and its web twin through the web
//! routes, each on a clean world of the matrix harness. For a direct
//! exposure, the MCP outcome equals the web outcome. For a pending
//! exposure, MCP gives `Pending`, and its web confirmation equals the
//! direct web outcome. The `_on_the_reference` twin runs the reference
//! alone.
//!
//! The teeth test plants an alternative MCP dispatcher in this test code
//! that skips the dry run for `fstp_submit_proposal`. It stores a pending
//! action the web refuses, and M-PARITY must catch it. No production code
//! holds a switch for it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    reason = "R-NF-02 print ban: test-only code that never ships, so it may print"
)]

use fstp_api_testkit::mc::parity_model::{
    Backend, Fault, ParityAction, ParityModel, SHORTCUT_OP, TRIPWIRE, parity_properties,
};
use fstp_domain_testkit::harness::mc::{check_exhaustive, tripwire};
use fstp_domain_testkit::harness::teeth::expect_violation;
use fstp_mc::{Config, Verdict, check};

fn model(backend: Backend) {
    let model = ParityModel::new(backend).unwrap_or_else(|e| panic!("M-PARITY: {e}"));
    if TRIPWIRE == 0 {
        let outcome = check(
            &model,
            &parity_properties(),
            &Config::default()
                .with_stop_when_decided(false)
                .with_max_depth(usize::MAX)
                .with_max_states(1_000_000),
        );
        panic!(
            "M-PARITY TRIPWIRE is 0: record the measured count. This run explored {} states \
             (exhaustive: {})\n{outcome}",
            outcome.stats.states, outcome.exhaustive
        );
    }
    match check_exhaustive(&model, &parity_properties(), TRIPWIRE) {
        Ok(o) => eprintln!("M-PARITY ({backend:?}): {} states", o.stats.states),
        Err(e) => panic!("{e}"),
    }
}

/// I-84, R-MC-05: M-PARITY on production. Two accounts, one proposal from
/// genesis to STAGE2, P-77 at both values, each operation with a tool
/// once per channel. A direct exposure gives the web outcome through MCP.
/// A pending exposure gives `Pending` through MCP, and its web
/// confirmation equals the direct web outcome. Witnesses: a pending
/// action confirmed, and a direct MCP success.
#[test]
fn i84_m_parity() {
    model(Backend::Production);
}

/// I-84: M-PARITY passes on the reference alone.
#[test]
fn i84_m_parity_on_the_reference() {
    model(Backend::Reference);
}

fn caught(backend: Backend) {
    let model = ParityModel::with_fault(backend, Fault::SkipDryRun)
        .unwrap_or_else(|e| panic!("M-PARITY: {e}"));
    let bound = TRIPWIRE.max(1).saturating_mul(4);
    let outcome = check(
        &model,
        &parity_properties(),
        &tripwire(bound).with_stop_when_decided(true),
    );
    let id = "I-84 pending";
    if let Err(e) = expect_violation(&outcome, id) {
        panic!("{e}\n{outcome}");
    }
    let Some(Verdict::Violated(v)) = outcome.verdict(id) else {
        panic!("{id} has no violation");
    };
    let last = v.trace.actions().last().copied();
    assert!(
        matches!(last, Some(ParityAction::Call(c)) if c.op == SHORTCUT_OP),
        "the first violation of {id} is not the shortcut tool but {last:?}\n{outcome}"
    );
}

/// I-84 teeth: an alternative MCP dispatcher that skips the dry run for
/// one tool is caught on production.
#[test]
fn i84_teeth_mcp_only_shortcut_is_caught() {
    caught(Backend::Production);
}

/// I-84 teeth: the same shortcut is caught on the reference alone.
#[test]
fn i84_teeth_mcp_only_shortcut_is_caught_on_the_reference() {
    caught(Backend::Reference);
}
