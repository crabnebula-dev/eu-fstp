//! Review reproducers for lane w6-audit (Q-W6-1: the call approval in reference mode).
//!
//! In reference mode the setup builder took `ApproveCallPublication` as
//! accepted with no records. Production emits `CallApproved`, and the
//! lifecycle reference folds its decision id. So the reference ledger
//! lacked the decisions of the setup, and the life model states differed
//! between the backends even where their counts matched. A reference twin
//! would also have accepted a later reuse of such a decision id.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Command;
use fstp_domain::record::Record;
use fstp_domain_testkit::r#gen::review::{L1, PR1};
use fstp_domain_testkit::r#gen::roster::{Backend, Facts, SodSetup, SodWorld, call, sod_truth};
use fstp_domain_testkit::mc::life_model::{LifeWorld, life_judges, story_setup};

/// The records of every `ApproveCallPublication` of the setup on `backend`.
fn approvals(backend: Backend) -> Vec<Vec<Record>> {
    let mut setup = SodSetup::one(1, &[1, 2]);
    setup.published = vec![call(1)];
    let mut w = SodWorld::new(backend, sod_truth());
    let mut out = Vec::new();
    for step in setup.steps().unwrap() {
        let records = w.exec(&step, Facts::Effective).unwrap().unwrap();
        if matches!(step.cmd, Command::ApproveCallPublication { .. }) {
            out.push(records);
        }
    }
    out
}

/// Design 6.1, R-PC-03: the reference-mode setup records each call
/// approval as production does, with the same `CallApproved` record.
#[test]
fn review_reference_mode_records_the_call_approval() {
    let production = approvals(Backend::Production);
    let reference = approvals(Backend::Reference);
    assert_eq!(production.len(), 2, "the setup approves two calls");
    assert!(
        production
            .iter()
            .all(|r| matches!(r.as_slice(), [Record::CallApproved { .. }])),
        "production records one CallApproved per approval: {production:?}"
    );
    assert_eq!(
        reference, production,
        "the reference-mode setup must record the call approvals production records"
    );
}

/// Design 6.1, R-PC-03, Q-W6-1: after the same setup, the lifecycle reference holds
/// the same decision ids on both backends.
#[test]
fn review_life_decisions_match_across_backends() {
    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let steps = setup.draft_steps().unwrap();
    let production = LifeWorld::from_steps(Backend::Production, setup.truth(), &steps).unwrap();
    let reference = LifeWorld::from_steps(Backend::Reference, setup.truth(), &steps).unwrap();
    assert!(
        !production.life.decisions.is_empty(),
        "the setup approves at least one call"
    );
    assert_eq!(
        reference.life.decisions, production.life.decisions,
        "the lifecycle reference must hold the call-approval decisions on both backends"
    );
}
