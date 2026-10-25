//! Adversarial review of lane L-REV (step W4a), second pass.
//!
//! Each test fails against the lane's current code and passes once the
//! named defect is fixed. They run production commands from genesis over
//! the synthetic vault of `gen::review`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Command;
use fstp_domain::id::{ContentDigest, MilestoneId, PlanVersionId};
use fstp_domain::proposal::{Milestone, PlanOrigin, Task};
use fstp_domain_testkit::r#gen::review::{
    L4, PR4, after, machine_accounts, machine_setup, plan_of, review_truth, run_records,
    scenario_from, submit,
};
use fstp_domain_testkit::r#gen::roster::{Flags, Step, T0};
use fstp_money::{Amount, Currency, PosAmount};

/// One milestone of the largest representable amount.
fn huge(id: u128) -> Milestone {
    let a = Amount::from_minor(Amount::MAX_ABS_MINOR, Currency::Eur).unwrap();
    Milestone {
        id: MilestoneId::from_raw(id),
        amount: PosAmount::new(a).unwrap(),
        start: T0,
        due: after(T0, 1_000_000),
        activity: None,
        deliverables: Vec::new(),
    }
}

/// ADR-006, R-SB-01, design 3.7: a plan whose total is outside the money
/// range has no requested amount. Today `RecordPlanVersion` and `Submit`
/// both accept it, and `visibility::requested` then reports zero for it in
/// the ranking view, so the committee sees a requested amount of 0.00 and
/// a remaining budget that ignores it. One of the two must refuse.
#[test]
fn review_plan_total_outside_the_money_range_is_refused() {
    let mut s = scenario_from(&machine_setup(), review_truth(machine_accounts())).unwrap();
    let plan = PlanVersionId::from_raw(91_001);
    let record = Step::by(
        L4,
        Flags::NONE,
        Command::RecordPlanVersion {
            plan,
            proposal: PR4,
            origin: PlanOrigin::Submitted,
            supersedes: Some(plan_of(PR4)),
            tasks: vec![Task {
                milestones: vec![huge(91_101), huge(91_102)],
            }],
            content: ContentDigest::from_bytes([9; 32]),
        },
    );
    let recorded = run_records(&mut s, &record, T0).unwrap();
    if recorded.is_err() {
        return;
    }
    let submitted = run_records(&mut s, &submit(L4, PR4, plan, false), T0).unwrap();
    assert!(
        submitted.is_err(),
        "a plan totalling 2 x {} minor units was recorded and submitted; \
         its total cannot be represented: {submitted:?}",
        Amount::MAX_ABS_MINOR
    );
}
