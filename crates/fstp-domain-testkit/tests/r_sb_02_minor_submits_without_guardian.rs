//! R-SB-02: minors can submit without guardian consent (design 2.8 and 3.2).
//!
//! AC: a minor-flagged submission reaches SUBMITTED without a guardian
//! record. The scenario runs production commands from genesis: the lead
//! of a minor-flagged draft submits with no guardian bound and no consent
//! in the vault.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::record::Record;
use fstp_domain::roles::{BindingScope, Role};
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::review::{
    L2, PR2, machine_accounts, machine_setup, plan_of, records_of, review_truth, run_records,
    scenario_from, submit,
};
use fstp_domain_testkit::r#gen::roster::T0;

/// R-SB-02: a minor-flagged draft reaches SUBMITTED without a guardian
/// binding and without a consent record.
#[test]
fn r_sb_02_minor_flagged_submission_needs_no_guardian() {
    let mut setup = machine_setup();
    for d in &mut setup.drafts {
        if d.proposal == PR2 {
            d.submit = false;
            d.minor = true;
        }
    }
    let mut s = scenario_from(&setup, review_truth(machine_accounts()))
        .unwrap_or_else(|e| panic!("setup from genesis: {e}"));
    assert!(!s.truth().has_consent(PR2), "the vault holds no consent");
    let records = run_records(&mut s, &submit(L2, PR2, plan_of(PR2), false), T0)
        .unwrap()
        .unwrap_or_else(|r| panic!("R-SB-02: the minor's submission was refused: {r}"));
    assert!(records.iter().any(|r| matches!(
        r,
        Record::Transitioned(t) if t.proposal == PR2 && t.to == StateTag::Submitted
    )));
    let guardians = records_of(&s)
        .unwrap()
        .into_iter()
        .filter(|r| matches!(
            r,
            Record::BindingGranted(g)
                if g.role == Role::Guardian
                    && matches!(g.scope, BindingScope::Proposal { proposal, .. } if proposal == PR2)
        ))
        .count();
    assert_eq!(guardians, 0, "no guardian record was needed");
}
