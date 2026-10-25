//! R-SB-05 and R-NG-06: the submission records the ethics self-declaration and the notice version (design 2.8).
//!
//! `Submit` carries an `EthicsDeclaration`, so no submission lacks one by
//! type. Declared ethics issues are flagged to the assigned reviewers from
//! the `Submitted` record, which M4 renders. The data protection notice
//! version that M4 showed is recorded with it (R-NG-06 seam).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::record::Record;
use fstp_domain_testkit::r#gen::review::{
    L4, NOTICE, PR4, ethics, machine_accounts, machine_setup, plan_of, review_truth, run_records,
    scenario_from, submit,
};
use fstp_domain_testkit::r#gen::roster::T0;

/// R-SB-05, R-NG-06: the `Submitted` record holds the declaration with its
/// issues flag and the notice version, exactly as submitted.
#[test]
fn r_sb_05_submission_records_the_ethics_declaration_and_notice() {
    let mut s = scenario_from(&machine_setup(), review_truth(machine_accounts()))
        .unwrap_or_else(|e| panic!("setup from genesis: {e}"));
    let records = run_records(&mut s, &submit(L4, PR4, plan_of(PR4), true), T0)
        .unwrap()
        .unwrap_or_else(|r| panic!("Submit refused: {r}"));
    let expected = Record::Submitted {
        proposal: PR4,
        plan: plan_of(PR4),
        ethics: ethics(PR4, true),
        notice: NOTICE,
    };
    assert!(
        records.contains(&expected),
        "the batch holds {expected:?}: {records:?}"
    );
}
