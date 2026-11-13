//! R-RP-03, M5 design Q3 (answered 2026-11-06): a funder document is a
//! draft until a Financial signatory who did not generate it approves it.
//! The approval is a `Report` ledger record.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use fstp_domain::id::AccountId;
use fstp_report::{
    ApprovalRefusal, ReportFoldError, ReportId, ReportRecord, ReportStore, Request, approve,
    generate, generated,
};
use support::{CALL, fixed, ledger_of};

const GEN: AccountId = AccountId::from_raw(5_000_000_001);
const SIGNATORY: AccountId = AccountId::from_raw(5_000_000_002);

fn store_with(report: ReportId, by: AccountId) -> ReportStore {
    let snap = ledger_of(&fixed()).snapshot();
    let out = generate(&snap, &support::he(), &Request::AuditFile { call: CALL }).unwrap();
    let mut store = ReportStore::default();
    store.apply(&generated(report, &out, by)).unwrap();
    store
}

/// R-RP-03, Q3: the generator cannot approve the document it generated,
/// even when it holds the Financial signatory role.
#[test]
fn r_rp_03_generator_cannot_approve_own_document() {
    let r = ReportId::from_raw(1);
    let store = store_with(r, GEN);
    assert_eq!(
        approve(&store, r, GEN, true),
        Err(ApprovalRefusal::Generator)
    );
}

/// R-RP-03, Q3: only a Financial signatory approves.
#[test]
fn r_rp_03_approver_must_be_financial_signatory() {
    let r = ReportId::from_raw(1);
    let store = store_with(r, GEN);
    assert_eq!(
        approve(&store, r, SIGNATORY, false),
        Err(ApprovalRefusal::NotFinancialSignatory)
    );
    let rec = approve(&store, r, SIGNATORY, true).unwrap();
    assert_eq!(
        rec,
        ReportRecord::Approved {
            report: r,
            approver: SIGNATORY
        }
    );
}

/// R-RP-03: approval is once only, of a known report.
#[test]
fn r_rp_03_unknown_or_approved_report_is_refused() {
    let r = ReportId::from_raw(1);
    let mut store = store_with(r, GEN);
    assert_eq!(
        approve(&store, ReportId::from_raw(2), SIGNATORY, true),
        Err(ApprovalRefusal::UnknownReport)
    );
    store
        .apply(&approve(&store, r, SIGNATORY, true).unwrap())
        .unwrap();
    assert_eq!(
        approve(&store, r, SIGNATORY, true),
        Err(ApprovalRefusal::AlreadyApproved)
    );
    assert!(store.report(r).unwrap().approver == Some(SIGNATORY));
}

/// R-RP-03, Q3: the fold refuses a self-approval record, so no ledger
/// that replays holds one.
#[test]
fn r_rp_03_fold_refuses_self_approval() {
    let r = ReportId::from_raw(1);
    let mut store = store_with(r, GEN);
    assert_eq!(
        store.apply(&ReportRecord::Approved {
            report: r,
            approver: GEN
        }),
        Err(ReportFoldError::SelfApproval)
    );
    assert_eq!(store.report(r).unwrap().approver, None);
}

/// R-RP-03, Q3: over random generate and approve sequences, no approved
/// report names its generator as approver, through `approve` or the fold.
#[test]
fn r_rp_03_no_report_is_approved_by_its_generator() {
    let snap = ledger_of(&fixed()).snapshot();
    let out = generate(
        &snap,
        &support::he(),
        &Request::DeliverableDraft { call: CALL },
    )
    .unwrap();
    fstp_prop::check("r_rp_03_no_report_is_approved_by_its_generator", |g| {
        let mut store = ReportStore::default();
        let steps = g.vec(0..=24, |g| {
            (g.bool(), g.u8_in(0..=3), g.u8_in(0..=3), g.bool())
        });
        for (gen_step, report, who, signatory) in steps {
            let id = ReportId::from_raw(u128::from(report));
            let account = AccountId::from_raw(5_000_000_000 + u128::from(who));
            if gen_step {
                let _ = store.apply(&generated(id, &out, account));
            } else {
                if let Ok(rec) = approve(&store, id, account, signatory) {
                    store
                        .apply(&rec)
                        .map_err(|e| format!("a decided approval did not fold: {e:?}"))?;
                }
                // A forged record straight into the fold.
                let _ = store.apply(&ReportRecord::Approved {
                    report: id,
                    approver: account,
                });
            }
        }
        for i in 0..=3u128 {
            if let Some(r) = store.report(ReportId::from_raw(i))
                && r.approver == Some(r.generator)
            {
                return Err(format!("R-RP-03: report {i} approved by its generator"));
            }
        }
        Ok(())
    });
}
