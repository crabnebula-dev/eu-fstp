//! Reviewer reproducers for lane W2c (spec and security fidelity). Each
//! test fails against the current code and passes once its defect is
//! fixed. Fixtures come from the synthetic corpus only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{
    MINUTE_US, admin_ended, admin_granted, as_cell, cid, ledger, m2_entries, m2_run, m2_setup,
    plus, state_of,
};
use fstp_cell_core::release::ReleaseCommand;
use fstp_cell_core::tenant::TenantCommand;
use fstp_cell_core::{CellCommand, CellCtx, CellRecord, CellState, KeyCommand};
use fstp_domain::id::{BindingId, VaultEpoch};
use fstp_domain::oracle::Answers;
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::review::{L1, PR1};
use fstp_domain_testkit::r#gen::roster::{A, ADMIN, B, P1, STAFF_PM, T0, call, draft, end, grant};

/// I-24, ADR-007, design sections 3.5 and 5.1: key records come from the
/// erasure runner, a system task. An account the gate admits must not be
/// able to record a key operation or a destroyed root epoch. Today
/// `decide` checks no actor for them, so any account forges erasure
/// evidence, and the real runner's record is later refused as reused.
#[test]
fn review_key_records_refused_for_an_account_actor() {
    let s = CellState::genesis();
    let x = CellCtx {
        actor: A,
        at: T0.micros(),
    };
    for c in [
        CellCommand::Key(KeyCommand::RecordEpochDestroyed {
            epoch: 1,
            receipt: [0x11; 32],
        }),
        CellCommand::Key(KeyCommand::RecordKeyOp {
            op: b"{\"op\":\"rotate\"}".to_vec(),
        }),
    ] {
        let r = fstp_cell_core::decide(&s, &c, &x, &Answers::new());
        assert!(
            r.is_err(),
            "an account recorded a system key record: {c:?} gave {r:?}"
        );
    }
}

/// ADR-008 "First admin delivery", design section 8.3, SoD-07: the first
/// tenant admin comes from provisioning. Once the cell has had a tenant
/// admin, an empty admin set must not let any account grant itself the
/// role. Today the "first grant" stand-in applies whenever the set is
/// empty, so after the last admin ends, any account takes the tenant.
#[test]
fn review_no_self_grant_of_tenant_admin_after_last_admin_ended() {
    let s = state_of(
        &ledger(&[
            (T0, cid(1), vec![admin_granted(ADMIN)]),
            (plus(T0, 1), cid(2), vec![admin_ended(ADMIN)]),
        ])
        .unwrap(),
    )
    .unwrap();
    assert!(s.tenant().admins().is_empty());
    let x = CellCtx {
        actor: B,
        at: plus(T0, 2).micros(),
    };
    let r = fstp_cell_core::decide(
        &s,
        &CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: B }),
        &x,
        &Answers::new(),
    );
    assert!(r.is_err(), "B granted itself tenant admin: {r:?}");
}

/// The cell state of the M2 corpus setup, with `extra` appended as one
/// more entry after it at `at`.
fn setup_with(extra: fstp_domain::Record, at: fstp_domain::time::Timestamp) -> CellState {
    let s = m2_setup().unwrap();
    let mut entries = as_cell(&m2_entries(&s).unwrap());
    let mut e = entries.last().cloned().unwrap();
    e.seq = fstp_ledger::Seq::from_raw(e.seq.raw() + 1);
    e.at = at.micros();
    e.command = cid(0x7E);
    e.record = CellRecord::Engine(fstp_engine::Record::Core(extra));
    entries.push(e);
    state_of(&entries).unwrap()
}

/// Q16 A, design sections 5.1 and 5.4 step 2: a suspended binding of the
/// Drafting, Judging or Operations groups ends every session of the
/// account, so the gate refuses a session started before the suspension.
/// `decide` appends no `SessionEnded` for it, and `binding_ended_between`
/// counts only recorded and scheduled ends, so the session lives on.
#[test]
fn review_suspended_binding_ends_earlier_sessions() {
    let base = m2_setup().unwrap();
    let base_state = state_of(&as_cell(&m2_entries(&base).unwrap())).unwrap();
    let binding = base_state
        .engine()
        .core
        .roster()
        .bindings()
        .find(|(_, b)| b.account == STAFF_PM && b.role == Role::ProgrammeManager)
        .map(|(id, _)| id)
        .unwrap();
    let suspended_at = plus(T0, 2 * MINUTE_US);
    let s = setup_with(
        fstp_domain::Record::BindingSuspended(fstp_domain::record::BindingSuspended {
            binding,
            rule: RuleRef::I06,
            epoch: VaultEpoch::from_raw(0),
        }),
        suspended_at,
    );
    let started = plus(T0, MINUTE_US);
    let now = plus(T0, 3 * MINUTE_US);
    assert!(
        s.binding_ended_between(STAFF_PM, started, now),
        "a session started before the suspension is still admitted"
    );
}

/// M2 `shared_checks` (SoD-05) and the Cooling-off NOTE: once a scheduled
/// binding end is due, the engine decides no command but `VaultChanged`
/// and `EndScheduledRole` until the end is recorded, and the binding
/// counts only until its end instant (design section 8.2). The cell
/// commands skip that check. A finance approver past its scheduled end
/// still passes the release-ticket holder check, so its refusal is the
/// same proposal-state refusal as before the end.
#[test]
fn review_release_ticket_holder_past_scheduled_end_is_refused_first() {
    const FINANCE: fstp_domain::id::AccountId = fstp_domain::id::AccountId::from_raw(501);
    let mut sc = m2_setup().unwrap();
    m2_run(
        &mut sc,
        &draft(L1, PR1, call(1), BindingId::from_raw(9_301), false),
        T0,
    )
    .unwrap();
    m2_run(
        &mut sc,
        &grant(
            BindingId::from_raw(9_501),
            FINANCE,
            P1,
            Role::FinanceApprover,
            T0,
        ),
        T0,
    )
    .unwrap();
    m2_run(
        &mut sc,
        &end(BindingId::from_raw(9_501), plus(T0, MINUTE_US)),
        T0,
    )
    .unwrap();
    let s = state_of(&as_cell(&m2_entries(&sc).unwrap())).unwrap();
    let cmd = CellCommand::Release(ReleaseCommand::IssueReleaseTicket {
        proposal: PR1.raw(),
    });
    let at = |t: fstp_domain::time::Timestamp| CellCtx {
        actor: FINANCE,
        at: t.micros(),
    };
    let before = fstp_cell_core::decide(&s, &cmd, &at(plus(T0, 30_000_000)), &Answers::new());
    let after = fstp_cell_core::decide(&s, &cmd, &at(plus(T0, 2 * MINUTE_US)), &Answers::new());
    assert!(before.is_err(), "PR1 is a draft: {before:?}");
    assert!(after.is_err(), "PR1 is a draft: {after:?}");
    assert_ne!(
        after, before,
        "the holder check admitted a finance approver past its scheduled end"
    );
}
