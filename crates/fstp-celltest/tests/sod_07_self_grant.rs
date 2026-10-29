//! SoD-07: a tenant admin granting a role to their own account requires
//! approval by a second tenant admin (`SPEC/02-domain/roles-and-sod.md`,
//! design section 5.1, Q40).
//!
//! `sod_07_self_grant_needs_second_admin_approval_of_the_same_digest`, the
//! scenario test of design section 14.4, lives in `i78_stepup.rs` (lane
//! W1b). The tests here compare production with the W1b reference rule
//! `fstp_celltest::reference::auth::admit_self_grant` over random approval
//! sets, and check that the digest binds the command id.
//!
//! Lane W1f wrote these tests before the production code. They are red
//! until the cell fold and the grant digest (lane W2c) land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_cell_core::CellCommand;
use fstp_cell_core::tenant::TenantCommand;
use fstp_celltest::mc::auth_model::{ProdCell, ProdError};
use fstp_celltest::mc::stepup_model::prod_self_grant_digest;
use fstp_celltest::reference::auth::{self as r, RefAdmin, RefRoster, RefSelfGrantApproval};
use fstp_domain::id::{AccountId, BindingId};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{A, ADMIN, ADMIN_2, P1, T0, grant};
use fstp_prop::{Gen, prop_assert_eq};

fn two_admins() -> RefRoster {
    RefRoster {
        bindings: Vec::new(),
        admins: vec![
            RefAdmin {
                account: ADMIN,
                end: None,
            },
            RefAdmin {
                account: ADMIN_2,
                end: None,
            },
        ],
    }
}

/// admin1's grant of `role` to its own account at `at`.
fn self_grant(role: Role, at: Timestamp) -> CellCommand {
    CellCommand::Engine(fstp_engine::Command::Core(
        grant(BindingId::from_raw(7_101), ADMIN, P1, role, at).cmd,
    ))
}

fn digest(cmd: &CellCommand, id: [u8; 16]) -> Result<[u8; 32], String> {
    prod_self_grant_digest(cmd, id).map_err(|e| e.to_string())
}

/// A production cell with admin1 and admin2 as tenant admins.
fn cell() -> Result<ProdCell, String> {
    let mut c = ProdCell::bootstrapped().map_err(|e| e.to_string())?;
    c.exec_tenant_admin_grant(ADMIN, ADMIN_2, T0)
        .map_err(|e| e.to_string())?;
    Ok(c)
}

/// Whether production commits `cmd` by admin1 at `at` under id `id`.
fn commits(
    c: &mut ProdCell,
    cmd: CellCommand,
    at: Timestamp,
    id: [u8; 16],
) -> Result<bool, String> {
    match c.exec_with_id(cmd, ADMIN, at, id) {
        Ok(batch) => Ok(!batch.is_empty()),
        Err(ProdError::Refused(_)) => Ok(false),
        Err(ProdError::NotImplemented(op)) => Err(format!("{op} is NotImplemented")),
    }
}

/// One generated approval: the approver, whether it approves the grant's
/// own digest, and how long after T0 its step-up was asserted.
#[derive(Clone, Copy, Debug)]
struct Gen1 {
    approver: AccountId,
    own_digest: bool,
    stepup_after_us: i64,
}

/// SoD-07, Q40: for random sets of approvals by admin2, by admin1 itself
/// and by a non-admin, of the grant's digest or another one, fresh or
/// older than P-71, production commits the self-grant exactly when the
/// reference rule admits it. The approvals run in time order, and the
/// grant runs after them. Half the draws put the grant at an approval's
/// step-up plus P-71, or one microsecond either side.
#[test]
fn sod_07_self_grant_matches_the_reference_rule() {
    fstp_prop::check(
        "sod_07_self_grant_matches_the_reference_rule",
        |g: &mut Gen| {
            let id: [u8; 16] = g.bytes(16..=16).try_into().unwrap();
            let mut approvals = g.vec(0..=3, |g| Gen1 {
                approver: *g.pick(&[ADMIN_2, ADMIN, A]),
                own_digest: g.bool(),
                stepup_after_us: g.i64_in(0..=2 * r::P71_DEFAULT_US),
            });
            // The ledger is time-monotone (R14, design section 2.2), so the
            // approvals reach the cell in time order. Every one still goes
            // to the reference, so a refusal of a valid approval shows.
            approvals.sort_by_key(|a| a.stepup_after_us);
            // Half the time the grant lands on an approval's expiry
            // instant, one microsecond before it or one after it (design
            // section 14.1, reduced clock at the P-71 boundary).
            let after_us = match approvals.as_slice() {
                [] => g.i64_in(0..=2 * r::P71_DEFAULT_US),
                some if g.bool() => {
                    let a = g.pick(some);
                    a.stepup_after_us + r::P71_DEFAULT_US + *g.pick(&[-1i64, 0, 1])
                }
                _ => g.i64_in(0..=2 * r::P71_DEFAULT_US),
            };
            let now = Timestamp::from_micros(T0.micros() + after_us);
            let cmd = self_grant(Role::FinanceApprover, now);
            let own = digest(&cmd, id)?;
            let other = digest(&self_grant(Role::Auditor, now), id)?;
            let mut c = cell()?;
            let mut reference = Vec::new();
            for a in &approvals {
                let d = if a.own_digest { own } else { other };
                let at = Timestamp::from_micros(T0.micros() + a.stepup_after_us);
                // An approval stamped after the grant cannot be used by it.
                if at.micros() > now.micros() {
                    continue;
                }
                let approve =
                    CellCommand::Tenant(TenantCommand::ApproveSelfGrant { grant_digest: d });
                match c.exec(approve, a.approver, at) {
                    Err(ProdError::NotImplemented(op)) => {
                        return Err(format!("{op} is NotImplemented"));
                    }
                    Ok(_) | Err(ProdError::Refused(_)) => {}
                }
                reference.push(RefSelfGrantApproval {
                    approver: a.approver,
                    grant_digest: d,
                    stepup_at: at,
                    used: false,
                });
            }
            let want = r::admit_self_grant(
                &two_admins(),
                ADMIN,
                ADMIN,
                own,
                &reference,
                now,
                r::P71_DEFAULT_US,
            )
            .is_ok();
            let got = commits(&mut c, cmd, now, id)?;
            prop_assert_eq!(got, want, "approvals {approvals:?} at {now:?}");
            Ok(())
        },
    );
}

/// SoD-07, design section 5.1: the grant digest binds the command id, so
/// an approval of one command does not admit the same grant under another
/// command id.
#[test]
fn sod_07_approval_is_bound_to_the_command_id() {
    let at = Timestamp::from_micros(T0.micros() + r::MINUTE_US);
    let cmd = self_grant(Role::FinanceApprover, at);
    let (approved, other) = ([0x31; 16], [0x32; 16]);
    let d = digest(&cmd, approved).unwrap();
    assert_ne!(
        d,
        digest(&cmd, other).unwrap(),
        "the digest ignores the command id"
    );
    let mut c = cell().unwrap();
    let approve = CellCommand::Tenant(TenantCommand::ApproveSelfGrant { grant_digest: d });
    let batch = c.exec(approve, ADMIN_2, T0).unwrap();
    assert!(!batch.is_empty(), "admin2's approval recorded nothing");
    assert!(
        !commits(&mut c, cmd.clone(), at, other).unwrap(),
        "an approval of another command id admitted the grant"
    );
    assert!(
        commits(&mut c, cmd, at, approved).unwrap(),
        "the approved command was refused"
    );
}
