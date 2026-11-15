//! SoD-08: platform operator staff hold no roles in SaaS cells. Content
//! access requires break-glass approval by the tenant and is logged
//! (`SPEC/02-domain/roles-and-sod.md`, design section 8.6, T-BREAKGLASS).
//!
//! The reference rule is the W1b one in
//! `fstp_celltest::reference::auth` (`approve_break_glass`,
//! `admit_break_glass`). Its own test is
//! `i78_sod_08_reference_break_glass_admits_only_the_named_staff_member`.
//!
//! Daniel decided on 2026-11-15 ("On the approval record") that the
//! request's staff member, scope and end enter the ledger on the approval:
//! `ApproveBreakGlass { request, staff, scope, until }` records
//! `BreakGlassApproved { grant, staff, scope, until }` (ADR-008, design
//! section 8.6). A staff read reaches the gate with a control-plane-signed
//! staff assertion, verified against the pinned key within
//! `STAFF_ASSERTION_US` (`gate::admit_break_glass`). Each admitted read
//! is logged as one `OpsRecord::BreakGlassRead`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_auth::breakglass::{BreakGlassRead, StaffAssertion};
use fstp_auth::recovery::StaffRef;
use fstp_cell_core::gate::{self, ReadAction};
use fstp_cell_core::ops::{OpsCommand, OpsRecord};
use fstp_cell_core::{CellCommand, CellRecord};
use fstp_celltest::mc::auth_model::{ProdCell, ProdError};
use fstp_celltest::reference::auth::{
    self as r, RefBreakGlass, RefRead, RefStaff, RefStaffRequest,
};
use fstp_crypto::composite::CompositeSigningKey;
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{A, ADMIN, T0};

/// The cell's staff reference of reference staff member `s`.
fn staff_ref(s: RefStaff) -> StaffRef {
    let mut out = [0x57; 16];
    out[14..].copy_from_slice(&s.0.to_be_bytes());
    StaffRef(out)
}

fn read_kind(read: RefRead) -> BreakGlassRead {
    match read {
        RefRead::Content => BreakGlassRead::Content,
        RefRead::Audit => BreakGlassRead::Audit,
        RefRead::ErasureLog => BreakGlassRead::ErasureLog,
    }
}

fn read_action(read: RefRead) -> ReadAction {
    match read {
        RefRead::Content => ReadAction::ReadContent,
        RefRead::Audit => ReadAction::ReadAudit,
        RefRead::ErasureLog => ReadAction::ReadErasureLog,
    }
}

/// The approval of request `request` for grant `g`, as the control
/// plane's request names it.
fn approval(request: [u8; 16], g: &RefBreakGlass) -> OpsCommand {
    OpsCommand::ApproveBreakGlass {
        request,
        staff: staff_ref(g.staff),
        scope: g.scope.iter().map(|x| read_kind(*x)).collect(),
        until: g.until,
    }
}

fn approve(
    c: &mut ProdCell,
    who: AccountId,
    request: [u8; 16],
    g: &RefBreakGlass,
) -> Result<Vec<CellRecord>, String> {
    let cmd = CellCommand::Ops(approval(request, g));
    match c.exec(cmd, who, T0) {
        Ok(batch) => Ok(batch),
        Err(ProdError::Refused(_)) => Ok(Vec::new()),
        Err(ProdError::NotImplemented(op)) => Err(format!("{op} is NotImplemented")),
    }
}

/// The control plane's staff assertion key, which the cell pins, and a
/// key the cell does not pin.
struct Keys {
    pinned: CompositeSigningKey,
    other: CompositeSigningKey,
}

impl Keys {
    fn new() -> Keys {
        Keys {
            pinned: fstp_crypto::composite::generate().unwrap(),
            other: fstp_crypto::composite::generate().unwrap(),
        }
    }
}

/// SoD-08, TH-18, design section 8.6: a break-glass request is approved
/// only by a tenant admin, its approval and its end are ledger records,
/// and the staff member's reads under it are admitted only within its
/// scope and window and each is logged as `BreakGlassRead`.
#[test]
fn sod_08_break_glass_needs_tenant_approval_and_logs_every_read() {
    let grant = RefBreakGlass {
        staff: RefStaff(7),
        scope: vec![RefRead::Content],
        approved_at: T0,
        until: Timestamp::from_micros(T0.micros() + r::HOUR_US),
        ended: None,
    };
    let keys = Keys::new();
    let mut c = ProdCell::bootstrapped().unwrap_or_else(|e| panic!("{e}"));
    let request = [0xB6; 16];

    // A non-admin's approval records nothing, as the reference refuses it.
    assert!(r::approve_break_glass(false, true, &grant).is_err());
    let by_a = approve(&mut c, A, request, &grant).unwrap();
    assert!(
        by_a.is_empty(),
        "a non-admin approved break-glass: {by_a:?}"
    );

    // A tenant admin's approval records `BreakGlassApproved` with the
    // request's staff member, scope and end.
    assert!(r::approve_break_glass(true, true, &grant).is_ok());
    let batch = approve(&mut c, ADMIN, request, &grant).unwrap();
    let granted: Vec<[u8; 16]> = batch
        .iter()
        .filter_map(|x| match x {
            CellRecord::Ops(OpsRecord::BreakGlassApproved {
                grant: id,
                staff,
                scope,
                until,
            }) => {
                assert_eq!(*staff, staff_ref(grant.staff));
                assert_eq!(*scope, vec![BreakGlassRead::Content]);
                assert_eq!(*until, grant.until);
                Some(*id)
            }
            _ => None,
        })
        .collect();
    assert_eq!(granted.len(), 1, "{batch:?}");

    // Reads inside the window: production must admit exactly the reads
    // the reference admits, and log each admitted one as one
    // `BreakGlassRead`. Every step runs in time order (R14).
    let inside = Timestamp::from_micros(T0.micros() + 1);
    let mut found = read_mismatches(&grant, inside, |s, r, p, t| {
        staff_read(&mut c, &keys, granted[0], s, r, p, t)
    });

    // Ending it records `BreakGlassEnded` for that grant.
    let ended_at = Timestamp::from_micros(T0.micros() + 2);
    let end = CellCommand::Ops(OpsCommand::EndBreakGlass { grant: granted[0] });
    let ended = c.exec(end, ADMIN, ended_at).unwrap();
    assert!(
        ended.iter().any(|x| matches!(
            x,
            CellRecord::Ops(OpsRecord::BreakGlassEnded { grant }) if *grant == granted[0]
        )),
        "{ended:?}"
    );

    // Reads after the end, and at `until`: the reference refuses all.
    let after = RefBreakGlass {
        ended: Some(ended_at),
        ..grant.clone()
    };
    for at in [ended_at, grant.until] {
        found.extend(read_mismatches(&after, at, |s, r, p, t| {
            staff_read(&mut c, &keys, granted[0], s, r, p, t)
        }));
    }
    assert!(found.is_empty(), "{found:#?}");
}

/// What production did with one staff read: whether the gate admitted it,
/// and how many `BreakGlassRead` records it logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StaffRead {
    admitted: bool,
    logged: usize,
}

/// A staff read under break-glass grant `grant`, by `staff` with a staff
/// assertion signed by the pinned key when `pinned` holds and by a key
/// the cell does not pin otherwise, at `at`.
///
/// The gate admits it through `gate::admit_break_glass` with
/// `Principal::BreakGlass`, and the harness appends the admission's log
/// record (`Admitted::break_glass_log`). The count is of the
/// `BreakGlassRead` records the ledger gained.
fn staff_read(
    c: &mut ProdCell,
    keys: &Keys,
    grant: [u8; 16],
    staff: RefStaff,
    read: RefRead,
    pinned: bool,
    at: Timestamp,
) -> Result<StaffRead, fstp_celltest::NotImplemented> {
    let assertion = StaffAssertion {
        grant,
        staff: staff_ref(staff),
        issued_at: at,
    };
    let signer = if pinned { &keys.pinned } else { &keys.other };
    let signature = signer
        .sign_with_context(
            &assertion.message(),
            fstp_auth::breakglass::STAFF_ASSERTION_CONTEXT,
        )
        .unwrap()
        .to_bytes();
    let pin = keys.pinned.public_key().to_bytes();
    let logged_before = break_glass_reads(c);
    let admitted = match gate::admit_break_glass(
        c.state(),
        &assertion,
        &signature,
        Some(&pin[..]),
        read_action(read),
        at,
    ) {
        Ok(a) => a,
        Err(_) => {
            return Ok(StaffRead {
                admitted: false,
                logged: break_glass_reads(c) - logged_before,
            });
        }
    };
    assert_eq!(
        admitted.principal(),
        gate::Principal::BreakGlass(grant),
        "a staff read is admitted as its grant"
    );
    c.log_break_glass_read(&admitted, at)
        .unwrap_or_else(|e| panic!("{e}"));
    Ok(StaffRead {
        admitted: true,
        logged: break_glass_reads(c) - logged_before,
    })
}

/// The `BreakGlassRead` records in the ledger.
fn break_glass_reads(c: &ProdCell) -> usize {
    c.log()
        .iter()
        .flat_map(|a| a.batch.iter())
        .filter(|x| matches!(x, CellRecord::Ops(OpsRecord::BreakGlassRead { .. })))
        .count()
}

/// Every staff read at `at` where `read_by` differs from
/// `reference::auth::admit_break_glass` under `g`, or logs other than one
/// `BreakGlassRead` per admitted read, one line each. The reads cover the
/// named and another staff member, each read kind, and the pinned and an
/// unpinned key.
fn read_mismatches(
    g: &RefBreakGlass,
    at: Timestamp,
    mut read_by: impl FnMut(
        RefStaff,
        RefRead,
        bool,
        Timestamp,
    ) -> Result<StaffRead, fstp_celltest::NotImplemented>,
) -> Vec<String> {
    let mut out = Vec::new();
    for staff in [g.staff, RefStaff(g.staff.0 + 1)] {
        for read in [RefRead::Content, RefRead::Audit, RefRead::ErasureLog] {
            for pinned in [true, false] {
                let want =
                    r::admit_break_glass(g, RefStaffRequest::Read(read), pinned, Some(staff), at);
                match read_by(staff, read, pinned, at) {
                    Err(e) => {
                        out.push(format!("{e}"));
                        return out;
                    }
                    Ok(got) => {
                        let logged = usize::from(want);
                        if got.admitted != want || got.logged != logged {
                            out.push(format!(
                                "{staff:?} {read:?} pinned {pinned} at {at:?}: production \
                                 {got:?}, the reference admits {want} and logs {logged}"
                            ));
                        }
                    }
                }
            }
        }
    }
    out
}

/// SoD-08 teeth: the read comparison reports a gate that admits every
/// staff read, and one that admits the right reads but logs none. A gate
/// that follows the reference and logs each read gives no mismatch.
#[test]
fn sod_08_teeth_read_comparison_catches_a_lax_gate() {
    let g = RefBreakGlass {
        staff: RefStaff(7),
        scope: vec![RefRead::Content],
        approved_at: T0,
        until: Timestamp::from_micros(T0.micros() + r::HOUR_US),
        ended: None,
    };
    let at = Timestamp::from_micros(T0.micros() + 1);
    let lax = read_mismatches(&g, at, |_, _, _, _| {
        Ok(StaffRead {
            admitted: true,
            logged: 1,
        })
    });
    // Twelve reads, of which the reference admits one.
    assert_eq!(lax.len(), 11, "{lax:#?}");
    let reference =
        |s, read, p, t| r::admit_break_glass(&g, RefStaffRequest::Read(read), p, Some(s), t);
    let silent = read_mismatches(&g, at, |s, read, p, t| {
        Ok(StaffRead {
            admitted: reference(s, read, p, t),
            logged: 0,
        })
    });
    assert_eq!(silent.len(), 1, "{silent:#?}");
    let exact = read_mismatches(&g, at, |s, read, p, t| {
        let admitted = reference(s, read, p, t);
        Ok(StaffRead {
            admitted,
            logged: usize::from(admitted),
        })
    });
    assert!(exact.is_empty(), "{exact:#?}");
}
