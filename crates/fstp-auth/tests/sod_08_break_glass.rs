//! SoD-08 and TH-18: break-glass approval and reads (ADR-008
//! "Break-glass", design section 8.6, interim pending Daniel, Q21).
//!
//! Lane W2b implementer.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use fstp_auth::HOUR_US;
use fstp_auth::breakglass::{
    BREAK_GLASS_MAX_US, BreakGlassDeny, BreakGlassGrant, BreakGlassRead, admit_break_glass_read,
    approve_break_glass,
};
use fstp_auth::recovery::StaffRef;
use fstp_auth::stepup::StepUpDeny;
use fstp_domain::time::Timestamp;
use fstp_prop::{Gen, check, prop_assert_eq};

const T0: Timestamp = Timestamp::from_micros(1_700_000_000_000_000);
const STAFF: StaffRef = StaffRef([0x5A; 16]);

const fn at(us: i64) -> Timestamp {
    Timestamp::from_micros(T0.micros() + us)
}

fn grant(until: i64) -> BreakGlassGrant {
    BreakGlassGrant {
        staff: STAFF,
        scope: vec![BreakGlassRead::Audit],
        approved_at: T0,
        until: at(until),
        ended: None,
    }
}

/// SoD-08, ADR-008: a tenant admin approves with a step-up, for a
/// non-empty scope and an end at most 4 hours after the approval.
#[test]
fn sod_08_approval_needs_admin_step_up_window_and_scope() {
    assert_eq!(BREAK_GLASS_MAX_US, 4 * HOUR_US);
    let g = grant(BREAK_GLASS_MAX_US);
    assert_eq!(approve_break_glass(true, Ok(()), &g), Ok(()));
    assert_eq!(
        approve_break_glass(false, Ok(()), &g),
        Err(BreakGlassDeny::NotAdmin)
    );
    assert_eq!(
        approve_break_glass(true, Err(StepUpDeny::Required), &g),
        Err(BreakGlassDeny::StepUp(StepUpDeny::Required))
    );
    assert_eq!(
        approve_break_glass(true, Ok(()), &grant(BREAK_GLASS_MAX_US + 1)),
        Err(BreakGlassDeny::Window)
    );
    assert_eq!(
        approve_break_glass(true, Ok(()), &grant(0)),
        Err(BreakGlassDeny::Window)
    );
    let empty = BreakGlassGrant {
        scope: Vec::new(),
        ..g
    };
    assert_eq!(
        approve_break_glass(true, Ok(()), &empty),
        Err(BreakGlassDeny::EmptyScope)
    );
}

/// SoD-08: only the named staff member reads, only in scope, only from
/// the approval to before the end or an early end, and only where a
/// staff key is pinned.
#[test]
fn sod_08_reads_only_by_the_named_staff_in_scope_and_time() {
    check(
        "sod_08_reads_only_by_the_named_staff_in_scope_and_time",
        |g: &mut Gen| {
            let mut gr = grant(10);
            gr.ended = g.option(|g| at(g.i64_in(-2..=12)));
            let read = *g.pick(&[
                BreakGlassRead::Content,
                BreakGlassRead::Audit,
                BreakGlassRead::ErasureLog,
            ]);
            let pinned = g.bool();
            let asserted = g.option(|g| *g.pick(&[STAFF, StaffRef([0; 16])]));
            let now = at(g.i64_in(-2..=12));
            let want = pinned
                && asserted == Some(STAFF)
                && read == BreakGlassRead::Audit
                && T0 <= now
                && now < at(10)
                && gr.ended.is_none_or(|e| now < e);
            prop_assert_eq!(
                admit_break_glass_read(&gr, read, pinned, asserted, now),
                want
            );
            Ok(())
        },
    );
}
