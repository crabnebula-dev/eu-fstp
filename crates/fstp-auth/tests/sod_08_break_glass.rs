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

/// SoD-08, ADR-008 "Break-glass" (Daniel, 2026-11-15): a staff assertion
/// verifies only under the pinned control-plane key, in its own context,
/// for the grant, staff member and instant it signs, and only within its
/// lifetime. A cell that pins no key admits no staff assertion.
#[test]
fn sod_08_staff_assertion_needs_the_pinned_key_and_its_lifetime() {
    use fstp_auth::breakglass::{
        STAFF_ASSERTION_CONTEXT, StaffAssertion, StaffAssertionDeny, verify_staff_assertion,
    };
    const LIFE: i64 = 15 * 60 * 1_000_000;
    let key = fstp_crypto::composite::generate().unwrap();
    let other = fstp_crypto::composite::generate().unwrap();
    let pin = key.public_key().to_bytes();
    let a = StaffAssertion {
        grant: [0xB6; 16],
        staff: STAFF,
        issued_at: T0,
    };
    let sign = |k: &fstp_crypto::composite::CompositeSigningKey, ctx: &[u8], m: &[u8]| {
        k.sign_with_context(m, ctx).unwrap().to_bytes()
    };
    let good = sign(&key, STAFF_ASSERTION_CONTEXT, &a.message());
    let v = verify_staff_assertion(&a, &good, Some(&pin[..]), at(1), LIFE).unwrap();
    assert_eq!(v.grant(), a.grant);
    assert_eq!(v.staff(), STAFF);
    assert_eq!(
        verify_staff_assertion(&a, &good, Some(&pin[..]), T0, LIFE).map(|v| v.staff()),
        Ok(STAFF),
        "at the issue instant"
    );
    assert_eq!(
        verify_staff_assertion(&a, &good, None, at(1), LIFE).err(),
        Some(StaffAssertionDeny::NoPinnedKey)
    );
    let unpinned = sign(&other, STAFF_ASSERTION_CONTEXT, &a.message());
    assert_eq!(
        verify_staff_assertion(&a, &unpinned, Some(&pin[..]), at(1), LIFE).err(),
        Some(StaffAssertionDeny::Signature)
    );
    let wrong_context = sign(&key, b"fstp-operator-ticket-break-glass-v1", &a.message());
    assert_eq!(
        verify_staff_assertion(&a, &wrong_context, Some(&pin[..]), at(1), LIFE).err(),
        Some(StaffAssertionDeny::Signature)
    );
    for changed in [
        StaffAssertion {
            grant: [0xB7; 16],
            ..a
        },
        StaffAssertion {
            staff: StaffRef([0x5B; 16]),
            ..a
        },
        StaffAssertion {
            issued_at: at(1),
            ..a
        },
    ] {
        assert_eq!(
            verify_staff_assertion(&changed, &good, Some(&pin[..]), at(1), LIFE).err(),
            Some(StaffAssertionDeny::Signature),
            "{changed:?}"
        );
    }
    assert_eq!(
        verify_staff_assertion(&a, &good, Some(&pin[..]), at(LIFE), LIFE).err(),
        Some(StaffAssertionDeny::Expired),
        "at the end of its lifetime"
    );
    assert_eq!(
        verify_staff_assertion(&a, &good, Some(&pin[..]), at(-1), LIFE).err(),
        Some(StaffAssertionDeny::Expired),
        "before its issue"
    );
}
