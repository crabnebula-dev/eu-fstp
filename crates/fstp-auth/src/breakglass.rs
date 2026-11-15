//! Break-glass (SoD-08, TH-18, ADR-008 "Break-glass", design section 8.6,
//! interim pending Daniel, Q21).
//!
//! Operator staff hold no binding in any cell. A request names one staff
//! member, a scope of read actions and an end at most 4 hours after the
//! approval. A tenant admin approves it with a step-up. The gate then
//! admits that staff member, and only them, for reads inside the scope
//! and before the end. A break-glass principal is admitted for no command.
//!
//! The staff assertion that names the staff member is verified against a
//! pinned key outside this module. Its byte form and lifetime are not set
//! by the design (ADR-008 open point "Unset lifetimes"), so the caller
//! passes the verified staff member, or `None`.

use fstp_domain::time::Timestamp;

use crate::recovery::StaffRef;
use crate::stepup::StepUpDeny;
use crate::{HOUR_US, within};

/// The longest break-glass grant: 4 hours (ADR-008 constant with no P- id,
/// interim pending Daniel, Q37).
pub const BREAK_GLASS_MAX_US: i64 = 4 * HOUR_US;

/// A read action a break-glass grant may cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BreakGlassRead {
    /// Read content.
    Content,
    /// Read the audit log.
    Audit,
    /// Read the erasure log.
    ErasureLog,
}

/// A break-glass grant: `BreakGlassApproved { grant, staff, scope, until }`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BreakGlassGrant {
    /// The one staff member the request named.
    pub staff: StaffRef,
    /// The read actions it covers.
    pub scope: Vec<BreakGlassRead>,
    /// When a tenant admin approved it.
    pub approved_at: Timestamp,
    /// When it ends.
    pub until: Timestamp,
    /// When `EndBreakGlass` ended it early, if it did.
    pub ended: Option<Timestamp>,
}

/// Why a break-glass approval is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakGlassDeny {
    /// The approver is not a current tenant admin.
    NotAdmin,
    /// The approval has no valid step-up.
    StepUp(StepUpDeny),
    /// The end lies at or before the approval, or more than 4 hours after it.
    Window,
    /// The scope is empty.
    EmptyScope,
}

/// The approval rule (design section 8.6, `ApproveBreakGlass`).
pub fn approve_break_glass(
    approver_admin: bool,
    stepup: Result<(), StepUpDeny>,
    g: &BreakGlassGrant,
) -> Result<(), BreakGlassDeny> {
    if !approver_admin {
        return Err(BreakGlassDeny::NotAdmin);
    }
    stepup.map_err(BreakGlassDeny::StepUp)?;
    if g.until.micros() <= g.approved_at.micros()
        || !within(g.approved_at, g.until, BREAK_GLASS_MAX_US)
    {
        return Err(BreakGlassDeny::Window);
    }
    if g.scope.is_empty() {
        return Err(BreakGlassDeny::EmptyScope);
    }
    Ok(())
}

/// Whether the staff member `asserted` may perform `read` at `now` under
/// `g`.
///
/// `pinned_key` says whether the cell pins a staff assertion key. A
/// self-hosted cell pins none, so it admits no break-glass principal
/// (ADR-008, proposed reading). The grant admits reads before `until`
/// and not at it.
pub fn admit_break_glass_read(
    g: &BreakGlassGrant,
    read: BreakGlassRead,
    pinned_key: bool,
    asserted: Option<StaffRef>,
    now: Timestamp,
) -> bool {
    pinned_key
        && asserted == Some(g.staff)
        && g.scope.contains(&read)
        && g.approved_at.micros() <= now.micros()
        && now.micros() < g.until.micros()
        && g.ended.is_none_or(|e| now.micros() < e.micros())
}

// ---------------------------------------------------------------------------
// Staff assertions (ADR-008 "Break-glass", Daniel, 2026-11-15).

/// The composite signature context of a staff assertion. It differs from
/// every operator ticket context, so no ticket verifies as an assertion.
pub const STAFF_ASSERTION_CONTEXT: &[u8] = b"fstp-staff-assertion-v1";

/// The length of the signed part of a staff assertion.
pub const STAFF_ASSERTION_MESSAGE_LEN: usize = 40;

/// A staff assertion: the control plane states that staff member `staff`
/// acts under break-glass grant `grant`, at `issued_at`. It names the
/// grant and an opaque staff reference only, never an account (I-20).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StaffAssertion {
    /// The break-glass grant.
    pub grant: [u8; 16],
    /// The staff member.
    pub staff: StaffRef,
    /// When the control plane issued it.
    pub issued_at: Timestamp,
}

impl StaffAssertion {
    /// The bytes the control plane signs: `grant || staff ||
    /// issued_at`, the instant as a big-endian `i64` of UTC microseconds.
    pub fn message(&self) -> [u8; STAFF_ASSERTION_MESSAGE_LEN] {
        let mut out = [0u8; STAFF_ASSERTION_MESSAGE_LEN];
        let (grant, rest) = out.split_at_mut(16);
        let (staff, at) = rest.split_at_mut(16);
        grant.copy_from_slice(&self.grant);
        staff.copy_from_slice(&self.staff.0);
        at.copy_from_slice(&self.issued_at.micros().to_be_bytes());
        out
    }
}

/// A staff assertion whose composite signature verified under the pinned
/// key, within its lifetime. Only [`verify_staff_assertion`] builds one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VerifiedStaff {
    assertion: StaffAssertion,
}

impl VerifiedStaff {
    /// The grant the assertion names.
    pub const fn grant(&self) -> [u8; 16] {
        self.assertion.grant
    }

    /// The staff member the assertion names.
    pub const fn staff(&self) -> StaffRef {
        self.assertion.staff
    }
}

/// Why a staff assertion is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaffAssertionDeny {
    /// The cell pins no staff assertion key: a self-hosted cell (ADR-008,
    /// proposed reading).
    NoPinnedKey,
    /// The composite signature did not verify under the pinned key.
    Signature,
    /// The instant lies before the issue or at or after its lifetime.
    Expired,
}

/// Verifies staff assertion `a` with composite signature `signature`
/// under `pinned_key`, the control plane's composite public key, at `now`
/// (ADR-008, I-90). Both halves must verify. It is valid from its issue
/// instant and before `issued_at + lifetime_us`.
pub fn verify_staff_assertion(
    a: &StaffAssertion,
    signature: &[u8],
    pinned_key: Option<&[u8]>,
    now: Timestamp,
    lifetime_us: i64,
) -> Result<VerifiedStaff, StaffAssertionDeny> {
    let Some(key) = pinned_key else {
        return Err(StaffAssertionDeny::NoPinnedKey);
    };
    fstp_crypto::composite::verify_with_context(
        key,
        &a.message(),
        STAFF_ASSERTION_CONTEXT,
        signature,
    )
    .map_err(|_| StaffAssertionDeny::Signature)?;
    let fresh = now
        .micros()
        .checked_sub(a.issued_at.micros())
        .is_some_and(|age| age >= 0 && age < lifetime_us);
    if !fresh {
        return Err(StaffAssertionDeny::Expired);
    }
    Ok(VerifiedStaff { assertion: *a })
}
