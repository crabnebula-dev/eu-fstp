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
#[derive(Clone, Debug, PartialEq, Eq)]
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
