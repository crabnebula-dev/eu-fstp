//! Break-glass, operator tickets and scheduled session ends (design
//! sections 5.1 and 8.6).
//!
//! Daniel decided on 2026-11-15 ("On the approval record") that a
//! break-glass request's staff member, scope and end enter the ledger on
//! the approval: `ApproveBreakGlass` carries them as the request names
//! them, and `BreakGlassApproved { grant, staff, scope, until }` records
//! them (ADR-008 "Break-glass").

use fstp_auth::breakglass::BreakGlassRead;
use fstp_auth::recovery::StaffRef;
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;

/// An ops command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpsCommand {
    /// Approve break-glass access, as the request names it.
    ApproveBreakGlass {
        /// The request id, which becomes the grant id.
        request: [u8; 16],
        /// The one staff member the request names.
        staff: StaffRef,
        /// The read actions it covers, strictly ascending.
        scope: Vec<BreakGlassRead>,
        /// When it ends: after the approval, and at most 4 hours after.
        until: Timestamp,
    },
    /// End break-glass access.
    EndBreakGlass {
        /// The grant id.
        grant: [u8; 16],
    },
    /// Apply an operator ticket.
    ApplyOperatorTicket {
        /// The ticket, canonical.
        ticket: Vec<u8>,
    },
    /// End the sessions a scheduled binding end ended (system).
    EndSessionsAtBindingEnd {
        /// The account.
        account: AccountId,
    },
    /// Spend the passkey step-up of an agent consent approval
    /// (`agents.consent`, I-78, ADR-026 record of lane L12). Connecting an
    /// agent links a device (`HighRiskAction::LinkDevice`), so the gate
    /// admits it only with a step-up bound to `request_digest`, the API
    /// core's request digest. It records nothing of its own: its batch is
    /// the `StepUpConsumed` record of that step-up, so the step-up approves
    /// one consent only.
    ApproveAgentConsent {
        /// The API core's digest of the approval request.
        request_digest: [u8; 32],
    },
}

/// An ops record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpsRecord {
    /// Break-glass access was approved.
    BreakGlassApproved {
        /// The grant id.
        grant: [u8; 16],
        /// The one staff member it admits.
        staff: StaffRef,
        /// The read actions it covers, strictly ascending.
        scope: Vec<BreakGlassRead>,
        /// When it ends.
        until: Timestamp,
    },
    /// Break-glass access ended.
    BreakGlassEnded {
        /// The grant id.
        grant: [u8; 16],
    },
    /// A staff member read under a break-glass grant (SoD-08: every use
    /// is logged). The grant names the staff member.
    BreakGlassRead {
        /// The grant id.
        grant: [u8; 16],
        /// The read action.
        read: BreakGlassRead,
    },
}

/// Whether `scope` is strictly ascending: sorted, with no read twice. A
/// recorded scope has one form, so its canonical bytes are unique.
pub fn scope_is_canonical(scope: &[BreakGlassRead]) -> bool {
    scope.windows(2).all(|w| matches!(w, [a, b] if a < b))
}
