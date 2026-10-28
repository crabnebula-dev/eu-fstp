//! Break-glass, operator tickets and scheduled session ends (design
//! sections 5.1 and 8.6).

use fstp_domain::id::AccountId;

/// An ops command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpsCommand {
    /// Approve break-glass access.
    ApproveBreakGlass {
        /// The request id.
        request: [u8; 16],
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
}

/// An ops record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpsRecord {
    /// Break-glass access was approved.
    BreakGlassApproved {
        /// The grant id.
        grant: [u8; 16],
    },
    /// Break-glass access ended.
    BreakGlassEnded {
        /// The grant id.
        grant: [u8; 16],
    },
}
