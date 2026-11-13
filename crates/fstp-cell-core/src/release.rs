//! Release and write tickets for the vault origin (design sections 6.5 and
//! 6.8, I-17).

use fstp_domain::id::AccountId;

/// A release command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseCommand {
    /// Issue a release ticket.
    IssueReleaseTicket {
        /// The proposal.
        proposal: u128,
    },
    /// Issue a release ticket with the download scope: the released
    /// fields may be saved as a file. It is the high-risk action
    /// `IdentityDownload` (ADR-008, ADR-009 "Releases", design sections 6.5
    /// and 8.7), so it is a command of its own and the gate asks for a
    /// step-up by its kind.
    IssueDownloadTicket {
        /// The proposal.
        proposal: u128,
    },
    /// Issue a write ticket.
    IssueWriteTicket {
        /// The write kind.
        kind: u16,
    },
    /// Record a relationship (system).
    RecordRelationship {
        /// The relationship, canonical.
        relationship: Vec<u8>,
    },
}

/// A release record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseRecord {
    /// A write ticket was issued. It names its kind, the proposal it
    /// writes for and the account it was issued to, so the issue is
    /// logged as the release ticket is (design section 6.5).
    TicketIssued {
        /// The ticket id.
        id: [u8; 16],
        /// The write kind (ADR-009 "Write kinds").
        kind: u16,
        /// The proposal the write is for.
        proposal: u128,
        /// The account the ticket was issued to.
        holder: AccountId,
    },
    /// A release ticket for the identity attributes of a proposal was
    /// issued, so the read is logged with who asked for it and for which
    /// proposal (R-AU-01, design section 6.5, ADR-009).
    ///
    /// The view scope. A download is `IdentityDownloadIssued`.
    IdentityReleaseIssued {
        /// The ticket id.
        id: [u8; 16],
        /// The proposal whose identity attributes the ticket releases.
        proposal: u128,
        /// The account the ticket was issued to.
        by: AccountId,
    },
    /// A release ticket with the download scope was issued
    /// (`IssueDownloadTicket`). It names the proposal and the account, as
    /// `IdentityReleaseIssued` does, and its kind names the scope, so the
    /// log tells a download from a view (R-AU-01, design section 6.5).
    IdentityDownloadIssued {
        /// The ticket id.
        id: [u8; 16],
        /// The proposal whose identity attributes the ticket releases.
        proposal: u128,
        /// The account the ticket was issued to.
        by: AccountId,
    },
}
