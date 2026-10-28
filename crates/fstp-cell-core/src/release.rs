//! Release and write tickets for the vault origin (design sections 6.5 and
//! 6.8, I-17).

/// A release command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseCommand {
    /// Issue a release ticket.
    IssueReleaseTicket {
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
    /// A ticket was issued.
    TicketIssued {
        /// The ticket id.
        id: [u8; 16],
    },
}
