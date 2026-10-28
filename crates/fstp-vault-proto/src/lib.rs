//! Identity vault wire types, tickets and codecs (M3 design section 6.2).
//!
//! The crate has its own id newtypes and no `fstp-domain` dependency
//! (layering rule 2).
//!
//! Status: W0 stub. Lane W2d fills the crate. Every decoder refuses with
//! [`ProtoError::NotImplemented`].

/// An account, by its vault-side id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WireAccount(pub u128);

/// A proposal, by id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WireProposal(pub u128);

/// A programme, by id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WireProgramme(pub u128);

/// A query of the oracle, encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireQuery {
    /// The query kind.
    pub kind: u16,
    /// The query arguments, canonical.
    pub args: Vec<u8>,
}

/// A relationship the cell records in the vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelationshipKind {
    /// A declared conflict of interest.
    Conflict,
}

/// A request from the cell to its vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultRequest {
    /// Ask for the current epoch.
    Epoch,
    /// Ask queries.
    Ask {
        /// UTC microseconds.
        at: u64,
        /// The epoch of a reaction, if this asks for one.
        reaction_for: Option<u64>,
        /// The queries.
        queries: Vec<WireQuery>,
    },
    /// Acknowledge a reaction (NOTE 4).
    Ack {
        /// The epoch.
        epoch: u64,
        /// The ledger sequence of the reaction.
        ledger_seq: u64,
        /// The chain link of the reaction.
        link: [u8; 32],
    },
    /// A proposal entered negotiation.
    NegotiationOpened {
        /// The proposal.
        proposal: WireProposal,
        /// Its accounts.
        accounts: Vec<WireAccount>,
        /// The ledger sequence.
        ledger_seq: u64,
    },
    /// A proposal left negotiation.
    NegotiationClosed {
        /// The proposal.
        proposal: WireProposal,
        /// The ledger sequence.
        ledger_seq: u64,
    },
    /// Record a relationship between two accounts.
    RecordRelationship {
        /// The first account.
        a: WireAccount,
        /// The second account.
        b: WireAccount,
        /// The kind.
        kind: RelationshipKind,
        /// The programme.
        programme: WireProgramme,
        /// The ledger sequence.
        ledger_seq: u64,
    },
}

/// One answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireAnswer {
    /// Whether the queried fact holds.
    pub holds: bool,
    /// The accounts, only for the queries that return them.
    pub accounts: Option<Vec<WireAccount>>,
    /// The epoch the answer is at.
    pub epoch: u64,
}

/// Why the vault refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultRefusal {
    /// A provisional epoch waits for its acknowledgement.
    Pending {
        /// The provisional epoch.
        epoch: u64,
    },
    /// The request named an old epoch.
    StaleEpoch {
        /// The current epoch.
        current: u64,
    },
    /// The request is for another cell.
    NotThisCell,
    /// The request did not decode.
    Malformed,
    /// The vault is unavailable.
    Unavailable,
}

/// A response of the vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultResponse {
    /// The current epoch.
    Epoch(u64),
    /// Answers, in query order.
    Answers(Vec<WireAnswer>),
    /// The acknowledgement was recorded.
    Acked,
    /// The vault refused.
    Refused(VaultRefusal),
}

/// A release or write ticket for the vault origin (design section 6.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    /// The ticket bytes, signed by the cell.
    pub bytes: Vec<u8>,
}

/// Why a message did not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtoError {
    /// The codec is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// Decodes a request. Fuzzed (`vault_request_decode`).
pub fn decode_request(bytes: &[u8]) -> Result<VaultRequest, ProtoError> {
    let _ = bytes;
    Err(ProtoError::NotImplemented(
        "fstp_vault_proto::decode_request",
    ))
}

/// Decodes a response. Fuzzed (`vault_response_decode`).
pub fn decode_response(bytes: &[u8]) -> Result<VaultResponse, ProtoError> {
    let _ = bytes;
    Err(ProtoError::NotImplemented(
        "fstp_vault_proto::decode_response",
    ))
}

/// Decodes a ticket. Fuzzed (`ticket_decode`).
pub fn decode_ticket(bytes: &[u8]) -> Result<Ticket, ProtoError> {
    let _ = bytes;
    Err(ProtoError::NotImplemented(
        "fstp_vault_proto::decode_ticket",
    ))
}
