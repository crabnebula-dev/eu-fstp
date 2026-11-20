//! The durable records of the authorisation server, and the journal of
//! their changes (ADR-013 amendment of 2026-11-20, lane L2).
//!
//! The server stays sans-IO. A shell that persists it turns the journal
//! on ([`crate::AuthorizationServer::with_journal`]), takes the changes of
//! each endpoint call ([`crate::AuthorizationServer::take_changes`]) and
//! writes them in one transaction before it sends the reply. At start it
//! reads its rows back into [`Records`] and calls
//! [`crate::AuthorizationServer::restore`].
//!
//! Durable: clients, refresh families, and the hash of every refresh token
//! a family issued, current and retired, so reuse is still detected after
//! a restart (TH-61). In memory only: pending consents, codes, access
//! tokens and registration counts. A restart burns them, which fails
//! closed.
//!
//! No record holds a token, a code or a consent handle. A refresh token is
//! held as its labelled SHA-256 only (ADR-013 "Token storage"). An account
//! is held by its raw id only (I-86).

use crate::scope::ScopeSet;
use crate::server::{Account, ClientNumber, LoginMethod, Micros};

/// A registered client.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientRecord {
    /// The cell's number for the client.
    pub number: ClientNumber,
    /// The `client_id`: 16 random bytes as 22 characters of base64url.
    pub client_id: String,
    /// The registration metadata as the server keeps it: RFC 7591 JSON
    /// with `redirect_uris` and, when given, `client_name`. The client
    /// name is untrusted text, so a shell stores these bytes sealed.
    pub metadata: Vec<u8>,
    /// When it registered.
    pub registered: Micros,
}

impl std::fmt::Debug for ClientRecord {
    /// The number only: no metadata, which holds untrusted text.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientRecord")
            .field("number", &self.number)
            .field("registered", &self.registered)
            .finish_non_exhaustive()
    }
}

/// A refresh family: one consent's grant, from the redemption of its code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyRecord {
    /// The family id, unique in the cell.
    pub id: u64,
    /// The client's number.
    pub client: ClientNumber,
    /// The account that consented.
    pub account: Account,
    /// The scopes it was granted.
    pub scopes: ScopeSet,
    /// When it started: the redemption of its code.
    pub start: Micros,
    /// When it ends at the latest (P-72).
    pub end: Micros,
    /// The hash of its current refresh token.
    pub current: [u8; 32],
    /// How many refreshes it made.
    pub refreshes: u32,
    /// Whether it is revoked.
    pub revoked: bool,
    /// How the session that consented logged in.
    pub method: LoginMethod,
    /// The server's change counter at this state. A stored row is replaced
    /// only by a record with a higher version, so two calls that commit out
    /// of order leave the later state.
    pub version: u64,
}

/// The hash of one refresh token a family issued, current or retired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefreshHash {
    /// The labelled SHA-256 of the token.
    pub hash: [u8; 32],
    /// The family that issued it.
    pub family: u64,
}

/// One change of the durable records, in the order the server made it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// A client registered. A client never changes after that.
    Client(ClientRecord),
    /// A client was dropped by `purge`, with no family left.
    ClientDropped(ClientNumber),
    /// A family started or changed: insert it, or replace a stored row of
    /// a lower version.
    Family(FamilyRecord),
    /// A family was dropped, with its refresh hashes.
    FamilyDropped(u64),
    /// A family issued a refresh token. A hash never changes.
    Refresh(RefreshHash),
}

/// Every durable record of a server.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Records {
    /// The clients.
    pub clients: Vec<ClientRecord>,
    /// The families.
    pub families: Vec<FamilyRecord>,
    /// The refresh hashes.
    pub refresh: Vec<RefreshHash>,
}

/// A server restored from its records.
#[derive(Debug)]
pub struct Restored {
    /// The server.
    pub server: crate::AuthorizationServer,
    /// How many records it dropped because they did not hold: a client
    /// whose metadata does not decode, a family of no restored client, or
    /// a refresh hash of no restored family. Dropping a record ends its
    /// grant, which fails closed.
    pub dropped: usize,
}

/// The view of a pending consent that the consent page shows (ADR-013
/// amendment of 2026-11-20, `agents.consent_request`). It names no
/// account, no handle and no digest (I-86).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentView {
    /// The client's number.
    pub client: ClientNumber,
    /// The client name, untrusted and unverified.
    pub client_name: Option<String>,
    /// The host of the redirect URI.
    pub redirect_host: String,
    /// Whether the redirect goes to a loopback host on the user's device.
    pub loopback_redirect: bool,
    /// The scopes asked for.
    pub scopes: ScopeSet,
    /// When the consent expires.
    pub expires: Micros,
}

/// Decides whether a grant still holds against facts the server does not
/// keep, such as the account's last completed recovery (I-79, H-21).
pub trait GrantGuard {
    /// Whether a grant of `account` that began at `since` is refused: a
    /// code issued then, or a family started then.
    fn refused(&self, account: Account, since: Micros) -> bool;
}

/// The guard that refuses nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoGuard;

impl GrantGuard for NoGuard {
    fn refused(&self, _account: Account, _since: Micros) -> bool {
        false
    }
}
