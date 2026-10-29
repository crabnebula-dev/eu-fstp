//! Shared helpers of the `fstp-vault` test binaries.
//!
//! - [`vc`]: the vault-core helpers (fact writes, tickets, signers), so
//!   the service tests use the same spellings as the core tests.
//! - [`origin_write`] and [`fact_body`]: the reference encodings of the
//!   vault origin's write body and of a stored fact body.
//! - [`Origin`]: one adapter over the vault origin. The W0 stub has no
//!   origin handler, so every call returns [`Fail::Stub`] with
//!   [`ORIGIN_SEAM`] until lane W2d lands one. Only this file changes then.
//!
//! The encodings, proposed by the W2d test author:
//!
//! - An origin write is canonical JSON `{"body":<object>,"ticket":"<hex>"}`.
//!   The ticket is the signed ticket of ADR-009 in lowercase hex, as the
//!   loader script reads it from the URL fragment. The body is the write's
//!   canonical fields, W1c's fact body of the ticket's kind.
//! - A stored fact body (`vault.fact.body` before sealing) is canonical
//!   JSON `{"fields":<object>,"kind":<code>}`, with W1c's kind codes.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "a shared test module: each test binary uses part of it"
)]

#[path = "../../../fstp-vault-core/tests/common/mod.rs"]
pub mod vc;

use std::fmt;

pub use vc::wire;

/// The reference bytes of an origin write.
pub fn origin_write(ticket: &[u8], body: &str) -> Vec<u8> {
    format!("{{\"body\":{body},\"ticket\":\"{}\"}}", wire::hex(ticket)).into_bytes()
}

/// The reference bytes of a stored fact body.
pub fn fact_body(kind: u16, fields: &str) -> Vec<u8> {
    format!("{{\"fields\":{fields},\"kind\":{kind}}}").into_bytes()
}

/// Why the vault origin refused a request. The names follow W1c's
/// `reference::vault::TicketRefusal`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The bytes do not decode.
    Malformed,
    /// No pinned key verifies the ticket signature.
    BadSignature,
    /// The ticket names another cell.
    ForeignCell,
    /// The ticket kind does not match the route or the write.
    WrongKind,
    /// Outside the validity window or too long.
    Expired,
    /// The ticket was used before.
    Replayed,
    /// No negotiation fact lists the release subject.
    NoNegotiationFact,
}

/// Why an adapter call did not give the outcome a test wanted.
#[derive(Clone, PartialEq, Eq)]
pub enum Fail {
    /// The origin refused.
    Refused(Refusal),
    /// The W0 stub or a missing API. Red for the right reason.
    Stub(String),
    /// The origin answered, but not as the test expected.
    Unexpected(String),
}

impl fmt::Debug for Fail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fail::Refused(r) => write!(f, "refused: {r:?}"),
            Fail::Stub(s) => write!(f, "{s} (NotImplemented)"),
            Fail::Unexpected(s) => write!(f, "unexpected: {s}"),
        }
    }
}

/// The refusal of `r`, or the stub outcome, or an unexpected answer.
pub fn refusal<T: fmt::Debug>(r: Result<T, Fail>) -> Result<Refusal, Fail> {
    match r {
        Err(Fail::Refused(v)) => Ok(v),
        Err(other) => Err(other),
        Ok(v) => Err(Fail::Unexpected(format!(
            "answered {v:?}, a refusal was due"
        ))),
    }
}

/// The seam of the vault origin.
pub const ORIGIN_SEAM: &str = "fstp_vault has no vault origin handler: no POST /w or POST /r over a provisioned vault with pinned ticket keys, a used-ticket set and response headers (design section 6.5, ADR-009, lane W2d)";

/// The seam of the identity match key.
pub const MATCH_KEY_SEAM: &str = "fstp_vault has no match key function over a cell's Match key and a method's attribute tuple (design section 6.4, Q17, lane W2d)";

/// One HTTP response of the vault origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The headers, lowercase names.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    /// The values of header `name`.
    pub fn header(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

/// What a write did: the epoch it became provisional at, or none when it
/// queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Written {
    /// The provisional epoch, if the write opened one.
    pub epoch: Option<u64>,
}

/// The vault origin of one cell, provisioned with a cell id and the pinned
/// ticket keys.
#[derive(Debug)]
pub struct Origin {
    /// The vault service, sans I/O.
    pub vault: fstp_vault::Vault,
}

fn origin_refusal(r: fstp_vault::OriginRefusal) -> Fail {
    use fstp_vault::OriginRefusal as O;
    Fail::Refused(match r {
        O::Malformed | O::TooLarge => Refusal::Malformed,
        O::BadSignature => Refusal::BadSignature,
        O::ForeignCell => Refusal::ForeignCell,
        O::WrongKind => Refusal::WrongKind,
        O::NotYetValid | O::Expired | O::TooLong => Refusal::Expired,
        O::Replayed => Refusal::Replayed,
        O::NoNegotiationFact => Refusal::NoNegotiationFact,
        O::Unprovisioned | O::Unavailable => {
            return Fail::Unexpected(format!("the origin refused with {r:?}"));
        }
    })
}

impl Origin {
    /// A provisioned origin.
    pub fn new(cell: [u8; 16], pinned: &[[u8; 32]]) -> Result<Origin, Fail> {
        fstp_vault::Vault::new(cell, pinned)
            .map(|vault| Origin { vault })
            .map_err(|e| Fail::Unexpected(format!("provisioning refused: {e:?}")))
    }

    /// `POST /w` with `bytes` at `now`.
    pub fn post_write(&mut self, bytes: &[u8], now: i64) -> Result<Written, Fail> {
        self.vault
            .post_write(bytes, now)
            .map(|w| Written { epoch: w.epoch })
            .map_err(origin_refusal)
    }

    /// `POST /r` with the signed ticket `ticket` at `now`. The response
    /// renders the released fields.
    pub fn post_release(&mut self, ticket: &[u8], now: i64) -> Result<Response, Fail> {
        self.vault
            .post_release(ticket, now)
            .map(|r| Response {
                status: r.status,
                headers: r
                    .headers
                    .into_iter()
                    .map(|(n, v)| (n.to_owned(), v))
                    .collect(),
                body: r.body,
            })
            .map_err(origin_refusal)
    }

    /// Records the negotiation fact for `proposal` (internal API).
    pub fn negotiation_opened(&mut self, proposal: u128, accounts: &[u128]) -> Result<(), Fail> {
        let set = accounts
            .iter()
            .map(|a| fstp_vault_proto::WireAccount(*a))
            .collect();
        self.vault
            .negotiation_opened(fstp_vault_proto::WireProposal(proposal), &set, 1)
            .map_err(|e| Fail::Unexpected(format!("negotiation fact refused: {e:?}")))
    }
}

/// The identity match key of `tuple` under the cell Match key `key`
/// (design section 6.4, Q17).
pub fn match_key(key: &[u8; 32], tuple: &[u8]) -> Result<[u8; 32], Fail> {
    Ok(fstp_vault::match_key(key, tuple))
}
