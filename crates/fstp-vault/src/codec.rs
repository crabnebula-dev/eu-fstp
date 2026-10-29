//! The codecs of the vault service (design sections 4.3 and 6.5, ADR-009
//! "Vault origin").
//!
//! - An origin write is canonical JSON `{"body":<object>,"ticket":"<hex>"}`.
//!   The ticket is the signed ticket in lowercase hex, as the loader script
//!   reads it from the URL fragment. The body is the canonical fact body of
//!   the write. [`decode_origin_write`] only frames the request. It reads
//!   no ticket claim and does not interpret the body, since the signature
//!   is checked before any other field is used.
//! - A stored fact body (`vault.fact.body` before sealing) is canonical
//!   JSON `{"fields":<object>,"kind":<code>}`, with lane W1c's kind codes.

use fstp_json::Value;
use fstp_vault_core::{Fact, decode_fact, fact::fact_from_value};
use fstp_vault_proto::json::{self, parse_canonical};
use fstp_vault_proto::{MAX_TICKET_LEN, ProtoError};

use crate::VaultError;

/// The largest origin write request, in bytes: the largest body limit of
/// any write kind, plus the ticket in hex and the frame.
pub const MAX_ORIGIN_WRITE_LEN: usize = (64 << 10) + 2 * MAX_TICKET_LEN + 64;

/// A write that arrives on the vault origin (design section 6.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginWrite {
    /// The ticket bytes.
    pub ticket: Vec<u8>,
    /// The body bytes: the canonical fact body.
    pub body: Vec<u8>,
}

/// A stored fact body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactBody {
    /// The fact kind.
    pub kind: u16,
    /// The canonical fields.
    pub fields: Vec<u8>,
}

const ORIGIN: &str = "origin write";
const STORED: &str = "stored fact body";

fn limits() -> fstp_json::ParseLimits {
    fstp_vault_proto::json::limits().with_max_input_bytes(MAX_ORIGIN_WRITE_LEN)
}

fn malformed(_: ProtoError) -> VaultError {
    VaultError::Malformed(ORIGIN)
}

/// Decodes an origin write. Fuzzed (`origin_write_decode`). It frames the
/// request only: the ticket signature is checked before any field of the
/// ticket or the body is used.
///
/// # Errors
///
/// [`VaultError::Malformed`] for any spelling other than the canonical
/// frame, an empty or odd ticket, or a body that is not an object.
pub fn decode_origin_write(bytes: &[u8]) -> Result<OriginWrite, VaultError> {
    let v = parse_canonical(bytes, &limits()).map_err(malformed)?;
    let o = json::object(&v, &["body", "ticket"], ORIGIN).map_err(malformed)?;
    let body = json::member(o, "body", ORIGIN).map_err(malformed)?;
    if body.as_object().is_none() {
        return Err(VaultError::Malformed(ORIGIN));
    }
    let ticket = json::unhex(
        json::string(o, "ticket", ORIGIN).map_err(malformed)?,
        ORIGIN,
    )
    .map_err(malformed)?;
    if ticket.is_empty() || ticket.len() > MAX_TICKET_LEN {
        return Err(VaultError::Malformed(ORIGIN));
    }
    Ok(OriginWrite {
        ticket,
        body: json::to_canonical(body).map_err(malformed)?,
    })
}

/// Encodes an origin write, as the loader script sends it.
///
/// # Errors
///
/// [`VaultError::Malformed`] when the body is not a canonical object or
/// the ticket is empty or too long.
pub fn encode_origin_write(w: &OriginWrite) -> Result<Vec<u8>, VaultError> {
    if w.ticket.is_empty() || w.ticket.len() > MAX_TICKET_LEN {
        return Err(VaultError::Malformed(ORIGIN));
    }
    let body = parse_canonical(&w.body, &limits()).map_err(malformed)?;
    if body.as_object().is_none() {
        return Err(VaultError::Malformed(ORIGIN));
    }
    let v = json::obj(vec![
        ("body", body),
        ("ticket", Value::String(json::hex(&w.ticket))),
    ])
    .map_err(malformed)?;
    json::to_canonical(&v).map_err(malformed)
}

/// Decodes a stored fact body. Fuzzed (`fact_body_decode`). A stored body
/// is decoded after unsealing, so a refusal means a corrupt row, and the
/// caller fails closed (NOTE 2).
///
/// # Errors
///
/// [`VaultError::Malformed`] for any spelling other than the canonical
/// frame, an unknown kind, or fields that are not the kind's canonical
/// fields.
pub fn decode_fact_body(bytes: &[u8]) -> Result<FactBody, VaultError> {
    let bad = |_: ProtoError| VaultError::Malformed(STORED);
    let v = parse_canonical(bytes, &fstp_vault_proto::json::limits()).map_err(bad)?;
    let o = json::object(&v, &["fields", "kind"], STORED).map_err(bad)?;
    let kind = json::small(o, "kind", STORED).map_err(bad)?;
    let fields = json::member(o, "fields", STORED).map_err(bad)?;
    fact_from_value(kind, fields).map_err(bad)?;
    Ok(FactBody {
        kind,
        fields: json::to_canonical(fields).map_err(bad)?,
    })
}

/// The stored body of `fact`.
///
/// # Errors
///
/// [`VaultError::Malformed`] when the fact has no canonical body.
pub fn encode_fact_body(fact: &Fact) -> Result<Vec<u8>, VaultError> {
    let bad = |_: ProtoError| VaultError::Malformed(STORED);
    let v = json::obj(vec![
        ("fields", fact.body_value().map_err(bad)?),
        (
            "kind",
            json::uint_json(u64::from(fact.kind()), STORED).map_err(bad)?,
        ),
    ])
    .map_err(bad)?;
    json::to_canonical(&v).map_err(bad)
}

/// The fact a stored body holds.
///
/// # Errors
///
/// As [`decode_fact_body`].
pub fn stored_fact(bytes: &[u8]) -> Result<Fact, VaultError> {
    let b = decode_fact_body(bytes)?;
    decode_fact(b.kind, &b.fields).map_err(|_| VaultError::Malformed(STORED))
}
