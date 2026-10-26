//! JSON codecs for commands, records and policies (design sections 2.1,
//! 2.3, 2.10, 5.1 and 7). Owned by lane L-CODEC.
//!
//! [`Record`], [`Command`] and [`PolicyVersion`] implement
//! [`fstp_json::ToJson`] and [`fstp_json::FromJson`]. Stored bytes are the
//! RFC 8785 text of the encoding, so the codec gives every value exactly
//! one spelling (I-23, ADR-007):
//!
//! - Every object is decoded against its schema. An unknown member or a
//!   missing member is refused. An optional value is always present, as
//!   `null` when absent.
//! - Ids, `Seq`, vault epochs, timestamps and ratio terms are canonical
//!   decimal strings, because RFC 8785 numbers are exact only up to 2^53.
//!   A leading zero, a sign on an unsigned value, `-0`, space, a fraction
//!   or another base is refused.
//! - Amounts are ADR-006 decimal strings in the currency's fixed scale,
//!   and percentages are two-decimal strings. A record or command that
//!   holds amounts names its currency in a `currency` member. A policy
//!   version names its own currency. JSON numbers are never amounts.
//!   A record with no amount names EUR, and no other code is accepted.
//! - A signed amount never carries a sign. A negative value is written as
//!   `{"shortfall": "<amount>"}` with a positive amount (design 3.7).
//! - Digests and handles are lowercase hexadecimal strings.
//! - Sets are lists in strictly ascending order. Maps are objects keyed by
//!   a canonical id or parameter spelling.
//! - An opaque parameter value is a string holding its RFC 8785 text,
//!   which must already be canonical.
//! - Free text never appears in a record body. It travels as a `TextRef`
//!   of text id and content digest (ADR-007).
//!
//! Decoding is structural. It never runs a guard or a policy check, so a
//! stored record decodes to the record that was appended. The payloads
//! that only a witness builds decode through their crate-private
//! `from_decoded` seams. The witnesses themselves have no codec.
//!
//! Decode errors carry a kind, schema member names and array indices. They
//! never carry input content, such as an unknown member's name or a
//! refused string (R-NF-02). No decode path panics.

mod command;
mod policy;
mod record;
mod types;
mod wire;

#[cfg(test)]
mod tests;

use fstp_json::{FromJson, FromJsonError, Value};
use fstp_ledger::SCHEMA_V1;

use crate::command::Command;
use crate::policy::PolicyVersion;
use crate::record::Record;

/// The record schema versions this build decodes. Version 1 is the only
/// published version. A later version adds an upcast here, and stored bytes
/// are never rewritten (design section 5.1).
pub const PUBLISHED_SCHEMAS: [u16; 1] = [SCHEMA_V1];

/// The schema version that [`fstp_json::ToJson`] writes for a record.
pub const CURRENT_SCHEMA: u16 = SCHEMA_V1;

/// Decodes a record stored under schema version `schema`.
///
/// It refuses a version that is not in [`PUBLISHED_SCHEMAS`]. Version 1
/// decodes as [`FromJson`] does for [`Record`]. Errors hold no input content
/// (R-NF-02).
pub fn record_from_json_at(schema: u16, value: &Value) -> Result<Record, FromJsonError> {
    if !PUBLISHED_SCHEMAS.contains(&schema) {
        return Err(FromJsonError::invalid("unpublished record schema version"));
    }
    Record::from_json(value)
}

/// Decodes a command. The same as [`FromJson`] for [`Command`].
pub fn command_from_json(value: &Value) -> Result<Command, FromJsonError> {
    Command::from_json(value)
}

/// Decodes a policy version. The same as [`FromJson`] for [`PolicyVersion`].
pub fn policy_from_json(value: &Value) -> Result<PolicyVersion, FromJsonError> {
    PolicyVersion::from_json(value)
}
