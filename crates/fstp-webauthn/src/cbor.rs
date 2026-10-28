//! The strict CBOR subset: definite lengths, shortest forms, no duplicate
//! map keys, bounded depth and size.

use crate::WebAuthnError;

/// A decoded CBOR item of the subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    /// An unsigned integer.
    Unsigned(u64),
    /// A negative integer, as `-1 - n`.
    Negative(u64),
    /// A byte string.
    Bytes(Vec<u8>),
    /// A text string.
    Text(String),
    /// An array.
    Array(Vec<Item>),
    /// A map, in encoded order.
    Map(Vec<(Item, Item)>),
}

/// Decodes exactly one item from `b`. Fuzzed (`cbor_decode`).
pub fn decode(b: &[u8]) -> Result<Item, WebAuthnError> {
    let _ = b;
    Err(WebAuthnError::NotImplemented("fstp_webauthn::cbor::decode"))
}
