//! Attestation objects (WebAuthn Level 2 section 6.5, ADR-008
//! "Attestation").
//!
//! The object is one strict CBOR map of exactly `fmt`, `attStmt` and
//! `authData`, in any order. ADR-008 admits the format `none` only, and
//! no attestation statement is parsed or trusted, so `attStmt` must be
//! the empty map. Any other member, such as `ep` or `largeBlobKey`, is
//! refused.

use crate::cbor::{self, Item};
use crate::{WebAuthnError, auth_data};

/// Parses an attestation object, with its authenticator data in full.
/// Fuzzed (`attestation_object_decode`).
pub(crate) fn parse(b: &[u8]) -> Result<auth_data::Parsed, WebAuthnError> {
    let Item::Map(pairs) = cbor::decode(b)? else {
        return Err(WebAuthnError::AttestationObject);
    };
    let mut fmt = None;
    let mut stmt = None;
    let mut data = None;
    for (k, v) in &pairs {
        // The CBOR decoder refuses a repeated key, so each slot fills once.
        let slot = match k {
            Item::Text(name) if name == "fmt" => &mut fmt,
            Item::Text(name) if name == "attStmt" => &mut stmt,
            Item::Text(name) if name == "authData" => &mut data,
            _ => return Err(WebAuthnError::AttestationObject),
        };
        *slot = Some(v);
    }
    let (Some(fmt), Some(stmt), Some(data)) = (fmt, stmt, data) else {
        return Err(WebAuthnError::AttestationObject);
    };
    match fmt {
        Item::Text(f) if f == "none" => {}
        Item::Text(_) => return Err(WebAuthnError::AttestationFormat),
        _ => return Err(WebAuthnError::AttestationObject),
    }
    match stmt {
        Item::Map(m) if m.is_empty() => {}
        _ => return Err(WebAuthnError::AttestationFormat),
    }
    let Item::Bytes(ad) = data else {
        return Err(WebAuthnError::AttestationObject);
    };
    auth_data::parse(ad)
}
