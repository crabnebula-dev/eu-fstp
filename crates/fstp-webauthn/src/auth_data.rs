//! Authenticator data (WebAuthn Level 2 section 6.1).
//!
//! The layout is the SHA-256 of the RP id (32 bytes), the flags (1 byte)
//! and the signature counter (4 bytes, big-endian). The attested
//! credential data follows when AT is set: the AAGUID (16 bytes), the
//! credential id length (2 bytes, big-endian), the credential id and the
//! COSE key. A CBOR map of extensions follows when ED is set. The parser
//! reads all of it and refuses any rest.
//!
//! The parser reports the flags as given. The verifiers decide which
//! flags a ceremony needs. The reserved bits 0x02 and 0x20 are not
//! refused, since WebAuthn asks relying parties to ignore them.

use crate::cbor::{self, Item};
use crate::{AuthenticatorData, CoseKey, WebAuthnError, cose, flags};

/// The fixed part: RP id hash, flags and counter.
const FIXED_LEN: usize = 37;
/// The AAGUID length.
const AAGUID_LEN: usize = 16;
/// The longest credential id (WebAuthn Level 3 section 6.5.1). An empty
/// id names no credential and is refused as well.
pub(crate) const MAX_CREDENTIAL_ID: usize = 1023;

/// Attested credential data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Attested {
    /// The credential id.
    pub(crate) id: Vec<u8>,
    /// The credential public key.
    pub(crate) key: CoseKey,
}

/// Authenticator data with its attested credential data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Parsed {
    /// The fixed fields.
    pub(crate) data: AuthenticatorData,
    /// The attested credential data, present exactly when AT is set.
    pub(crate) attested: Option<Attested>,
}

/// Parses authenticator data. Fuzzed (`authenticator_data_decode`).
pub(crate) fn parse(b: &[u8]) -> Result<Parsed, WebAuthnError> {
    if b.len() > cbor::MAX_INPUT {
        return Err(WebAuthnError::AuthenticatorData);
    }
    let (fixed, mut rest) = b
        .split_at_checked(FIXED_LEN)
        .ok_or(WebAuthnError::AuthenticatorData)?;
    let (hash, tail) = fixed
        .split_first_chunk::<32>()
        .ok_or(WebAuthnError::AuthenticatorData)?;
    let (&flag_bits, count) = tail.split_first().ok_or(WebAuthnError::AuthenticatorData)?;
    let count: [u8; 4] = count
        .try_into()
        .map_err(|_| WebAuthnError::AuthenticatorData)?;
    let data = AuthenticatorData {
        rp_id_hash: *hash,
        flags: flag_bits,
        sign_count: u32::from_be_bytes(count),
    };

    let attested = if flag_bits & flags::AT != 0 {
        let (a, after) = attested(rest)?;
        rest = after;
        Some(a)
    } else {
        None
    };

    if flag_bits & flags::ED != 0 {
        let (ext, used) =
            cbor::decode_prefix(rest).map_err(|_| WebAuthnError::AuthenticatorData)?;
        if !matches!(ext, Item::Map(_)) {
            return Err(WebAuthnError::AuthenticatorData);
        }
        rest = rest.get(used..).ok_or(WebAuthnError::AuthenticatorData)?;
    }

    if !rest.is_empty() {
        return Err(WebAuthnError::AuthenticatorData);
    }
    Ok(Parsed { data, attested })
}

/// Reads attested credential data from the front of `b`, and returns it
/// with the bytes after it.
fn attested(b: &[u8]) -> Result<(Attested, &[u8]), WebAuthnError> {
    let (_aaguid, rest) = b
        .split_at_checked(AAGUID_LEN)
        .ok_or(WebAuthnError::AuthenticatorData)?;
    let (len, rest) = rest
        .split_first_chunk::<2>()
        .ok_or(WebAuthnError::AuthenticatorData)?;
    let len = usize::from(u16::from_be_bytes(*len));
    if len == 0 || len > MAX_CREDENTIAL_ID {
        return Err(WebAuthnError::CredentialId);
    }
    let (id, rest) = rest
        .split_at_checked(len)
        .ok_or(WebAuthnError::AuthenticatorData)?;
    let (item, used) = cbor::decode_prefix(rest)?;
    let key = cose::from_item(&item)?;
    let rest = rest.get(used..).ok_or(WebAuthnError::AuthenticatorData)?;
    Ok((
        Attested {
            id: id.to_vec(),
            key,
        },
        rest,
    ))
}
