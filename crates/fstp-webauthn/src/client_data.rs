//! Client data JSON (WebAuthn Level 2 section 5.8.1), read through
//! `fstp-json`.
//!
//! The text must be one JSON object under the I-JSON rules of
//! `fstp-json`, so a repeated member is refused. `type`, `challenge` and
//! `origin` must be strings. `crossOrigin`, when present, must be a
//! boolean. Browsers add other members, so unknown members are not
//! refused. The challenge has one spelling, unpadded base64url (RFC 4648
//! section 5) with zero unused bits.

use fstp_json::{ParseLimits, Value};

use crate::{ClientData, WebAuthnError};

/// The input limit, as for CBOR (ADR-008).
const MAX_INPUT: usize = 64 * 1024;
/// The nesting limit. Browsers nest at most one level, in `tokenBinding`.
const MAX_DEPTH: usize = 8;
/// The member and element limit of one container.
const MAX_CONTAINER: usize = 64;

/// Client data with the members the verifiers need beyond [`ClientData`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Parsed {
    /// The type, challenge and origin.
    pub(crate) data: ClientData,
    /// The `crossOrigin` member, false when absent.
    pub(crate) cross_origin: bool,
}

/// Parses client data JSON. Fuzzed (`client_data_decode`).
pub(crate) fn parse(b: &[u8]) -> Result<Parsed, WebAuthnError> {
    let limits = ParseLimits::default()
        .with_max_input_bytes(MAX_INPUT)
        .with_max_depth(MAX_DEPTH)
        .with_max_string_bytes(MAX_INPUT)
        .with_max_container_len(MAX_CONTAINER)
        .with_max_nodes(MAX_INPUT)
        .with_max_memory_bytes(MAX_INPUT.saturating_mul(8));
    let value = fstp_json::parse_with(b, &limits).map_err(|_| WebAuthnError::ClientData)?;
    let Value::Object(obj) = value else {
        return Err(WebAuthnError::ClientData);
    };
    let text = |name: &str| {
        obj.get(name)
            .and_then(Value::as_str)
            .ok_or(WebAuthnError::ClientData)
    };
    let kind = text("type")?.to_owned();
    let challenge = base64url_decode(text("challenge")?)?;
    let origin = text("origin")?.to_owned();
    let cross_origin = match obj.get("crossOrigin") {
        None => false,
        Some(v) => v.as_bool().ok_or(WebAuthnError::ClientData)?,
    };
    Ok(Parsed {
        data: ClientData {
            kind,
            challenge,
            origin,
        },
        cross_origin,
    })
}

/// The 6-bit value of a base64url character.
fn sextet(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c.checked_sub(b'A')?,
        b'a'..=b'z' => c.checked_sub(b'a')?.checked_add(26)?,
        b'0'..=b'9' => c.checked_sub(b'0')?.checked_add(52)?,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// Decodes unpadded base64url. Padding, other characters, a length that
/// leaves one character over, and non-zero unused bits are refused.
fn base64url_decode(s: &str) -> Result<Vec<u8>, WebAuthnError> {
    let mut out = Vec::new();
    for chunk in s.as_bytes().chunks(4) {
        let mut acc = 0u32;
        for c in chunk {
            let v = sextet(*c).ok_or(WebAuthnError::ClientData)?;
            acc = acc.checked_shl(6).ok_or(WebAuthnError::ClientData)? | v;
        }
        // Each character carries 6 bits. The bytes are the whole octets.
        let (bytes, unused) = match chunk.len() {
            4 => (3usize, 0u32),
            3 => (2, 2),
            2 => (1, 4),
            _ => return Err(WebAuthnError::ClientData),
        };
        let mask = 1u32
            .checked_shl(unused)
            .ok_or(WebAuthnError::ClientData)?
            .wrapping_sub(1);
        if acc & mask != 0 {
            return Err(WebAuthnError::ClientData);
        }
        let octets = acc
            .checked_shr(unused)
            .ok_or(WebAuthnError::ClientData)?
            .to_be_bytes();
        let start = octets.len().saturating_sub(bytes);
        out.extend_from_slice(octets.get(start..).ok_or(WebAuthnError::ClientData)?);
    }
    Ok(out)
}
