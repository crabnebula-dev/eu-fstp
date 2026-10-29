//! The session cookie's text armour (B11, I-19, ADR-008 "Sessions",
//! design section 8.2).
//!
//! `fstp_auth::codec` holds the cookie's byte form: the 16-byte cell id,
//! then the 32-byte token. This module writes it as 96 lowercase
//! hexadecimal digits, which are cookie-octets (RFC 6265 section 4.1.1),
//! and reads it back with one spelling only.
//!
//! - The cookie is `__Host-fstp` with `Path=/`, `Secure`, `HttpOnly` and
//!   `SameSite=Strict`, and no `Domain`, so a sibling host can neither
//!   read it nor set it under that name.
//! - Only the exact name `__Host-fstp` is the session cookie. Cookie names
//!   are case-sensitive, so `__host-fstp` or `fstp` are other cookies and
//!   are ignored.
//! - Two session cookies in one request are refused, whether they share a
//!   field or not, so a tossed cookie never shadows the real one.
//! - A value of another cell is refused before any lookup (B11), through
//!   `fstp_auth::codec::decode_session_cookie_for`.

use fstp_auth::codec::{
    CodecError, SessionCookie, Token, decode_session_cookie_for, encode_session_cookie,
};
use fstp_http::{HeaderValue, Headers};

use crate::http::body::{hex, hex_array};

/// The session cookie name (ADR-008).
pub const COOKIE_NAME: &str = "__Host-fstp";

/// The attributes written after the value, in a fixed order.
const ATTRIBUTES: &str = "; Path=/; Secure; HttpOnly; SameSite=Strict";

/// The length of the cookie value: 48 bytes as hexadecimal.
pub const COOKIE_VALUE_LEN: usize = 96;

/// Why a request's session cookie was refused before any lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CookieRefusal {
    /// The request carries the session cookie more than once.
    Ambiguous,
    /// The value is not 96 lowercase hexadecimal digits.
    Malformed,
    /// The value names another cell (B11).
    OtherCell,
}

impl std::fmt::Display for CookieRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CookieRefusal::Ambiguous => "the request carries the session cookie twice",
            CookieRefusal::Malformed => "the session cookie is malformed",
            CookieRefusal::OtherCell => "the session cookie names another cell",
        })
    }
}

impl std::error::Error for CookieRefusal {}

/// The `Set-Cookie` field value for a session of `cell` with `token`.
pub fn set_session_cookie(cell: [u8; 16], token: &[u8; 32]) -> HeaderValue {
    let value = encode_session_cookie(&SessionCookie::new(cell, Token(*token)));
    let text = format!("{COOKIE_NAME}={}{ATTRIBUTES}", hex(&value));
    // The text is ASCII cookie-octets and fixed attributes, so the field
    // value is always valid. The empty value is never reached.
    HeaderValue::new(text).unwrap_or_else(|_| HeaderValue::from_u64(0))
}

/// The `Set-Cookie` field value that clears the session cookie.
pub fn clear_session_cookie() -> HeaderValue {
    let text = format!("{COOKIE_NAME}={ATTRIBUTES}; Max-Age=0");
    HeaderValue::new(text).unwrap_or_else(|_| HeaderValue::from_u64(0))
}

/// Reads the session cookie of a request to the cell `cell` from its
/// `Cookie` field lines.
///
/// # Errors
///
/// A [`CookieRefusal`] for a doubled, malformed or foreign session
/// cookie. Other cookies are ignored. `Ok(None)` means no session cookie.
pub fn read_session_cookie(
    cell: [u8; 16],
    headers: &Headers,
) -> Result<Option<SessionCookie>, CookieRefusal> {
    read_session_cookie_values(cell, headers.get_all("cookie").map(HeaderValue::as_bytes))
}

/// [`read_session_cookie`] over the values of every `Cookie` field line,
/// in order.
///
/// # Errors
///
/// As [`read_session_cookie`].
pub fn read_session_cookie_values<'a>(
    cell: [u8; 16],
    fields: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Option<SessionCookie>, CookieRefusal> {
    let mut found: Option<&'a [u8]> = None;
    for field in fields {
        for pair in field.split(|b| *b == b';') {
            let pair = trim(pair);
            let Some(eq) = pair.iter().position(|b| *b == b'=') else {
                continue;
            };
            let (name, value) = pair.split_at(eq);
            if trim(name) != COOKIE_NAME.as_bytes() {
                continue;
            }
            if found.is_some() {
                return Err(CookieRefusal::Ambiguous);
            }
            found = Some(value.get(1..).unwrap_or_default());
        }
    }
    let Some(value) = found else {
        return Ok(None);
    };
    let text = std::str::from_utf8(value).map_err(|_| CookieRefusal::Malformed)?;
    let bytes = hex_array::<48>(text).ok_or(CookieRefusal::Malformed)?;
    match decode_session_cookie_for(&bytes, cell) {
        Ok(c) => Ok(Some(c)),
        Err(CodecError::OtherCell) => Err(CookieRefusal::OtherCell),
        Err(_) => Err(CookieRefusal::Malformed),
    }
}

/// `b` without leading and trailing spaces and tabs.
fn trim(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|c| *c != b' ' && *c != b'\t')
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| *c != b' ' && *c != b'\t')
        .map_or(start, |i| i.saturating_add(1));
    b.get(start..end).unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// B11: a written cookie reads back on its own cell only.
    #[test]
    fn b11_cookie_round_trips_on_its_own_cell_only() {
        let set = set_session_cookie([1; 16], &[2; 32]);
        let text = set.to_str().unwrap();
        let pair = text.split(';').next().unwrap();
        let read = read_session_cookie_values([1; 16], [pair.as_bytes()]).unwrap();
        assert_eq!(
            read.map(|c| (c.cell(), c.token().0)),
            Some(([1; 16], [2; 32]))
        );
        assert_eq!(
            read_session_cookie_values([3; 16], [pair.as_bytes()]),
            Err(CookieRefusal::OtherCell)
        );
        assert_eq!(
            text.len(),
            COOKIE_NAME.len() + 1 + COOKIE_VALUE_LEN + ATTRIBUTES.len()
        );
    }
}
