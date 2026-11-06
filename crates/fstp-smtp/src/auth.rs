//! SASL PLAIN (RFC 4616) for `AUTH PLAIN`.

use std::fmt;

use crate::base64;

/// The three fields of a PLAIN message.
#[derive(Clone, PartialEq, Eq)]
pub struct PlainCredentials {
    /// The authorisation identity, usually empty.
    pub authzid: String,
    /// The authentication identity.
    pub authcid: String,
    /// The password. Never printed.
    pub password: String,
}

impl fmt::Debug for PlainCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlainCredentials")
            .field("authzid", &self.authzid)
            .field("authcid", &self.authcid)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Why PLAIN data was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// Not canonical base64.
    Base64,
    /// Not three NUL-separated UTF-8 fields with a non-empty identity and
    /// password.
    Fields,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AuthError::Base64 => "AUTH PLAIN data is not canonical base64",
            AuthError::Fields => "AUTH PLAIN data has bad fields",
        })
    }
}

impl std::error::Error for AuthError {}

impl PlainCredentials {
    /// Credentials with an authorisation identity.
    pub fn new(authzid: &str, authcid: &str, password: &str) -> Self {
        PlainCredentials {
            authzid: authzid.to_owned(),
            authcid: authcid.to_owned(),
            password: password.to_owned(),
        }
    }

    /// The base64 initial response.
    pub fn encode(&self) -> String {
        let mut raw = Vec::new();
        raw.extend(self.authzid.as_bytes());
        raw.push(0);
        raw.extend(self.authcid.as_bytes());
        raw.push(0);
        raw.extend(self.password.as_bytes());
        base64::encode(&raw)
    }
}

/// Decodes a base64 PLAIN message.
///
/// # Errors
///
/// [`AuthError`] when the base64 or the fields are malformed.
pub fn decode_plain(b64: &str) -> Result<PlainCredentials, AuthError> {
    let raw = base64::decode(b64.as_bytes()).ok_or(AuthError::Base64)?;
    let mut parts = raw.split(|&b| b == 0);
    let (Some(z), Some(c), Some(p), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AuthError::Fields);
    };
    if c.is_empty() || p.is_empty() {
        return Err(AuthError::Fields);
    }
    let s = |b: &[u8]| String::from_utf8(b.to_vec()).map_err(|_| AuthError::Fields);
    Ok(PlainCredentials {
        authzid: s(z)?,
        authcid: s(c)?,
        password: s(p)?,
    })
}
