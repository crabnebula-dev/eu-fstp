//! Codecs of auth records, commands, session cookies and tokens. Each
//! decoder is fuzzed (design section 15).

use crate::{AuthCommand, AuthError, AuthRecord};

/// A session cookie value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionCookie {
    /// The session id.
    pub session: [u8; 16],
    /// The authenticator over the id.
    pub tag: [u8; 32],
}

/// A one-time token (magic link or enrolment), constant length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token(pub [u8; 32]);

/// Decodes an auth record. Fuzzed (`auth_record_decode`).
pub fn decode_auth_record(bytes: &[u8]) -> Result<AuthRecord, AuthError> {
    let _ = bytes;
    Err(AuthError::NotImplemented(
        "fstp_auth::codec::decode_auth_record",
    ))
}

/// Decodes an auth command. Fuzzed (`auth_command_decode`).
pub fn decode_auth_command(bytes: &[u8]) -> Result<AuthCommand, AuthError> {
    let _ = bytes;
    Err(AuthError::NotImplemented(
        "fstp_auth::codec::decode_auth_command",
    ))
}

/// Decodes a session cookie. Fuzzed (`session_cookie_decode`).
pub fn decode_session_cookie(bytes: &[u8]) -> Result<SessionCookie, AuthError> {
    let _ = bytes;
    Err(AuthError::NotImplemented(
        "fstp_auth::codec::decode_session_cookie",
    ))
}

/// Decodes a token. Fuzzed (`token_decode`).
pub fn decode_token(bytes: &[u8]) -> Result<Token, AuthError> {
    let _ = bytes;
    Err(AuthError::NotImplemented("fstp_auth::codec::decode_token"))
}
