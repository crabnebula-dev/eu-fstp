//! A sans-IO OAuth 2.1 authorisation server (M4 design section 3.8).
//!
//! The crate covers RFC 8414 and RFC 9728 metadata, RFC 7591 registration,
//! authorisation with PKCE `S256`, token issue and refresh rotation, RFC
//! 7009 revocation, RFC 8707 resource binding, a strict URL parser and a
//! form decoder. Its profile is recorded in ADR-013, a draft pending Q8 and
//! Q25.
//!
//! Status: W0 stub. Lane W1e (L-OAUTH) owns this crate, and waits for
//! ADR-013. Every operation refuses with [`OauthError::NotImplemented`].

/// Why an operation of this crate failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OauthError {
    /// The W0 stub of the named operation refuses.
    NotImplemented(&'static str),
}

impl std::fmt::Display for OauthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OauthError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for OauthError {}

/// A parsed URL of the strict subset.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    _w0: (),
}

/// Parses a URL in the strict RFC 3986 subset. Fuzzed (`url_parse`).
pub fn parse_url(bytes: &[u8]) -> Result<Url, OauthError> {
    let _ = bytes;
    Err(OauthError::NotImplemented("fstp_oauth::parse_url"))
}

/// A decoded form body.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Form {
    _w0: (),
}

/// Decodes an `application/x-www-form-urlencoded` body. Duplicate parameters are refused. Fuzzed (`form_urlencoded_decode`).
pub fn decode_form_urlencoded(bytes: &[u8]) -> Result<Form, OauthError> {
    let _ = bytes;
    Err(OauthError::NotImplemented(
        "fstp_oauth::decode_form_urlencoded",
    ))
}

/// A decoded authorisation request.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizeRequest {
    _w0: (),
}

/// Decodes the query of an authorisation request. Fuzzed (`authorize_query_decode`).
pub fn decode_authorize_query(bytes: &[u8]) -> Result<AuthorizeRequest, OauthError> {
    let _ = bytes;
    Err(OauthError::NotImplemented(
        "fstp_oauth::decode_authorize_query",
    ))
}

/// A decoded token request.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRequest {
    _w0: (),
}

/// Decodes a token request body. Fuzzed (`token_request_decode`).
pub fn decode_token_request(bytes: &[u8]) -> Result<TokenRequest, OauthError> {
    let _ = bytes;
    Err(OauthError::NotImplemented(
        "fstp_oauth::decode_token_request",
    ))
}

/// Decoded client registration metadata.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientMetadata {
    _w0: (),
}

/// Decodes RFC 7591 client metadata. Fuzzed (`client_metadata_decode`).
pub fn decode_client_metadata(bytes: &[u8]) -> Result<ClientMetadata, OauthError> {
    let _ = bytes;
    Err(OauthError::NotImplemented(
        "fstp_oauth::decode_client_metadata",
    ))
}

/// A parsed bearer token.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BearerToken {
    _w0: (),
}

/// Parses an `Authorization: Bearer` header value. Fuzzed (`bearer_header_parse`).
pub fn parse_bearer_header(bytes: &[u8]) -> Result<BearerToken, OauthError> {
    let _ = bytes;
    Err(OauthError::NotImplemented(
        "fstp_oauth::parse_bearer_header",
    ))
}

/// Decoded base64url bytes.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Base64Url {
    _w0: (),
}

/// Decodes unpadded base64url text. Fuzzed (`base64url_decode`).
pub fn decode_base64url(bytes: &[u8]) -> Result<Base64Url, OauthError> {
    let _ = bytes;
    Err(OauthError::NotImplemented("fstp_oauth::decode_base64url"))
}
