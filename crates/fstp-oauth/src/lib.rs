//! A sans-IO OAuth 2.1 authorisation server (M4 design section 3.8,
//! ADR-013).
//!
//! The crate covers RFC 8414 and RFC 9728 metadata, open RFC 7591
//! registration with a rate limit, authorisation with PKCE `S256` only,
//! token issue and refresh rotation with reuse detection, RFC 7009
//! revocation, RFC 8707 resource binding, the RFC 9207 `iss` response
//! parameter, a strict URL parser and the request decoders. Its profile,
//! and the MCP revision it was checked against, are recorded in ADR-013.
//!
//! - [`AuthorizationServer`] holds the clients, consents, codes, refresh
//!   families and access tokens of one cell, in memory. Each endpoint takes
//!   request bytes and the time and returns reply bytes.
//! - The decoders ([`parse_url`], [`decode_form_urlencoded`],
//!   [`decode_authorize_query`], [`decode_token_request`],
//!   [`decode_revocation_request`], [`decode_client_metadata`],
//!   [`parse_bearer_header`] and [`decode_base64url`]) check structure only.
//!   Each has a fuzz target.
//!
//! The server never learns an identity attribute. It knows an account by
//! its raw id and never writes that id into a reply (I-86). Consent needs
//! a fresh phishing-resistant step-up bound to the consent (I-78).

mod b64;
mod form;
mod metadata;
mod request;
mod scope;
mod server;
mod url;

pub use b64::{Base64Url, MAX_BASE64URL_LEN, decode_base64url, encode_base64url};
pub use form::{
    Form, MAX_FORM_BYTES, MAX_FORM_PAIRS, decode_form_urlencoded, encode_form_urlencoded,
};
pub use metadata::{
    ClientMetadata, MAX_CLIENT_NAME_CHARS, MAX_METADATA_BYTES, MAX_REDIRECT_URIS,
    decode_client_metadata,
};
pub use request::{
    AuthorizeRequest, BearerToken, MAX_BEARER_HEADER, RevocationRequest, TokenRequest,
    decode_authorize_query, decode_revocation_request, decode_token_request, parse_bearer_header,
};
pub use scope::{Scope, ScopeSet};
pub use server::{
    ACCESS_LIFETIME_MICROS, AUTHORIZE_PATH, Account, AgentGrant, AuthorizationServer,
    AuthorizeOutcome, CODE_LIFETIME_MICROS, CONSENT_LIFETIME_MICROS, ClientNumber, Config,
    ConsentAuth, ConsentRequest, Grant, LoginMethod, MAX_STATE_BYTES, Micros, REGISTER_PATH,
    RESOURCE_METADATA_PATH, REVOKE_PATH, RateKey, Reply, SERVER_METADATA_PATH, StepUpProof,
    Strength, TOKEN_PATH,
};
pub use url::{MAX_URL_LEN, Scheme, Url, UrlError, parse_url, redirect_matches};

/// Why a decoder or the server refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OauthError {
    /// The input is longer than its limit.
    TooLong,
    /// A form or query is malformed: a raw byte outside visible ASCII, an
    /// empty segment, a segment without `=` or an empty name.
    MalformedForm,
    /// A `%` not followed by two hexadecimal digits.
    BadPercentEncoding,
    /// A decoded name or value is not UTF-8.
    NotUtf8,
    /// A parameter appears more than once (RFC 6749 section 3.1).
    DuplicateParameter,
    /// More parameters than [`MAX_FORM_PAIRS`].
    TooManyParameters,
    /// A required parameter is absent.
    MissingParameter(&'static str),
    /// A grant type other than `authorization_code` and `refresh_token`.
    UnsupportedGrantType,
    /// A URL outside the strict subset.
    Url(UrlError),
    /// Text that is not canonical unpadded base64url.
    InvalidBase64,
    /// An `Authorization` value that is not one `Bearer` credential.
    InvalidBearer,
    /// A registration body that is not JSON within the limits.
    InvalidJson,
    /// Registration metadata outside the profile.
    InvalidClientMetadata(&'static str),
    /// A missing, empty, duplicated or unsafe redirect URI list.
    InvalidRedirectUri,
    /// The system random generator failed.
    Randomness,
    /// A server configuration outside the profile.
    InvalidConfig(&'static str),
}

impl std::fmt::Display for OauthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OauthError::TooLong => f.write_str("the input is too long"),
            OauthError::MalformedForm => f.write_str("the form is malformed"),
            OauthError::BadPercentEncoding => f.write_str("bad percent-encoding"),
            OauthError::NotUtf8 => f.write_str("a decoded value is not UTF-8"),
            OauthError::DuplicateParameter => f.write_str("a parameter appears more than once"),
            OauthError::TooManyParameters => f.write_str("too many parameters"),
            OauthError::MissingParameter(p) => write!(f, "the parameter {p} is missing"),
            OauthError::UnsupportedGrantType => f.write_str("the grant type is not supported"),
            OauthError::Url(e) => write!(f, "{e}"),
            OauthError::InvalidBase64 => f.write_str("not canonical unpadded base64url"),
            OauthError::InvalidBearer => f.write_str("not one Bearer credential"),
            OauthError::InvalidJson => f.write_str("the body is not JSON within the limits"),
            OauthError::InvalidClientMetadata(why) => write!(f, "invalid client metadata: {why}"),
            OauthError::InvalidRedirectUri => f.write_str("the redirect URIs are invalid"),
            OauthError::Randomness => f.write_str("the random generator failed"),
            OauthError::InvalidConfig(why) => write!(f, "invalid configuration: {why}"),
        }
    }
}

impl std::error::Error for OauthError {}
