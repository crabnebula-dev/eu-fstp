//! Decoders for the OAuth request surfaces: the authorisation query, the
//! token and revocation bodies and the `Authorization` header. Each is
//! fuzzed (design section 9). They check structure only. The server
//! judges meaning, so that each refusal gets the RFC error it needs.

use crate::OauthError;
use crate::form::decode_form_urlencoded;

/// A decoded authorisation request (RFC 6749 section 4.1.1, RFC 7636,
/// RFC 8707). Parameters the server does not know are ignored, as RFC
/// 6749 section 3.1 requires. Every parameter appears at most once.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizeRequest {
    /// `response_type`.
    pub response_type: Option<String>,
    /// `client_id`.
    pub client_id: Option<String>,
    /// `redirect_uri`.
    pub redirect_uri: Option<String>,
    /// `code_challenge`.
    pub code_challenge: Option<String>,
    /// `code_challenge_method`.
    pub code_challenge_method: Option<String>,
    /// `scope`.
    pub scope: Option<String>,
    /// `resource` (RFC 8707).
    pub resource: Option<String>,
    /// `state`.
    pub state: Option<String>,
}

impl std::fmt::Debug for AuthorizeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizeRequest")
            .field("response_type", &self.response_type)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("code_challenge_method", &self.code_challenge_method)
            .field("scope", &self.scope)
            .field("resource", &self.resource)
            .finish_non_exhaustive()
    }
}

fn owned(form: &crate::Form, name: &str) -> Option<String> {
    form.get(name).map(str::to_owned)
}

/// Decodes the query of an authorisation request. Fuzzed (`authorize_query_decode`).
pub fn decode_authorize_query(bytes: &[u8]) -> Result<AuthorizeRequest, OauthError> {
    let form = decode_form_urlencoded(bytes)?;
    Ok(AuthorizeRequest {
        response_type: owned(&form, "response_type"),
        client_id: owned(&form, "client_id"),
        redirect_uri: owned(&form, "redirect_uri"),
        code_challenge: owned(&form, "code_challenge"),
        code_challenge_method: owned(&form, "code_challenge_method"),
        scope: owned(&form, "scope"),
        resource: owned(&form, "resource"),
        state: owned(&form, "state"),
    })
}

/// A decoded token request (RFC 6749 sections 4.1.3 and 6). Values that
/// must match stored grants stay as written. The server checks them.
#[derive(Clone, PartialEq, Eq)]
pub enum TokenRequest {
    /// `grant_type=authorization_code`.
    AuthorizationCode {
        /// `code`.
        code: String,
        /// `client_id`, required of a public client.
        client_id: String,
        /// `redirect_uri`.
        redirect_uri: Option<String>,
        /// `code_verifier` (RFC 7636).
        code_verifier: Option<String>,
        /// `resource` (RFC 8707).
        resource: Option<String>,
    },
    /// `grant_type=refresh_token`.
    RefreshToken {
        /// `refresh_token`.
        refresh_token: String,
        /// `client_id`, required of a public client.
        client_id: String,
        /// `scope`, a subset of the grant's.
        scope: Option<String>,
        /// `resource` (RFC 8707).
        resource: Option<String>,
    },
}

impl std::fmt::Debug for TokenRequest {
    /// Never shows a code, verifier or token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenRequest::AuthorizationCode {
                client_id,
                redirect_uri,
                resource,
                ..
            } => f
                .debug_struct("AuthorizationCode")
                .field("client_id", client_id)
                .field("redirect_uri", redirect_uri)
                .field("resource", resource)
                .finish_non_exhaustive(),
            TokenRequest::RefreshToken {
                client_id,
                scope,
                resource,
                ..
            } => f
                .debug_struct("RefreshToken")
                .field("client_id", client_id)
                .field("scope", scope)
                .field("resource", resource)
                .finish_non_exhaustive(),
        }
    }
}

fn required(form: &crate::Form, name: &'static str) -> Result<String, OauthError> {
    form.get(name)
        .map(str::to_owned)
        .ok_or(OauthError::MissingParameter(name))
}

/// Decodes a token request body. Fuzzed (`token_request_decode`).
pub fn decode_token_request(bytes: &[u8]) -> Result<TokenRequest, OauthError> {
    let form = decode_form_urlencoded(bytes)?;
    match form.get("grant_type") {
        None => Err(OauthError::MissingParameter("grant_type")),
        Some("authorization_code") => Ok(TokenRequest::AuthorizationCode {
            code: required(&form, "code")?,
            client_id: required(&form, "client_id")?,
            redirect_uri: owned(&form, "redirect_uri"),
            code_verifier: owned(&form, "code_verifier"),
            resource: owned(&form, "resource"),
        }),
        Some("refresh_token") => Ok(TokenRequest::RefreshToken {
            refresh_token: required(&form, "refresh_token")?,
            client_id: required(&form, "client_id")?,
            scope: owned(&form, "scope"),
            resource: owned(&form, "resource"),
        }),
        Some(_) => Err(OauthError::UnsupportedGrantType),
    }
}

/// A decoded revocation request (RFC 7009 section 2.1).
#[derive(Clone, PartialEq, Eq)]
pub struct RevocationRequest {
    /// `token`.
    pub token: String,
    /// `token_type_hint`, which the server may ignore.
    pub token_type_hint: Option<String>,
    /// `client_id`, required of a public client.
    pub client_id: String,
}

impl std::fmt::Debug for RevocationRequest {
    /// Never shows the token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationRequest")
            .field("token_type_hint", &self.token_type_hint)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// Decodes a revocation request body. Fuzzed (`revocation_request_decode`).
pub fn decode_revocation_request(bytes: &[u8]) -> Result<RevocationRequest, OauthError> {
    let form = decode_form_urlencoded(bytes)?;
    Ok(RevocationRequest {
        token: required(&form, "token")?,
        token_type_hint: owned(&form, "token_type_hint"),
        client_id: required(&form, "client_id")?,
    })
}

/// The longest `Authorization` header value [`parse_bearer_header`] reads.
pub const MAX_BEARER_HEADER: usize = 4096;

/// A parsed bearer credential (RFC 6750 section 2.1).
#[derive(Clone, PartialEq, Eq)]
pub struct BearerToken(String);

impl BearerToken {
    /// The credential as sent.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for BearerToken {
    /// Never shows the credential.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BearerToken({} bytes)", self.0.len())
    }
}

/// Parses an `Authorization: Bearer` header value. Fuzzed (`bearer_header_parse`).
///
/// The value is the scheme `Bearer` in any case, one space and one
/// `b64token` (RFC 6750 section 2.1). A second credential, other
/// whitespace and a trailing line break are refused.
pub fn parse_bearer_header(bytes: &[u8]) -> Result<BearerToken, OauthError> {
    if bytes.len() > MAX_BEARER_HEADER {
        return Err(OauthError::InvalidBearer);
    }
    let (scheme, rest) = match bytes.iter().position(|&b| b == b' ') {
        Some(i) => bytes.split_at(i),
        None => return Err(OauthError::InvalidBearer),
    };
    if !scheme.eq_ignore_ascii_case(b"bearer") {
        return Err(OauthError::InvalidBearer);
    }
    let token = rest.get(1..).unwrap_or(&[]);
    let body_len = token.iter().position(|&b| b == b'=').unwrap_or(token.len());
    let (body, pad) = token.split_at(body_len);
    let body_ok = !body.is_empty()
        && body
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b));
    if !body_ok || !pad.iter().all(|&b| b == b'=') {
        return Err(OauthError::InvalidBearer);
    }
    let text = std::str::from_utf8(token).map_err(|_| OauthError::InvalidBearer)?;
    Ok(BearerToken(text.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-013, RFC 6750: the scheme is case-insensitive and the
    /// credential is one `b64token`.
    #[test]
    fn adr013_bearer_cases() {
        assert!(parse_bearer_header(b"bearer abc").is_ok());
        assert!(parse_bearer_header(b"BEARER abc==").is_ok());
        assert!(parse_bearer_header(b"Bearer  abc").is_err());
        assert!(parse_bearer_header(b"Bearer a=b").is_err());
        assert!(parse_bearer_header(b"Bearer\tabc").is_err());
    }

    /// ADR-013, design section 9: a token request names its grant.
    #[test]
    fn adr013_token_request_grants() {
        assert_eq!(
            decode_token_request(b"client_id=c"),
            Err(OauthError::MissingParameter("grant_type"))
        );
        assert_eq!(
            decode_token_request(b"grant_type=password&client_id=c"),
            Err(OauthError::UnsupportedGrantType)
        );
        assert_eq!(
            decode_token_request(b"grant_type=authorization_code&code=x"),
            Err(OauthError::MissingParameter("client_id"))
        );
    }
}
