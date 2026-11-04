//! The RFC 7591 client metadata decoder (ADR-013, Q8).
//!
//! Registration is open, so every member is untrusted. The decoder keeps
//! what the server uses: the redirect URIs and the client name. It checks
//! the grant and response types and the token endpoint authentication
//! method against the public-client profile. It ignores other members, as
//! RFC 7591 section 2 allows. It never fetches a URL.

use fstp_json::{ParseLimits, Value};

use crate::OauthError;
use crate::url::{Url, parse_url};

/// The largest registration body, in bytes.
pub const MAX_METADATA_BYTES: usize = 16 * 1024;
/// The most redirect URIs one client may register.
pub const MAX_REDIRECT_URIS: usize = 8;
/// The longest client name, in characters.
pub const MAX_CLIENT_NAME_CHARS: usize = 64;

/// Decoded client registration metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientMetadata {
    redirect_uris: Vec<Url>,
    client_name: Option<String>,
}

impl ClientMetadata {
    /// The redirect URIs, each in the strict subset, in written order.
    pub fn redirect_uris(&self) -> &[Url] {
        &self.redirect_uris
    }

    /// The client name: untrusted text, shown with an "unverified" label.
    pub fn client_name(&self) -> Option<&str> {
        self.client_name.as_deref()
    }
}

fn limits() -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(MAX_METADATA_BYTES)
        .with_max_depth(8)
        .with_max_string_bytes(4096)
        .with_max_container_len(256)
        .with_max_nodes(2048)
        .with_max_memory_bytes(512 * 1024)
}

/// Characters a client name may not hold: controls, and the format
/// characters that reorder or hide text on a consent page.
fn refused_in_name(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}' | '\u{feff}'
        )
}

fn string_subset(v: Option<&Value>, allowed: &[&str]) -> Result<(), OauthError> {
    let Some(v) = v else {
        return Ok(());
    };
    let items = v.as_array().ok_or(OauthError::InvalidClientMetadata(
        "a type list is not an array",
    ))?;
    for x in items.iter() {
        match x.as_str() {
            Some(s) if allowed.contains(&s) => {}
            _ => {
                return Err(OauthError::InvalidClientMetadata(
                    "a grant or response type is outside the profile",
                ));
            }
        }
    }
    Ok(())
}

/// Decodes RFC 7591 client metadata. Fuzzed (`client_metadata_decode`).
///
/// The body is one JSON object without duplicate members.
/// `redirect_uris` is required: 1 to [`MAX_REDIRECT_URIS`] distinct URLs
/// of the strict subset. `client_name`, when present, is a string of 1 to
/// [`MAX_CLIENT_NAME_CHARS`] characters with no control or bidirectional
/// format character. `grant_types` may name only `authorization_code` and
/// `refresh_token`, `response_types` only `code`, and
/// `token_endpoint_auth_method` only `none`.
pub fn decode_client_metadata(bytes: &[u8]) -> Result<ClientMetadata, OauthError> {
    let v = fstp_json::parse_with(bytes, &limits()).map_err(|_| OauthError::InvalidJson)?;
    let o = v
        .as_object()
        .ok_or(OauthError::InvalidClientMetadata("not a JSON object"))?;
    let uris = o
        .get("redirect_uris")
        .and_then(Value::as_array)
        .ok_or(OauthError::InvalidRedirectUri)?;
    if uris.is_empty() || uris.len() > MAX_REDIRECT_URIS {
        return Err(OauthError::InvalidRedirectUri);
    }
    let mut redirect_uris: Vec<Url> = Vec::new();
    for u in uris.iter() {
        let s = u.as_str().ok_or(OauthError::InvalidRedirectUri)?;
        let url = parse_url(s.as_bytes()).map_err(|_| OauthError::InvalidRedirectUri)?;
        if redirect_uris.iter().any(|r| r.as_str() == url.as_str()) {
            return Err(OauthError::InvalidRedirectUri);
        }
        redirect_uris.push(url);
    }
    let client_name = match o.get("client_name") {
        None => None,
        Some(n) => {
            let s = n.as_str().ok_or(OauthError::InvalidClientMetadata(
                "client_name is not a string",
            ))?;
            let chars = s.chars().count();
            if chars == 0 || chars > MAX_CLIENT_NAME_CHARS || s.chars().any(refused_in_name) {
                return Err(OauthError::InvalidClientMetadata(
                    "client_name is empty, too long or holds a refused character",
                ));
            }
            Some(s.to_owned())
        }
    };
    string_subset(
        o.get("grant_types"),
        &["authorization_code", "refresh_token"],
    )?;
    string_subset(o.get("response_types"), &["code"])?;
    match o.get("token_endpoint_auth_method") {
        None => {}
        Some(m) if m.as_str() == Some("none") => {}
        Some(_) => {
            return Err(OauthError::InvalidClientMetadata(
                "token_endpoint_auth_method is not none",
            ));
        }
    }
    Ok(ClientMetadata {
        redirect_uris,
        client_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-013, TW-8: a client name that could reorder or hide text on the
    /// consent page is refused.
    #[test]
    fn adr013_client_name_refuses_format_characters() {
        for name in ["a\u{202e}b", "a\u{0007}", "a\u{2066}b", ""] {
            let body = format!(
                r#"{{"redirect_uris":["https://agent.example/cb"],"client_name":"{name}"}}"#
            );
            assert!(
                decode_client_metadata(body.as_bytes()).is_err(),
                "{name:?} accepted"
            );
        }
        let body = br#"{"redirect_uris":["https://a.example/cb","https://a.example/cb"]}"#;
        assert_eq!(
            decode_client_metadata(body),
            Err(OauthError::InvalidRedirectUri)
        );
        let body = br#"{"redirect_uris":["https://a.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}"#;
        assert!(decode_client_metadata(body).is_err());
    }
}
