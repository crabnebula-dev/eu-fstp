//! ADR-013 and TH-61 (TW-6): metadata, the 401 challenge and resource
//! binding (M4 design section 3.8, RFC 8414, RFC 8707, RFC 9728, MCP
//! authorisation 2026-07-28).
//!
//! The server metadata advertises `S256` as the only PKCE method, since
//! MCP clients refuse a server whose metadata omits
//! `code_challenge_methods_supported`. It names the open registration
//! endpoint. The protected resource metadata names this cell's MCP URL and
//! its issuer. A request without a token gets 401 with a `Bearer`
//! challenge that points at the protected resource metadata. The
//! `resource` parameter must equal the MCP URL, and a token works at that
//! audience only. Each test has a `_reference` twin that must pass now.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_api_testkit::mc::oauth_model::{
    Access, AuthorizeReply, Backend, Harness, ISSUER, MCP_URL, MODEL_ACCOUNT, OTHER_RESOURCE,
    PRM_PATH, VERIFIER, refused_authorization,
};
use fstp_json::Value;
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

fn strings(v: &Value, key: &str) -> Result<Vec<String>, String> {
    v.get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("no array {key}"))?
        .iter()
        .map(|x| {
            x.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{key} holds a non-string"))
        })
        .collect()
}

fn metadata(backend: Backend, _: &mut Gen) -> Result<(), String> {
    let mut h = Harness::start(backend)?;
    let asm = h.server().as_metadata().map_err(|e| e.to_string())?;
    prop_assert_eq!(asm.status, 200);
    let m = asm.json()?;
    prop_assert_eq!(m.get("issuer").and_then(Value::as_str), Some(ISSUER));
    prop_assert_eq!(
        strings(&m, "code_challenge_methods_supported")?,
        vec!["S256".to_owned()]
    );
    prop_assert_eq!(
        strings(&m, "response_types_supported")?,
        vec!["code".to_owned()]
    );
    let mut grants = strings(&m, "grant_types_supported")?;
    grants.sort();
    prop_assert_eq!(
        grants,
        vec!["authorization_code".to_owned(), "refresh_token".to_owned()]
    );
    for k in [
        "authorization_endpoint",
        "token_endpoint",
        "registration_endpoint",
        "revocation_endpoint",
    ] {
        let url = m
            .get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("no {k}"))?;
        prop_assert!(
            url.starts_with(&format!("{ISSUER}/")),
            "{k} {url} is not under the issuer"
        );
    }
    let prm = h.server().resource_metadata().map_err(|e| e.to_string())?;
    prop_assert_eq!(prm.status, 200);
    let p = prm.json()?;
    prop_assert_eq!(p.get("resource").and_then(Value::as_str), Some(MCP_URL));
    prop_assert!(
        strings(&p, "authorization_servers")?.contains(&ISSUER.to_owned()),
        "the resource metadata does not name the issuer"
    );
    Ok(())
}

/// ADR-013, RFC 8414, RFC 9728: the server metadata offers `S256` only,
/// the code and refresh grants only, and the open registration endpoint;
/// the resource metadata names the MCP URL and the issuer.
#[test]
fn adr013_metadata_advertises_s256_only() {
    check("adr013_metadata_advertises_s256_only", |g| {
        metadata(Backend::Production, g)
    });
}

/// The reference twin of `adr013_metadata_advertises_s256_only`.
#[test]
fn adr013_metadata_advertises_s256_only_reference() {
    check("adr013_metadata_advertises_s256_only_reference", |g| {
        metadata(Backend::Reference, g)
    });
}

fn challenge(backend: Backend, _: &mut Gen) -> Result<(), String> {
    let mut h = Harness::start(backend)?;
    let a = h
        .server()
        .resource(None, MCP_URL, 0)
        .map_err(|e| e.to_string())?;
    let Access::Denied(r) = a else {
        return Err(format!("no token was granted: {a:?}"));
    };
    prop_assert_eq!(r.status, 401);
    let www = r
        .header("WWW-Authenticate")
        .ok_or("no WWW-Authenticate header")?;
    prop_assert!(
        www.starts_with("Bearer "),
        "the challenge is not Bearer: {www}"
    );
    let key = "resource_metadata=\"";
    let at = www
        .find(key)
        .ok_or_else(|| format!("no resource_metadata in {www}"))?;
    let rest = &www[at + key.len()..];
    let url = &rest[..rest.find('"').ok_or("an unterminated resource_metadata")?];
    let base = format!("{ISSUER}{PRM_PATH}");
    prop_assert!(
        url == base || url == format!("{base}/mcp"),
        "resource_metadata {url} is not this cell's protected resource metadata"
    );
    Ok(())
}

/// ADR-013, RFC 9728: a request without a token gets 401 with
/// `WWW-Authenticate: Bearer resource_metadata="..."` naming this cell's
/// protected resource metadata.
#[test]
fn adr013_missing_token_gets_401_with_resource_metadata() {
    check(
        "adr013_missing_token_gets_401_with_resource_metadata",
        |g| challenge(Backend::Production, g),
    );
}

/// The reference twin of
/// `adr013_missing_token_gets_401_with_resource_metadata`.
#[test]
fn adr013_missing_token_gets_401_with_resource_metadata_reference() {
    check(
        "adr013_missing_token_gets_401_with_resource_metadata_reference",
        |g| challenge(Backend::Reference, g),
    );
}

/// `resource` values other than the MCP URL. `None` leaves it out.
const RESOURCES: [Option<&str>; 6] = [
    None,
    Some(OTHER_RESOURCE),
    Some("https://cell-a.example/mcp/"),
    Some("https://cell-a.example"),
    Some("https://cell-a.example/mcp/public"),
    Some("https://cell-a.example/mcp#x"),
];

fn bound(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let mut h = Harness::start(backend)?;
    let resource = *g.pick(&RESOURCES);
    g.note("resource", &resource);
    let mut p = h.params(VERIFIER);
    p.resource = resource.map(str::to_owned);
    refused_authorization(&h.authorize(&p, 0)?, &h.redirect)?;
    let control = h.authorize(&h.params(VERIFIER), 0)?;
    prop_assert!(
        matches!(control, AuthorizeReply::Consent(_)),
        "the MCP URL as resource got {control:?}"
    );
    let t = h.family(VERIFIER, MODEL_ACCOUNT, 1)?;
    prop_assert!(
        matches!(h.bearer(&t.access, MCP_URL, 2)?, Access::Granted(_)),
        "the token is refused at its audience"
    );
    let elsewhere = resource.unwrap_or(OTHER_RESOURCE);
    let a = h.bearer(&t.access, elsewhere, 2)?;
    let Access::Denied(r) = a else {
        return Err(format!("the token worked at {elsewhere}: {a:?}"));
    };
    prop_assert_eq!(r.status, 401);
    Ok(())
}

/// ADR-013, RFC 8707, TW-6: an authorisation request whose `resource` is
/// absent or differs from the MCP URL is refused, and a token issued for
/// the MCP URL is refused at any other resource.
#[test]
fn adr013_resource_must_equal_mcp_url() {
    check("adr013_resource_must_equal_mcp_url", |g| {
        bound(Backend::Production, g)
    });
}

/// The reference twin of `adr013_resource_must_equal_mcp_url`.
#[test]
fn adr013_resource_must_equal_mcp_url_reference() {
    check("adr013_resource_must_equal_mcp_url_reference", |g| {
        bound(Backend::Reference, g)
    });
}
