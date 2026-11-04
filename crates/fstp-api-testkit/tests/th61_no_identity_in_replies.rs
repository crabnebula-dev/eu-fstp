//! I-86 and ADR-013: no identity attribute reaches any token or OAuth reply
//! (M4 design section 3.8, `mcp-server.md`).
//!
//! The authorisation server learns the account by id only. A full journey
//! runs with a generated canary account id: registration, authorisation,
//! consent, exchange, rotation, a reused refresh token, revocation, a
//! denied resource request and both metadata documents. Every body,
//! header and redirect is scanned for the id in decimal and hexadecimal.
//! Each JSON reply holds only its RFC members, so no `id_token`, `sub`,
//! `email` or `name` exists. Every token is 256 opaque bits as 43
//! characters of base64url, never a structured token. The `_reference`
//! twin must pass now.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_api_testkit::mc::oauth_model::{
    Access, AccountRef, AuthorizeReply, Backend, Harness, MCP_URL, OTHER_RESOURCE, Reply, TokenSet,
    gen_verifier, location_params, opaque_256, tokens,
};
use fstp_prop::{Gen, check, prop_assert};

const TOKEN_MEMBERS: [&str; 5] = [
    "access_token",
    "token_type",
    "expires_in",
    "refresh_token",
    "scope",
];
const ERROR_MEMBERS: [&str; 3] = ["error", "error_description", "error_uri"];
/// RFC 7591 sections 2 and 3.2.1.
const REGISTRATION_MEMBERS: [&str; 19] = [
    "client_id",
    "client_secret",
    "client_id_issued_at",
    "client_secret_expires_at",
    "redirect_uris",
    "token_endpoint_auth_method",
    "grant_types",
    "response_types",
    "client_name",
    "client_uri",
    "logo_uri",
    "scope",
    "contacts",
    "tos_uri",
    "policy_uri",
    "jwks_uri",
    "jwks",
    "software_id",
    "software_version",
];
const REDIRECT_PARAMS: [&str; 6] = [
    "code",
    "state",
    "iss",
    "error",
    "error_description",
    "error_uri",
];

struct Scan {
    canaries: Vec<String>,
    seen: usize,
}

impl Scan {
    fn text(&mut self, what: &str, s: &str) -> Result<(), String> {
        let lower = s.to_ascii_lowercase();
        for c in &self.canaries {
            prop_assert!(
                !lower.contains(&c.to_ascii_lowercase()),
                "{what} carries the account id {c}: {s}"
            );
        }
        Ok(())
    }

    fn reply(&mut self, what: &str, r: &Reply, allowed: &[&str]) -> Result<(), String> {
        self.seen += 1;
        for (k, v) in &r.headers {
            self.text(&format!("{what} header {k}"), v)?;
        }
        let body = String::from_utf8_lossy(&r.body).into_owned();
        self.text(&format!("{what} body"), &body)?;
        if !r.body.is_empty() && !allowed.is_empty() {
            let v = r.json()?;
            let o = v
                .as_object()
                .ok_or_else(|| format!("{what} is not a JSON object"))?;
            for (k, _) in o.iter() {
                prop_assert!(
                    allowed.contains(&k),
                    "{what} holds the member {k}, outside its RFC set"
                );
            }
        }
        Ok(())
    }

    fn tokens(&mut self, what: &str, r: &Reply) -> Result<TokenSet, String> {
        self.reply(what, r, &TOKEN_MEMBERS)?;
        let t = tokens(r)?;
        prop_assert!(
            opaque_256(&t.access),
            "{what}: the access token is not 256 opaque bits"
        );
        prop_assert!(
            opaque_256(&t.refresh),
            "{what}: the refresh token is not 256 opaque bits"
        );
        Ok(t)
    }

    fn location(&mut self, what: &str, loc: &str) -> Result<(), String> {
        self.seen += 1;
        self.text(what, loc)?;
        for k in location_params(loc)?.keys() {
            prop_assert!(
                REDIRECT_PARAMS.contains(&k.as_str()),
                "{what} carries the parameter {k}"
            );
        }
        Ok(())
    }
}

fn journey(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let account = AccountRef(0x7f3a_0000_0000_0000 | u64::from(g.u32()));
    let mut scan = Scan {
        canaries: vec![
            account.0.to_string(),
            format!("{:x}", account.0),
            format!("{:X}", account.0),
        ],
        seen: 0,
    };
    let mut h = Harness::start(backend)?;
    let redirect = h.redirect.clone();
    let reg = h
        .server()
        .register(
            fstp_api_testkit::mc::oauth_model::SOURCE_B,
            &fstp_api_testkit::mc::oauth_model::registration_body(&[&redirect], None),
            0,
        )
        .map_err(|e| e.to_string())?;
    scan.reply("registration", &reg, &REGISTRATION_MEMBERS)?;
    let verifier = gen_verifier(g);
    let AuthorizeReply::Consent(ticket) = h.authorize(&h.params(&verifier), 0)? else {
        return Err("a valid request got no consent".to_owned());
    };
    let AuthorizeReply::Redirect(loc) = h.approve(&ticket, account, 0)? else {
        return Err("a fresh consent got no redirect".to_owned());
    };
    scan.location("the code redirect", &loc)?;
    let code = location_params(&loc)?
        .get("code")
        .cloned()
        .ok_or("no code")?;
    let first = scan.tokens("the exchange", &h.exchange(&code, Some(&verifier), 1)?)?;
    let second = scan.tokens("the rotation", &h.refresh(&first.refresh, 2)?)?;
    let reused = h.refresh(&first.refresh, 3)?;
    scan.reply("the reuse refusal", &reused, &ERROR_MEMBERS)?;
    let replay = h.exchange(&code, Some(&verifier), 4)?;
    scan.reply("the code replay refusal", &replay, &ERROR_MEMBERS)?;
    let revoked = h.revoke(&second.refresh, 5)?;
    scan.reply("the revocation", &revoked, &ERROR_MEMBERS)?;
    for (what, resource) in [
        ("a dead token", MCP_URL),
        ("another audience", OTHER_RESOURCE),
    ] {
        match h.bearer(&second.access, resource, 6)? {
            Access::Denied(r) => scan.reply(what, &r, &ERROR_MEMBERS)?,
            Access::Granted(g) => return Err(format!("{what} was granted: {g:?}")),
        }
    }
    let none = h
        .server()
        .resource(None, MCP_URL, 6)
        .map_err(|e| e.to_string())?;
    match none {
        Access::Denied(r) => scan.reply("a missing token", &r, &ERROR_MEMBERS)?,
        Access::Granted(g) => return Err(format!("no token was granted: {g:?}")),
    }
    let asm = h.server().as_metadata().map_err(|e| e.to_string())?;
    scan.reply("the server metadata", &asm, &[])?;
    let prm = h.server().resource_metadata().map_err(|e| e.to_string())?;
    scan.reply("the resource metadata", &prm, &[])?;
    let meta = asm.json()?;
    prop_assert!(
        meta.get("userinfo_endpoint").is_none() && meta.get("claims_supported").is_none(),
        "the server metadata offers identity claims"
    );
    prop_assert!(scan.seen == 12, "the scan saw too little: {}", scan.seen);
    Ok(())
}

/// I-86: no reply of the authorisation server carries the account id or
/// any member outside its RFC set, and every code and token is 256 opaque
/// bits.
#[test]
fn i86_no_identity_attribute_in_any_oauth_reply() {
    check("i86_no_identity_attribute_in_any_oauth_reply", |g| {
        journey(Backend::Production, g)
    });
}

/// The reference twin of `i86_no_identity_attribute_in_any_oauth_reply`.
#[test]
fn i86_no_identity_attribute_in_any_oauth_reply_reference() {
    check(
        "i86_no_identity_attribute_in_any_oauth_reply_reference",
        |g| journey(Backend::Reference, g),
    );
}
