//! ADR-013 (Q8): open dynamic client registration (RFC 7591), rate-limited,
//! with no client metadata fetch, and no rights for a client before a
//! consent (M4 design section 3.8).
//!
//! The rate-limit test reads no window shape into ADR-013. It checks that
//! one source gets at most the configured number at one instant and a 429
//! after that, that another source is unaffected, and that one full window
//! later the source registers again. Each test has a `_reference` twin
//! that must pass now.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_api_testkit::mc::oauth_model::{
    Access, AuthorizeParams, Backend, Harness, MCP_URL, MODEL_ACCOUNT, SOURCE_A, SOURCE_B,
    ServerConfig, VERIFIER, client_id_of, form, refused_without_redirect, registration_body,
    server, tokens,
};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

fn rate_limited(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let mut cfg = ServerConfig::synthetic();
    cfg.registration_max = g.u32_in(1..=6);
    cfg.registration_window_micros = g.i64_in(1_000_000..=86_400_000_000);
    let max = cfg.registration_max;
    let window = cfg.registration_window_micros;
    g.note("max", &max);
    g.note("window", &window);
    let mut s = server(backend, &cfg);
    let t0 = g.i64_in(0..=1_000_000_000);
    let extra = g.u32_in(1..=4);
    let body = registration_body(&["https://agent.example/cb"], Some("Synthetic agent"));
    let mut ids = Vec::new();
    for i in 0..max + extra {
        let r = s.register(SOURCE_A, &body, t0).map_err(|e| e.to_string())?;
        if i < max {
            ids.push(client_id_of(&r)?);
        } else {
            prop_assert_eq!(r.status, 429);
            prop_assert!(
                r.json()
                    .ok()
                    .and_then(|v| v.get("client_id").cloned())
                    .is_none(),
                "a rate-limited registration issued a client_id"
            );
        }
    }
    let distinct: std::collections::BTreeSet<&String> = ids.iter().collect();
    prop_assert_eq!(distinct.len(), ids.len());
    let other = s.register(SOURCE_B, &body, t0).map_err(|e| e.to_string())?;
    client_id_of(&other)?;
    let later = s
        .register(SOURCE_A, &body, t0 + window)
        .map_err(|e| e.to_string())?;
    client_id_of(&later)?;
    Ok(())
}

/// ADR-013 (Q8): registration is rate-limited per source. Past the limit a
/// source gets 429 and no client; another source is unaffected; a window
/// later the source registers again.
#[test]
fn adr013_registration_is_rate_limited() {
    check("adr013_registration_is_rate_limited", |g| {
        rate_limited(Backend::Production, g)
    });
}

/// The reference twin of `adr013_registration_is_rate_limited`.
#[test]
fn adr013_registration_is_rate_limited_reference() {
    check("adr013_registration_is_rate_limited_reference", |g| {
        rate_limited(Backend::Reference, g)
    });
}

/// Client ids a client ID metadata document flow would fetch.
const URL_CLIENT_IDS: [&str; 4] = [
    "https://agent.example/oauth/client.json",
    "https://agent.example/cb",
    "http://127.0.0.1:8080/client.json",
    "https://cell-a.example/.well-known/oauth-client",
];

fn no_fetch(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let mut h = Harness::start(backend)?;
    let client_id = *g.pick(&URL_CLIENT_IDS);
    g.note("client_id", &client_id);
    let p = AuthorizeParams::valid(client_id, &h.redirect, VERIFIER);
    refused_without_redirect(&h.authorize(&p, 0)?)?;
    let control = h.authorize(&h.params(VERIFIER), 0)?;
    prop_assert!(
        matches!(
            control,
            fstp_api_testkit::mc::oauth_model::AuthorizeReply::Consent(_)
        ),
        "the registered client got {control:?}"
    );
    Ok(())
}

/// ADR-013 (Q8): client metadata documents are off. A URL `client_id` that
/// was never registered is refused with no redirect, so the cell never
/// fetches it.
#[test]
fn adr013_no_client_metadata_fetch() {
    check("adr013_no_client_metadata_fetch", |g| {
        no_fetch(Backend::Production, g)
    });
}

/// The reference twin of `adr013_no_client_metadata_fetch`.
#[test]
fn adr013_no_client_metadata_fetch_reference() {
    check("adr013_no_client_metadata_fetch_reference", |g| {
        no_fetch(Backend::Reference, g)
    });
}

fn no_rights(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let mut h = Harness::start(backend)?;
    let client = h.client_id.clone();
    let redirect = h.redirect.clone();
    let guess: String = g
        .vec(43..=43, |g| {
            char::from(*g.pick(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"))
        })
        .into_iter()
        .collect();
    let attempts: [Vec<u8>; 5] = [
        form(&[
            ("grant_type", "client_credentials"),
            ("client_id", &client),
            ("scope", "calls:read"),
        ]),
        form(&[
            ("grant_type", "password"),
            ("client_id", &client),
            ("username", "a"),
            ("password", "b"),
        ]),
        form(&[
            ("grant_type", "authorization_code"),
            ("client_id", &client),
            ("code", &guess),
            ("redirect_uri", &redirect),
            ("code_verifier", VERIFIER),
        ]),
        form(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client),
            ("refresh_token", &guess),
        ]),
        form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", &client),
            ("device_code", &guess),
        ]),
    ];
    let pick = g.usize_in(0..=attempts.len() - 1);
    g.note("attempt", &pick);
    let body = attempts.get(pick).cloned().unwrap_or_default();
    let r = h.server().token(&body, 1).map_err(|e| e.to_string())?;
    prop_assert!(
        r.status == 400 || r.status == 401,
        "a client without consent got status {}",
        r.status
    );
    prop_assert!(
        r.json()
            .ok()
            .and_then(|v| v.get("access_token").cloned())
            .is_none(),
        "a client without consent got a token"
    );
    let a = h.bearer(&guess, MCP_URL, 1)?;
    prop_assert!(matches!(a, Access::Denied(_)), "a guessed token works");
    let code = h.connect(VERIFIER, MODEL_ACCOUNT, 2)?;
    tokens(&h.exchange(&code, Some(VERIFIER), 2)?)?;
    Ok(())
}

/// ADR-013 (Q8): a registered client has no rights until a consent. No
/// other grant type, guessed code, guessed refresh token or guessed access
/// token gets anything. After a consent, the code flow works.
#[test]
fn adr013_registered_client_has_no_rights_until_consent() {
    check(
        "adr013_registered_client_has_no_rights_until_consent",
        |g| no_rights(Backend::Production, g),
    );
}

/// The reference twin of
/// `adr013_registered_client_has_no_rights_until_consent`.
#[test]
fn adr013_registered_client_has_no_rights_until_consent_reference() {
    check(
        "adr013_registered_client_has_no_rights_until_consent_reference",
        |g| no_rights(Backend::Reference, g),
    );
}
