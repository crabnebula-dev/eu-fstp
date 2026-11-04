//! Review reproducer for TW-4 (M4 design section 5.2, ADR-013).
//!
//! Registration is open (Q8), so every redirect URI is chosen by whoever
//! registers. An error at `/oauth/authorize` that redirects at once, with
//! no user interaction, turns the cell's own origin into an open
//! redirector to any registered URI (RFC 9700 section 4.11.2).

use fstp_oauth::{AuthorizationServer, AuthorizeOutcome, Config, RateKey};

const ISSUER: &str = "https://cell-a.example";
const MCP: &str = "https://cell-a.example/mcp";
const EVIL: &str = "https://evil.example/landing";

fn server_with_evil_client() -> Result<(AuthorizationServer, String), String> {
    let cfg = Config::new(ISSUER, MCP, 43_200_000_000, 300_000_000);
    let mut s = AuthorizationServer::new(cfg).map_err(|e| e.to_string())?;
    let r = s.register(
        RateKey::from_raw(9),
        br#"{"redirect_uris":["https://evil.example/landing"]}"#,
        0,
    );
    let id = fstp_json::parse(&r.body)
        .ok()
        .and_then(|v| {
            v.get("client_id")
                .and_then(fstp_json::Value::as_str)
                .map(str::to_owned)
        })
        .ok_or_else(|| format!("registration refused: {}", r.status))?;
    Ok((s, id))
}

/// TW-4, ADR-013 (no open redirect): an authorisation request that fails
/// before any user interaction must not send the user agent to a
/// dynamically registered, untrusted redirect URI. Here the request names
/// no PKCE challenge, so it can never yield a code, yet the server answers
/// with an immediate redirect to the attacker's URI.
#[test]
fn review_tw4_error_redirect_to_untrusted_uri_without_user_interaction() {
    let setup = server_with_evil_client();
    assert!(setup.is_ok(), "{setup:?}");
    let Ok((mut s, id)) = setup else {
        return;
    };
    let q = fstp_oauth::encode_form_urlencoded(&[
        ("response_type", "token"),
        ("client_id", &id),
        ("redirect_uri", EVIL),
    ]);
    let outcome = s.authorize(q.as_bytes(), 0);
    assert!(
        !matches!(outcome, AuthorizeOutcome::Redirect(_)),
        "the cell's authorise endpoint redirected at once to a self-registered URI: {outcome:?}"
    );
}
