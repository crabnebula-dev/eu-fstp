//! Issue 6 open question: a revoked or unknown bearer on `/mcp`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::decode::decode_tool;
use fstp_api_core::meta::Scope;
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, Credential, ErrorCode};
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::fixture::{AGENT, LEAD};

fn public_call(c: &FakeCell, cred: Credential) -> Result<fstp_api_core::OpResult, ApiError> {
    c.call(
        cred,
        decode_tool("fstp_public_get_programme", br#"{"slug":"nowhere"}"#),
    )
}

fn is_unauthenticated(r: &Result<fstp_api_core::OpResult, ApiError>) -> bool {
    matches!(
        r,
        Err(ApiError::Refused {
            code: ErrorCode::Unauthenticated,
            ..
        })
    )
}

/// Issue 6 open question, H-23, ADR-013 ("An invalid or expired token
/// gets 401"): a bearer that resolves to no grant (unknown, revoked or
/// expired, which the token port answers alike) is refused as
/// unauthenticated on a public tool, and is not made anonymous. A valid
/// token and a call with no credential are unchanged.
#[test]
fn issue6_mcp_revoked_bearer_gets_401_on_public_tool() {
    let c = FakeCell::new().unwrap_or_else(|e| panic!("the fake cell: {e}"));
    // Unknown token.
    let unknown = public_call(&c, Credential::Bearer(b"no-such-token".to_vec()));
    assert!(is_unauthenticated(&unknown), "unknown: {unknown:?}");
    // Revoked token.
    let token = c.token(LEAD, AGENT, [Scope::CallsRead], LoginMethod::Passkey);
    let live = public_call(&c, Credential::Bearer(token.clone()));
    assert!(!is_unauthenticated(&live), "valid: {live:?}");
    c.ports.tokens.revoke(LEAD, AGENT).unwrap();
    let revoked = public_call(&c, Credential::Bearer(token));
    assert!(is_unauthenticated(&revoked), "revoked: {revoked:?}");
    // Control: no credential stays anonymous and reaches the public tool.
    let none = public_call(&c, Credential::None);
    assert!(!is_unauthenticated(&none), "no credential: {none:?}");
}
