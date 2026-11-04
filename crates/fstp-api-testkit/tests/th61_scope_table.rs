//! ADR-013 "Scopes": `fstp-oauth` and the `fstp-access` registry spell the
//! same twelve M4 scopes in the same order.
//!
//! `fstp-oauth` depends only on `fstp-json` and `fstp-crypto` (design
//! section 1.1), so it cannot name `fstp_access::Scope`. The API core maps
//! a grant's scopes by their wire spelling. This test keeps the two tables
//! equal, so no grant can carry a scope the registry does not know.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_api_testkit::mc::oauth_model::SCOPES;

/// ADR-013: the authorisation server, the registry and the M-OAUTH test
/// surface hold one scope table.
#[test]
fn adr013_scope_tables_agree() {
    let oauth: Vec<&str> = fstp_oauth::Scope::ALL.iter().map(|s| s.as_str()).collect();
    let access: Vec<&str> = fstp_access::Scope::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(oauth, access, "fstp-oauth and fstp-access disagree");
    assert_eq!(
        oauth,
        SCOPES.to_vec(),
        "fstp-oauth and the test surface disagree"
    );
}
