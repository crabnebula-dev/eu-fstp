//! ADR-013 and TH-61 (TW-5): authorisation codes are single use and live
//! 60 seconds (M4 design section 3.8).
//!
//! A second redemption is refused, and it revokes the family the first
//! redemption issued (interim reading of the OAuth 2.1 "SHOULD revoke"). A
//! code is redeemable while younger than 60 seconds and dead at exactly 60
//! seconds, as the repository's other lifetimes are. Each test has a
//! `_reference` twin that must pass now.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_api_testkit::mc::oauth_model::{
    Access, Backend, CODE_LIFETIME_MICROS, Harness, MCP_URL, MODEL_ACCOUNT, gen_verifier, tokens,
};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

fn single_use(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let mut h = Harness::start(backend)?;
    let verifier = gen_verifier(g);
    let t0 = g.i64_in(0..=1_000_000_000);
    let code = h.connect(&verifier, MODEL_ACCOUNT, t0)?;
    let gap = g.i64_in(0..=CODE_LIFETIME_MICROS - 2);
    let first = tokens(&h.exchange(&code, Some(&verifier), t0 + gap)?)?;
    let again = h.exchange(&code, Some(&verifier), t0 + gap + 1)?;
    prop_assert_eq!(again.status, 400);
    prop_assert_eq!(again.error_code(), Some("invalid_grant".to_owned()));
    let now = t0 + gap + 1;
    let a = h.bearer(&first.access, MCP_URL, now)?;
    prop_assert!(
        matches!(a, Access::Denied(_)),
        "the access token of a replayed code still works: {a:?}"
    );
    let r = h.refresh(&first.refresh, now)?;
    prop_assert_eq!(r.status, 400);
    Ok(())
}

/// ADR-013, TH-61, TW-5: a code redeems once. The second redemption gets
/// `invalid_grant` and revokes the tokens of the first.
#[test]
fn th61_code_is_single_use() {
    check("th61_code_is_single_use", |g| {
        single_use(Backend::Production, g)
    });
}

/// The reference twin of `th61_code_is_single_use`.
#[test]
fn th61_code_is_single_use_reference() {
    check("th61_code_is_single_use_reference", |g| {
        single_use(Backend::Reference, g)
    });
}

fn lifetime(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let mut h = Harness::start(backend)?;
    let verifier = gen_verifier(g);
    let t0 = g.i64_in(0..=1_000_000_000);
    let code = h.connect(&verifier, MODEL_ACCOUNT, t0)?;
    let age = g.i64_in(0..=2 * CODE_LIFETIME_MICROS);
    g.note("age", &age);
    let reply = h.exchange(&code, Some(&verifier), t0 + age)?;
    if age < CODE_LIFETIME_MICROS {
        tokens(&reply)?;
    } else {
        prop_assert_eq!(reply.status, 400);
        prop_assert_eq!(reply.error_code(), Some("invalid_grant".to_owned()));
    }
    Ok(())
}

/// ADR-013, TW-5: a code redeems while younger than 60 seconds, and is
/// refused at 60 seconds and after.
#[test]
fn th61_code_lives_60_seconds() {
    check("th61_code_lives_60_seconds", |g| {
        lifetime(Backend::Production, g)
    });
}

/// The reference twin of `th61_code_lives_60_seconds`.
#[test]
fn th61_code_lives_60_seconds_reference() {
    check("th61_code_lives_60_seconds_reference", |g| {
        lifetime(Backend::Reference, g)
    });
}
