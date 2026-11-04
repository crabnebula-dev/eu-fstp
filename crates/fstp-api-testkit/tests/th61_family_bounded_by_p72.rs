//! ADR-013, Q25 and P-72: no refresh family outlives the P-72 absolute
//! lifetime, and access tokens live 10 minutes (M4 design section 3.8).
//!
//! A family starts when its code is redeemed. Refreshing is accepted while
//! the family is younger than P-72 and refused from P-72 on. Every access
//! token expires at the earlier of 10 minutes after issue and the end of
//! its family, so no token outlives its family. `expires_in` never claims
//! more than that. Each test has a `_reference` twin that must pass now.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_api_testkit::mc::oauth_model::{
    ACCESS_LIFETIME_MICROS, Access, Backend, Harness, MCP_URL, MODEL_ACCOUNT, P72_ABSOLUTE_MICROS,
    TokenSet, gen_verifier, tokens,
};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

fn granted(h: &mut Harness, access: &str, now: i64) -> Result<bool, String> {
    Ok(matches!(
        h.bearer(access, MCP_URL, now)?,
        Access::Granted(_)
    ))
}

/// Checks `t`, issued at `issued` in a family ending at `end`: it works at
/// `issued`, works just before its expiry, and is dead at its expiry.
fn check_access(h: &mut Harness, t: &TokenSet, issued: i64, end: i64) -> Result<(), String> {
    let expiry = (issued + ACCESS_LIFETIME_MICROS).min(end);
    prop_assert!(t.expires_in >= 0, "expires_in is negative");
    prop_assert!(
        t.expires_in * 1_000_000 <= expiry - issued + 999_999,
        "expires_in {} claims more than the {} µs left",
        t.expires_in,
        expiry - issued
    );
    prop_assert!(
        granted(h, &t.access, issued)?,
        "a new access token is refused"
    );
    prop_assert!(
        granted(h, &t.access, expiry - 1)?,
        "an access token is refused before its expiry"
    );
    prop_assert!(
        !granted(h, &t.access, expiry)?,
        "an access token works at its expiry ({} µs after issue, family end {})",
        expiry - issued,
        end - issued
    );
    Ok(())
}

fn bounded(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let mut h = Harness::start(backend)?;
    let start = g.i64_in(0..=1_000_000_000);
    let end = start + P72_ABSOLUTE_MICROS;
    let first = h.family(&gen_verifier(g), MODEL_ACCOUNT, start)?;
    let mut current = first.refresh.clone();
    let mut now = start;
    check_access(&mut h, &first, start, end)?;
    let mut refreshes = 0usize;
    loop {
        let gap = g.i64_in(ACCESS_LIFETIME_MICROS..=P72_ABSOLUTE_MICROS / 3);
        now += gap;
        let reply = h.refresh(&current, now)?;
        if now < end {
            let t = tokens(&reply)?;
            check_access(&mut h, &t, now, end)?;
            current = t.refresh;
            refreshes += 1;
        } else {
            prop_assert_eq!(reply.status, 400);
            prop_assert_eq!(reply.error_code(), Some("invalid_grant".to_owned()));
            break;
        }
    }
    g.note("refreshes", &refreshes);
    Ok(())
}

/// P-72, ADR-013 (Q25): refreshing works while the family is younger than
/// P-72 and is refused from then on. Each access token works until the
/// earlier of 10 minutes and the family's end, and not at that instant.
#[test]
fn th61_family_never_outlives_p72() {
    check("th61_family_never_outlives_p72", |g| {
        bounded(Backend::Production, g)
    });
}

/// The reference twin of `th61_family_never_outlives_p72`.
#[test]
fn th61_family_never_outlives_p72_reference() {
    check("th61_family_never_outlives_p72_reference", |g| {
        bounded(Backend::Reference, g)
    });
}

fn near_end(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let mut h = Harness::start(backend)?;
    let start = g.i64_in(0..=1_000_000_000);
    let end = start + P72_ABSOLUTE_MICROS;
    let first = h.family(&gen_verifier(g), MODEL_ACCOUNT, start)?;
    let left = g.i64_in(1..=ACCESS_LIFETIME_MICROS);
    g.note("left", &left);
    let at = end - left;
    let t = tokens(&h.refresh(&first.refresh, at)?)?;
    check_access(&mut h, &t, at, end)?;
    let r = h.refresh(&t.refresh, end)?;
    prop_assert_eq!(r.status, 400);
    Ok(())
}

/// P-72, ADR-013 (Q25): a refresh in the family's last 10 minutes issues
/// an access token that dies with the family, and the family's last
/// refresh token is refused at its end.
#[test]
fn th61_access_token_dies_with_its_family() {
    check("th61_access_token_dies_with_its_family", |g| {
        near_end(Backend::Production, g)
    });
}

/// The reference twin of `th61_access_token_dies_with_its_family`.
#[test]
fn th61_access_token_dies_with_its_family_reference() {
    check("th61_access_token_dies_with_its_family_reference", |g| {
        near_end(Backend::Reference, g)
    });
}
