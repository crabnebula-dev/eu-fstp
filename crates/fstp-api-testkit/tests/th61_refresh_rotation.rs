//! TH-61 (T-MC-TOKEN), ADR-013 and R-MC-03: refresh tokens rotate, reuse
//! revokes the family, and revocation takes effect at once (M4 design
//! sections 3.8 and 5.1, Q25).
//!
//! Each rotation issues a new refresh token and a new access token, both
//! distinct from every earlier one. Presenting a rotated refresh token is
//! refused and revokes the whole family: its current refresh token and
//! every access token it issued. Another family of the same account and
//! client is untouched. RFC 7009 revocation of a refresh token ends its
//! family, and ending the agent ends every family and unredeemed code of
//! that client. Each test has a `_reference` twin that must pass now.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeSet;

use fstp_api_testkit::mc::oauth_model::{
    ACCESS_LIFETIME_MICROS, Access, Backend, Harness, MCP_URL, MODEL_ACCOUNT, TokenSet,
    gen_verifier, tokens,
};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

fn granted(h: &mut Harness, access: &str, now: i64) -> Result<bool, String> {
    Ok(matches!(
        h.bearer(access, MCP_URL, now)?,
        Access::Granted(_)
    ))
}

/// A family with `n` rotations, one second apart from `t0`. Returns every
/// token set in issue order and the instant of the last.
fn chain(
    h: &mut Harness,
    verifier: &str,
    t0: i64,
    n: usize,
) -> Result<(Vec<TokenSet>, i64), String> {
    let mut sets = vec![h.family(verifier, MODEL_ACCOUNT, t0)?];
    let mut now = t0;
    for _ in 0..n {
        now += 1_000_000;
        let last = sets.last().map(|t| t.refresh.clone()).unwrap_or_default();
        sets.push(tokens(&h.refresh(&last, now)?)?);
    }
    Ok((sets, now))
}

fn rotates(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let mut h = Harness::start(backend)?;
    let verifier = gen_verifier(g);
    let n = g.usize_in(1..=4);
    let (sets, now) = chain(&mut h, &verifier, 0, n)?;
    let mut seen = BTreeSet::new();
    for t in &sets {
        prop_assert!(seen.insert(t.refresh.clone()), "a refresh token repeats");
        prop_assert!(seen.insert(t.access.clone()), "an access token repeats");
        prop_assert_eq!(t.expires_in, ACCESS_LIFETIME_MICROS / 1_000_000);
    }
    let newest = sets.last().cloned().ok_or("no token set")?;
    prop_assert!(
        granted(&mut h, &newest.access, now)?,
        "the newest access token is refused"
    );
    tokens(&h.refresh(&newest.refresh, now + 1)?)?;
    Ok(())
}

/// TH-61, ADR-013: every rotation issues a new refresh token and a new
/// 10-minute access token, and the newest refresh token rotates again.
#[test]
fn th61_refresh_rotates_tokens() {
    check("th61_refresh_rotates_tokens", |g| {
        rotates(Backend::Production, g)
    });
}

/// The reference twin of `th61_refresh_rotates_tokens`.
#[test]
fn th61_refresh_rotates_tokens_reference() {
    check("th61_refresh_rotates_tokens_reference", |g| {
        rotates(Backend::Reference, g)
    });
}

fn reuse(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let mut h = Harness::start(backend)?;
    let verifier = gen_verifier(g);
    let n = g.usize_in(1..=4);
    let (sets, now) = chain(&mut h, &verifier, 0, n)?;
    let other = h.family(&gen_verifier(g), MODEL_ACCOUNT, now)?;
    let stale = g.usize_in(0..=n - 1);
    g.note("stale", &stale);
    let stale_token = sets
        .get(stale)
        .map(|t| t.refresh.clone())
        .unwrap_or_default();
    let r = h.refresh(&stale_token, now + 1)?;
    prop_assert_eq!(r.status, 400);
    prop_assert_eq!(r.error_code(), Some("invalid_grant".to_owned()));
    let current = sets.last().map(|t| t.refresh.clone()).unwrap_or_default();
    let r = h.refresh(&current, now + 2)?;
    prop_assert_eq!(r.status, 400);
    for (i, t) in sets.iter().enumerate() {
        prop_assert!(
            !granted(&mut h, &t.access, now + 3)?,
            "access token {i} of the reused family still works"
        );
    }
    prop_assert!(
        granted(&mut h, &other.access, now + 3)?,
        "the reuse revoked another family"
    );
    tokens(&h.refresh(&other.refresh, now + 4)?)?;
    Ok(())
}

/// TH-61 (T-MC-TOKEN): presenting a rotated refresh token is refused and
/// revokes the family: its current refresh token and every access token
/// it issued. Another family is untouched.
#[test]
fn th61_refresh_reuse_revokes_family() {
    check("th61_refresh_reuse_revokes_family", |g| {
        reuse(Backend::Production, g)
    });
}

/// The reference twin of `th61_refresh_reuse_revokes_family`.
#[test]
fn th61_refresh_reuse_revokes_family_reference() {
    check("th61_refresh_reuse_revokes_family_reference", |g| {
        reuse(Backend::Reference, g)
    });
}

fn revocation(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let mut h = Harness::start(backend)?;
    let a = h.family(&gen_verifier(g), MODEL_ACCOUNT, 0)?;
    let b = h.family(&gen_verifier(g), MODEL_ACCOUNT, 1)?;
    let pending_verifier = gen_verifier(g);
    let pending = h.connect(&pending_verifier, MODEL_ACCOUNT, 2)?;
    let by_agent = g.bool();
    g.note("by_agent", &by_agent);
    if by_agent {
        let client = h.client_id.clone();
        h.server()
            .revoke_agent(MODEL_ACCOUNT, &client, 3)
            .map_err(|e| e.to_string())?;
        for (name, t) in [("a", &a), ("b", &b)] {
            prop_assert!(
                !granted(&mut h, &t.access, 4)?,
                "family {name} survives ending the agent"
            );
            prop_assert_eq!(h.refresh(&t.refresh, 4)?.status, 400);
        }
        let r = h.exchange(&pending, Some(&pending_verifier), 4)?;
        prop_assert_eq!(r.status, 400);
    } else {
        let r = h.revoke(&a.refresh, 3)?;
        prop_assert_eq!(r.status, 200);
        prop_assert!(
            !granted(&mut h, &a.access, 4)?,
            "a revoked family's access token works"
        );
        prop_assert_eq!(h.refresh(&a.refresh, 4)?.status, 400);
        prop_assert!(
            granted(&mut h, &b.access, 4)?,
            "revoking one family revoked another"
        );
        tokens(&h.exchange(&pending, Some(&pending_verifier), 4)?)?;
    }
    Ok(())
}

/// R-MC-03, TH-61: RFC 7009 revocation of a refresh token ends its family
/// at once and no other. Ending the agent ends every family and every
/// unredeemed code of that client at once.
#[test]
fn th61_revocation_takes_effect_at_once() {
    check("th61_revocation_takes_effect_at_once", |g| {
        revocation(Backend::Production, g)
    });
}

/// The reference twin of `th61_revocation_takes_effect_at_once`.
#[test]
fn th61_revocation_takes_effect_at_once_reference() {
    check("th61_revocation_takes_effect_at_once_reference", |g| {
        revocation(Backend::Reference, g)
    });
}
