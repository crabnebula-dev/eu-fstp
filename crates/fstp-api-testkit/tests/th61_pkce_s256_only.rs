//! ADR-013 and TH-61 (TW-5): PKCE with `S256` only (M4 design section
//! 3.8). `plain`, an absent method, any other spelling and an absent
//! challenge are refused at the authorisation endpoint. At the token
//! endpoint, only the verifier of the challenge redeems the code.
//!
//! Every case carries a control: the same verifier with a valid `S256`
//! request reaches a consent, or redeems a fresh code. So a server that
//! refuses everything fails. Each test has a `_reference` twin that runs
//! the reference server and must pass now.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_api_testkit::mc::oauth_model::{
    AuthorizeReply, Backend, Harness, MODEL_ACCOUNT, gen_verifier, refused_authorization, s256,
    tokens,
};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

/// Methods other than `S256`. `None` leaves the parameter out.
const METHODS: [Option<&str>; 8] = [
    Some("plain"),
    None,
    Some(""),
    Some("s256"),
    Some("S256 "),
    Some("PLAIN"),
    Some("S512"),
    Some("S256,plain"),
];

fn methods(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let mut h = Harness::start(backend)?;
    let verifier = gen_verifier(g);
    let method = *g.pick(&METHODS);
    g.note("method", &method);
    let mut p = h.params(&verifier);
    p.code_challenge_method = method.map(str::to_owned);
    if method.is_some_and(|m| m.eq_ignore_ascii_case("plain")) {
        p.code_challenge = Some(verifier.clone());
    }
    let reply = h.authorize(&p, 0)?;
    refused_authorization(&reply, &h.redirect)?;
    let control = h.authorize(&h.params(&verifier), 0)?;
    prop_assert!(
        matches!(control, AuthorizeReply::Consent(_)),
        "a valid S256 request got {control:?}"
    );
    Ok(())
}

/// ADR-013, TW-5: every `code_challenge_method` other than `S256`, absent
/// included, is refused, and the `S256` request with the same verifier is
/// accepted.
#[test]
fn adr013_pkce_methods_other_than_s256_refused() {
    check("adr013_pkce_methods_other_than_s256_refused", |g| {
        methods(Backend::Production, g)
    });
}

/// The reference twin of `adr013_pkce_methods_other_than_s256_refused`.
#[test]
fn adr013_pkce_methods_other_than_s256_refused_reference() {
    check(
        "adr013_pkce_methods_other_than_s256_refused_reference",
        |g| methods(Backend::Reference, g),
    );
}

fn absent_challenge(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let mut h = Harness::start(backend)?;
    let verifier = gen_verifier(g);
    let mut p = h.params(&verifier);
    p.code_challenge = None;
    if g.bool() {
        p.code_challenge_method = None;
    }
    let reply = h.authorize(&p, 0)?;
    refused_authorization(&reply, &h.redirect)?;
    let control = h.authorize(&h.params(&verifier), 0)?;
    prop_assert!(
        matches!(control, AuthorizeReply::Consent(_)),
        "a valid S256 request got {control:?}"
    );
    Ok(())
}

/// ADR-013, TW-5: a request without `code_challenge` is refused, with or
/// without a method.
#[test]
fn adr013_pkce_absent_challenge_refused() {
    check("adr013_pkce_absent_challenge_refused", |g| {
        absent_challenge(Backend::Production, g)
    });
}

/// The reference twin of `adr013_pkce_absent_challenge_refused`.
#[test]
fn adr013_pkce_absent_challenge_refused_reference() {
    check("adr013_pkce_absent_challenge_refused_reference", |g| {
        absent_challenge(Backend::Reference, g)
    });
}

/// A verifier that does not belong to the challenge of `verifier`.
#[derive(Clone, Copy, Debug)]
enum Bad {
    /// No `code_verifier` parameter.
    Absent,
    /// Another valid verifier.
    Other,
    /// The challenge itself, as a `plain` client would send.
    TheChallenge,
    /// The verifier with its last character changed.
    OneOff,
    /// The verifier cut to 42 characters.
    TooShort,
}

const BAD: [Bad; 5] = [
    Bad::Absent,
    Bad::Other,
    Bad::TheChallenge,
    Bad::OneOff,
    Bad::TooShort,
];

fn verifier_must_match(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let mut h = Harness::start(backend)?;
    let verifier = gen_verifier(g);
    let bad = *g.pick(&BAD);
    g.note("bad", &bad);
    let sent = match bad {
        Bad::Absent => None,
        Bad::Other => {
            let other = gen_verifier(g);
            g.assume(s256(&other) != s256(&verifier));
            Some(other)
        }
        Bad::TheChallenge => Some(s256(&verifier)),
        Bad::OneOff => {
            let mut v = verifier.clone();
            let last = v.pop().unwrap_or('a');
            v.push(if last == 'a' { 'b' } else { 'a' });
            Some(v)
        }
        Bad::TooShort => Some(verifier.chars().take(42).collect()),
    };
    let code = h.connect(&verifier, MODEL_ACCOUNT, 0)?;
    let reply = h.exchange(&code, sent.as_deref(), 1)?;
    prop_assert!(
        reply.status == 400,
        "a wrong verifier got status {}",
        reply.status
    );
    prop_assert_eq!(reply.error_code(), Some("invalid_grant".to_owned()));
    prop_assert!(
        reply
            .json()
            .ok()
            .and_then(|v| v.get("access_token").cloned())
            .is_none(),
        "a refused exchange carries a token"
    );
    let fresh = h.connect(&verifier, MODEL_ACCOUNT, 2)?;
    tokens(&h.exchange(&fresh, Some(&verifier), 3)?)?;
    Ok(())
}

/// ADR-013, TW-5: only the verifier of the `S256` challenge redeems the
/// code. An absent verifier, another verifier, the challenge itself, a
/// verifier one character off and one too short get `invalid_grant`.
#[test]
fn adr013_pkce_verifier_must_match_challenge() {
    check("adr013_pkce_verifier_must_match_challenge", |g| {
        verifier_must_match(Backend::Production, g)
    });
}

/// The reference twin of `adr013_pkce_verifier_must_match_challenge`.
#[test]
fn adr013_pkce_verifier_must_match_challenge_reference() {
    check("adr013_pkce_verifier_must_match_challenge_reference", |g| {
        verifier_must_match(Backend::Reference, g)
    });
}
