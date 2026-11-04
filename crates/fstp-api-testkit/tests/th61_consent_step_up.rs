//! I-78 and TH-61 (TW-8): connecting an agent links a device, so the
//! consent needs a fresh phishing-resistant step-up bound to that consent
//! (`mcp-server.md`, `authentication.md`, M4 design section 3.8).
//!
//! The authorisation server checks the proof itself, as defence in depth
//! behind the API core: a magic-link session, a missing proof, a proof by
//! magic link, a proof by another account, a proof for another digest and
//! a proof at or past P-71 all get no code. A proof younger than P-71
//! gets a code. The consent shows the client name as untrusted text and
//! the redirect host. Each test has a `_reference` twin that must pass
//! now.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_api_testkit::mc::oauth_model::{
    AccountRef, AuthorizeReply, Backend, ConsentAuth, ConsentTicket, Harness, MODEL_ACCOUNT,
    Method, P71_MICROS, ServerConfig, StepUpProof, code_of, gen_verifier,
};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

/// A consent approval that must get no code.
#[derive(Clone, Copy, Debug)]
enum Weak {
    MagicLinkSession,
    NoProof,
    MagicLinkProof,
    OtherAccount,
    OtherDigest,
    Stale,
    Future,
}

const WEAK: [Weak; 7] = [
    Weak::MagicLinkSession,
    Weak::NoProof,
    Weak::MagicLinkProof,
    Weak::OtherAccount,
    Weak::OtherDigest,
    Weak::Stale,
    Weak::Future,
];

fn ticket(h: &mut Harness, verifier: &str, now: i64) -> Result<ConsentTicket, String> {
    match h.authorize(&h.params(verifier), now)? {
        AuthorizeReply::Consent(t) => Ok(t),
        other => Err(format!("a valid request got {other:?}")),
    }
}

fn weak(w: Weak, t: &ConsentTicket, now: i64, g: &mut Gen) -> ConsentAuth {
    let mut auth = ConsentAuth::fresh(MODEL_ACCOUNT, t, now);
    let proof = |f: &dyn Fn(&mut StepUpProof)| {
        let mut p = StepUpProof {
            account: MODEL_ACCOUNT,
            digest: t.digest,
            at: now,
            method: Method::PhishingResistant,
        };
        f(&mut p);
        Some(p)
    };
    match w {
        Weak::MagicLinkSession => auth.session = Method::MagicLink,
        Weak::NoProof => auth.step_up = None,
        Weak::MagicLinkProof => auth.step_up = proof(&|p| p.method = Method::MagicLink),
        Weak::OtherAccount => {
            auth.step_up = proof(&|p| p.account = AccountRef(MODEL_ACCOUNT.0 ^ 1));
        }
        Weak::OtherDigest => {
            let bit = g.u8_in(0..=7);
            let byte = g.usize_in(0..=31);
            auth.step_up = proof(&|p| {
                if let Some(b) = p.digest.get_mut(byte) {
                    *b ^= 1 << bit;
                }
            });
        }
        Weak::Stale => {
            let age = g.i64_in(P71_MICROS..=2 * P71_MICROS);
            auth.step_up = proof(&|p| p.at = now - age);
        }
        Weak::Future => {
            let ahead = g.i64_in(1..=P71_MICROS);
            auth.step_up = proof(&|p| p.at = now + ahead);
        }
    }
    auth
}

fn step_up(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let mut h = Harness::start(backend)?;
    let verifier = gen_verifier(g);
    let now = g.i64_in(2 * P71_MICROS..=1_000_000_000);
    let t = ticket(&mut h, &verifier, now)?;
    let w = *g.pick(&WEAK);
    g.note("weak", &w);
    let auth = weak(w, &t, now, g);
    let reply = h
        .server()
        .consent(&t, MODEL_ACCOUNT, &auth, now)
        .map_err(|e| e.to_string())?;
    if let AuthorizeReply::Redirect(loc) = &reply {
        prop_assert!(
            code_of(loc, &h.redirect)?.is_none(),
            "a {w:?} approval got a code: {loc}"
        );
    }
    let fresh = ticket(&mut h, &verifier, now)?;
    let age = g.i64_in(0..=P71_MICROS - 1);
    g.note("control age", &age);
    let mut ok = ConsentAuth::fresh(MODEL_ACCOUNT, &fresh, now);
    if let Some(p) = ok.step_up.as_mut() {
        p.at = now - age;
    }
    let control = h
        .server()
        .consent(&fresh, MODEL_ACCOUNT, &ok, now)
        .map_err(|e| e.to_string())?;
    match control {
        AuthorizeReply::Redirect(loc) => {
            prop_assert!(
                code_of(&loc, &h.redirect)?.is_some(),
                "a fresh step-up got no code: {loc}"
            );
        }
        other => return Err(format!("a fresh step-up got {other:?}")),
    }
    Ok(())
}

/// I-78, TH-61: the consent issues a code only for a phishing-resistant
/// session with a phishing-resistant step-up by the same account, bound
/// to this consent's digest, younger than P-71.
#[test]
fn i78_consent_needs_fresh_phishing_resistant_step_up() {
    check("i78_consent_needs_fresh_phishing_resistant_step_up", |g| {
        step_up(Backend::Production, g)
    });
}

/// The reference twin of
/// `i78_consent_needs_fresh_phishing_resistant_step_up`.
#[test]
fn i78_consent_needs_fresh_phishing_resistant_step_up_reference() {
    check(
        "i78_consent_needs_fresh_phishing_resistant_step_up_reference",
        |g| step_up(Backend::Reference, g),
    );
}

fn shown(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let pool: Vec<char> = "abcXYZ019<>\"'&/\\=:.-_\u{e9}\u{6f22}".chars().collect();
    let name: String = g.vec(1..=40, |g| *g.pick(&pool)).into_iter().collect();
    let host = "agent-7.example";
    let redirect = format!("https://{host}/cb");
    let mut h = Harness::with(backend, ServerConfig::synthetic(), &[&redirect], 0)?;
    let reg = fstp_api_testkit::mc::oauth_model::registration_body(&[&redirect], Some(&name));
    let r = h
        .server()
        .register(fstp_api_testkit::mc::oauth_model::SOURCE_B, &reg, 0)
        .map_err(|e| e.to_string())?;
    let client = fstp_api_testkit::mc::oauth_model::client_id_of(&r)?;
    let p = fstp_api_testkit::mc::oauth_model::AuthorizeParams::valid(
        &client,
        &redirect,
        &gen_verifier(g),
    );
    let AuthorizeReply::Consent(t) = h.authorize(&p, 0)? else {
        return Err("a valid request got no consent".to_owned());
    };
    prop_assert_eq!(t.client_name.as_deref(), Some(name.as_str()));
    prop_assert_eq!(t.redirect_host.as_str(), host);
    prop_assert_eq!(
        t.scopes,
        vec!["calls:read".to_owned(), "calls:draft".to_owned()]
    );
    Ok(())
}

/// TH-61 (TW-8): the consent carries the client name byte for byte, for
/// display as untrusted text, the redirect host and every scope asked
/// for.
#[test]
fn th61_consent_shows_client_name_redirect_host_and_scopes() {
    check(
        "th61_consent_shows_client_name_redirect_host_and_scopes",
        |g| shown(Backend::Production, g),
    );
}

/// The reference twin of
/// `th61_consent_shows_client_name_redirect_host_and_scopes`.
#[test]
fn th61_consent_shows_client_name_redirect_host_and_scopes_reference() {
    check(
        "th61_consent_shows_client_name_redirect_host_and_scopes_reference",
        |g| shown(Backend::Reference, g),
    );
}
