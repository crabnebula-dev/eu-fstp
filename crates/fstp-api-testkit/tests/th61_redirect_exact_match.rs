//! ADR-013 and TH-61 (TW-4): redirect URIs match exactly (M4 design
//! section 3.8, OAuth 2.1, MCP authorisation "Open Redirection").
//!
//! A presented redirect URI that differs from the registered one in case,
//! a trailing slash, a port, a fragment, a query, userinfo,
//! percent-encoding or a dot segment is refused with no redirect at all.
//! The one exception is the port of a loopback redirect for a native
//! client (RFC 8252 section 7.3). Registration refuses a redirect URI with
//! a fragment, userinfo, a non-ASCII host or plain `http` to a host other
//! than a loopback literal.
//!
//! Every case carries a control: the registered URI itself reaches a
//! consent. Each test has a `_reference` twin that must pass now.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_api_testkit::mc::oauth_model::{
    AuthorizeReply, Backend, Harness, SOURCE_B, ServerConfig, VERIFIER, client_id_of,
    refused_without_redirect, registration_body, server,
};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

fn label(g: &mut Gen, len: std::ops::RangeInclusive<usize>) -> String {
    g.vec(len, |g| char::from(*g.pick(b"abcdefghijklmnopqrstuvwxyz")))
        .into_iter()
        .collect()
}

/// How a presented URI differs from the registered `https` one.
#[derive(Clone, Copy, Debug)]
enum Https {
    UpperHost,
    UpperScheme,
    UpperPath,
    TrailingSlash,
    DefaultPort,
    OtherPort,
    Fragment,
    EmptyFragment,
    Query,
    Userinfo,
    HostAsUserinfo,
    PercentPath,
    DotSegment,
    LongerPath,
    PlainHttp,
    SubdomainOfHost,
}

const HTTPS: [Https; 16] = [
    Https::UpperHost,
    Https::UpperScheme,
    Https::UpperPath,
    Https::TrailingSlash,
    Https::DefaultPort,
    Https::OtherPort,
    Https::Fragment,
    Https::EmptyFragment,
    Https::Query,
    Https::Userinfo,
    Https::HostAsUserinfo,
    Https::PercentPath,
    Https::DotSegment,
    Https::LongerPath,
    Https::PlainHttp,
    Https::SubdomainOfHost,
];

fn upper_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_ascii_uppercase().to_string() + c.as_str(),
        None => String::new(),
    }
}

fn https_variant(host: &str, path: &str, v: Https) -> String {
    match v {
        Https::UpperHost => format!("https://{}/{path}", upper_first(host)),
        Https::UpperScheme => format!("HTTPS://{host}/{path}"),
        Https::UpperPath => format!("https://{host}/{}", upper_first(path)),
        Https::TrailingSlash => format!("https://{host}/{path}/"),
        Https::DefaultPort => format!("https://{host}:443/{path}"),
        Https::OtherPort => format!("https://{host}:8443/{path}"),
        Https::Fragment => format!("https://{host}/{path}#x"),
        Https::EmptyFragment => format!("https://{host}/{path}#"),
        Https::Query => format!("https://{host}/{path}?x=1"),
        Https::Userinfo => format!("https://agent@{host}/{path}"),
        Https::HostAsUserinfo => format!("https://{host}@attacker.example/{path}"),
        Https::PercentPath => {
            let mut c = path.chars();
            let first = c.next().map(u32::from).unwrap_or(0x61);
            format!("https://{host}/%{first:02X}{}", c.as_str())
        }
        Https::DotSegment => format!("https://{host}/./{path}"),
        Https::LongerPath => format!("https://{host}/{path}/x"),
        Https::PlainHttp => format!("http://{host}/{path}"),
        Https::SubdomainOfHost => format!("https://{host}.attacker.example/{path}"),
    }
}

fn exact_https(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let host = format!("{}.example", label(g, 1..=12));
    let path = label(g, 1..=8);
    let registered = format!("https://{host}/{path}");
    let mut h = Harness::with(backend, ServerConfig::synthetic(), &[&registered], 0)?;
    let v = *g.pick(&HTTPS);
    let presented = https_variant(&host, &path, v);
    g.note("presented", &presented);
    prop_assert!(
        presented != registered,
        "the variant equals the registered URI"
    );
    let mut p = h.params(VERIFIER);
    p.redirect_uri = Some(presented);
    refused_without_redirect(&h.authorize(&p, 0)?)?;
    let control = h.authorize(&h.params(VERIFIER), 0)?;
    prop_assert!(
        matches!(control, AuthorizeReply::Consent(_)),
        "the registered URI got {control:?}"
    );
    Ok(())
}

/// ADR-013, TW-4: an `https` redirect URI that differs from the registered
/// one in case, trailing slash, port, fragment, query, userinfo,
/// percent-encoding, a dot segment, a longer path, scheme or host is
/// refused with no redirect.
#[test]
fn adr013_redirect_https_matches_exactly() {
    check("adr013_redirect_https_matches_exactly", |g| {
        exact_https(Backend::Production, g)
    });
}

/// The reference twin of `adr013_redirect_https_matches_exactly`.
#[test]
fn adr013_redirect_https_matches_exactly_reference() {
    check("adr013_redirect_https_matches_exactly_reference", |g| {
        exact_https(Backend::Reference, g)
    });
}

/// How a presented URI relates to a registered loopback one.
#[derive(Clone, Copy, Debug)]
enum Loopback {
    AnyPort,
    NoPort,
    TrailingSlash,
    UpperPath,
    OtherLoopbackHost,
    Https,
    Fragment,
    LongerPath,
}

const LOOPBACK: [Loopback; 8] = [
    Loopback::AnyPort,
    Loopback::NoPort,
    Loopback::TrailingSlash,
    Loopback::UpperPath,
    Loopback::OtherLoopbackHost,
    Loopback::Https,
    Loopback::Fragment,
    Loopback::LongerPath,
];

fn loopback(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let v6 = g.bool();
    let host = if v6 { "[::1]" } else { "127.0.0.1" };
    let other = if v6 { "127.0.0.1" } else { "[::1]" };
    let path = label(g, 1..=8);
    let reg_port = g.option(|g| g.u16_in(1..=65535));
    let port = g.u16_in(1..=65535);
    let registered = match reg_port {
        Some(rp) => format!("http://{host}:{rp}/{path}"),
        None => format!("http://{host}/{path}"),
    };
    let mut h = Harness::with(backend, ServerConfig::synthetic(), &[&registered], 0)?;
    let v = *g.pick(&LOOPBACK);
    let (presented, accepted) = match v {
        Loopback::AnyPort => (format!("http://{host}:{port}/{path}"), true),
        Loopback::NoPort => (format!("http://{host}/{path}"), true),
        Loopback::TrailingSlash => (format!("http://{host}:{port}/{path}/"), false),
        Loopback::UpperPath => (
            format!("http://{host}:{port}/{}", upper_first(&path)),
            false,
        ),
        Loopback::OtherLoopbackHost => (format!("http://{other}:{port}/{path}"), false),
        Loopback::Https => (format!("https://{host}:{port}/{path}"), false),
        Loopback::Fragment => (format!("http://{host}:{port}/{path}#x"), false),
        Loopback::LongerPath => (format!("http://{host}:{port}/{path}/x"), false),
    };
    g.note("registered", &registered);
    g.note("presented", &presented);
    let mut p = h.params(VERIFIER);
    p.redirect_uri = Some(presented);
    let reply = h.authorize(&p, 0)?;
    if accepted {
        prop_assert!(
            matches!(reply, AuthorizeReply::Consent(_)),
            "a loopback redirect with another port got {reply:?}"
        );
    } else {
        refused_without_redirect(&reply)?;
        let control = h.authorize(&h.params(VERIFIER), 0)?;
        prop_assert!(
            matches!(control, AuthorizeReply::Consent(_)),
            "the registered URI got {control:?}"
        );
    }
    Ok(())
}

/// ADR-013, TW-4, RFC 8252: a loopback redirect matches with any port and
/// otherwise exactly.
#[test]
fn adr013_redirect_loopback_port_may_vary() {
    check("adr013_redirect_loopback_port_may_vary", |g| {
        loopback(Backend::Production, g)
    });
}

/// The reference twin of `adr013_redirect_loopback_port_may_vary`.
#[test]
fn adr013_redirect_loopback_port_may_vary_reference() {
    check("adr013_redirect_loopback_port_may_vary_reference", |g| {
        loopback(Backend::Reference, g)
    });
}

/// Redirect URIs registration refuses.
const UNREGISTRABLE: [&str; 9] = [
    "https://agent.example/cb#x",
    "https://agent.example/cb#",
    "https://user@agent.example/cb",
    "https://user:pw@agent.example/cb",
    "https://ag\u{e9}nt.example/cb",
    "https://agent.\u{0435}xample/cb",
    "http://agent.example/cb",
    "javascript:alert(1)",
    "//agent.example/cb",
];

fn registration(backend: Backend, g: &mut Gen) -> Result<(), String> {
    let mut s = server(backend, &ServerConfig::synthetic());
    let bad = *g.pick(&UNREGISTRABLE);
    g.note("redirect", &bad);
    let reply = s
        .register(SOURCE_B, &registration_body(&[bad], None), 0)
        .map_err(|e| e.to_string())?;
    prop_assert_eq!(reply.status, 400);
    prop_assert!(
        reply
            .json()
            .ok()
            .and_then(|v| v.get("client_id").cloned())
            .is_none(),
        "a refused registration issued a client_id"
    );
    let ok = s
        .register(
            SOURCE_B,
            &registration_body(&["https://agent.example/cb"], None),
            0,
        )
        .map_err(|e| e.to_string())?;
    client_id_of(&ok)?;
    Ok(())
}

/// ADR-013, TW-4: registration refuses a redirect URI with a fragment,
/// userinfo or a non-ASCII host, plain `http` to a non-loopback host, and
/// anything that is not an absolute `https` or loopback `http` URI.
#[test]
fn adr013_registration_refuses_unsafe_redirect_uris() {
    check("adr013_registration_refuses_unsafe_redirect_uris", |g| {
        registration(Backend::Production, g)
    });
}

/// The reference twin of `adr013_registration_refuses_unsafe_redirect_uris`.
#[test]
fn adr013_registration_refuses_unsafe_redirect_uris_reference() {
    check(
        "adr013_registration_refuses_unsafe_redirect_uris_reference",
        |g| registration(Backend::Reference, g),
    );
}
