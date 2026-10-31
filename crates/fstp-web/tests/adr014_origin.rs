//! The `Origin` header parser of the web adapter (ADR-014 "CSRF", M4
//! design sections 3.8, 3.9 and 9, TH-26, H-05).
//!
//! The parser accepts one serialised origin (RFC 6454 section 6.1) of
//! scheme `http` or `https`, an ASCII host and an optional port. It
//! refuses a list, `null`, a path, a query, a fragment, userinfo,
//! non-ASCII and white space. Equality of parsed values follows the
//! serialised text for origins without an explicit default port. Lane
//! W4e's test author wrote these tests before the parser exists, so each
//! is red because the W0 stub of `fstp_web::parse_origin_header` refuses.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod web_common;

use fstp_prop::{Gen, prop_assert, prop_assert_eq, prop_assert_ne};
use web_common::{Red, all, parse_origin};

/// `Ok` when `r` is a typed refusal that is not the W0 stub.
fn refused<T: std::fmt::Debug>(r: Result<T, Red>) -> Result<(), String> {
    match r {
        Err(Red::Refused(_)) => Ok(()),
        Err(other) => Err(format!("not a typed refusal: {other}")),
        Ok(v) => Err(format!("accepted: {v:?}")),
    }
}

/// ADR-014: serialised origins parse.
#[test]
fn adr014_origin_parse_accepts_serialised_origins() {
    let cases = [
        "https://tenant.fstp.test",
        "https://tenant.fstp.test:8443",
        "http://localhost:8080",
        "https://a.b.c.example",
        "https://xn--bcher-kva.example",
        "https://t-1.example",
    ];
    all(&cases, |o| {
        parse_origin(o.as_bytes())
            .map(|_| ())
            .map_err(|e| e.to_string())
    });
}

/// ADR-014, TH-26: everything that is not one serialised origin is
/// refused with a typed error.
#[test]
fn adr014_origin_parse_refuses_non_origins() {
    let cases: &[&[u8]] = &[
        b"",
        b"null",
        b"https://",
        b"https://tenant.fstp.test/",
        b"https://tenant.fstp.test/path",
        b"https://tenant.fstp.test?q=1",
        b"https://tenant.fstp.test#f",
        b"https://user@tenant.fstp.test",
        b"https://user:pw@tenant.fstp.test",
        b"https://tenant.fstp.test:",
        b"https://tenant.fstp.test:99999",
        b"https://tenant.fstp.test:8a",
        b"https://tenant.fstp.test:-1",
        b"ftp://tenant.fstp.test",
        b"javascript://tenant.fstp.test",
        b"file://",
        b"tenant.fstp.test",
        b"//tenant.fstp.test",
        b"https:tenant.fstp.test",
        b"https:/tenant.fstp.test",
        b"https:///tenant.fstp.test",
        b"https://tenant.fstp.test https://evil.test",
        b"https://tenant.fstp.test,https://evil.test",
        b"https://tenant.fstp.test, https://evil.test",
        b" https://tenant.fstp.test",
        b"https://tenant.fstp.test ",
        b"https://ten ant.fstp.test",
        b"https://ten\tant.fstp.test",
        b"https://tenant.fstp.test\0",
        b"https://t\xc3\xa9nant.fstp.test",
        b"https://tenant.fstp.test\xff",
        b"https://ten%61nt.fstp.test",
        b"https://tenant..fstp.test",
        b"https://.tenant.fstp.test",
        b"https://ten_ant.fstp.test",
        b"https://ten\\ant.fstp.test",
        b"https://[::1",
    ];
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|c| {
            refused(parse_origin(c))
                .err()
                .map(|e| format!("{:?}: {e}", String::from_utf8_lossy(c)))
        })
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A serialised origin with lowercase host labels and no explicit default
/// port.
fn origin(g: &mut Gen) -> String {
    const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let scheme = if g.bool() { "https" } else { "http" };
    let labels = g.vec(1..=3, |g| {
        let n = g.usize_in(1..=6);
        (0..n)
            .map(|_| char::from(*g.pick(ALPHA)))
            .collect::<String>()
    });
    let mut o = format!("{scheme}://{}", labels.join("."));
    if let Some(p) = g.option(|g| g.u16_in(1..=65535)) {
        let default = (scheme == "https" && p == 443) || (scheme == "http" && p == 80);
        if !default {
            o.push_str(&format!(":{p}"));
        }
    }
    o
}

/// ADR-014: two generated origins parse, and their parsed values are
/// equal exactly when their texts are.
#[test]
fn adr014_origin_equality_follows_the_text() {
    fstp_prop::check("adr014_origin_equality_follows_the_text", |g| {
        let a = origin(g);
        let b = if g.bool() { a.clone() } else { origin(g) };
        g.note("a", &a);
        g.note("b", &b);
        let pa = parse_origin(a.as_bytes());
        let pb = parse_origin(b.as_bytes());
        prop_assert!(pa.is_ok() && pb.is_ok(), "{pa:?} {pb:?}");
        if a == b {
            prop_assert_eq!(pa, pb);
        } else {
            prop_assert_ne!(pa, pb);
        }
        Ok(())
    });
}

/// ADR-014, TH-26: one forbidden byte put anywhere into a valid origin
/// makes it refused.
#[test]
fn adr014_origin_parse_refuses_a_forbidden_byte_anywhere() {
    fstp_prop::check(
        "adr014_origin_parse_refuses_a_forbidden_byte_anywhere",
        |g| {
            const FORBIDDEN: &[u8] = b" \t\r\n\0\x7f/?#@,;\\\"'<>%[]|^`{}";
            let o = origin(g).into_bytes();
            let at = g.usize_in(0..=o.len());
            let bad = if g.bool() {
                *g.pick(FORBIDDEN)
            } else {
                g.u8_in(0x80..=0xff)
            };
            let mut changed = o[..at].to_vec();
            changed.push(bad);
            changed.extend_from_slice(&o[at..]);
            g.note("value", &String::from_utf8_lossy(&changed));
            refused(parse_origin(&changed))
        },
    );
}
