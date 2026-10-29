//! Tests of `fstp_release_svc::decode_refresh_request` (I-38, design
//! sections 10.1 and 15, `refresh_request_decode`).
//!
//! The licence service accepts only the refresh template: `POST
//! /v1/licences/{hex id}/refresh` with Host, Content-Type and
//! Content-Length, and the body `{"version":"x.y.z"}`. Every accepted
//! input is exactly what `fstp_release::egress::encode` gives for the
//! decoded fields, so a request that carries anything else is refused.
//!
//! The tests are red until lane W2j lands `encode` and the decoder.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/common.rs"]
mod common;

use fstp_prop::{Gen, check, prop_assert_eq};
use fstp_release::egress::CnCall;
use fstp_release_svc::RefreshRequest;

use common::{
    decode_refresh, encode, gen_refresh, gen_update, mutate, refresh_call, replace_once,
    with_header,
};

/// A random refresh call and its production bytes.
fn sample(g: &mut Gen) -> Result<(CnCall, Vec<u8>), String> {
    let call = CnCall::Licence(gen_refresh(g));
    let bytes = encode(&call)?;
    Ok((call, bytes))
}

/// I-38, design section 10.1: the service decodes every request the cell
/// can send to exactly the licence id and version it carries.
#[test]
fn i38_refresh_request_decodes_what_egress_encodes() {
    check("i38_refresh_request_decodes_what_egress_encodes", |g| {
        let r = gen_refresh(g);
        let bytes = encode(&CnCall::Licence(r))?;
        let want = RefreshRequest {
            licence: r.licence.0,
            version: (r.version.0, r.version.1, r.version.2),
        };
        prop_assert_eq!(decode_refresh(&bytes)?, Some(want));
        Ok(())
    });
}

/// I-38, design section 15 ("only the permitted grammar"): after any one
/// byte is changed, inserted or deleted, the request is refused, or it
/// decodes to fields whose template is exactly the edited bytes. So no
/// second spelling of a request is accepted.
#[test]
fn i38_refresh_request_has_one_spelling() {
    check("i38_refresh_request_has_one_spelling", |g| {
        let (_, bytes) = sample(g)?;
        let edited = mutate(g, &bytes);
        if let Some(r) = decode_refresh(&edited)? {
            prop_assert_eq!(encode(&refresh_call(&r))?, edited);
        }
        Ok(())
    });
}

/// I-38, design section 10.1: a request with any further header is
/// refused: a cookie, a User-Agent, a tenant or cell header, a second
/// Host or an authorization header.
#[test]
fn i38_refresh_request_refuses_extra_headers() {
    const HEADERS: [&str; 7] = [
        "Cookie: session=0123",
        "User-Agent: fstp-cell/1.2.3",
        "X-Tenant: acme",
        "X-Cell: c-0001",
        "Host: other.example.com",
        "Authorization: Bearer abc",
        "Forwarded: for=192.0.2.1",
    ];
    check("i38_refresh_request_refuses_extra_headers", |g| {
        let (_, bytes) = sample(g)?;
        let line = *g.pick(&HEADERS);
        prop_assert_eq!(decode_refresh(&with_header(&bytes, line))?, None, "{line}");
        Ok(())
    });
}

/// I-38, design section 10.1: a body with any member other than
/// `version`, or with whitespace, is refused even when Content-Length
/// matches.
#[test]
fn i38_refresh_request_refuses_other_bodies() {
    check("i38_refresh_request_refuses_other_bodies", |g| {
        let (_, bytes) = sample(g)?;
        let text = String::from_utf8(bytes).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        let other = match g.u8_in(0..=4) {
            0 => body.replacen('}', ",\"tenant\":\"acme\"}", 1),
            1 => body.replacen(':', ": ", 1),
            2 => format!("{body}\n"),
            3 => body.replacen("\"version\"", "\"Version\"", 1),
            _ => "{}".to_owned(),
        };
        let old_len = format!("Content-Length: {}", body.len());
        let new_len = format!("Content-Length: {}", other.len());
        let request = format!("{}\r\n\r\n{other}", head.replacen(&old_len, &new_len, 1));
        prop_assert_eq!(decode_refresh(request.as_bytes())?, None, "{other}");
        Ok(())
    });
}

/// I-38, design section 10.1: path segments and the version are closed
/// grammars. Upper-case or short hex, a query string, a percent-encoded
/// digit, a version with a leading zero, a fourth part or a number above
/// 65535 are each refused.
#[test]
fn i38_refresh_request_refuses_off_grammar_fields() {
    check("i38_refresh_request_refuses_off_grammar_fields", |g| {
        let (call, bytes) = sample(g)?;
        let CnCall::Licence(r) = call else {
            return Err("not a refresh".to_owned());
        };
        let hex: String = r.licence.0.iter().map(|b| format!("{b:02x}")).collect();
        let v = format!("{}.{}.{}", r.version.0, r.version.1, r.version.2);
        let edited = match g.u8_in(0..=6) {
            0 => replace_once(&bytes, &hex, &hex.to_uppercase()),
            1 => replace_once(&bytes, &hex, &hex[1..]),
            2 => replace_once(&bytes, "/refresh ", "/refresh?x=1 "),
            3 => replace_once(
                &bytes,
                &format!("/licences/{hex}"),
                &format!("/licences/%{:02x}{}", hex.as_bytes()[0], &hex[1..]),
            ),
            4 => replace_once(&bytes, &format!("\"{v}\""), &format!("\"0{v}\"")),
            5 => replace_once(&bytes, &format!("\"{v}\""), &format!("\"{v}.0\"")),
            _ => replace_once(&bytes, &format!("\"{v}\""), "\"65536.0.0\""),
        };
        if edited == bytes {
            return Ok(());
        }
        prop_assert_eq!(decode_refresh(&edited)?, None);
        Ok(())
    });
}

/// I-38, design section 10.1: an update check, a request line of another
/// method or protocol version, or bytes past the body are refused by the
/// licence service.
#[test]
fn i38_refresh_request_refuses_other_requests() {
    check("i38_refresh_request_refuses_other_requests", |g| {
        let (_, bytes) = sample(g)?;
        let edited = match g.u8_in(0..=3) {
            0 => encode(&CnCall::Update(gen_update(g)))?,
            1 => replace_once(&bytes, "POST ", "PUT "),
            2 => replace_once(&bytes, "HTTP/1.1", "HTTP/1.0"),
            _ => [bytes.as_slice(), &g.bytes(1..=32)].concat(),
        };
        prop_assert_eq!(decode_refresh(&edited)?, None);
        Ok(())
    });
}

/// I-38, TH-26 (design section 15): a 1 MiB request is refused with a
/// typed error, and arbitrary bytes never panic.
#[test]
fn i38_refresh_request_refuses_oversized_input() {
    let mut big = b"POST /v1/licences/".to_vec();
    big.extend(std::iter::repeat_n(b'a', 1024 * 1024));
    let got = decode_refresh(&big).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got, None, "I-38: a 1 MiB request was accepted");
}
