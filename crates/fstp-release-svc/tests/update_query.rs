//! Tests of `fstp_release_svc::decode_update_query` (I-38, design
//! sections 10.1 and 15, `update_query_decode`).
//!
//! The update service accepts only the update template: `GET
//! /v1/updates/{channel}/{version}` with the Host header only, and no
//! body, cookie or User-Agent. The check is deliberately anonymous.
//! Every accepted input is exactly what `fstp_release::egress::encode`
//! gives for the decoded fields.
//!
//! The tests are red until lane W2j lands `encode` and the decoder.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/common.rs"]
mod common;

use fstp_prop::{Gen, check, prop_assert_eq};
use fstp_release::egress::CnCall;
use fstp_release_svc::UpdateQuery;

use common::{
    STABLE_CODE, decode_update, encode, gen_refresh, gen_update, mutate, replace_once, update_call,
    with_header,
};

/// A random update call and its production bytes.
fn sample(g: &mut Gen) -> Result<(CnCall, Vec<u8>), String> {
    let call = CnCall::Update(gen_update(g));
    let bytes = encode(&call)?;
    Ok((call, bytes))
}

/// I-38, design section 10.1: the service decodes every update check the
/// cell can send to exactly its channel and version.
#[test]
fn i38_update_query_decodes_what_egress_encodes() {
    check("i38_update_query_decodes_what_egress_encodes", |g| {
        let u = gen_update(g);
        let bytes = encode(&CnCall::Update(u))?;
        let want = UpdateQuery {
            channel: STABLE_CODE,
            version: (u.version.0, u.version.1, u.version.2),
        };
        prop_assert_eq!(decode_update(&bytes)?, Some(want));
        Ok(())
    });
}

/// I-38, design section 15 ("only the permitted grammar"): after any one
/// byte is changed, inserted or deleted, the query is refused, or it
/// decodes to fields whose template is exactly the edited bytes.
#[test]
fn i38_update_query_has_one_spelling() {
    check("i38_update_query_has_one_spelling", |g| {
        let (_, bytes) = sample(g)?;
        let edited = mutate(g, &bytes);
        if let Some(q) = decode_update(&edited)? {
            prop_assert_eq!(encode(&update_call(&q)?)?, edited);
        }
        Ok(())
    });
}

/// I-38, design section 10.1: an update check with any header other than
/// Host is refused, including a body with Content-Length.
#[test]
fn i38_update_query_refuses_extra_headers() {
    const HEADERS: [&str; 6] = [
        "Cookie: session=0123",
        "User-Agent: fstp-cell/1.2.3",
        "X-Tenant: acme",
        "If-None-Match: \"abc\"",
        "Host: other.example.com",
        "Content-Length: 0",
    ];
    check("i38_update_query_refuses_extra_headers", |g| {
        let (_, bytes) = sample(g)?;
        let line = *g.pick(&HEADERS);
        prop_assert_eq!(decode_update(&with_header(&bytes, line))?, None, "{line}");
        Ok(())
    });
}

/// I-38, design section 10.1: the channel and version segments are
/// closed. An unknown or upper-case channel, a query string, a trailing
/// slash, a version with a leading zero or a fourth part, and a body are
/// each refused.
#[test]
fn i38_update_query_refuses_off_grammar_fields() {
    check("i38_update_query_refuses_off_grammar_fields", |g| {
        let (call, bytes) = sample(g)?;
        let CnCall::Update(u) = call else {
            return Err("not an update check".to_owned());
        };
        let v = format!("{}.{}.{}", u.version.0, u.version.1, u.version.2);
        let edited = match g.u8_in(0..=6) {
            0 => replace_once(&bytes, "/stable/", "/beta/"),
            1 => replace_once(&bytes, "/stable/", "/Stable/"),
            2 => replace_once(&bytes, &format!("/{v} "), &format!("/{v}?tenant=acme ")),
            3 => replace_once(&bytes, &format!("/{v} "), &format!("/{v}/ ")),
            4 => replace_once(&bytes, &format!("/{v} "), &format!("/0{v} ")),
            5 => replace_once(&bytes, &format!("/{v} "), &format!("/{v}.0 ")),
            _ => [bytes.as_slice(), b"{}"].concat(),
        };
        prop_assert_eq!(decode_update(&edited)?, None);
        Ok(())
    });
}

/// I-38, design section 10.1: a licence refresh, a request line of
/// another method or protocol version are refused by the update service.
#[test]
fn i38_update_query_refuses_other_requests() {
    check("i38_update_query_refuses_other_requests", |g| {
        let (_, bytes) = sample(g)?;
        let edited = match g.u8_in(0..=2) {
            0 => encode(&CnCall::Licence(gen_refresh(g)))?,
            1 => replace_once(&bytes, "GET ", "HEAD "),
            _ => replace_once(&bytes, "HTTP/1.1", "HTTP/1.0"),
        };
        prop_assert_eq!(decode_update(&edited)?, None);
        Ok(())
    });
}

/// I-38, TH-26 (design section 15): a 1 MiB query is refused with a
/// typed error, without a panic.
#[test]
fn i38_update_query_refuses_oversized_input() {
    let mut big = b"GET /v1/updates/stable/".to_vec();
    big.extend(std::iter::repeat_n(b'1', 1024 * 1024));
    let got = decode_update(&big).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got, None, "I-38: a 1 MiB query was accepted");
}
