//! Tests of `fstp_release::egress` (I-38, design sections 10.1 and 15).
//!
//! `encode` is the only code that builds requests to CrabNebula hosts. Its
//! bytes are exactly the two templates, so only the version, the channel
//! and the licence id vary. `decode_response` reads the reply of either
//! service and hands its body on. The body's own signature is checked by
//! the token, transition and metadata decoders, never here.
//!
//! The tests are red until lane W2j lands `encode` and `decode_response`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/oracle.rs"]
mod oracle;
#[path = "support/seams.rs"]
mod seams;

use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};
use fstp_release::egress::{
    self, Channel, CnCall, EgressResponse, LicenceRefresh, ProductVersion, UpdateCheck,
};
use fstp_release::licence::LicenceId;

use oracle::Version;
use seams::{is_stub, stub_msg};

fn gen_version(g: &mut Gen) -> ProductVersion {
    ProductVersion(g.u16(), g.u16(), g.u16())
}

fn gen_licence(g: &mut Gen) -> LicenceId {
    let mut id = [0u8; 16];
    for b in &mut id {
        *b = g.u8();
    }
    LicenceId(id)
}

fn v(p: ProductVersion) -> Version {
    Version(p.0, p.1, p.2)
}

/// `encode`, with a stub refusal named.
fn encode(call: &CnCall) -> Result<Vec<u8>, String> {
    egress::encode(call).map_err(|e| {
        stub_msg(&e).unwrap_or_else(|| format!("I-38: encode refused {call:?}: {e:?}"))
    })
}

/// The host of the production request of `call`, which must be a plain
/// DNS host name.
fn host(call: CnCall) -> Result<String, String> {
    let bytes = encode(&call)?;
    let host = oracle::host_of(&bytes)
        .ok_or_else(|| format!("I-38: the second line of {call:?} is not a Host header"))?;
    if oracle::host_ok(&host) {
        Ok(host)
    } else {
        Err(format!(
            "I-38: the Host of {call:?} is not a plain DNS name: {host:?}"
        ))
    }
}

fn update_host() -> Result<String, String> {
    host(CnCall::Update(UpdateCheck {
        version: ProductVersion(1, 2, 3),
        channel: Channel::Stable,
    }))
}

fn licence_host() -> Result<String, String> {
    host(CnCall::Licence(LicenceRefresh {
        licence: LicenceId([0; 16]),
        version: ProductVersion(1, 2, 3),
    }))
}

// ---------------------------------------------------------------------------
// encode.

/// I-38, design section 10.1: every update check is byte for byte
/// `GET /v1/updates/stable/{version}` with the Host header only, and no
/// body, cookie or User-Agent. The host is the same on every request.
#[test]
fn i38_update_check_bytes_match_the_template() {
    check("i38_update_check_bytes_match_the_template", |g| {
        let host = update_host()?;
        let version = gen_version(g);
        let call = CnCall::Update(UpdateCheck {
            version,
            channel: Channel::Stable,
        });
        prop_assert_eq!(
            encode(&call)?,
            oracle::update_request(&host, "stable", v(version)),
            "{call:?}"
        );
        Ok(())
    });
}

/// I-38, design section 10.1: every licence refresh is byte for byte
/// `POST /v1/licences/{hex id}/refresh` with Host, Content-Type and
/// Content-Length, and the body `{"version":"x.y.z"}`.
#[test]
fn i38_licence_refresh_bytes_match_the_template() {
    check("i38_licence_refresh_bytes_match_the_template", |g| {
        let host = licence_host()?;
        let licence = gen_licence(g);
        let version = gen_version(g);
        let call = CnCall::Licence(LicenceRefresh { licence, version });
        prop_assert_eq!(
            encode(&call)?,
            oracle::licence_request(&host, licence.0, v(version)),
            "{call:?}"
        );
        Ok(())
    });
}

/// I-38, design section 10.1: two different calls never give the same
/// bytes, so the service reads back exactly the version, channel and
/// licence id the cell sent, and nothing else.
#[test]
fn i38_encode_is_injective_over_its_fields() {
    check("i38_encode_is_injective_over_its_fields", |g| {
        let gen_call = |g: &mut Gen| {
            if g.bool() {
                CnCall::Update(UpdateCheck {
                    version: gen_version(g),
                    channel: Channel::Stable,
                })
            } else {
                CnCall::Licence(LicenceRefresh {
                    licence: gen_licence(g),
                    version: gen_version(g),
                })
            }
        };
        let a = gen_call(g);
        let b = if g.bool() { a } else { gen_call(g) };
        let (ea, eb) = (encode(&a)?, encode(&b)?);
        prop_assert_eq!(ea == eb, a == b, "{a:?} and {b:?}");
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// decode_response.

const REASONS: [(u16, &str); 6] = [
    (200, "OK"),
    (304, "Not Modified"),
    (400, "Bad Request"),
    (404, "Not Found"),
    (500, "Internal Server Error"),
    (503, "Service Unavailable"),
];

/// A response with a Content-Length body.
fn response(status: u16, reason: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// `decode_response`, with a stub refusal named. `Ok(Err(()))` is a
/// typed refusal.
fn decode(bytes: &[u8]) -> Result<Result<EgressResponse, ()>, String> {
    match egress::decode_response(bytes) {
        Ok(r) => Ok(Ok(r)),
        Err(e) if is_stub(&e) => Err(stub_msg(&e).unwrap_or_default()),
        Err(_) => Ok(Err(())),
    }
}

/// I-38, design section 15 (`egress_response_decode`): a well-formed
/// response with a Content-Length body decodes to its status and exactly
/// its body, for success and error statuses alike. A 304 carries no
/// content (RFC 9112 section 6.3), so its body is empty.
#[test]
fn i38_decode_response_reads_status_and_body() {
    check("i38_decode_response_reads_status_and_body", |g| {
        let (status, reason) = *g.pick(&REASONS);
        let body = if status == 304 {
            Vec::new()
        } else {
            g.bytes(0..=2048)
        };
        let got = decode(&response(status, reason, &body))?;
        prop_assert_eq!(got, Ok(EgressResponse { status, body }));
        Ok(())
    });
}

/// I-38, design section 15, RFC 9112 section 6.3 and RFC 9110 section
/// 6.4.1: an interim 1xx response is never the answer, and a 204 or 304
/// response carries no content. Each is refused with a typed error, so
/// an interim response is never taken as the reply. A 204 or 304 in its
/// conforming form, with no content, is accepted.
#[test]
fn i38_decode_response_refuses_interim_and_bodied_no_content_responses() {
    check(
        "i38_decode_response_refuses_interim_and_bodied_no_content_responses",
        |g| {
            let interim = g.u16_in(100..=199);
            let got = decode(&response(interim, "Continue", &g.bytes(0..=64)))?;
            prop_assert_eq!(got, Err(()), "status {interim} was accepted");
            let (status, reason) = *g.pick(&[(204u16, "No Content"), (304, "Not Modified")]);
            let body = g.bytes(1..=64);
            let got = decode(&response(status, reason, &body))?;
            prop_assert_eq!(got, Err(()), "a {status} with content was accepted");
            let length = if status == 204 { None } else { Some(0) };
            let got = decode(&no_content(status, reason, length))?;
            prop_assert_eq!(
                got,
                Ok(EgressResponse {
                    status,
                    body: Vec::new()
                })
            );
            Ok(())
        },
    );
}

/// A 204 or 304 response with no content, and with `length` as its
/// Content-Length when one is given.
fn no_content(status: u16, reason: &str, length: Option<usize>) -> Vec<u8> {
    match length {
        Some(n) => format!("HTTP/1.1 {status} {reason}\r\nContent-Length: {n}\r\n\r\n"),
        None => format!("HTTP/1.1 {status} {reason}\r\n\r\n"),
    }
    .into_bytes()
}

/// Review, fix round 2. I-38, design section 15, RFC 9110 sections
/// 6.4.1 and 8.6: a conforming 204 carries no Content-Length, and a
/// conforming 304 may carry the Content-Length of the 200 body it
/// stands for, with no content. Both decode to an empty body.
#[test]
fn review_i38_decode_response_reads_conforming_no_content_responses() {
    check(
        "review_i38_decode_response_reads_conforming_no_content_responses",
        |g| {
            let (status, length) = if g.bool() {
                (204u16, None)
            } else {
                (304, g.option(|g| g.usize_in(0..=4096)))
            };
            let reason = if status == 204 {
                "No Content"
            } else {
                "Not Modified"
            };
            let bytes = no_content(status, reason, length);
            prop_assert_eq!(
                decode(&bytes)?,
                Ok(EgressResponse {
                    status,
                    body: Vec::new()
                }),
                "{}",
                String::from_utf8_lossy(&bytes)
            );
            Ok(())
        },
    );
}

/// Review, fix round 2. I-38, design section 15, RFC 9110 section 8.6:
/// a server never sends Content-Length in a 204, so a 204 that carries
/// one is refused, whatever its value.
#[test]
fn review_i38_decode_response_refuses_a_204_with_content_length() {
    check(
        "review_i38_decode_response_refuses_a_204_with_content_length",
        |g| {
            let length = g.usize_in(0..=4096);
            let got = decode(&no_content(204, "No Content", Some(length)))?;
            prop_assert_eq!(got, Err(()), "a 204 with Content-Length {length}");
            Ok(())
        },
    );
}

/// I-38, design section 15: a body shorter than its Content-Length is
/// refused with a typed error. A cut connection never yields a short
/// token or metadata body.
#[test]
fn i38_decode_response_refuses_a_truncated_body() {
    check("i38_decode_response_refuses_a_truncated_body", |g| {
        let body = g.bytes(1..=512);
        let mut bytes = response(200, "OK", &body);
        let cut = g.usize_in(1..=body.len());
        bytes.truncate(bytes.len() - cut);
        prop_assert_eq!(decode(&bytes)?, Err(()), "cut {cut} bytes");
        Ok(())
    });
}

/// I-38, design section 15. Reading: one request gets one response, so
/// bytes past the Content-Length body are refused, not kept for later.
#[test]
fn i38_decode_response_refuses_bytes_past_the_body() {
    check("i38_decode_response_refuses_bytes_past_the_body", |g| {
        let body = g.bytes(0..=512);
        let mut bytes = response(200, "OK", &body);
        bytes.extend_from_slice(&g.bytes(1..=64));
        prop_assert_eq!(decode(&bytes)?, Err(()));
        Ok(())
    });
}

/// I-38, design section 15 ("bounded"): a 16 MiB body is refused. Every
/// body a service sends is a token response or a metadata document of a
/// few kilobytes.
#[test]
fn i38_decode_response_refuses_an_oversized_body() {
    let body = vec![b'A'; 16 * 1024 * 1024];
    let got = decode(&response(200, "OK", &body)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got, Err(()), "I-38: a 16 MiB response body was accepted");
}

/// I-38, design section 15: a response that is not HTTP/1.1 with a
/// three-digit status, or whose Content-Length is not one plain decimal,
/// is refused.
#[test]
fn i38_decode_response_refuses_malformed_framing() {
    let body = b"FSTPRR01";
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty input", Vec::new()),
        ("HTTP/1.0", {
            let mut b = response(200, "OK", body);
            b[7] = b'0';
            b
        }),
        (
            "two-digit status",
            b"HTTP/1.1 20 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ),
        (
            "status 999",
            b"HTTP/1.1 999 X\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ),
        (
            "signed Content-Length",
            b"HTTP/1.1 200 OK\r\nContent-Length: +8\r\n\r\nFSTPRR01".to_vec(),
        ),
        (
            "two Content-Length headers",
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nContent-Length: 8\r\n\r\nFSTPRR01".to_vec(),
        ),
        (
            "bare line feeds",
            b"HTTP/1.1 200 OK\nContent-Length: 8\n\nFSTPRR01".to_vec(),
        ),
        (
            "no blank line",
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nFSTPRR01".to_vec(),
        ),
    ];
    for (name, bytes) in cases {
        let got = decode(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(got, Err(()), "I-38: {name} was accepted");
    }
}

/// I-38, TH-26 (design section 15): arbitrary bytes and mutations of
/// valid responses never panic, and every answer is a decoded response or
/// a typed refusal. A decoded body is never longer than the input.
#[test]
fn i38_decode_response_answers_every_input() {
    check("i38_decode_response_answers_every_input", |g| {
        let bytes = if g.bool() {
            g.bytes(0..=512)
        } else {
            let mut b = response(200, "OK", &g.bytes(0..=128));
            for _ in 0..g.usize_in(1..=4) {
                let i = g.usize_in(0..=b.len() - 1);
                b[i] = g.u8();
            }
            b
        };
        if let Ok(r) = decode(&bytes)? {
            prop_assert!(r.body.len() <= bytes.len(), "{r:?}");
            prop_assert!((100..=599).contains(&r.status), "{r:?}");
        }
        Ok(())
    });
}
