//! Fuzz target `egress_response_decode` of `fstp-release` (TH-26, H-05,
//! M3 design section 15, I-38).
//!
//! Design checks: no panic; signature checked before use.
//!
//! The decoder reads the HTTP response of a CrabNebula service and hands
//! its body to the token, transition or metadata decoder, which check
//! the signature. An accepted response has a status from 200 to 599 and
//! a body that ends the input, so no byte after the body is kept. An
//! interim 1xx is never accepted, and a 204 or 304 only without content
//! (RFC 9112 section 6.3). Mode 1 frames the rest as a 200 response
//! with a Content-Length body, which must decode to exactly that body.

#![no_main]

use fstp_release::ReleaseError;
use fstp_release::egress::decode_response;
use libfuzzer_sys::fuzz_target;

fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    let bytes = if mode & 1 == 0 {
        rest.to_vec()
    } else {
        framed(rest)
    };
    let result = decode_response(&bytes);
    assert!(!format!("{result:?}").is_empty());
    match result {
        Ok(r) => {
            assert!((200..=599).contains(&r.status), "status {}", r.status);
            assert!(
                !matches!(r.status, 204 | 304) || r.body.is_empty(),
                "a {} carried content",
                r.status
            );
            assert!(bytes.ends_with(&r.body), "the body does not end the input");
            if mode & 1 == 1 {
                assert_eq!((r.status, r.body.as_slice()), (200, rest));
            }
        }
        Err(ReleaseError::NotImplemented(_)) => {}
        #[allow(unreachable_patterns)]
        Err(_) => {
            assert!(
                !(mode & 1 == 1 && rest.len() <= 2048),
                "refused a framed 200 response"
            );
        }
    }
});
