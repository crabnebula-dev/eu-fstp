//! Fuzz target `invitation_token_decode` of `fstp-api-core` (TH-26, H-05,
//! M4 design sections 2.2 J2 and 9; SoD-09; lane inv).
//!
//! Design checks: the link token of `GET /invitations/{token}`, of its
//! acceptance and of its verification is decoded strictly, and only a
//! token of 32 to 128 lowercase hexadecimal digits reaches an operation.
//!
//! The first byte picks the route: the landing, the acceptance or the
//! verification. The bytes up to the next zero byte are the token
//! segment, and the rest is the body. The target checks that no input
//! panics and that a refusal formats. When the segment holds no `/`, a
//! decoded request names the operation of its route and its segment is a
//! link token. A link token with an empty body always decodes to the
//! landing, so no valid link is refused.

#![no_main]

use fstp_api_core::decode::{Method, decode_route};
use libfuzzer_sys::fuzz_target;

/// Whether `s` is a link token: 32 to 128 lowercase hexadecimal digits.
fn link_token(s: &str) -> bool {
    (32..=128).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fuzz_target!(|data: &[u8]| {
    let Some((pick, rest)) = data.split_first() else {
        return;
    };
    let (segment, body) = match rest.iter().position(|b| *b == 0) {
        Some(i) => (
            rest.get(..i).unwrap_or_default(),
            rest.get(i + 1..).unwrap_or_default(),
        ),
        None => (rest, &[][..]),
    };
    let Ok(segment) = std::str::from_utf8(segment) else {
        return;
    };
    let (method, suffix, name, body) = match pick % 3 {
        0 => (Method::Get, "", "people.get_invitation", &[][..]),
        1 => (Method::Post, "/accept", "people.accept_invitation", body),
        _ => (
            Method::Post,
            "/verification",
            "people.begin_verification",
            body,
        ),
    };
    let path = format!("/invitations/{segment}{suffix}");
    let decoded = decode_route(method, &path, body);
    let shown = format!("{decoded:?}");
    assert!(!shown.is_empty());
    if segment.contains('/') {
        return;
    }
    if let Ok(op) = &decoded {
        assert_eq!(op.name(), name, "{path}");
        assert!(link_token(segment), "a non-token segment decoded: {path}");
    }
    if pick % 3 == 0 && link_token(segment) {
        assert!(decoded.is_ok(), "a link token was refused: {path} {shown}");
    }
});
