//! Fuzz target `command_request_decode` of `fstp-cell` (TH-26, H-05, I-18,
//! M3 design section 15).
//!
//! Design checks: no panic; size limits; a minor field is refused.
//!
//! - No input panics, and every refusal formats.
//! - Decoding is a function of the input: the same bytes give the same
//!   answer twice.
//! - Every accepted body stays refused once a `minor` member is added, as
//!   the first member or as the last. The flag never comes from a request
//!   (I-18, NOTE 14).
//! - Every accepted body stays refused once padded past 1 MiB with JSON
//!   white space, which no M3 route needs (size limits).
//!
//! The seeds under `fuzz/seeds/command_request_decode` are accepted
//! bodies, so the minor and size checks run from the first input.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// A padding size no command body needs.
const OVERSIZE: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    let first = fstp_cell::http::decode_command_request(data);
    let shown = format!("{first:?}");
    assert!(!shown.is_empty());
    if let Err(e) = &first {
        assert!(!e.to_string().is_empty());
    }
    let again = fstp_cell::http::decode_command_request(data);
    assert_eq!(
        first, again,
        "the decoder answered the same bytes twice differently"
    );
    if first.is_err() {
        return;
    }
    let Some(rest) = data.strip_prefix(b"{") else {
        return;
    };
    for value in [&b"true"[..], b"false", b"null", b"0"] {
        let mut lead = b"{\"minor\":".to_vec();
        lead.extend_from_slice(value);
        lead.push(b',');
        lead.extend_from_slice(rest);
        assert!(
            fstp_cell::http::decode_command_request(&lead).is_err(),
            "I-18: an accepted body with a leading minor member decoded"
        );
        if let Some(body) = data.strip_suffix(b"}") {
            let mut trail = body.to_vec();
            trail.extend_from_slice(b",\"minor\":");
            trail.extend_from_slice(value);
            trail.push(b'}');
            assert!(
                fstp_cell::http::decode_command_request(&trail).is_err(),
                "I-18: an accepted body with a trailing minor member decoded"
            );
        }
    }
    let mut padded = b"{".to_vec();
    padded.resize(OVERSIZE + 1, b' ');
    padded.extend_from_slice(rest);
    assert!(
        fstp_cell::http::decode_command_request(&padded).is_err(),
        "an accepted body padded past 1 MiB decoded"
    );
});
