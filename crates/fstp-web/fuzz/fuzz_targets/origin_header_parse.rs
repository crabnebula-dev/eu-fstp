//! Fuzz target `origin_header_parse` of `fstp-web` (TH-26, H-05, ADR-014, M4 design section 9).
//!
//! Design checks: Origin headers.
//!
//! - No input panics, and a refusal formats.
//! - The parser is deterministic.
//! - An accepted value lies inside a superset of one serialised origin:
//!   `http://` or `https://`, then ASCII letters, digits, `.` and `-`,
//!   then an optional `:` and one to five digits. So no list, path, query,
//!   fragment, userinfo, white space or non-ASCII byte is ever accepted.
//!   `crates/fstp-web/tests/adr014_origin.rs` pins the exact grammar.
//!
//! The W0 stub refuses every input with `NotImplemented`, which the
//! superset check never sees. It takes effect once lane W4e lands the
//! parser.

#![no_main]

use fstp_web::parse_origin_header;
use libfuzzer_sys::fuzz_target;

/// Whether `v` lies inside the superset of the module comment.
fn superset(v: &[u8]) -> bool {
    let Some(rest) = v
        .strip_prefix(b"https://")
        .or_else(|| v.strip_prefix(b"http://"))
    else {
        return false;
    };
    let (host, port) = match rest.iter().position(|b| *b == b':') {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None => (rest, None),
    };
    let host_ok = !host.is_empty()
        && host
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'.' || *b == b'-');
    let port_ok =
        port.is_none_or(|p| (1..=5).contains(&p.len()) && p.iter().all(u8::is_ascii_digit));
    host_ok && port_ok
}

fuzz_target!(|data: &[u8]| {
    let first = parse_origin_header(data);
    let shown = format!("{first:?}");
    assert!(!shown.is_empty());
    assert_eq!(
        first,
        parse_origin_header(data),
        "the parser is not deterministic"
    );
    if first.is_ok() {
        assert!(
            superset(data),
            "an accepted Origin lies outside the origin grammar"
        );
    }
});
