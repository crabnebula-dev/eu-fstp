//! Fuzz target `client_hello_sni` of `fstp-edge` (TH-26, H-05, I-19, M3
//! design section 15).
//!
//! Design checks: no panic; on valid hellos the SNI equals what an
//! `fstp-tls` server reports.
//!
//! The first input byte picks a mode.
//!
//! - Even: the rest of the input goes to the parser as it is. Beyond "no
//!   panic", the verdict must keep these properties. A buffer that does
//!   not start with a handshake record is `NotTls`. `NeedMore` never
//!   comes after more than 16 KiB, and a shorter prefix of a `NeedMore`
//!   buffer needs more too. A named host is a lowercase LDH name of at
//!   most 253 bytes, and appending bytes never changes that verdict.
//!   On inputs up to 2 KiB, the record scan `HelloScan` never waits on a
//!   prefix that the parser routes or closes as `NoSni` or `NotTls`.
//! - Odd: the differential. Real handshakes between an `fstp-tls` client
//!   and an `fstp-tls` server run once per process, one per name the test
//!   certificate covers. The input picks a capture, a cut point and a
//!   tail. Every proper prefix of the client's ClientHello record needs
//!   more bytes. The whole record, followed by the tail, names the host
//!   the server reported, or `NoSni` when the server saw none.
//!   Fed one byte at a time, the record scan asks for one parse, at the
//!   end of the hello.
//!
//! While the parser is the W0 stub, it refuses every input with
//! `NotImplemented`. The target then checks only that no input panics.
//! It tells that refusal apart by its `Debug` form, so the target still
//! builds once lane W2i replaces the error type.

#![no_main]

#[path = "../../tests/support/capture.rs"]
mod capture;
#[path = "../../tests/support/hello.rs"]
mod hello;

use std::fmt::Debug;
use std::sync::OnceLock;

use fstp_edge::{HelloScan, SniOutcome, parse_client_hello_sni};
use libfuzzer_sys::fuzz_target;

fn is_stub<E: Debug>(e: &E) -> bool {
    format!("{e:?}").starts_with("NotImplemented")
}

fn captures() -> &'static [capture::Capture] {
    static CAPS: OnceLock<Vec<capture::Capture>> = OnceLock::new();
    CAPS.get_or_init(|| {
        capture::DNS_NAMES
            .iter()
            .chain(capture::IP_NAMES.iter())
            .map(|n| capture::handshake(n))
            .collect()
    })
}

fn is_ldh_host(h: &str) -> bool {
    h.len() <= 253
        && h.split('.').all(|label| {
            let b = label.as_bytes();
            !b.is_empty()
                && b.len() <= 63
                && b.iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
                && b.first() != Some(&b'-')
                && b.last() != Some(&b'-')
        })
}

/// The longest input `check_any` also feeds to the record scan byte by
/// byte. The check parses every prefix, so it is bounded.
const SCAN_CHECK_MAX: usize = 2048;

fn check_any(data: &[u8]) {
    let verdict = parse_client_hello_sni(data);
    if matches!(&verdict, Err(e) if is_stub(e)) {
        return;
    }
    if data.len() <= SCAN_CHECK_MAX {
        check_scan(data);
    }
    if let Some(&first) = data.first()
        && first != hello::CONTENT_HANDSHAKE
    {
        assert_eq!(verdict, Ok(SniOutcome::NotTls), "first byte {first:#04x}");
    }
    match &verdict {
        Ok(SniOutcome::NeedMore) => {
            assert!(
                data.len() <= hello::MAX_SNI_BUF,
                "asked for more after {} bytes",
                data.len()
            );
            if let Some(shorter) = data.len().checked_sub(1).and_then(|n| data.get(..n)) {
                assert_eq!(
                    parse_client_hello_sni(shorter),
                    Ok(SniOutcome::NeedMore),
                    "a prefix of an incomplete hello did not need more"
                );
            }
        }
        Ok(SniOutcome::Host(h)) => {
            assert!(
                is_ldh_host(h.as_str()),
                "host {:?} is not a lowercase LDH name",
                h
            );
            let mut longer = data.to_vec();
            longer.extend_from_slice(&[0xa5, 0x17, 0x03, 0x03, 0x00]);
            assert_eq!(
                parse_client_hello_sni(&longer),
                verdict,
                "bytes after the hello changed the verdict"
            );
        }
        _ => {}
    }
}

/// Feeds `data` to the record scan one byte at a time, as a slow client
/// sends it. Wherever the scan says "wait", the parser must need more or
/// refuse. A refusal is safe to delay, since every longer buffer gets it
/// too. A routing verdict must never wait for a byte the client may not
/// send.
fn check_scan(data: &[u8]) {
    let mut scan = HelloScan::default();
    for end in 1..=data.len() {
        let prefix = &data[..end];
        if scan.ready(prefix) {
            continue;
        }
        let verdict = parse_client_hello_sni(prefix);
        assert!(
            matches!(verdict, Ok(SniOutcome::NeedMore) | Err(_)),
            "the scan waited on {end} bytes, but the parser said {verdict:?}"
        );
    }
}

fn check_differential(data: &[u8]) {
    let caps = captures();
    let pick = usize::from(data.first().copied().unwrap_or(0)) % caps.len();
    let Some(cap) = caps.get(pick) else {
        return;
    };
    let hello = cap.first_record();
    let raw_cut = data
        .get(1..3)
        .map_or(0, |b| usize::from(u16::from_be_bytes([b[0], b[1]])));
    let cut = raw_cut % (hello.len() + 1);
    let tail = data.get(3..).unwrap_or(&[]);
    if let Some(prefix) = hello.get(..cut).filter(|p| p.len() < hello.len()) {
        let verdict = parse_client_hello_sni(prefix);
        if matches!(&verdict, Err(e) if is_stub(e)) {
            return;
        }
        assert_eq!(
            verdict,
            Ok(SniOutcome::NeedMore),
            "{}: prefix of {cut}",
            cap.name
        );
        return;
    }
    let mut bytes = hello.to_vec();
    bytes.extend_from_slice(tail);
    // Fed one byte at a time, a real hello is parsed once, at its end.
    let mut scan = HelloScan::default();
    let points: Vec<usize> = (1..=hello.len())
        .filter(|end| scan.ready(&hello[..*end]))
        .collect();
    assert_eq!(points, vec![hello.len()], "{}: scan points", cap.name);
    let verdict = parse_client_hello_sni(&bytes);
    if matches!(&verdict, Err(e) if is_stub(e)) {
        return;
    }
    match (&verdict, &cap.server_sni) {
        (Ok(SniOutcome::Host(h)), Some(s)) => assert_eq!(h.as_str(), s, "{}", cap.name),
        (Ok(SniOutcome::NoSni), None) => {}
        _ => panic!(
            "{}: the parser said {verdict:?}, the fstp-tls server saw {:?}",
            cap.name, cap.server_sni
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    match data.split_first() {
        Some((mode, rest)) if mode & 1 == 1 => check_differential(rest),
        Some((_, rest)) => check_any(rest),
        None => check_any(data),
    }
});
