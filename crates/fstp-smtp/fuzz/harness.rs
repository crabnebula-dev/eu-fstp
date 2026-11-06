//! Shared bodies of the fstp-smtp fuzz targets (TH-26, H-05).
//!
//! The fuzz targets in `fuzz_targets/` call these functions, and
//! `tests/th26_smtp_parsers.rs` runs them over the committed seeds on
//! every `cargo test`. Each function panics when a property fails:
//!
//! - [`reply`]: parsing the whole input agrees with parsing it as it
//!   arrives in chunks. Every accepted reply re-encodes to its exact bytes
//!   and respects the line length and line count limits.
//! - [`sink_command`]: every accepted command line re-encodes to its exact
//!   bytes. Accepted AUTH PLAIN data re-encodes to the same base64. A DATA
//!   stream the sink accepts is the dot-stuffed form of the message it
//!   yields, and stuffing any input decodes back to a fixed point.

#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_smtp::auth::decode_plain;
use fstp_smtp::command::{MAX_COMMAND_LINE, parse_command};
use fstp_smtp::data::{DataDecoder, DataError, MAX_DATA_LINE, stuff};
use fstp_smtp::lines::split_line;
use fstp_smtp::reply::{Reply, ReplyError, ReplyLimits, parse_reply};

/// Every reply in `bytes`, then the error that stopped parsing, if any.
fn parse_stream(bytes: &[u8], limits: &ReplyLimits) -> (Vec<(Reply, usize)>, Option<ReplyError>) {
    let mut out = Vec::new();
    let mut off = 0;
    loop {
        match parse_reply(&bytes[off..], limits) {
            Ok(Some((r, n))) => {
                assert!(n > 0, "a reply consumed no bytes");
                off += n;
                out.push((r, n));
            }
            Ok(None) => return (out, None),
            Err(e) => return (out, Some(e)),
        }
    }
}

/// Fuzz target `smtp_reply`. Byte 0 picks the limits, byte 1 the chunk
/// size, and the rest is the would-be server output.
pub(crate) fn reply(data: &[u8]) {
    let [sel, chunk, rest @ ..] = data else {
        return;
    };
    let limits = ReplyLimits {
        max_line: 8 + usize::from(sel & 0x3f) * 16,
        max_lines: 1 + usize::from(sel >> 6) * 8,
    };
    let chunk = usize::from(*chunk).max(1);
    let (whole, whole_err) = parse_stream(rest, &limits);
    let mut off = 0;
    for (r, n) in &whole {
        let enc = r.encode();
        assert_eq!(enc, &rest[off..off + n], "reply does not re-encode exactly");
        assert!(r.lines().len() <= limits.max_lines, "too many lines");
        for line in enc.split_inclusive(|&b| b == b'\n') {
            assert!(line.len() <= limits.max_line, "line over the limit");
        }
        assert_eq!(Reply::new(r.code(), r.lines().to_vec()).as_ref(), Ok(r));
        off += n;
    }
    // Streaming: bytes arrive `chunk` at a time.
    let mut buf: Vec<u8> = Vec::new();
    let mut got = Vec::new();
    let mut err = None;
    let mut fed = 0;
    'feed: while fed < rest.len() {
        let end = (fed + chunk).min(rest.len());
        buf.extend(&rest[fed..end]);
        fed = end;
        loop {
            match parse_reply(&buf, &limits) {
                Ok(Some((r, n))) => {
                    buf.drain(..n);
                    got.push(r);
                }
                Ok(None) => break,
                Err(e) => {
                    err = Some(e);
                    break 'feed;
                }
            }
        }
    }
    let whole_replies: Vec<Reply> = whole.into_iter().map(|(r, _)| r).collect();
    assert_eq!(got, whole_replies, "chunked parsing disagrees");
    assert_eq!(
        err.is_some(),
        whole_err.is_some(),
        "chunked errors disagree"
    );
}

/// Decodes one DATA stream: the message and the bytes used, `None` when
/// the terminator has not arrived.
pub(crate) fn decode_data(raw: &[u8]) -> Result<Option<(Vec<u8>, usize)>, DataError> {
    let mut d = DataDecoder::new(1 << 20);
    let mut off = 0;
    loop {
        let Some(n) = split_line(&raw[off..], MAX_DATA_LINE).map_err(DataError::Line)? else {
            return Ok(None);
        };
        let done = d.feed_line(&raw[off..off + n])?;
        off += n;
        if done {
            return Ok(Some((d.into_message(), off)));
        }
    }
}

/// Fuzz target `smtp_sink_command`. The same input drives the command
/// parser line by line, AUTH PLAIN decoding, DATA decoding and stuffing.
pub(crate) fn sink_command(data: &[u8]) {
    // Commands, line by line.
    let mut off = 0;
    while off < data.len() {
        let line = match split_line(&data[off..], MAX_COMMAND_LINE) {
            Ok(Some(n)) => &data[off..off + n],
            _ => &data[off..],
        };
        if let Ok(cmd) = parse_command(line) {
            assert_eq!(cmd.encode(), line, "command does not re-encode exactly");
            assert_eq!(parse_command(&cmd.encode()), Ok(cmd));
        }
        off += line.len().max(1);
    }
    // AUTH PLAIN data.
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(creds) = decode_plain(text)
    {
        assert_eq!(creds.encode(), text, "AUTH PLAIN does not re-encode");
    }
    // DATA as the sink receives it.
    if let Ok(Some((msg, used))) = decode_data(data) {
        let wire = stuff(&msg).expect("an accepted message stuffs");
        assert_eq!(wire, &data[..used - 3], "accepted DATA is not canonical");
    }
    // Stuffing any body reaches a fixed point after one decode.
    if let Ok(wire) = stuff(data) {
        let mut framed = wire.clone();
        framed.extend(b".\r\n");
        let (msg, used) = decode_data(&framed)
            .expect("stuffed output decodes")
            .expect("stuffed output terminates");
        assert_eq!(used, framed.len());
        assert_eq!(
            stuff(&msg).expect("restuff"),
            wire,
            "stuffing is not stable"
        );
    }
}
