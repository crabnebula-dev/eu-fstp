//! TH-26, H-05: the SMTP reply parser, the command parser of the test sink,
//! AUTH PLAIN and the DATA stuffing round-trip and refuse malformed input.
//!
//! The last tests run the fuzz harness (`fuzz/harness.rs`) over the
//! committed seeds and over deterministic pseudo-random inputs, so the fuzz
//! properties also hold on every `cargo test`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "../fuzz/harness.rs"]
mod harness;

use std::path::Path;

use fstp_smtp::auth::{PlainCredentials, decode_plain};
use fstp_smtp::command::{Command, CommandError, parse_command};
use fstp_smtp::data::{DataDecoder, DataError, stuff};
use fstp_smtp::lines::LineError;
use fstp_smtp::reply::{Reply, ReplyClass, ReplyError, ReplyLimits, parse_reply};

fn parse_all(bytes: &[u8]) -> Result<Option<(Reply, usize)>, ReplyError> {
    parse_reply(bytes, &ReplyLimits::default())
}

/// TH-26: single-line, multi-line and empty-text replies parse and
/// re-encode to their exact bytes.
#[test]
fn th26_smtp_reply_round_trips() {
    let cases: [&[u8]; 6] = [
        b"220 sink.fstp.test ESMTP\r\n",
        b"250-sink.fstp.test\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n",
        b"250\r\n",
        b"250-\r\n250 ok\r\n",
        b"451 4.3.0 try\tlater\r\n",
        b"554-a\r\n554-b\r\n554 c\r\n",
    ];
    for bytes in cases {
        let (reply, used) = parse_all(bytes).unwrap().unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(reply.encode(), bytes);
        let again = Reply::new(reply.code(), reply.lines().to_vec()).unwrap();
        assert_eq!(again, reply);
    }
    let (ehlo, _) = parse_all(cases[1]).unwrap().unwrap();
    assert_eq!(ehlo.code(), 250);
    assert_eq!(ehlo.lines(), ["sink.fstp.test", "AUTH PLAIN", "8BITMIME"]);
    assert_eq!(ehlo.class(), ReplyClass::Positive);
}

/// TH-26: a reply cut short asks for more bytes, and the bytes after one
/// reply are left for the next.
#[test]
fn th26_smtp_reply_needs_more_and_stops_at_reply_end() {
    assert_eq!(parse_all(b"250-a\r\n250 b").unwrap(), None);
    assert_eq!(parse_all(b"250 ok\r").unwrap(), None);
    assert_eq!(parse_all(b"").unwrap(), None);
    let (r, used) = parse_all(b"250 ok\r\n221 bye\r\n").unwrap().unwrap();
    assert_eq!(r.code(), 250);
    assert_eq!(used, 8);
}

/// TH-26: malformed replies are refused with a typed error.
#[test]
fn th26_smtp_reply_refuses_malformed() {
    let refused: [(&[u8], ReplyError); 12] = [
        (b"25 ok\r\n", ReplyError::BadCode),
        (b"2a0 ok\r\n", ReplyError::BadCode),
        (b"150 ok\r\n", ReplyError::BadCode),
        (b"260 ok\r\n", ReplyError::BadCode),
        (b"250_ok\r\n", ReplyError::BadSeparator),
        (b"250 \r\n", ReplyError::BadText),
        (b"250 caf\xc3\xa9\r\n", ReplyError::BadText),
        (b"250 a\x00b\r\n", ReplyError::BadText),
        (b"250-a\r\n251 b\r\n", ReplyError::CodeMismatch),
        (b"250 ok\n", ReplyError::Line(LineError::BareLf)),
        (b"250 o\rk\r\n", ReplyError::Line(LineError::BareCr)),
        (b"\r\n", ReplyError::BadCode),
    ];
    for (bytes, want) in refused {
        assert_eq!(
            parse_all(bytes),
            Err(want),
            "{:?}",
            String::from_utf8_lossy(bytes)
        );
    }
    // Bounded line length (1000 octets with CRLF) and line count.
    let mut long = b"250 ".to_vec();
    long.extend(std::iter::repeat_n(b'x', 995));
    long.extend(b"\r\n");
    assert_eq!(long.len(), 1001);
    assert_eq!(parse_all(&long), Err(ReplyError::Line(LineError::TooLong)));
    assert_eq!(
        parse_all(&long[..1000]),
        Err(ReplyError::Line(LineError::TooLong))
    );
    let mut many = Vec::new();
    for _ in 0..ReplyLimits::default().max_lines {
        many.extend(b"250-x\r\n");
    }
    many.extend(b"250 x\r\n");
    assert_eq!(parse_all(&many), Err(ReplyError::TooManyLines));
    assert!(Reply::new(250, vec![]).is_err());
    assert!(Reply::new(250, vec!["a\r\nb".to_owned()]).is_err());
    assert!(Reply::new(199, vec!["x".to_owned()]).is_err());
}

/// TH-26: the commands the client sends parse back to themselves, byte
/// for byte, and the sink refuses anything else.
#[test]
fn th26_smtp_sink_command_round_trips_and_refuses_malformed() {
    let ok: [(&[u8], Command); 9] = [
        (
            b"EHLO cell.fstp.test\r\n",
            Command::Ehlo("cell.fstp.test".into()),
        ),
        (
            b"AUTH PLAIN AGRlbW8AZGVtbw==\r\n",
            Command::AuthPlain(Some("AGRlbW8AZGVtbw==".into())),
        ),
        (
            b"MAIL FROM:<noreply@cell.fstp.test> BODY=8BITMIME\r\n",
            Command::MailFrom {
                path: "noreply@cell.fstp.test".into(),
                params: vec!["BODY=8BITMIME".into()],
            },
        ),
        (
            b"MAIL FROM:<>\r\n",
            Command::MailFrom {
                path: String::new(),
                params: vec![],
            },
        ),
        (
            b"RCPT TO:<applicant-1@example.test>\r\n",
            Command::RcptTo("applicant-1@example.test".into()),
        ),
        (b"DATA\r\n", Command::Data),
        (b"RSET\r\n", Command::Rset),
        (b"NOOP\r\n", Command::Noop),
        (b"QUIT\r\n", Command::Quit),
    ];
    for (bytes, want) in ok {
        let got = parse_command(bytes).unwrap();
        assert_eq!(got, want);
        assert_eq!(got.encode(), bytes);
    }
    let bad: [&[u8]; 12] = [
        b"ehlo x\r\n",
        b"EHLO\r\n",
        b"EHLO a b\r\n",
        b"MAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\n",
        b"MAIL FROM: <a@b>\r\n",
        b"MAIL FROM:<a@b>  X=1\r\n",
        b"RCPT TO:<>\r\n",
        b"RCPT TO:<a<b@c>\r\n",
        b"RCPT TO:<ab>\r\n",
        b"DATA \r\n",
        b"AUTH PLAIN a\x00b\r\n",
        b"QUIT",
    ];
    for bytes in bad {
        assert!(
            parse_command(bytes).is_err(),
            "{:?}",
            String::from_utf8_lossy(bytes)
        );
    }
    let mut long = b"EHLO ".to_vec();
    long.extend(std::iter::repeat_n(b'a', 600));
    long.extend(b"\r\n");
    assert_eq!(
        parse_command(&long),
        Err(CommandError::Line(LineError::TooLong))
    );
}

/// TH-26: AUTH PLAIN decodes only canonical base64 of three NUL-separated
/// parts, and the credentials never appear in debug output.
#[test]
fn th26_smtp_auth_plain_round_trips_and_redacts() {
    let creds = PlainCredentials::new("", "demo-user", "demo-secret");
    let b64 = creds.encode();
    assert_eq!(decode_plain(&b64).unwrap(), creds);
    assert!(!format!("{creds:?}").contains("demo-secret"));
    for bad in [
        "",
        "AGRlbW8=",
        "AGRlbW8AZGVtbx==",
        "AGRlbW8AZGVtbw",
        "!!!!",
        "AAAA",
    ] {
        assert!(decode_plain(bad).is_err(), "{bad}");
    }
}

/// TH-26, I-25: dot-stuffing and CRLF normalisation give the wire form,
/// and decoding the wire form gives back the canonical body.
#[test]
fn th26_smtp_data_stuffing_round_trips() {
    let canonical = b"Subject: t\r\n\r\n.hidden\r\n..two\r\nend\r\n";
    let wire = stuff(canonical).unwrap();
    assert_eq!(wire, b"Subject: t\r\n\r\n..hidden\r\n...two\r\nend\r\n");
    let mut framed = wire.clone();
    framed.extend(b".\r\n");
    assert_eq!(harness::decode_data(&framed).unwrap().unwrap().0, canonical);
    // Bare LF and CR become CRLF, and a missing final CRLF is added.
    assert_eq!(stuff(b"a\nb\rc").unwrap(), b"a\r\nb\r\nc\r\n");
    assert_eq!(stuff(b"").unwrap(), b"");
    // Lines over 998 octets are refused.
    assert!(stuff(&[b'x'; 999]).is_err());
    assert!(stuff(&[b'x'; 998]).is_ok());
    // The sink refuses non-canonical stuffing.
    let mut d = DataDecoder::new(1 << 20);
    assert_eq!(d.feed_line(b".x\r\n"), Err(DataError::BadDotStuffing));
}

/// TH-26, H-05: the fuzz properties hold on every committed seed.
#[test]
fn th26_smtp_fuzz_seeds_keep_properties() {
    for target in ["smtp_reply", "smtp_sink_command"] {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/seeds")
            .join(target);
        let mut n = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let data = std::fs::read(entry.unwrap().path()).unwrap();
            match target {
                "smtp_reply" => harness::reply(&data),
                _ => harness::sink_command(&data),
            }
            n += 1;
        }
        assert!(n >= 3, "{target} needs seeds");
    }
}

/// TH-26, H-05: the fuzz properties hold on pseudo-random mutations of
/// valid input.
#[test]
fn th26_smtp_fuzz_properties_hold_for_random_inputs() {
    let base: &[u8] =
        b"\x2a\x03250-sink\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\nEHLO a\r\nDATA\r\n..x\r\n.\r\n";
    let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..4000 {
        let mut input = base.to_vec();
        for _ in 0..(s % 4) {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let i = (s % input.len() as u64) as usize;
            input[i] = (s >> 32) as u8;
        }
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        harness::reply(&input);
        harness::sink_command(&input);
    }
}
