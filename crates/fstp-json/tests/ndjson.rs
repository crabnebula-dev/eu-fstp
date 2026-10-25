//! NDJSON reader and writer (export files, `SPEC/schemas/README.md`).

#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::{self, BufRead, BufReader, Read};

use fstp_json::{
    FromJsonErrorKind, Limit, NdjsonErrorKind, NdjsonOptions, NdjsonReader, NdjsonWriter,
    ParseErrorKind, ParseLimits, Value, json,
};

fn read_all(input: &[u8], options: NdjsonOptions) -> Vec<Result<Value, (u64, String)>> {
    NdjsonReader::with_options(input, options)
        .map(|r| r.map_err(|e| (e.line(), format!("{:?}", e.kind()))))
        .collect()
}

fn values(input: &[u8]) -> Vec<Value> {
    NdjsonReader::new(input)
        .map(|r| r.unwrap_or_else(|e| panic!("{e}")))
        .collect()
}

fn first_error(input: &[u8], options: NdjsonOptions) -> (u64, NdjsonErrorKind) {
    let mut reader = NdjsonReader::with_options(input, options);
    loop {
        match reader.next_value() {
            Some(Ok(_)) => {}
            Some(Err(e)) => {
                // The stream ends after the first error.
                assert!(reader.next_value().is_none());
                return (e.line(), e.into_kind());
            }
            None => panic!("no error in {:?}", String::from_utf8_lossy(input)),
        }
    }
}

#[test]
fn lf_and_crlf_line_endings() {
    let expected = vec![json!({"a": 1}), json!([2]), json!("three"), json!(null)];
    assert_eq!(values(b"{\"a\":1}\n[2]\n\"three\"\nnull\n"), expected);
    assert_eq!(
        values(b"{\"a\":1}\r\n[2]\r\n\"three\"\r\nnull\r\n"),
        expected
    );
    assert_eq!(values(b"{\"a\":1}\r\n[2]\n\"three\"\r\nnull"), expected);
}

#[test]
fn last_line_may_lack_a_newline_and_empty_input_is_empty() {
    assert_eq!(values(b"1\n2"), vec![json!(1), json!(2)]);
    assert_eq!(values(b"1"), vec![json!(1)]);
    assert!(values(b"").is_empty());
}

#[test]
fn whitespace_around_a_value_is_allowed() {
    assert_eq!(values(b"  1 \t\n\t[ ]  \r\n"), vec![json!(1), json!([])]);
}

#[test]
fn blank_lines_are_rejected() {
    let o = NdjsonOptions::default();
    for (input, line) in [
        (&b"\n"[..], 1),
        (b"1\n\n2\n", 2),
        (b"1\n\n", 2),
        (b"1\r\n\r\n", 2),
        (b"1\n   \n", 2),
        (b"1\n2\n \t\r\n", 3),
        (b"\r\n1", 1),
    ] {
        let (at, kind) = first_error(input, o);
        assert!(
            matches!(kind, NdjsonErrorKind::BlankLine),
            "{input:?}: {kind:?}"
        );
        assert_eq!(at, line, "{input:?}");
    }
}

#[test]
fn parse_errors_carry_line_and_column() {
    let (line, kind) = first_error(
        b"{\"a\":1}\n{\"a\":1,\"a\":2}\n3\n",
        NdjsonOptions::default(),
    );
    assert_eq!(line, 2);
    let NdjsonErrorKind::Parse(e) = kind else {
        panic!("{kind:?}");
    };
    assert_eq!(
        (e.kind(), e.line(), e.column()),
        (ParseErrorKind::DuplicateKey, 1, 8)
    );
    // Two values on one line.
    let (line, kind) = first_error(b"1\n2 3\n", NdjsonOptions::default());
    assert_eq!(line, 2);
    assert!(
        matches!(kind, NdjsonErrorKind::Parse(e) if e.kind() == ParseErrorKind::TrailingCharacters)
    );
    // A value split across lines.
    let (line, _) = first_error(b"[1,\n2]\n", NdjsonOptions::default());
    assert_eq!(line, 1);
    // A lone carriage return inside a line is not a line ending.
    let (line, kind) = first_error(b"1\r2\n", NdjsonOptions::default());
    assert_eq!(line, 1);
    assert!(matches!(kind, NdjsonErrorKind::Parse(_)));
}

#[test]
fn error_display_has_line_and_no_content() {
    let mut reader = NdjsonReader::new(&b"{\"secret\":1}\n{\"secret\":1,\"secret\":2}\n"[..]);
    assert!(reader.next_value().unwrap().is_ok());
    let e = reader.next_value().unwrap().unwrap_err();
    let shown = e.to_string();
    assert_eq!(shown, "line 2: duplicate member name at column 13");
    assert!(!format!("{e:?}").contains("secret"));
}

#[test]
fn line_length_limit_is_exact() {
    let o = NdjsonOptions {
        max_line_bytes: 5,
        ..NdjsonOptions::default()
    };
    // Five bytes of content pass with LF, CRLF or no ending.
    for ok in [
        &b"12345\n"[..],
        b"12345\r\n",
        b"12345",
        b"[1,2]\n\"abc\"\r\n",
    ] {
        let all = read_all(ok, o);
        assert!(all.iter().all(Result::is_ok), "{ok:?}: {all:?}");
    }
    for (bad, line) in [
        (&b"123456\n"[..], 1),
        (b"1\n123456", 2),
        (b"123456\r\n", 1),
        (b"12345\r\r\n", 1),
    ] {
        let (at, kind) = first_error(bad, o);
        assert!(
            matches!(kind, NdjsonErrorKind::LineTooLong),
            "{bad:?}: {kind:?}"
        );
        assert_eq!(at, line);
    }
}

#[test]
fn reader_never_buffers_past_the_line_limit() {
    /// An endless stream of digits with no newline.
    struct Endless(usize);
    impl Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            buf.fill(b'1');
            self.0 += buf.len();
            Ok(buf.len())
        }
    }
    let o = NdjsonOptions {
        max_line_bytes: 1 << 16,
        ..NdjsonOptions::default()
    };
    let mut reader = NdjsonReader::with_options(BufReader::with_capacity(4096, Endless(0)), o);
    let e = reader.next_value().unwrap().unwrap_err();
    assert!(matches!(e.kind(), NdjsonErrorKind::LineTooLong));
    let consumed = reader.into_inner().into_inner().0;
    assert!(consumed <= (1 << 16) + 2 * 4096, "read {consumed} bytes");
}

#[test]
fn per_line_parse_limits_apply() {
    let o = NdjsonOptions {
        max_line_bytes: 1 << 20,
        limits: ParseLimits::default().with_max_depth(2),
    };
    let (line, kind) = first_error(b"[[1]]\n[[[1]]]\n", o);
    assert_eq!(line, 2);
    assert!(
        matches!(kind, NdjsonErrorKind::Parse(e) if e.kind() == ParseErrorKind::LimitExceeded(Limit::Depth))
    );
}

#[test]
fn io_errors_are_reported_with_the_line() {
    struct Failing(u8);
    impl Read for Failing {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0 == 0 {
                return Err(io::Error::other("disk gone"));
            }
            self.0 -= 1;
            buf[0] = b"1\n"[usize::from(self.0.is_multiple_of(2))];
            Ok(1)
        }
    }
    let mut reader = NdjsonReader::new(BufReader::new(Failing(4)));
    assert_eq!(reader.next_value().unwrap().unwrap(), json!(1));
    assert_eq!(reader.next_value().unwrap().unwrap(), json!(1));
    let e = reader.next_value().unwrap().unwrap_err();
    assert_eq!(e.line(), 3);
    assert!(matches!(e.kind(), NdjsonErrorKind::Io(_)));
    assert!(reader.next_value().is_none());
}

#[test]
fn interrupted_reads_are_retried() {
    struct Interrupting(bool, &'static [u8]);
    impl Read for Interrupting {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0 = !self.0;
            if self.0 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let n = self.1.len().min(buf.len()).min(1);
            buf[..n].copy_from_slice(&self.1[..n]);
            self.1 = &self.1[n..];
            Ok(n)
        }
    }
    let reader = NdjsonReader::new(BufReader::new(Interrupting(false, b"[1]\n{}\n")));
    let all: Vec<Value> = reader.map(Result::unwrap).collect();
    assert_eq!(all, vec![json!([1]), json!({})]);
}

#[test]
fn chunking_does_not_change_the_result() {
    let input = b"{\"a\":[1,2,{\"b\":\"\xc3\xa9\"}]}\r\n2\n\"x\\ny\"\r\n[]\n\n9\n";
    let whole = read_all(input, NdjsonOptions::default());
    for capacity in [1, 2, 3, 7, 64] {
        let chunked: Vec<_> = NdjsonReader::new(BufReader::with_capacity(capacity, &input[..]))
            .map(|r| r.map_err(|e| (e.line(), format!("{:?}", e.kind()))))
            .collect();
        assert_eq!(chunked, whole, "capacity {capacity}");
    }
    assert_eq!(whole.len(), 5);
    assert!(whole[4].is_err());
}

#[test]
fn writer_emits_one_compact_value_per_line() {
    let mut w = NdjsonWriter::new(Vec::new());
    let n = fstp_json::Number::from_lexeme("1.50").unwrap();
    w.write_value(&json!({"text": "line one\nline two", "n": n.clone()}))
        .unwrap();
    w.write(&vec![1u8, 2]).unwrap();
    w.write("\u{2028}").unwrap();
    w.flush().unwrap();
    let out = w.into_inner();
    assert_eq!(
        String::from_utf8(out.clone()).unwrap(),
        "{\"text\":\"line one\\nline two\",\"n\":1.50}\n[1,2]\n\"\u{2028}\"\n"
    );
    let back = values(&out);
    assert_eq!(
        back,
        vec![
            json!({"text": "line one\nline two", "n": n}),
            json!([1, 2]),
            json!("\u{2028}")
        ]
    );
}

#[test]
fn typed_reading_reports_the_line_and_path() {
    let mut reader = NdjsonReader::new(&b"[1,2]\n[3,\"x\"]\n"[..]);
    assert_eq!(reader.next_typed::<Vec<u8>>().unwrap().unwrap(), vec![1, 2]);
    let e = reader.next_typed::<Vec<u8>>().unwrap().unwrap_err();
    assert_eq!(e.line(), 2);
    let NdjsonErrorKind::Typed(t) = e.kind() else {
        panic!("{e:?}");
    };
    assert!(matches!(t.kind(), FromJsonErrorKind::WrongType { .. }));
    assert_eq!(t.path().full(), "$[1]");
    assert_eq!(
        e.to_string(),
        "line 2: $[1]: expected an integer, found string"
    );
    assert!(reader.next_typed::<Vec<u8>>().is_none());
}

#[test]
fn line_counter_tracks_lines_read() {
    let mut reader = NdjsonReader::new(&b"1\n2\n"[..]);
    assert_eq!(reader.line(), 0);
    assert!(reader.next_value().is_some());
    assert_eq!(reader.line(), 1);
    assert!(reader.next_value().is_some());
    assert!(reader.next_value().is_none());
    assert_eq!(reader.line(), 2);
}

#[test]
fn reader_works_on_any_bufread() {
    fn count<R: BufRead>(r: R) -> usize {
        NdjsonReader::new(r).filter(Result::is_ok).count()
    }
    assert_eq!(count(io::Cursor::new(b"1\n2\n3\n".to_vec())), 3);
    assert_eq!(count(&b"1\n2\n"[..]), 2);
}
