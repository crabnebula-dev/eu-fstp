//! Table tests for every request smuggling and limit rule of the strict
//! HTTP/1.1 parser (TH-26, H-05).
//!
//! Each row is checked three ways: fed at once, fed one byte at a time, and
//! fed in two halves. All three must give the same outcome, and the error
//! kind must map to the documented status code.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{
    ReqOutcome, decode_requests, decode_responses, every_byte, same_request_outcome,
    same_response_outcome,
};
use fstp_http::{
    BodyKind, ChunkedDecoder, ChunkedEvent, Limits, Method, ParseErrorKind as K, StatusCode,
    Version,
};

#[derive(Debug, Clone, Copy)]
enum Expect {
    /// Parses into this many complete requests, the last with this body.
    Ok {
        messages: usize,
        body: &'static [u8],
    },
    /// Fails with this kind and status.
    Err(K, u16),
}

struct Row {
    name: &'static str,
    input: Vec<u8>,
    limits: Limits,
    eof: bool,
    expect: Expect,
}

fn row(name: &'static str, input: impl Into<Vec<u8>>, expect: Expect) -> Row {
    Row {
        name,
        input: input.into(),
        limits: Limits::default(),
        eof: false,
        expect,
    }
}

fn ok(body: &'static [u8]) -> Expect {
    Expect::Ok { messages: 1, body }
}

fn err(kind: K, status: u16) -> Expect {
    Expect::Err(kind, status)
}

fn run_rows(rows: Vec<Row>) {
    let mut failures = Vec::new();
    for r in &rows {
        let whole = decode_requests(&r.input, &[], r.limits, r.eof);
        let bytewise = decode_requests(&r.input, &every_byte(&r.input), r.limits, r.eof);
        let halves = decode_requests(&r.input, &[r.input.len() / 2], r.limits, r.eof);
        if !same_request_outcome(&whole, &bytewise) || !same_request_outcome(&whole, &halves) {
            failures.push(format!(
                "{}: outcome depends on chunking\n whole: {whole:?}\n bytes: {bytewise:?}",
                r.name
            ));
            continue;
        }
        if let Err(msg) = check(&whole, r.expect) {
            failures.push(format!("{}: {msg}", r.name));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn check(o: &ReqOutcome, expect: Expect) -> Result<(), String> {
    match expect {
        Expect::Ok { messages, body } => {
            if let Some(e) = o.error {
                return Err(format!("expected success, got {e:?}"));
            }
            if o.messages.len() != messages {
                return Err(format!("expected {messages} messages, got {o:?}"));
            }
            let last = o.messages.last().unwrap();
            if last.1 != body {
                return Err(format!("body {:?} != {:?}", last.1, body));
            }
            Ok(())
        }
        Expect::Err(kind, status) => {
            if o.error != Some(kind) {
                return Err(format!("expected {kind:?}, got {:?}", o.error));
            }
            if kind.status().as_u16() != status {
                return Err(format!(
                    "{kind:?} maps to {}, expected {status}",
                    kind.status()
                ));
            }
            Ok(())
        }
    }
}

fn get(headers: &str) -> String {
    format!("GET / HTTP/1.1\r\nHost: a\r\n{headers}\r\n")
}

fn post(headers: &str, body: &str) -> String {
    format!("POST / HTTP/1.1\r\nHost: a\r\n{headers}\r\n{body}")
}

/// TH-26: request smuggling defences (RFC 9112 section 6.3 and 11.2).
#[test]
fn th26_smuggling_rules() {
    run_rows(vec![
        row(
            "cl body",
            post("Content-Length: 5\r\n", "hello"),
            ok(b"hello"),
        ),
        row(
            "te chunked",
            post("Transfer-Encoding: chunked\r\n", "5\r\nhello\r\n0\r\n\r\n"),
            ok(b"hello"),
        ),
        row(
            "te chunked mixed case",
            post("Transfer-Encoding: ChUnKeD\r\n", "0\r\n\r\n"),
            ok(b""),
        ),
        row(
            "te with tab ows",
            post("Transfer-Encoding:\tchunked\t\r\n", "0\r\n\r\n"),
            ok(b""),
        ),
        row(
            "cl and te",
            post(
                "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",
                "0\r\n\r\n",
            ),
            err(K::ContentLengthWithTransferEncoding, 400),
        ),
        row(
            "te and cl",
            post(
                "Transfer-Encoding: chunked\r\nContent-Length: 5\r\n",
                "0\r\n\r\n",
            ),
            err(K::ContentLengthWithTransferEncoding, 400),
        ),
        row(
            "two cl same",
            post("Content-Length: 5\r\nContent-Length: 5\r\n", "hello"),
            err(K::MultipleContentLength, 400),
        ),
        row(
            "two cl different",
            post("Content-Length: 5\r\nContent-Length: 6\r\n", "hello!"),
            err(K::MultipleContentLength, 400),
        ),
        row(
            "cl list",
            post("Content-Length: 5, 5\r\n", "hello"),
            err(K::InvalidContentLength, 400),
        ),
        row(
            "cl plus",
            post("Content-Length: +5\r\n", "hello"),
            err(K::InvalidContentLength, 400),
        ),
        row(
            "cl negative",
            post("Content-Length: -1\r\n", ""),
            err(K::InvalidContentLength, 400),
        ),
        row(
            "cl hex",
            post("Content-Length: 0x5\r\n", "hello"),
            err(K::InvalidContentLength, 400),
        ),
        row(
            "cl empty",
            post("Content-Length:\r\n", ""),
            err(K::InvalidContentLength, 400),
        ),
        row(
            "cl inner space",
            post("Content-Length: 1 2\r\n", ""),
            err(K::InvalidContentLength, 400),
        ),
        row(
            "cl overflow",
            post("Content-Length: 99999999999999999999999\r\n", ""),
            err(K::BodyTooLarge, 413),
        ),
        row(
            "cl leading zeros",
            post("Content-Length: 0005\r\n", "hello"),
            ok(b"hello"),
        ),
        row(
            "te gzip only",
            post("Transfer-Encoding: gzip\r\n", ""),
            err(K::TransferEncodingNotChunked, 400),
        ),
        row(
            "te identity",
            post("Transfer-Encoding: identity\r\n", ""),
            err(K::TransferEncodingNotChunked, 400),
        ),
        row(
            "te chunked then gzip",
            post("Transfer-Encoding: chunked, gzip\r\n", ""),
            err(K::TransferEncodingNotChunked, 400),
        ),
        row(
            "te xchunked",
            post("Transfer-Encoding: xchunked\r\n", ""),
            err(K::TransferEncodingNotChunked, 400),
        ),
        row(
            "te gzip then chunked",
            post("Transfer-Encoding: gzip, chunked\r\n", "0\r\n\r\n"),
            err(K::UnsupportedTransferCoding, 501),
        ),
        row(
            "te unknown then chunked",
            post("Transfer-Encoding: foo, chunked\r\n", "0\r\n\r\n"),
            err(K::UnsupportedTransferCoding, 501),
        ),
        row(
            "te split lines",
            post(
                "Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n",
                "0\r\n\r\n",
            ),
            err(K::UnsupportedTransferCoding, 501),
        ),
        row(
            "te chunked twice",
            post("Transfer-Encoding: chunked, chunked\r\n", "0\r\n\r\n"),
            err(K::ChunkedAppliedTwice, 400),
        ),
        row(
            "te chunked twice lines",
            post(
                "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
                "0\r\n\r\n",
            ),
            err(K::ChunkedAppliedTwice, 400),
        ),
        row(
            "te empty element",
            post("Transfer-Encoding: chunked,\r\n", "0\r\n\r\n"),
            err(K::InvalidTransferEncoding, 400),
        ),
        row(
            "te leading empty element",
            post("Transfer-Encoding: , chunked\r\n", "0\r\n\r\n"),
            err(K::InvalidTransferEncoding, 400),
        ),
        row(
            "te empty",
            post("Transfer-Encoding:\r\n", ""),
            err(K::InvalidTransferEncoding, 400),
        ),
        row(
            "te parameter",
            post("Transfer-Encoding: chunked;q=1\r\n", "0\r\n\r\n"),
            err(K::InvalidTransferEncoding, 400),
        ),
        row(
            "te quoted",
            post("Transfer-Encoding: \"chunked\"\r\n", "0\r\n\r\n"),
            err(K::InvalidTransferEncoding, 400),
        ),
        row(
            "te in http/1.0",
            "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            err(K::TransferEncodingInHttp10, 400),
        ),
        row(
            "te space before colon",
            post("Transfer-Encoding : chunked\r\n", "0\r\n\r\n"),
            err(K::WhitespaceBeforeColon, 400),
        ),
        row(
            "te tab before colon",
            post("Transfer-Encoding\t: chunked\r\n", "0\r\n\r\n"),
            err(K::WhitespaceBeforeColon, 400),
        ),
        row(
            "te folded",
            post("X: a\r\n Transfer-Encoding: chunked\r\n", "0\r\n\r\n"),
            err(K::ObsoleteLineFolding, 400),
        ),
        row(
            "obs-fold value",
            get("X: a\r\n b\r\n"),
            err(K::ObsoleteLineFolding, 400),
        ),
        row(
            "obs-fold tab",
            get("X: a\r\n\tb\r\n"),
            err(K::ObsoleteLineFolding, 400),
        ),
        row(
            "whitespace after start line",
            "GET / HTTP/1.1\r\n Host: a\r\n\r\n",
            err(K::ObsoleteLineFolding, 400),
        ),
        row(
            "underscore name is another field",
            post("Transfer_Encoding: chunked\r\n", ""),
            ok(b""),
        ),
        row(
            "bare lf head",
            "GET / HTTP/1.1\nHost: a\n\n",
            err(K::BareLf, 400),
        ),
        row(
            "bare lf header",
            "GET / HTTP/1.1\r\nHost: a\nX: b\r\n\r\n",
            err(K::BareLf, 400),
        ),
        row("bare cr in value", get("X: a\rb\r\n"), err(K::BareCr, 400)),
        row(
            "bare cr in request line",
            "GET /\r HTTP/1.1\r\nHost: a\r\n\r\n",
            err(K::BareCr, 400),
        ),
        row(
            "nul in value",
            get("X: a\0b\r\n"),
            err(K::InvalidHeaderValue, 400),
        ),
        row(
            "del in value",
            get("X: a\x7fb\r\n"),
            err(K::InvalidHeaderValue, 400),
        ),
        row(
            "ctl in value",
            get("X: a\x01b\r\n"),
            err(K::InvalidHeaderValue, 400),
        ),
        row(
            "vertical tab in value",
            get("X: a\x0bb\r\n"),
            err(K::InvalidHeaderValue, 400),
        ),
        row(
            "obs-text in value",
            [get("X: \u{e9}\r\n").as_bytes()].concat(),
            ok(b""),
        ),
        row(
            "space in name",
            get("X Y: z\r\n"),
            err(K::InvalidHeaderName, 400),
        ),
        row("empty name", get(": z\r\n"), err(K::InvalidHeaderName, 400)),
        row(
            "non-ascii name",
            get("\u{e9}: z\r\n"),
            err(K::InvalidHeaderName, 400),
        ),
        row("missing colon", get("XYZ\r\n"), err(K::MissingColon, 400)),
        row(
            "chunk size not hex",
            post("Transfer-Encoding: chunked\r\n", "g\r\n"),
            err(K::InvalidChunkSize, 400),
        ),
        row(
            "chunk size empty",
            post("Transfer-Encoding: chunked\r\n", "\r\n"),
            err(K::InvalidChunkSize, 400),
        ),
        row(
            "chunk size negative",
            post("Transfer-Encoding: chunked\r\n", "-5\r\n"),
            err(K::InvalidChunkSize, 400),
        ),
        row(
            "chunk size 0x prefix",
            post(
                "Transfer-Encoding: chunked\r\n",
                "0x5\r\nhello\r\n0\r\n\r\n",
            ),
            err(K::InvalidChunkExtension, 400),
        ),
        row(
            "chunk size trailing space",
            post("Transfer-Encoding: chunked\r\n", "5 \r\nhello\r\n0\r\n\r\n"),
            err(K::InvalidChunkExtension, 400),
        ),
        row(
            "chunk ext ok",
            post(
                "Transfer-Encoding: chunked\r\n",
                "5 ; a=b;c=\"d\\\"e\"\r\nhello\r\n0;z\r\n\r\n",
            ),
            ok(b"hello"),
        ),
        row(
            "chunk ext bad value",
            post(
                "Transfer-Encoding: chunked\r\n",
                "5;a=\r\nhello\r\n0\r\n\r\n",
            ),
            err(K::InvalidChunkExtension, 400),
        ),
        row(
            "chunk ext unterminated quote",
            post(
                "Transfer-Encoding: chunked\r\n",
                "5;a=\"x\r\nhello\r\n0\r\n\r\n",
            ),
            err(K::InvalidChunkExtension, 400),
        ),
        row(
            "chunk overflow",
            post("Transfer-Encoding: chunked\r\n", "fffffffffffffffffff\r\n"),
            err(K::ChunkTooLarge, 413),
        ),
        row(
            "chunk data no crlf",
            post("Transfer-Encoding: chunked\r\n", "3\r\nabcX\r\n0\r\n\r\n"),
            err(K::InvalidChunkTerminator, 400),
        ),
        row(
            "chunk data lf only",
            post("Transfer-Encoding: chunked\r\n", "3\r\nabc\n0\r\n\r\n"),
            err(K::InvalidChunkTerminator, 400),
        ),
        row(
            "chunk data cr only",
            post("Transfer-Encoding: chunked\r\n", "3\r\nabc\r0\r\n\r\n"),
            err(K::InvalidChunkTerminator, 400),
        ),
        row(
            "chunk line bare lf",
            post("Transfer-Encoding: chunked\r\n", "3\nabc\r\n0\r\n\r\n"),
            err(K::BareLf, 400),
        ),
        row(
            "chunk line bare cr",
            post(
                "Transfer-Encoding: chunked\r\n",
                "3\r;a\r\nabc\r\n0\r\n\r\n",
            ),
            err(K::BareCr, 400),
        ),
        row(
            "chunk too long data",
            post("Transfer-Encoding: chunked\r\n", "2\r\nabc\r\n0\r\n\r\n"),
            err(K::InvalidChunkTerminator, 400),
        ),
        row(
            "trailers kept",
            post(
                "Transfer-Encoding: chunked\r\n",
                "1\r\na\r\n0\r\nX-T: 1\r\nContent-Length: 9\r\n\r\n",
            ),
            ok(b"a"),
        ),
        row(
            "trailer folded",
            post("Transfer-Encoding: chunked\r\n", "0\r\nX: a\r\n b\r\n\r\n"),
            err(K::ObsoleteLineFolding, 400),
        ),
        row(
            "trailer bad name",
            post("Transfer-Encoding: chunked\r\n", "0\r\nX Y: a\r\n\r\n"),
            err(K::InvalidHeaderName, 400),
        ),
    ]);
}

/// TH-26: request-line, Host, Expect and Connection rules.
#[test]
fn th26_start_line_and_host_rules() {
    run_rows(vec![
        row(
            "get",
            "GET /a?b=c HTTP/1.1\r\nHost: example.com\r\n\r\n",
            ok(b""),
        ),
        row("http/1.0 without host", "GET / HTTP/1.0\r\n\r\n", ok(b"")),
        row(
            "http/1.9 reads as 1.1",
            "GET / HTTP/1.9\r\nHost: a\r\n\r\n",
            ok(b""),
        ),
        row(
            "absolute form",
            "GET http://example.com:8080/x?y HTTP/1.1\r\nHost: other\r\n\r\n",
            ok(b""),
        ),
        row(
            "asterisk form",
            "OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n",
            ok(b""),
        ),
        row(
            "asterisk with get",
            "GET * HTTP/1.1\r\nHost: a\r\n\r\n",
            err(K::InvalidTarget, 400),
        ),
        row("empty host", "GET / HTTP/1.1\r\nHost:\r\n\r\n", ok(b"")),
        row(
            "host ipv6",
            "GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n",
            ok(b""),
        ),
        row(
            "one leading crlf",
            "\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n",
            ok(b""),
        ),
        row(
            "two leading crlf",
            "\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n",
            err(K::TooManyEmptyLines, 400),
        ),
        row(
            "missing host",
            "GET / HTTP/1.1\r\n\r\n",
            err(K::MissingHost, 400),
        ),
        row(
            "missing host absolute form",
            "GET http://a/ HTTP/1.1\r\n\r\n",
            err(K::MissingHost, 400),
        ),
        row(
            "two hosts",
            "GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n",
            err(K::MultipleHost, 400),
        ),
        row(
            "two hosts http/1.0",
            "GET / HTTP/1.0\r\nHost: a\r\nHost: b\r\n\r\n",
            err(K::MultipleHost, 400),
        ),
        row(
            "host userinfo",
            "GET / HTTP/1.1\r\nHost: u@a\r\n\r\n",
            err(K::InvalidHost, 400),
        ),
        row(
            "host bad port",
            "GET / HTTP/1.1\r\nHost: a:99999\r\n\r\n",
            err(K::InvalidHost, 400),
        ),
        row(
            "host two ports",
            "GET / HTTP/1.1\r\nHost: a:1:2\r\n\r\n",
            err(K::InvalidHost, 400),
        ),
        row(
            "host slash",
            "GET / HTTP/1.1\r\nHost: a/b\r\n\r\n",
            err(K::InvalidHost, 400),
        ),
        row(
            "double space",
            "GET  / HTTP/1.1\r\nHost: a\r\n\r\n",
            err(K::InvalidRequestLine, 400),
        ),
        row(
            "trailing space",
            "GET / HTTP/1.1 \r\nHost: a\r\n\r\n",
            err(K::InvalidRequestLine, 400),
        ),
        row(
            "tab separator",
            "GET\t/ HTTP/1.1\r\nHost: a\r\n\r\n",
            err(K::InvalidRequestLine, 400),
        ),
        row(
            "missing version",
            "GET /\r\nHost: a\r\n\r\n",
            err(K::InvalidRequestLine, 400),
        ),
        row(
            "http/0.9 style",
            "GET /\r\n\r\n",
            err(K::InvalidRequestLine, 400),
        ),
        row(
            "lowercase version",
            "GET / http/1.1\r\nHost: a\r\n\r\n",
            err(K::InvalidVersion, 400),
        ),
        row(
            "two digit minor",
            "GET / HTTP/1.10\r\nHost: a\r\n\r\n",
            err(K::InvalidVersion, 400),
        ),
        row(
            "http/2",
            "GET / HTTP/2.0\r\nHost: a\r\n\r\n",
            err(K::UnsupportedVersion, 505),
        ),
        row(
            "h2 preface",
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            err(K::UnsupportedVersion, 505),
        ),
        row(
            "method not token",
            "GE(T / HTTP/1.1\r\nHost: a\r\n\r\n",
            err(K::InvalidMethod, 400),
        ),
        row(
            "connect",
            "CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n",
            err(K::UnsupportedMethod, 501),
        ),
        row(
            "relative target",
            "GET a/b HTTP/1.1\r\nHost: a\r\n\r\n",
            err(K::InvalidTarget, 400),
        ),
        row(
            "fragment",
            "GET /a#b HTTP/1.1\r\nHost: a\r\n\r\n",
            err(K::InvalidTarget, 400),
        ),
        row(
            "non-ascii target",
            "GET /\u{e9} HTTP/1.1\r\nHost: a\r\n\r\n",
            err(K::InvalidTarget, 400),
        ),
        row(
            "bad percent",
            "GET /%zz HTTP/1.1\r\nHost: a\r\n\r\n",
            err(K::InvalidTarget, 400),
        ),
        row(
            "userinfo target",
            "GET http://u:p@a/ HTTP/1.1\r\nHost: a\r\n\r\n",
            err(K::InvalidTarget, 400),
        ),
        row(
            "ftp target",
            "GET ftp://a/ HTTP/1.1\r\nHost: a\r\n\r\n",
            err(K::InvalidTarget, 400),
        ),
        row(
            "expect continue",
            post("Expect: 100-continue\r\nContent-Length: 1\r\n", "x"),
            ok(b"x"),
        ),
        row(
            "expect continue case",
            post("Expect: 100-Continue\r\nContent-Length: 1\r\n", "x"),
            ok(b"x"),
        ),
        row(
            "expect other",
            get("Expect: something\r\n"),
            err(K::UnsupportedExpectation, 417),
        ),
        row(
            "expect list",
            get("Expect: 100-continue, x\r\n"),
            err(K::UnsupportedExpectation, 417),
        ),
        row(
            "expect ignored in 1.0",
            "GET / HTTP/1.0\r\nExpect: something\r\n\r\n",
            ok(b""),
        ),
        row("connection close", get("Connection: close\r\n"), ok(b"")),
        row(
            "connection bad token",
            get("Connection: close, (x)\r\n"),
            err(K::InvalidConnection, 400),
        ),
        row(
            "eof inside head",
            "GET / HTTP/1.1\r\nHost: a\r\n",
            err(K::UnexpectedEof, 400),
        )
        .with_eof(),
        row(
            "eof inside body",
            post("Content-Length: 5\r\n", "he"),
            err(K::UnexpectedEof, 400),
        )
        .with_eof(),
        row(
            "eof inside chunk",
            post("Transfer-Encoding: chunked\r\n", "5\r\nhello\r\n0\r\n"),
            err(K::UnexpectedEof, 400),
        )
        .with_eof(),
        row("clean eof", get(""), ok(b"")).with_eof(),
    ]);
}

impl Row {
    fn with_eof(mut self) -> Row {
        self.eof = true;
        self
    }

    fn with_limits(mut self, f: impl FnOnce(&mut Limits)) -> Row {
        f(&mut self.limits);
        self
    }
}

/// TH-26: every explicit limit, at the boundary and one past it.
#[test]
fn th26_limit_rules() {
    let line_at = |n: usize| format!("GET /{} HTTP/1.1\r\nHost: a\r\n\r\n", "a".repeat(n - 14));
    let headers_n = |n: usize| {
        let mut s = String::from("GET / HTTP/1.1\r\nHost: a\r\n");
        for i in 0..n - 1 {
            s.push_str(&format!("X-{i}: v\r\n"));
        }
        s.push_str("\r\n");
        s
    };
    // "Host: a\r\n" is 9 bytes; each "X: <v>\r\n" is 5 + len(v) bytes.
    let header_bytes = |total: usize| {
        format!(
            "GET / HTTP/1.1\r\nHost: a\r\nX: {}\r\n\r\n",
            "v".repeat(total - 9 - 5)
        )
    };
    let chunked = |body: &str| post("Transfer-Encoding: chunked\r\n", body);
    run_rows(vec![
        row("request line at limit", line_at(100), ok(b"")).with_limits(|l| l.max_start_line = 100),
        row(
            "request line over limit",
            line_at(101),
            err(K::RequestLineTooLong, 414),
        )
        .with_limits(|l| l.max_start_line = 100),
        row(
            "request line huge no lf",
            vec![b'a'; 10_000],
            err(K::RequestLineTooLong, 414),
        ),
        row("headers at count", headers_n(10), ok(b"")).with_limits(|l| l.max_headers = 10),
        row(
            "headers over count",
            headers_n(11),
            err(K::TooManyHeaders, 431),
        )
        .with_limits(|l| l.max_headers = 10),
        row("header bytes at limit", header_bytes(64), ok(b""))
            .with_limits(|l| l.max_header_bytes = 64),
        row(
            "header bytes over limit",
            header_bytes(65),
            err(K::HeaderSectionTooLarge, 431),
        )
        .with_limits(|l| l.max_header_bytes = 64),
        row(
            "header line without lf",
            format!("GET / HTTP/1.1\r\nX: {}", "v".repeat(100)),
            err(K::HeaderSectionTooLarge, 431),
        )
        .with_limits(|l| l.max_header_bytes = 64),
        row("zero header budget", "GET / HTTP/1.0\r\n\r\n", ok(b""))
            .with_limits(|l| l.max_header_bytes = 0),
        row(
            "zero header budget with field",
            "GET / HTTP/1.0\r\nX: y\r\n\r\n",
            err(K::HeaderSectionTooLarge, 431),
        )
        .with_limits(|l| l.max_header_bytes = 0),
        row(
            "cl at limit",
            post("Content-Length: 10\r\n", "0123456789"),
            ok(b"0123456789"),
        )
        .with_limits(|l| l.max_body_bytes = 10),
        row(
            "cl over limit",
            post("Content-Length: 11\r\n", ""),
            err(K::BodyTooLarge, 413),
        )
        .with_limits(|l| l.max_body_bytes = 10),
        row(
            "chunked at limit",
            chunked("5\r\n01234\r\n5\r\n56789\r\n0\r\n\r\n"),
            ok(b"0123456789"),
        )
        .with_limits(|l| l.max_body_bytes = 10),
        row(
            "chunked over limit",
            chunked("5\r\n01234\r\n6\r\n567890\r\n0\r\n\r\n"),
            err(K::BodyTooLarge, 413),
        )
        .with_limits(|l| l.max_body_bytes = 10),
        row(
            "chunk at size limit",
            chunked("8\r\n01234567\r\n0\r\n\r\n"),
            ok(b"01234567"),
        )
        .with_limits(|l| l.max_chunk_size = 8),
        row(
            "chunk over size limit",
            chunked("9\r\n012345678\r\n0\r\n\r\n"),
            err(K::ChunkTooLarge, 413),
        )
        .with_limits(|l| l.max_chunk_size = 8),
        row(
            "chunk line at limit",
            chunked("1;abcdefg\r\nx\r\n0\r\n\r\n"),
            ok(b"x"),
        )
        .with_limits(|l| l.max_chunk_line = 9),
        row(
            "chunk line over limit",
            chunked("1;abcdefgh\r\nx\r\n0\r\n\r\n"),
            err(K::ChunkLineTooLong, 400),
        )
        .with_limits(|l| l.max_chunk_line = 9),
        row(
            "chunk ext total at limit",
            chunked("1;ab\r\nx\r\n1;cd\r\ny\r\n0\r\n\r\n"),
            ok(b"xy"),
        )
        .with_limits(|l| l.max_chunk_ext_bytes = 6),
        row(
            "chunk ext total over limit",
            chunked("1;ab\r\nx\r\n1;cd\r\ny\r\n0;e\r\n\r\n"),
            err(K::ChunkExtensionsTooLarge, 400),
        )
        .with_limits(|l| l.max_chunk_ext_bytes = 6),
        row(
            "trailers at count",
            chunked("0\r\nA: 1\r\nB: 2\r\n\r\n"),
            ok(b""),
        )
        .with_limits(|l| l.max_trailers = 2),
        row(
            "trailers over count",
            chunked("0\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n"),
            err(K::TooManyTrailers, 431),
        )
        .with_limits(|l| l.max_trailers = 2),
        row(
            "trailer bytes at limit",
            chunked("0\r\nA: 12\r\n\r\n"),
            ok(b""),
        )
        .with_limits(|l| l.max_trailer_bytes = 7),
        row(
            "trailer bytes over limit",
            chunked("0\r\nA: 123\r\n\r\n"),
            err(K::TrailerSectionTooLarge, 431),
        )
        .with_limits(|l| l.max_trailer_bytes = 7),
    ]);
}

/// TH-26: pipelined requests parse one after another, and an error in the
/// second leaves the first intact.
#[test]
fn th26_pipelining() {
    let input = b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\nPOST /2 HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhiGET /3 HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n";
    let o = decode_requests(input, &[], Limits::default(), true);
    assert_eq!(o.error, None);
    let paths: Vec<_> = o
        .messages
        .iter()
        .map(|m| m.0.target.path().to_owned())
        .collect();
    assert_eq!(paths, ["/1", "/2", "/3"]);
    assert_eq!(o.messages[1].1, b"hi");
    assert_eq!(o.messages[2].1, b"x");
    assert_eq!(o.messages[2].0.body, BodyKind::Chunked);
    let bytewise = decode_requests(input, &every_byte(input), Limits::default(), true);
    assert!(same_request_outcome(&o, &bytewise));

    let bad = b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx";
    let o = decode_requests(bad, &[], Limits::default(), false);
    assert_eq!(o.messages.len(), 1);
    assert_eq!(o.error, Some(K::MultipleContentLength));
}

/// TH-26: keep-alive is derived from the version and Connection.
#[test]
fn th26_keep_alive_flags() {
    let cases: [(&str, bool); 5] = [
        ("GET / HTTP/1.1\r\nHost: a\r\n\r\n", true),
        (
            "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
            false,
        ),
        (
            "GET / HTTP/1.1\r\nHost: a\r\nConnection: Keep-Alive, CLOSE\r\n\r\n",
            false,
        ),
        ("GET / HTTP/1.0\r\n\r\n", false),
        ("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", true),
    ];
    for (input, keep) in cases {
        let o = decode_requests(input.as_bytes(), &[], Limits::default(), false);
        assert_eq!(o.messages[0].0.keep_alive, keep, "{input:?}");
    }
    let o = decode_requests(b"GET / HTTP/1.0\r\n\r\n", &[], Limits::default(), false);
    assert_eq!(o.messages[0].0.version, Version::Http10);
}

/// TH-26: response framing rules on the client side (RFC 9112 section 6.3).
#[test]
fn th26_response_rules() {
    struct R {
        name: &'static str,
        input: &'static [u8],
        method: Method,
        eof: bool,
        expect: Result<(u16, &'static [u8]), K>,
    }
    let r = |name, input, method, eof, expect| R {
        name,
        input,
        method,
        eof,
        expect,
    };
    let limits = Limits {
        max_body_bytes: 16,
        ..Limits::default()
    };
    let rows = vec![
        r(
            "cl",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
            Method::GET,
            false,
            Ok((200, b"hi")),
        ),
        r(
            "chunked",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n",
            Method::GET,
            false,
            Ok((200, b"hi")),
        ),
        r(
            "close delimited",
            b"HTTP/1.1 200 OK\r\n\r\nuntil close",
            Method::GET,
            true,
            Ok((200, b"until close")),
        ),
        r(
            "http/1.0 close delimited",
            b"HTTP/1.0 200 OK\r\n\r\nx",
            Method::GET,
            true,
            Ok((200, b"x")),
        ),
        r(
            "204 ignores length",
            b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n",
            Method::GET,
            false,
            Ok((204, b"")),
        ),
        r(
            "304 ignores te",
            b"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n",
            Method::GET,
            false,
            Ok((304, b"")),
        ),
        r(
            "head has no body",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
            Method::HEAD,
            false,
            Ok((200, b"")),
        ),
        r(
            "interim then final",
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx",
            Method::GET,
            false,
            Ok((200, b"x")),
        ),
        r(
            "no reason phrase",
            b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n",
            Method::GET,
            false,
            Ok((200, b"")),
        ),
        r(
            "obs-text reason",
            b"HTTP/1.1 200 \xe9\r\nContent-Length: 0\r\n\r\n",
            Method::GET,
            false,
            Ok((200, b"")),
        ),
        r(
            "switching protocols",
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n",
            Method::GET,
            false,
            Err(K::UnsupportedUpgrade),
        ),
        r(
            "cl and te",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            Method::GET,
            false,
            Err(K::ContentLengthWithTransferEncoding),
        ),
        r(
            "two cl",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nhi",
            Method::GET,
            false,
            Err(K::MultipleContentLength),
        ),
        r(
            "te gzip",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
            Method::GET,
            false,
            Err(K::TransferEncodingNotChunked),
        ),
        r(
            "te in 1.0",
            b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            Method::GET,
            false,
            Err(K::TransferEncodingInHttp10),
        ),
        r(
            "status 600",
            b"HTTP/1.1 600 X\r\n\r\n",
            Method::GET,
            false,
            Err(K::InvalidStatusCode),
        ),
        r(
            "status two digits",
            b"HTTP/1.1 20 X\r\n\r\n",
            Method::GET,
            false,
            Err(K::InvalidStatusCode),
        ),
        r(
            "http/2 status",
            b"HTTP/2.0 200 OK\r\n\r\n",
            Method::GET,
            false,
            Err(K::UnsupportedVersion),
        ),
        r(
            "leading empty line",
            b"\r\nHTTP/1.1 200 OK\r\n\r\n",
            Method::GET,
            false,
            Err(K::InvalidStatusLine),
        ),
        r(
            "bare lf",
            b"HTTP/1.1 200 OK\nContent-Length: 0\n\n",
            Method::GET,
            false,
            Err(K::BareLf),
        ),
        r(
            "cl over limit",
            b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n",
            Method::GET,
            false,
            Err(K::BodyTooLarge),
        ),
        r(
            "close delimited over limit",
            b"HTTP/1.1 200 OK\r\n\r\n01234567890123456",
            Method::GET,
            true,
            Err(K::BodyTooLarge),
        ),
        r(
            "chunked over limit",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n11\r\n",
            Method::GET,
            false,
            Err(K::BodyTooLarge),
        ),
        r(
            "eof in body",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi",
            Method::GET,
            true,
            Err(K::UnexpectedEof),
        ),
    ];
    let mut failures = Vec::new();
    for row in &rows {
        let whole = decode_responses(row.input, &[], &row.method, limits, row.eof);
        let bytes = decode_responses(
            row.input,
            &every_byte(row.input),
            &row.method,
            limits,
            row.eof,
        );
        if !same_response_outcome(&whole, &bytes) {
            failures.push(format!(
                "{}: chunking dependent: {whole:?} vs {bytes:?}",
                row.name
            ));
            continue;
        }
        match row.expect {
            Ok((status, body)) => {
                let last = whole.messages.last();
                let got = last.map(|m| (m.0.status.as_u16(), m.1.as_slice()));
                if whole.error.is_some() || got != Some((status, body)) {
                    failures.push(format!(
                        "{}: expected {status} {body:?}, got {whole:?}",
                        row.name
                    ));
                }
            }
            Err(kind) => {
                if whole.error != Some(kind) {
                    failures.push(format!(
                        "{}: expected {kind:?}, got {:?}",
                        row.name, whole.error
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// TH-26: every error kind maps to the status the crate documents.
#[test]
fn th26_status_mapping() {
    let expected: [(K, StatusCode); 12] = [
        (K::BodyTooLarge, StatusCode::CONTENT_TOO_LARGE),
        (K::ChunkTooLarge, StatusCode::CONTENT_TOO_LARGE),
        (K::RequestLineTooLong, StatusCode::URI_TOO_LONG),
        (
            K::TooManyHeaders,
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        ),
        (
            K::HeaderSectionTooLarge,
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        ),
        (
            K::TooManyTrailers,
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        ),
        (
            K::TrailerSectionTooLarge,
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        ),
        (K::UnsupportedTransferCoding, StatusCode::NOT_IMPLEMENTED),
        (K::UnsupportedMethod, StatusCode::NOT_IMPLEMENTED),
        (
            K::UnsupportedVersion,
            StatusCode::HTTP_VERSION_NOT_SUPPORTED,
        ),
        (K::UnsupportedExpectation, StatusCode::EXPECTATION_FAILED),
        (
            K::ContentLengthWithTransferEncoding,
            StatusCode::BAD_REQUEST,
        ),
    ];
    for (kind, status) in expected {
        assert_eq!(kind.status(), status, "{kind:?}");
    }
}

/// R-NF-02: parse errors never echo message bytes.
#[test]
fn r_nf_02_errors_carry_no_content() {
    let input = b"GET /canary-path HTTP/1.1\r\nHost: a\r\nX-Secret: canary\x00value\r\n\r\n";
    let o = decode_requests(input, &[], Limits::default(), false);
    let kind = o.error.unwrap();
    let shown = format!(
        "{} {:?} {}",
        fstp_http::ParseError::new(kind),
        kind,
        kind.description()
    );
    assert!(!shown.contains("canary"), "{shown}");
}

/// Feeds `input` to a chunked decoder and returns the decoded data and the
/// outcome: `Ok(true)` for a complete body, `Ok(false)` when more input is
/// needed, or the error kind.
fn chunked_outcome(input: &[u8], limits: Limits) -> (Vec<u8>, Result<bool, K>) {
    let mut d = ChunkedDecoder::new(limits);
    d.feed(input);
    let mut data = Vec::new();
    loop {
        match d.next_event() {
            Ok(Some(ChunkedEvent::Data(b))) => data.extend_from_slice(&b),
            Ok(Some(ChunkedEvent::End(_))) => return (data, Ok(true)),
            Ok(None) => return (data, Ok(false)),
            Err(e) => return (data, Err(e.kind())),
        }
    }
}

/// TH-26, review finding chunk-size-overflow-saturates. A chunk size that
/// overflows `u64` is rejected even when every limit is `u64::MAX`. The
/// bytes after it are never swallowed as chunk data, so this decoder
/// cannot disagree on framing with one that rejects the overflow.
#[test]
fn review_chunk_size_overflow_saturates() {
    let max = Limits {
        max_chunk_size: u64::MAX,
        max_body_bytes: u64::MAX,
        ..Limits::default()
    };
    let (data, outcome) = chunked_outcome(b"10000000000000005\r\nhello\r\n0\r\n\r\n", max);
    assert_eq!(
        outcome,
        Err(K::ChunkTooLarge),
        "swallowed {} bytes",
        data.len()
    );
    assert!(data.is_empty());
    let (_, outcome) = chunked_outcome(b"fffffffffffffffff\r\n", max);
    assert_eq!(outcome, Err(K::ChunkTooLarge));
    // The largest value that fits is still parsed exactly.
    let (_, outcome) = chunked_outcome(b"ffffffffffffffff\r\nab", max);
    assert_eq!(outcome, Ok(false));
    // The same holds through the request decoder.
    let input = post(
        "Transfer-Encoding: chunked\r\n",
        "10000000000000005\r\nhello\r\n0\r\n\r\n",
    );
    let o = decode_requests(input.as_bytes(), &[], max, false);
    assert_eq!(o.error, Some(K::ChunkTooLarge));
    assert!(o.messages.is_empty());
}

/// TH-26, review finding phase-deadline-bypass-streaming (wire cost). A
/// chunk size has at most 16 hex digits, leading zeros included. Leading
/// zeros can no longer make a one-byte chunk cost a kilobyte of input.
#[test]
fn review_phase_deadline_bypass_streaming_chunk_digits() {
    let limits = Limits::default();
    let sixteen = format!("{}1\r\nX\r\n0\r\n\r\n", "0".repeat(15));
    let (data, outcome) = chunked_outcome(sixteen.as_bytes(), limits);
    assert_eq!((data.as_slice(), outcome), (&b"X"[..], Ok(true)));
    let seventeen = format!("{}1\r\nX\r\n0\r\n\r\n", "0".repeat(16));
    let (data, outcome) = chunked_outcome(seventeen.as_bytes(), limits);
    assert_eq!(outcome, Err(K::InvalidChunkSize));
    assert!(data.is_empty());
    // The chunk from the review: 1023 zeros and "1", inside max_chunk_line.
    let long = format!("{}1\r\nX\r\n", "0".repeat(1023));
    let (_, outcome) = chunked_outcome(long.as_bytes(), limits);
    assert_eq!(outcome, Err(K::InvalidChunkSize));
    // The last chunk follows the same rule.
    let last = format!("1\r\nX\r\n{}\r\n\r\n", "0".repeat(17));
    let (_, outcome) = chunked_outcome(last.as_bytes(), limits);
    assert_eq!(outcome, Err(K::InvalidChunkSize));
    // The rule depends on the line, not on how the input is split.
    let input = post("Transfer-Encoding: chunked\r\n", &seventeen);
    let whole = decode_requests(input.as_bytes(), &[], limits, false);
    let bytes = decode_requests(
        input.as_bytes(),
        &every_byte(input.as_bytes()),
        limits,
        false,
    );
    assert_eq!(whole.error, Some(K::InvalidChunkSize));
    assert!(same_request_outcome(&whole, &bytes));
}

/// R-NF-02, review finding debug-prints-client-chosen-names. A client
/// chooses extension method names and header field names freely, so they
/// can carry content. `Debug` output of a parsed request shows standard
/// methods and registered field names only.
#[test]
fn review_debug_prints_client_chosen_names() {
    let input = b"CANARYMETHOD /canary-path HTTP/1.1\r\nHost: canary-host\r\n\
        Content-Type: text/plain\r\nX-User-Canary-Token: canary-value\r\n\r\n";
    let o = decode_requests(input, &[], Limits::default(), false);
    assert_eq!(o.error, None);
    let (head, body, trailers) = o.messages.into_iter().next().unwrap();
    let req = fstp_http::Request::from_parts(head.clone(), body, trailers);
    for shown in [
        format!("{head:?}"),
        format!("{req:?}"),
        format!("{:?}", head.method),
        format!("{:?}", head.headers),
    ] {
        assert!(!shown.to_ascii_lowercase().contains("canary"), "{shown}");
    }
    let shown = format!("{head:?}");
    assert!(shown.contains("Method(<extension>)"), "{shown}");
    assert!(shown.contains("\"content-type\""), "{shown}");
    assert!(shown.contains("\"host\""), "{shown}");
    assert_eq!(format!("{:?}", Method::GET), "Method(GET)");
    // Display stays exact: the encoder and the handler need the real name.
    assert_eq!(head.method.to_string(), "CANARYMETHOD");
}
