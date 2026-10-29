//! Reader for the shared corpora in `testdata/`.
//!
//! The format is shared with the TypeScript targets of lane W1c, so both
//! sides read the same cases:
//!
//! - a line starting with `#`, and an empty line, is a comment;
//! - `+ ` then an input the grammar accepts, `- ` then one it refuses;
//! - a line of only `+` or `-` stands for the empty input;
//! - escapes: `\\`, `\t`, `\n`, `\r`, `\xHH` (one raw byte) and
//!   `\u{H...}` (one scalar value in UTF-8). Write a trailing space as
//!   `\x20`.

/// One corpus case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Case {
    /// The line number, from 1.
    pub(crate) line: usize,
    /// Whether the grammar accepts the input.
    pub(crate) accept: bool,
    /// The input bytes.
    pub(crate) input: Vec<u8>,
}

fn unescape(s: &str, line: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        match it.next() {
            Some('\\') => out.push(b'\\'),
            Some('t') => out.push(b'\t'),
            Some('n') => out.push(b'\n'),
            Some('r') => out.push(b'\r'),
            Some('x') => {
                let hex: String = [it.next(), it.next()].into_iter().flatten().collect();
                let b = u8::from_str_radix(&hex, 16)
                    .unwrap_or_else(|_| panic!("line {line}: bad \\x escape"));
                out.push(b);
            }
            Some('u') => {
                assert_eq!(it.next(), Some('{'), "line {line}: bad \\u escape");
                let hex: String = it.by_ref().take_while(|&c| c != '}').collect();
                let cp = u32::from_str_radix(&hex, 16)
                    .unwrap_or_else(|_| panic!("line {line}: bad \\u escape"));
                let c = char::from_u32(cp)
                    .unwrap_or_else(|| panic!("line {line}: \\u escape is not a scalar value"));
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
            other => panic!("line {line}: unknown escape {other:?}"),
        }
    }
    out
}

/// Reads `testdata/{name}`.
pub(crate) fn read(name: &str) -> Vec<Case> {
    let path = format!("{}/testdata/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = i + 1;
        if raw.is_empty() || raw.starts_with('#') {
            continue;
        }
        let (accept, rest) = match raw {
            "+" => (true, ""),
            "-" => (false, ""),
            _ if raw.starts_with("+ ") => (true, &raw[2..]),
            _ if raw.starts_with("- ") => (false, &raw[2..]),
            _ => panic!("{path}:{line}: a case starts with \"+ \" or \"- \""),
        };
        out.push(Case {
            line,
            accept,
            input: unescape(rest, line),
        });
    }
    assert!(!out.is_empty(), "{path} holds no case");
    out
}
