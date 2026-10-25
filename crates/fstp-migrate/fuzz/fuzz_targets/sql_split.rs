//! TH-26, H-05: the migration statement splitter on arbitrary text.
//!
//! The first byte chooses the limits; the rest is the SQL text, decoded
//! lossily when it is not UTF-8. Properties beyond "no panic":
//!
//! - every statement is a non-empty subslice of the input, in order and
//!   without overlap, with the offset and line it reports;
//! - no statement starts or ends with whitespace or starts with a comment;
//! - each statement splits into exactly itself;
//! - the statements joined with `;\n` split into the same statements;
//! - no construct stays open at the end of an accepted input: a further
//!   statement after a semicolon splits off on its own, even one that
//!   uses `end` as a column label;
//! - an error points inside the input, at the line it reports.
//!
//! Whitespace is that of PostgreSQL 16, which excludes the vertical tab.

#![no_main]

use fstp_migrate::{SplitLimits, split_statements};
use libfuzzer_sys::fuzz_target;

fn limits(selector: u8) -> SplitLimits {
    if selector & 0x80 == 0 {
        return SplitLimits::default();
    }
    let s = usize::from(selector);
    SplitLimits {
        max_input_bytes: 64 << (s & 7),
        max_statements: ((s >> 3) & 3) * 4,
        max_comment_depth: 1 + ((s >> 5) & 3),
        max_paren_depth: 2 + ((s >> 3) & 3),
    }
}

fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0c')
}

/// A statement appended after an accepted input.
const TAIL: &str = "SELECT 1 AS end";

fn line_of(sql: &str, offset: usize) -> usize {
    sql.as_bytes()[..offset]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

fn check(sql: &str, limits: &SplitLimits) {
    let statements = match split_statements(sql, limits) {
        Ok(s) => s,
        Err(e) => {
            assert!(e.offset() <= sql.len(), "error offset outside the input");
            assert_eq!(e.line(), line_of(sql, e.offset()));
            return;
        }
    };
    assert!(statements.len() <= limits.max_statements);
    let base = sql.as_ptr() as usize;
    let mut end = 0usize;
    // Splitting a part of an accepted input stays within its depth limits;
    // only the size and count limits need room for the rejoined text.
    let relaxed = SplitLimits {
        max_input_bytes: usize::MAX,
        max_statements: usize::MAX,
        ..*limits
    };
    for s in &statements {
        let text = s.text();
        let start = (text.as_ptr() as usize)
            .checked_sub(base)
            .expect("statement starts before the input");
        assert_eq!(start, s.offset());
        assert!(start >= end, "statements overlap or are out of order");
        end = start + text.len();
        assert!(end <= sql.len(), "statement ends after the input");
        assert_eq!(&sql[start..end], text);
        assert!(!text.is_empty());
        assert!(!text.starts_with(is_space) && !text.ends_with(is_space));
        assert!(!text.starts_with("--") && !text.starts_with("/*"));
        assert_eq!(s.line(), line_of(sql, start));

        let again = split_statements(text, &relaxed).expect("a statement splits again");
        assert_eq!(again.len(), 1, "a statement splits into itself");
        assert_eq!(again[0].text(), text);
    }
    let texts: Vec<&str> = statements.iter().map(|s| s.text()).collect();
    let joined = texts.join(";\n");
    let rejoined = split_statements(&joined, &relaxed).expect("rejoined statements split");
    let retexts: Vec<&str> = rejoined.iter().map(|s| s.text()).collect();
    assert_eq!(retexts, texts, "rejoined statements split differently");

    let extended = format!("{sql}\n;{TAIL}");
    let more = split_statements(&extended, &relaxed).expect("a further statement splits");
    let mut want = texts.clone();
    want.push(TAIL);
    let got: Vec<&str> = more.iter().map(|s| s.text()).collect();
    assert_eq!(got, want, "a construct stayed open at the end of the input");
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, text)) = data.split_first() else {
        return;
    };
    let limits = limits(selector);
    match std::str::from_utf8(text) {
        Ok(sql) => check(sql, &limits),
        Err(_) => check(&String::from_utf8_lossy(text), &limits),
    }
});
