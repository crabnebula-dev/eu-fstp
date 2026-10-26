//! Fuzz target for the percentage parser (TH-26, H-05, P-02).
//!
//! Checks, for any UTF-8 input:
//! - parsing never panics;
//! - a text is accepted exactly when it is the canonical two-decimal
//!   spelling `(0|[1-9][0-9]*)\.[0-9]{2}` of a value from 0.00 to 100.00,
//!   checked by a byte-level grammar written separately from the parser;
//! - every accepted text is the spelling of its value, computed here from
//!   the basis points;
//! - a canonical spelling above 100.00 is `OutOfRange`, and any other
//!   refusal is a syntax error with an offset inside the input.

#![no_main]

use fstp_money::{Percent, PercentParseError};
use libfuzzer_sys::fuzz_target;

/// What the grammar says about one text.
enum Verdict {
    /// Canonical, with this value in basis points.
    Accept(u16),
    /// Canonical spelling, but above 100.00.
    OutOfRange,
    /// Not the grammar.
    Syntax,
}

fn percent_grammar(text: &[u8]) -> Verdict {
    let Some(dot) = text.iter().position(|&b| b == b'.') else {
        return Verdict::Syntax;
    };
    let (int, rest) = text.split_at(dot);
    let frac = &rest[1..];
    let digits = |s: &[u8]| s.iter().all(u8::is_ascii_digit);
    let int_ok = match int {
        [b'0'] => true,
        [first, ..] => (b'1'..=b'9').contains(first) && digits(int),
        [] => false,
    };
    if !(int_ok && frac.len() == 2 && digits(frac)) {
        return Verdict::Syntax;
    }
    // Without leading zeros, more than three integer digits is above 100.
    if int.len() > 3 {
        return Verdict::OutOfRange;
    }
    let value = int
        .iter()
        .chain(frac)
        .fold(0u32, |v, &b| v * 10 + u32::from(b - b'0'));
    match u16::try_from(value) {
        Ok(bp) if bp <= 10_000 => Verdict::Accept(bp),
        _ => Verdict::OutOfRange,
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match (Percent::parse(text), percent_grammar(data)) {
        (Ok(p), Verdict::Accept(bp)) => {
            assert_eq!(p.bp(), bp, "wrong value");
            let canonical = format!("{}.{:02}", bp / 100, bp % 100);
            assert_eq!(canonical, text, "accepted a non-canonical spelling");
        }
        (Ok(_), _) => panic!("accepted a text outside the grammar or range"),
        (Err(_), Verdict::Accept(_)) => panic!("refused a canonical percentage"),
        (Err(e), Verdict::OutOfRange) => {
            assert_eq!(e, PercentParseError::OutOfRange, "wrong error kind");
        }
        (Err(e), Verdict::Syntax) => {
            assert!(
                matches!(e, PercentParseError::Syntax { offset } if offset <= data.len()),
                "wrong error kind or offset"
            );
            let _ = e.to_string();
        }
    }
});
