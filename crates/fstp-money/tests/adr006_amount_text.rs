//! The ADR-006 amount text grammar, its round trip and the rejected
//! spellings of design section 2.3 (ADR-006, TH-26, R-NF-02).
//!
//! ADR-006 states that an amount is never negative and carries no sign. The
//! reference grammar is therefore `(0|[1-9][0-9]*)\.[0-9]{2}` for EUR, with
//! the value at most `Amount::MAX_ABS_MINOR`.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test references compute in wide integers and index known strings"
)]

mod common;

use common::{
    MAX_ABS_MINOR, Reference, amount_reference, canonical_amount_text, eur, format_two_decimals,
    is_real_kind, is_syntax_kind, near_amount_text, non_neg_minor,
};
use fstp_money::{Amount, AmountParseErrorKind as K, Currency};
use fstp_prop::{Config, Gen, check_with, prop_assert, prop_assert_eq};

/// Cases per property. `FSTP_PROP_CASES` still overrides it.
const CASES: u32 = 2_000;

#[track_caller]
fn check<F: Fn(&mut Gen) -> Result<(), String>>(name: &str, prop: F) {
    check_with(name, Config::default().with_cases(CASES), prop);
}

/// ADR-006: `Amount::parse` accepts exactly the texts of the reference
/// grammar, in both directions. Accepted texts carry the reference value and
/// round-trip byte for byte. Refused texts get a real error kind and an
/// offset inside the input (TH-26).
#[test]
fn adr006_parse_accepts_exactly_the_reference_grammar() {
    check("adr006_parse_accepts_exactly_the_reference_grammar", |g| {
        let text = near_amount_text(g);
        g.note("text", &text);
        let reference = amount_reference(&text);
        g.note("reference", &reference);
        match (Amount::parse(&text, Currency::Eur), reference) {
            (Ok(a), Reference::Accept(v)) => {
                prop_assert_eq!(i128::from(a.minor()), v);
                prop_assert_eq!(a.currency(), Currency::Eur);
                prop_assert_eq!(a.to_string(), text);
            }
            (Ok(a), other) => {
                return Err(format!("accepted {a:?}, but the reference says {other:?}"));
            }
            (Err(e), Reference::Accept(v)) => {
                return Err(format!("refused a canonical text of value {v}: {e:?}"));
            }
            (Err(e), Reference::OutOfRange) => {
                prop_assert_eq!(e.kind, K::OutOfRange);
                prop_assert!(e.offset <= text.len(), "offset {} outside", e.offset);
            }
            (Err(e), Reference::Syntax) => {
                prop_assert!(
                    is_syntax_kind(e.kind),
                    "kind {:?} for a syntax error",
                    e.kind
                );
                prop_assert!(e.offset <= text.len(), "offset {} outside", e.offset);
                prop_assert_eq!(e.kind == K::Empty, text.is_empty());
            }
        }
        Ok(())
    });
}

/// ADR-006: every canonical text parses to its value, and `Display` writes
/// it back byte for byte.
#[test]
fn adr006_every_canonical_text_parses_and_round_trips() {
    check("adr006_every_canonical_text_parses_and_round_trips", |g| {
        let (text, minor) = canonical_amount_text(g);
        g.note("text", &text);
        let a = Amount::parse(&text, Currency::Eur).map_err(|e| format!("refused: {e:?}"))?;
        prop_assert_eq!(a.minor(), minor);
        prop_assert_eq!(a.to_string(), text);
        Ok(())
    });
}

/// ADR-006: `Display` of a non-negative amount writes the reference
/// spelling: integer digits without leading zeros, a full stop and exactly
/// two minor digits.
#[test]
fn adr006_display_writes_the_reference_spelling() {
    check("adr006_display_writes_the_reference_spelling", |g| {
        let minor = non_neg_minor(g);
        g.note("minor", &minor);
        let a = eur(minor)?;
        prop_assert_eq!(a.to_string(), format_two_decimals(minor.unsigned_abs()));
        Ok(())
    });
}

/// ADR-006: parsing the text that `Display` writes gives back the same
/// amount, for every non-negative amount.
#[test]
fn adr006_parse_inverts_display_for_non_negative_amounts() {
    check(
        "adr006_parse_inverts_display_for_non_negative_amounts",
        |g| {
            let minor = non_neg_minor(g);
            g.note("minor", &minor);
            let a = eur(minor)?;
            let back = Amount::parse(&a.to_string(), Currency::Eur)
                .map_err(|e| format!("refused its own text: {e:?}"))?;
            prop_assert_eq!(back, a);
            Ok(())
        },
    );
}

/// ADR-006: an amount carries no sign. A canonical text is accepted, and the
/// same text with `-` or `+` in front is refused at byte 0.
#[test]
fn adr006_any_sign_is_rejected() {
    check("adr006_any_sign_is_rejected", |g| {
        let (text, minor) = canonical_amount_text(g);
        let sign = *g.pick(&["-", "+"]);
        let signed = format!("{sign}{text}");
        g.note("signed", &signed);
        let a = Amount::parse(&text, Currency::Eur).map_err(|e| format!("refused: {e:?}"))?;
        prop_assert_eq!(a.minor(), minor);
        match Amount::parse(&signed, Currency::Eur) {
            Ok(a) => Err(format!("accepted a signed text as {a:?}")),
            Err(e) => {
                prop_assert!(is_real_kind(e.kind), "kind {:?}", e.kind);
                prop_assert_eq!(e.offset, 0);
                Ok(())
            }
        }
    });
}

/// One row of the rejected-spelling table: the text, the error kinds that
/// fit it, and the offset when only one byte can be the first offender.
struct Rejected {
    text: &'static str,
    kinds: &'static [K],
    offset: Option<usize>,
}

const fn row(text: &'static str, kinds: &'static [K], offset: Option<usize>) -> Rejected {
    Rejected {
        text,
        kinds,
        offset,
    }
}

const SCALE: &[K] = &[K::WrongScale];
const SCALE_OR_BYTE: &[K] = &[K::WrongScale, K::UnexpectedByte];
const BYTE: &[K] = &[K::UnexpectedByte];
const LEADING: &[K] = &[K::LeadingZero];
const SIGN_ZERO: &[K] = &[K::UnexpectedByte];
const RANGE: &[K] = &[K::OutOfRange];
const EMPTY: &[K] = &[K::Empty];

/// Design section 2.3 lists these rejected spellings. ADR-006 adds
/// `"-1234.50"`. The rows after the marked line are further cases of the
/// same classes. The JSON number `1234.50` is in `adr006_amount_json.rs`.
const REJECTED: &[Rejected] = &[
    // Design section 2.3, in its order.
    row("1234.5", SCALE, None),
    row("01234.50", LEADING, None),
    row("+1234.50", BYTE, Some(0)),
    row("1234.500", SCALE_OR_BYTE, None),
    row("1.23450e3", SCALE_OR_BYTE, None),
    row("-0.00", SIGN_ZERO, Some(0)),
    row("1234", SCALE_OR_BYTE, None),
    row(".50", BYTE, Some(0)),
    row("1234.", SCALE_OR_BYTE, None),
    // Whitespace.
    row(" 1234.50", BYTE, Some(0)),
    row("1234.50 ", SCALE_OR_BYTE, None),
    row("\t1234.50", BYTE, Some(0)),
    row("1234.50\n", SCALE_OR_BYTE, None),
    row("1234 .50", BYTE, Some(4)),
    row("\u{a0}1234.50", BYTE, Some(0)),
    // Separators.
    row("1,234.50", BYTE, Some(1)),
    row("1_234.50", BYTE, Some(1)),
    row("1'234.50", BYTE, Some(1)),
    row("1 234.50", BYTE, Some(1)),
    row("1.234.50", SCALE_OR_BYTE, None),
    // A comma as the decimal mark.
    row("1234,50", BYTE, Some(4)),
    // Non-ASCII digits.
    row("\u{661}\u{662}\u{663}\u{664}.\u{665}\u{660}", BYTE, Some(0)),
    row(
        "\u{ff11}\u{ff12}\u{ff13}\u{ff14}.\u{ff15}\u{ff10}",
        BYTE,
        Some(0),
    ),
    row("1234.5\u{660}", SCALE_OR_BYTE, None),
    // ADR-006: an amount is never negative and carries no sign.
    row("-1234.50", BYTE, Some(0)),
    // Further cases of the classes above.
    row("", EMPTY, Some(0)),
    row("-0.01", BYTE, Some(0)),
    row("\u{2212}1234.50", BYTE, Some(0)),
    row("00.50", LEADING, None),
    row("0.5", SCALE, None),
    row("-.50", BYTE, Some(0)),
    row("1e3", BYTE, None),
    row("NaN", BYTE, Some(0)),
    row("Infinity", BYTE, Some(0)),
    row("1234.50EUR", SCALE_OR_BYTE, None),
    row("EUR 1234.50", BYTE, Some(0)),
    row("1234.5\u{0}", SCALE_OR_BYTE, None),
    // Above `Amount::MAX_ABS_MINOR`.
    row("10000000000000000.00", RANGE, None),
    row("99999999999999999999.99", RANGE, None),
    row("340282366920938463463374607431768211456.00", RANGE, None),
];

/// ADR-006 and design section 2.3: every listed spelling is refused, never
/// normalised. A canonical control text is accepted, so a parser that
/// refuses everything fails this test.
#[test]
fn adr006_rejected_spellings_are_refused_never_normalised() {
    let control = Amount::parse("1234.50", Currency::Eur);
    assert!(
        control.is_ok(),
        "the control 1234.50 was refused: {control:?}"
    );
    let mut failures = Vec::new();
    for r in REJECTED {
        match Amount::parse(r.text, Currency::Eur) {
            Ok(a) => failures.push(format!("{:?}: accepted as {a:?}", r.text)),
            Err(e) => {
                if !r.kinds.contains(&e.kind) {
                    failures.push(format!(
                        "{:?}: kind {:?}, wanted {:?}",
                        r.text, e.kind, r.kinds
                    ));
                }
                if e.offset > r.text.len() {
                    failures.push(format!("{:?}: offset {} outside", r.text, e.offset));
                }
                if let Some(at) = r.offset
                    && e.offset != at
                {
                    failures.push(format!("{:?}: offset {}, wanted {at}", r.text, e.offset));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// ADR-006: canonical spellings, including zero, the P-04 default bounds and
/// `Amount::MAX_ABS_MINOR`, are accepted with their exact value.
#[test]
fn adr006_canonical_spellings_are_accepted() {
    let table: &[(&str, i64)] = &[
        ("0.00", 0),
        ("0.01", 1),
        ("0.50", 50),
        ("1.00", 100),
        ("10.05", 1_005),
        ("1234.50", 123_450),
        ("5000.00", 500_000),
        ("100000.00", 10_000_000),
        ("9999999999999999.99", MAX_ABS_MINOR),
    ];
    let mut failures = Vec::new();
    for &(text, minor) in table {
        match Amount::parse(text, Currency::Eur) {
            Ok(a) if a.minor() == minor && a.to_string() == text => {}
            other => failures.push(format!("{text:?}: {other:?}, wanted minor {minor}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// R-NF-02: a parse error names a byte offset and a kind, never the input.
/// `Display` and `Debug` hold no part of the refused text.
#[test]
fn r_nf_02_amount_parse_errors_hold_no_input_content() {
    let inputs = [
        "98765.4",
        "1234.567",
        "-55555.55",
        "77777.7x",
        "secret 12.00",
        "4242424242424242424242.42",
    ];
    let mut failures = Vec::new();
    for text in inputs {
        match Amount::parse(text, Currency::Eur) {
            Ok(a) => failures.push(format!("{text:?}: accepted as {a:?}")),
            Err(e) => {
                if !is_real_kind(e.kind) {
                    failures.push(format!("{text:?}: kind {:?}", e.kind));
                }
                for shown in [e.to_string(), format!("{e:?}")] {
                    if leaks(&shown, text) {
                        failures.push(format!("{text:?}: error text {shown:?} leaks input"));
                    }
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Whether `shown` contains any run of four input characters.
fn leaks(shown: &str, input: &str) -> bool {
    let chars: Vec<char> = input.chars().collect();
    chars
        .windows(4)
        .any(|w| shown.contains(&w.iter().collect::<String>()))
}
