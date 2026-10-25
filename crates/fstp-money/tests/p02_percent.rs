//! Percentages from 0.00 to 100.00 in basis points (P-02, NOTE 6 of
//! `policy-parameters.md`, design section 2.3).
//!
//! P-02 is a percentage with two decimals, compared exactly. Its canonical
//! text is the ADR-006 decimal form with two minor digits, such as `"75.00"`.
//!
//! The round trip checks `Percent::to_string` against a reference formatter
//! written here from `Percent::bp`. `Percent::from_bp` and the JSON form have
//! unit tests in `src/percent.rs` and `src/json.rs`.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "test references compute in wide integers"
)]

mod common;

use common::{
    MAX_BP, Reference, canonical_percent_text, format_two_decimals, near_percent_text,
    percent_reference,
};
use fstp_money::{Percent, PercentParseError};
use fstp_prop::{Config, Gen, check_with, prop_assert, prop_assert_eq};

/// Cases per property. `FSTP_PROP_CASES` still overrides it.
const CASES: u32 = 2_000;

#[track_caller]
fn check<F: Fn(&mut Gen) -> Result<(), String>>(name: &str, prop: F) {
    check_with(name, Config::default().with_cases(CASES), prop);
}

/// Whether `e` is a syntax error with an offset inside `text`.
fn is_syntax_inside(e: PercentParseError, text: &str) -> bool {
    matches!(e, PercentParseError::Syntax { offset } if offset <= text.len())
}

/// P-02: `Percent::parse` accepts exactly the canonical two-decimal texts
/// from 0.00 to 100.00, in both directions. A canonical text above 100.00 is
/// `OutOfRange`, and any other text is a syntax error inside the input.
#[test]
fn p02_percent_parse_accepts_exactly_the_reference_grammar() {
    check(
        "p02_percent_parse_accepts_exactly_the_reference_grammar",
        |g| {
            let text = near_percent_text(g);
            g.note("text", &text);
            match (Percent::parse(&text), percent_reference(&text)) {
                (Ok(p), Reference::Accept(v)) => {
                    prop_assert_eq!(i128::from(p.bp()), v);
                    prop_assert_eq!(format_two_decimals(u64::from(p.bp())), text);
                }
                (Ok(p), other) => return Err(format!("accepted {p:?}; reference {other:?}")),
                (Err(e), Reference::Accept(v)) => {
                    return Err(format!("refused a canonical text of {v} bp: {e:?}"));
                }
                (Err(e), Reference::OutOfRange) => {
                    prop_assert_eq!(e, PercentParseError::OutOfRange);
                }
                (Err(e), Reference::Syntax) => {
                    prop_assert!(is_syntax_inside(e, &text), "{e:?} for a syntax error");
                }
            }
            Ok(())
        },
    );
}

/// P-02: every canonical percentage text parses to its basis points, and the
/// basis points format back to the same text, both through the
/// reference formatter and through `Display`.
#[test]
fn p02_canonical_percent_text_round_trips() {
    check("p02_canonical_percent_text_round_trips", |g| {
        let (text, bp) = canonical_percent_text(g);
        g.note("text", &text);
        let p = Percent::parse(&text).map_err(|e| format!("refused: {e:?}"))?;
        prop_assert_eq!(p.bp(), bp);
        prop_assert_eq!(format_two_decimals(u64::from(p.bp())), text);
        prop_assert_eq!(p.to_string(), text);
        Ok(())
    });
}

/// P-02: every value from 0.00 to 100.00 in steps of 0.01 parses, and
/// distinct texts give distinct values.
#[test]
fn p02_every_basis_point_value_parses() {
    let mut failures = Vec::new();
    for bp in 0..=MAX_BP {
        let text = format_two_decimals(u64::from(bp));
        match Percent::parse(&text) {
            Ok(p) if p.bp() == bp => {}
            other => failures.push(format!("{text}: {other:?}")),
        }
        if failures.len() > 10 {
            break;
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// P-02: spellings other than the canonical two-decimal form are refused,
/// never normalised. Values above 100.00 are `OutOfRange`.
#[test]
fn p02_percent_rejected_spellings() {
    assert_eq!(Percent::parse("75.00").map(Percent::bp), Ok(7_500));
    assert_eq!(Percent::parse("100.00").map(Percent::bp), Ok(10_000));
    assert_eq!(Percent::parse("0.00").map(Percent::bp), Ok(0));
    assert_eq!(Percent::parse("0.75").map(Percent::bp), Ok(75));
    let syntax = [
        "",
        "75",
        "75.0",
        "75.000",
        "075.00",
        "00.00",
        "+75.00",
        "-75.00",
        "-0.00",
        "75,00",
        " 75.00",
        "75.00 ",
        "75.00%",
        "75%",
        ".75",
        "75.",
        "7.5e1",
        "\u{667}\u{665}.00",
    ];
    let mut failures = Vec::new();
    for text in syntax {
        match Percent::parse(text) {
            Err(e) if is_syntax_inside(e, text) => {}
            other => failures.push(format!("{text:?}: {other:?}")),
        }
    }
    for text in [
        "100.01",
        "101.00",
        "200.00",
        "99999.99",
        "340282366920938463463374607431768211456.00",
    ] {
        match Percent::parse(text) {
            Err(PercentParseError::OutOfRange) => {}
            other => failures.push(format!("{text:?}: {other:?}, wanted OutOfRange")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
