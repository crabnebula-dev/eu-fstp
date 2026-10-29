//! `Accept-Language` parsing and locale negotiation (R-NF-04, TH-26,
//! H-05).
//!
//! A server-rendered page picks its catalogue from the request's
//! `Accept-Language` header, with the programme's default when nothing
//! matches. The header is attacker-controlled input to an in-house parser,
//! so the parser is bounded and fuzzed (`accept_language_parse`). The
//! grammar and the negotiation rule are in `common::lang` (interim
//! reading, pending Daniel).
//!
//! Red against the W0 stub: `parse_accept_language` refuses every input
//! with `NotImplemented`, and the negotiation API does not exist yet.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::bind;
use common::chars::is_typed;
use common::lang::{self, MAX_HEADER_BYTES, MAX_RANGES};
use fstp_html::parse_accept_language;
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

/// R-NF-04, TH-26: `parse_accept_language` accepts and refuses exactly the
/// cases of the shared corpus, and enforces the length and range bounds.
#[test]
fn r_nf_04_accept_language_corpus() {
    let mut cases: Vec<(String, bool, Vec<u8>)> = common::corpus::read("accept_language.corpus")
        .into_iter()
        .map(|c| (format!("line {}", c.line), c.accept, c.input))
        .collect();
    let ranges = |n: usize| vec!["en"; n].join(",").into_bytes();
    cases.push(("most ranges".to_owned(), true, ranges(MAX_RANGES)));
    cases.push((
        "one range too many".to_owned(),
        false,
        ranges(MAX_RANGES + 1),
    ));
    let mut longest = b"en".to_vec();
    longest.resize(MAX_HEADER_BYTES, b',');
    cases.push(("longest header".to_owned(), true, longest.clone()));
    longest.push(b',');
    cases.push(("one byte too long".to_owned(), false, longest));
    let mut failures = Vec::new();
    for (name, accept, input) in cases {
        match parse_accept_language(&input) {
            Ok(_) if accept => {}
            Err(e) if !accept && is_typed(&e) => {}
            other => failures.push(format!(
                "{name} {:?}: {other:?}",
                String::from_utf8_lossy(&input)
            )),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A header value near the grammar.
fn near_header(g: &mut Gen) -> Vec<u8> {
    const PIECES: &[&str] = &[
        "en",
        "fr",
        "de-AT",
        "zh-Hant-TW",
        "x-priv",
        "*",
        "abcdefghi",
        "EN",
        ",",
        ", ",
        ";",
        ";q=",
        "q=",
        "Q=",
        "0",
        "1",
        ".",
        "5",
        "000",
        "0.5",
        "1.000",
        " ",
        "\t",
        "-",
        "_",
        "=",
        "\"",
        "\u{e9}",
        "\n",
        "\u{0}",
    ];
    if g.u8_in(0..=4) == 0 {
        return g.bytes(0..=32);
    }
    g.vec(0..=12, |g| g.pick(PIECES).as_bytes().to_vec())
        .concat()
}

/// TH-26, H-05: on inputs near the grammar and on arbitrary bytes,
/// `parse_accept_language` accepts exactly what the reference accepts,
/// refuses with a typed error, and answers the same twice.
#[test]
fn th26_accept_language_parse_agrees_with_reference() {
    check("th26_accept_language_parse_agrees_with_reference", |g| {
        let input = near_header(g);
        g.note_with(|| String::from_utf8_lossy(&input).into_owned());
        let got = parse_accept_language(&input);
        prop_assert_eq!(&got, &parse_accept_language(&input));
        let want = lang::parse(&input);
        match got {
            Ok(_) => prop_assert!(want.is_ok(), "accepted, the reference refuses: {want:?}"),
            Err(e) => {
                prop_assert!(is_typed(&e), "{e}");
                prop_assert!(want.is_err(), "refused, the reference accepts: {e}");
            }
        }
        Ok(())
    });
}

/// R-NF-04: negotiation gives the expected locale for each fixed example,
/// the same examples the reference passes.
#[test]
fn r_nf_04_negotiation_examples() {
    let mut failures = Vec::new();
    for &(header, available, default, want) in lang::EXAMPLES {
        match bind::negotiate(header.as_bytes(), available, default) {
            Ok(got) if got == want => {}
            other => failures.push(format!("{header:?} {available:?}: {other:?}, want {want}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// R-NF-04: over generated headers and locale sets, negotiation agrees
/// with the reference lookup, and falls back to the default for a header
/// that does not parse.
#[test]
fn r_nf_04_negotiation_agrees_with_reference() {
    const LOCALES: &[&str] = &["en", "fr", "fr-CA", "de", "de-AT", "zh-Hant", "pt-BR"];
    check("r_nf_04_negotiation_agrees_with_reference", |g| {
        let header = near_header(g);
        let mut available: Vec<&str> = LOCALES.iter().copied().filter(|_| g.bool()).collect();
        if available.is_empty() {
            available.push("en");
        }
        let default = *g.pick(&available);
        g.note_with(|| String::from_utf8_lossy(&header).into_owned());
        g.note("available", &available);
        let got = bind::negotiate(&header, &available, default).map_err(|e| e.to_string())?;
        prop_assert_eq!(got, lang::negotiate(&header, &available, default));
        Ok(())
    });
}
