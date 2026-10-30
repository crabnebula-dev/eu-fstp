//! The Guide template parser (R-GA-01, I-51, M4 design section 3.10).
//!
//! - The shipped Horizon Europe template parses, from the specification's
//!   bytes and from the shipped profile.
//! - A placeholder the crate does not know is refused, by its key.
//! - A malformed placeholder is refused.
//! - Markdown outside the subset is refused inside a template too.
//! - Parsing is deterministic.
//!
//! The tests were written red against the W0 stub, which refused every
//! input with `NotImplemented`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use fstp_guide::{HORIZON_EUROPE, ProfileSource, ShippedProfiles};
use fstp_prop::{check, prop_assert};
use support::{Fail, SPEC_TEMPLATE, parse_template, parse_template_is_stable};

/// The characters of a generated key tail.
const KEY_CHARS: &[char] = &['a', 'b', 'k', 'x', 'z', '0', '7', '9', '_'];

/// The specification's template with `block` appended as its own block.
fn with_block(block: &str) -> String {
    format!("{SPEC_TEMPLATE}\n{block}\n")
}

/// R-GA-01: the specification's Horizon Europe template parses.
#[test]
fn r_ga_01_shipped_template_parses() {
    if let Err(e) = parse_template(SPEC_TEMPLATE.as_bytes()) {
        panic!("the shipped template does not parse: {e}");
    }
}

/// R-GA-01: the template the shipped profile serves parses.
#[test]
fn r_ga_01_shipped_profile_template_parses() {
    let p = ShippedProfiles.profile(HORIZON_EUROPE).unwrap();
    if let Err(e) = parse_template(p.guide_template().as_bytes()) {
        panic!("the shipped profile's template does not parse: {e}");
    }
}

/// R-GA-01: parsing the shipped template twice gives equal templates.
#[test]
fn r_ga_01_template_parse_is_deterministic() {
    match parse_template_is_stable(SPEC_TEMPLATE.as_bytes()) {
        Ok(true) => {}
        Ok(false) => panic!("two parses of the shipped template differ"),
        Err(e) => panic!("{e}"),
    }
}

/// I-51, R-GA-01: a placeholder with no resolver is refused, and the
/// refusal names its key. Each key here is near a real one.
#[test]
fn i51_unknown_placeholder_is_refused_by_name() {
    let keys = [
        "P-99",
        "P-04",
        "P-04.mid",
        "P-4.min",
        "p-04.min",
        "P-05.max",
        "call.secret",
        "programme.Name",
        "programme",
        "guide.digest",
        "applicant.email",
    ];
    let mut wrong = Vec::new();
    for key in keys {
        let text = with_block(&format!("Value {{{{{key}}}}} here."));
        match parse_template(text.as_bytes()) {
            Err(Fail::Refused(m)) if m.contains(key) => {}
            Err(Fail::Refused(m)) => wrong.push(format!("{key}: refused without its key: {m}")),
            Err(Fail::Missing(m)) => wrong.push(format!("{key}: {m}")),
            Ok(()) => wrong.push(format!("{key}: accepted")),
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// R-GA-01: a malformed placeholder is refused, never kept as text.
#[test]
fn r_ga_01_malformed_placeholder_is_refused() {
    let cases = [
        ("unterminated", "Value {{P-04.min here."),
        ("unterminated at the end", "Value {{P-04.min"),
        ("one closing brace", "Value {{P-04.min} here."),
        ("empty", "Value {{}} here."),
        ("space inside", "Value {{ P-04.min }} here."),
        ("nested", "Value {{{{P-04.min}}}} here."),
        ("line break inside", "Value {{P-04\n.min}} here."),
        (
            "placeholder inside a placeholder",
            "Value {{P-04.{{P-05}}}} here.",
        ),
    ];
    let mut wrong = Vec::new();
    for (name, block) in cases {
        match parse_template(with_block(block).as_bytes()) {
            Err(Fail::Refused(_)) => {}
            Err(Fail::Missing(m)) => wrong.push(format!("{name}: {m}")),
            Ok(()) => wrong.push(format!("{name}: accepted {block:?}")),
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// R-GA-01, I-68: Markdown outside the subset is refused inside a template,
/// as `parse_markdown` refuses it (design section 3.10).
#[test]
fn r_ga_01_template_refuses_markdown_outside_the_subset() {
    let cases = [
        ("raw HTML", "<script>alert(1)</script>"),
        ("inline HTML", "Text <b>bold</b> here."),
        ("fenced code", "```\ncode\n```"),
        ("block quote", "> quoted"),
        ("image", "![alt](https://example.org/a.png)"),
    ];
    let mut wrong = Vec::new();
    for (name, block) in cases {
        match parse_template(with_block(block).as_bytes()) {
            Err(Fail::Refused(_)) => {}
            Err(Fail::Missing(m)) => wrong.push(format!("{name}: {m}")),
            Ok(()) => wrong.push(format!("{name}: accepted {block:?}")),
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// I-51, R-GA-01: a placeholder key that no resolver can hold, put into any
/// paragraph of the shipped template, is refused by its key.
#[test]
fn i51_unknown_placeholder_anywhere_is_refused_by_name() {
    let paragraphs: Vec<(usize, &str)> = SPEC_TEMPLATE
        .match_indices("\n\n")
        .filter(|(at, _)| {
            SPEC_TEMPLATE[at + 2..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
        })
        .collect();
    assert!(paragraphs.len() > 20, "too few paragraphs to place a key");
    check("i51_unknown_placeholder_anywhere_is_refused_by_name", |g| {
        let tail: String = g.vec(1..=12, |g| *g.pick(KEY_CHARS)).into_iter().collect();
        let key = format!("unknown.{tail}");
        let at = paragraphs[g.usize_in(0..=paragraphs.len() - 1)].0 + 2;
        let mut text = SPEC_TEMPLATE.to_owned();
        text.insert_str(at, &format!("{{{{{key}}}}} "));
        g.note("key", &key);
        g.note("at", &at);
        match parse_template(text.as_bytes()) {
            Err(Fail::Refused(m)) => {
                prop_assert!(m.contains(&key), "refused without naming {key}: {m}");
                Ok(())
            }
            Err(Fail::Missing(m)) => Err(m),
            Ok(()) => Err(format!("accepted the unknown placeholder {key}")),
        }
    });
}

/// R-GA-01: the shipped template is in the canonical spelling of the
/// subset, so encoding the parsed template gives its bytes back, and
/// parsing that encoding gives an equal template.
#[test]
fn r_ga_01_shipped_template_round_trips() {
    let t = fstp_guide::parse_template(SPEC_TEMPLATE.as_bytes()).unwrap();
    let text = t.to_markdown();
    assert_eq!(text, SPEC_TEMPLATE);
    assert_eq!(fstp_guide::parse_template(text.as_bytes()).unwrap(), t);
}
