//! Self-tests of the independent references in `tests/common`.
//!
//! The other test files use these references as oracles for I-68, I-72,
//! I-87, R-NF-04, R-PB-04 and TH-26. A wrong oracle would let a wrong
//! writer pass, so each one is checked here against its own fixtures. These
//! tests need no production code and pass against the W0 stub.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::chars::is_safe_url;
use common::{cases, corpus, lang, message, reference, serial, spec};
use fstp_prop::{check, prop_assert_eq};

/// I-68, R-PB-04: the reference serializer and parser agree. Every
/// generated page's expected tree, written with random but valid spelling
/// choices, parses back to the same tree.
#[test]
fn i68_reference_round_trips_generated_documents() {
    let cats = message::fixture();
    check("i68_reference_round_trips_generated_documents", |g| {
        let page = spec::page(g, &cats, spec::VALID);
        let tree = spec::expected_tree(&page, &cats)?;
        let bytes = serial::document(g, &tree);
        g.note_with(|| String::from_utf8_lossy(&bytes).into_owned());
        let back = reference::parse(&bytes)?;
        prop_assert_eq!(back, tree);
        Ok(())
    });
}

/// TH-26, R-PB-04: the reference refuses every fixed refusal.
#[test]
fn th26_reference_refuses_each_fixed_refusal() {
    for (rule, doc) in cases::refused() {
        assert!(
            reference::parse(&doc).is_err(),
            "the reference accepts {rule}: {}",
            String::from_utf8_lossy(&doc)
        );
    }
}

/// TH-26, R-NF-03: the reference accepts every fixed acceptance.
#[test]
fn th26_reference_accepts_each_fixed_acceptance() {
    for (allowance, doc) in cases::accepted() {
        if let Err(e) = reference::parse(&doc) {
            panic!(
                "the reference refuses {allowance}: {e}\n{}",
                String::from_utf8_lossy(&doc)
            );
        }
    }
}

/// I-68: the safe URL rule on examples from ADR-014 `safeUrl`.
#[test]
fn i68_reference_safe_url_examples() {
    let safe = [
        "/",
        "/p/x/",
        "/p/x/calls/y?z=1#top",
        "/a\"b",
        "/<script>",
        "https://example.org",
        "https://example.org/x?y",
    ];
    let unsafe_ = [
        "",
        "//evil.example",
        "/\\evil.example",
        "\\/evil.example",
        "javascript:alert(1)",
        "http://example.org/",
        "HTTPS://example.org/",
        "https:/x",
        "https:///x",
        "https://",
        "/a b",
        "/\t/x",
        "/\u{e9}",
        "#top",
        "x",
    ];
    for u in safe {
        assert!(is_safe_url(u), "{u:?} should be safe");
    }
    for u in unsafe_ {
        assert!(!is_safe_url(u), "{u:?} should be unsafe");
    }
}

/// R-NF-04: the reference message grammar agrees with the shared corpus.
#[test]
fn r_nf_04_reference_message_grammar_agrees_with_corpus() {
    for c in corpus::read("message_format.corpus") {
        let got = message::parse(&c.input);
        assert_eq!(
            got.is_ok(),
            c.accept,
            "line {}: {:?} gives {got:?}",
            c.line,
            String::from_utf8_lossy(&c.input)
        );
    }
}

/// R-NF-04: the reference formatter on the fixture, including literal
/// braces and a placeholder used twice.
#[test]
fn r_nf_04_reference_formats_fixture_messages() {
    let cats = message::fixture();
    let amount = vec![("amount".to_owned(), "5".to_owned())];
    let (en, en_uses) = cats
        .resolve("en", message::Kind::Label, "call.budget", &amount)
        .unwrap();
    assert_eq!(en, "Budget & costs <up to> 5 \"EUR\" {fixed}");
    assert_eq!(en_uses, ["amount"]);
    let (fr, fr_uses) = cats
        .resolve("fr", message::Kind::Label, "call.budget", &amount)
        .unwrap();
    assert_eq!(fr, "5 & co\u{fb}ts {fixe} <5>");
    assert_eq!(fr_uses, ["amount", "amount"]);
    assert!(
        cats.resolve("en", message::Kind::Approved, "call.budget", &amount)
            .is_err()
    );
    assert!(
        cats.resolve("en", message::Kind::Label, "call.budget", &[])
            .is_err()
    );
}

/// R-NF-04, I-72: the fixture catalogue set meets every catalogue rule.
#[test]
fn r_nf_04_reference_fixture_catalogue_is_valid() {
    message::fixture().check().unwrap();
}

/// TH-26, R-NF-04: the reference `Accept-Language` grammar agrees with the
/// shared corpus.
#[test]
fn th26_reference_accept_language_agrees_with_corpus() {
    for c in corpus::read("accept_language.corpus") {
        let got = lang::parse(&c.input);
        assert_eq!(
            got.is_ok(),
            c.accept,
            "line {}: {:?} gives {got:?}",
            c.line,
            String::from_utf8_lossy(&c.input)
        );
    }
}

/// R-NF-04: the reference negotiation gives the expected locale for each
/// example.
#[test]
fn r_nf_04_reference_negotiation_examples() {
    for &(header, available, default, want) in lang::EXAMPLES {
        assert_eq!(
            lang::negotiate(header.as_bytes(), available, default),
            want,
            "header {header:?}"
        );
    }
}
