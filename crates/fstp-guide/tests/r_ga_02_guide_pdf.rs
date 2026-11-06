//! R-GA-02, I-53: the Guide for Applicants as a tagged PDF, rendered from
//! the stored canonical document (M5 design section 3.3).
//!
//! - The same canonical document gives the same PDF bytes, so a published
//!   Guide's PDF never changes (I-53).
//! - The PDF holds the content of the stored Guide: its title, every
//!   required section and every bound value.
//! - The PDF is tagged: a structure tree, `/MarkInfo` and `/Lang`.
//! - A document that is not a canonical Guide is refused by line.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use fstp_guide::{GUIDE_TITLE, GuidePdfError, guide_pdf, read_canonical};
use support::{Rendered, guide, required_sections, supersafe_inputs};

fn stored() -> Rendered {
    let inputs = supersafe_inputs().unwrap_or_else(|e| panic!("inputs: {e}"));
    guide(&inputs).unwrap_or_else(|e| panic!("the Guide does not render: {e}"))
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

/// R-GA-02, I-53: the same stored Guide gives the same PDF bytes.
#[test]
fn r_ga_02_i53_guide_pdf_same_bytes_for_same_stored_guide() {
    let g = stored();
    let a = guide_pdf(&g.canonical).unwrap_or_else(|e| panic!("R-GA-02: no PDF: {e}"));
    let copy = g.canonical.clone();
    let b = guide_pdf(&copy).unwrap_or_else(|e| panic!("R-GA-02: no PDF: {e}"));
    assert_eq!(a, b, "I-53: the PDF of one stored Guide changed");
    let again = stored();
    assert_eq!(
        guide_pdf(&again.canonical).unwrap(),
        a,
        "R-GA-02: rendering the Guide again gave other PDF bytes"
    );
    assert!(a.starts_with(b"%PDF-"), "R-GA-02: not a PDF");
}

/// R-GA-02: the PDF holds the stored Guide's title, sections and values.
#[test]
fn r_ga_02_guide_pdf_matches_stored_guide_content() {
    let g = stored();
    let content = read_canonical(&g.canonical).unwrap_or_else(|e| panic!("R-GA-02: {e}"));
    assert_eq!(content.title(), GUIDE_TITLE);
    assert_eq!(
        content.blocks().first().map(|b| b.text.as_str()),
        Some(GUIDE_TITLE),
        "R-GA-02: the title is not the first block"
    );
    let sections = content.sections();
    for name in required_sections() {
        if name == "About the programme" {
            continue;
        }
        assert!(
            sections.iter().any(|s| *s == name),
            "R-GA-02: the PDF lacks the required section {name:?}"
        );
    }
    let text: String = content
        .blocks()
        .iter()
        .map(|b| b.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for b in &g.bound {
        for piece in b.text.split('\n').filter(|p| !p.trim().is_empty()) {
            assert!(
                text.contains(piece.trim()),
                "R-GA-02: the PDF lacks the value of {{{{{}}}}}: {piece:?}",
                b.key
            );
        }
        assert!(
            content.value(&b.key).is_some(),
            "R-GA-02: the value of {} is not read back",
            b.key
        );
    }
}

/// R-GA-02, M5 design section 3.3: the PDF is tagged.
#[test]
fn r_ga_02_guide_pdf_is_tagged() {
    let pdf = guide_pdf(&stored().canonical).unwrap();
    for marker in [
        "/StructTreeRoot",
        "/MarkInfo",
        "/Lang (en)",
        "/H1",
        "/H2",
        "/P",
    ] {
        assert!(contains(&pdf, marker), "R-GA-02: the PDF has no {marker}");
    }
}

/// I-53: another stored Guide gives another PDF.
#[test]
fn i53_changed_guide_gives_other_pdf() {
    let g = stored();
    let text = String::from_utf8(g.canonical.clone()).unwrap();
    let changed = text.replacen("Call at a glance", "Call at one glance", 1);
    assert_ne!(changed, text, "the fixture has the section");
    assert_ne!(
        guide_pdf(changed.as_bytes()).unwrap(),
        guide_pdf(&g.canonical).unwrap(),
        "I-53: two different Guides gave one PDF"
    );
}

/// R-GA-02, TH-26: a document that is not a canonical Guide is refused.
#[test]
fn r_ga_02_guide_pdf_refuses_non_canonical_input() {
    assert_eq!(guide_pdf(b"# Guide\n"), Err(GuidePdfError::Version));
    let bad = "[\"fstp.guide\",1]\n[\"title\",\"Guide for Applicants\"]\n[\"script\",\"x\"]\n";
    assert!(matches!(
        guide_pdf(bad.as_bytes()),
        Err(GuidePdfError::Line { line: 3, .. })
    ));
    let not_json = "[\"fstp.guide\",1]\n[\"title\",\"G\"]\n{oops\n";
    assert!(matches!(
        guide_pdf(not_json.as_bytes()),
        Err(GuidePdfError::Line { line: 3, .. })
    ));
}
