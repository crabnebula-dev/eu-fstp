//! ADR-034: the funding card's platform asset, its colours and its
//! lines (I-68, I-69, I-70, R-WL-04, R-NF-04).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::string_slice
)]

use fstp_brand::funding::{
    CARD_GROUND, CARD_LABEL, CARD_TEXT, FUNDED_BY_EU_ALT, FUNDED_BY_EU_PNG, FUNDED_BY_EU_SVG,
    FundingCard, FundingDefaults, MAX_DEFAULT_BYTES,
};
use fstp_brand::{ThemeMode, meets_aa};

/// The vendored original, as Daniel supplied it on 2026-11-22.
const ORIGINAL: &str = include_str!("../../../third_party/eu-emblem/funded-by-eu.svg");

/// Every value of attribute `name` in `svg`, in document order. The
/// attribute must follow white space, so `id="..."` never matches `d`.
fn attrs(svg: &str, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let needle = format!("{name}=\"");
    let mut rest = svg;
    while let Some(i) = rest.find(&needle) {
        let before = rest[..i].chars().last();
        let after = &rest[i + needle.len()..];
        let Some(end) = after.find('"') else { break };
        if before.is_some_and(char::is_whitespace) {
            out.push(after[..end].to_owned());
        }
        rest = &after[end..];
    }
    out
}

/// ADR-034 section 1: the web copy keeps every path, colour, the group
/// transform, the view box and the size of the vendored original. Only
/// the Inkscape and sodipodi metadata is gone.
#[test]
fn adr034_web_copy_keeps_the_path_data_of_the_original() {
    for name in [
        "d",
        "fill",
        "fill-rule",
        "fill-opacity",
        "style",
        "transform",
        "viewBox",
        "width",
        "height",
    ] {
        let a = attrs(ORIGINAL, name);
        assert!(!a.is_empty() || name == "style", "{name} occurs");
        assert_eq!(a, attrs(FUNDED_BY_EU_SVG, name), "{name} unchanged");
    }
    assert_eq!(attrs(FUNDED_BY_EU_SVG, "d").len(), 16);
}

/// I-68 by analogy, ADR-034 section 1: the served SVG holds no script,
/// link, event attribute or editor metadata.
#[test]
fn i68_web_copy_holds_no_script_link_or_metadata() {
    let lower = FUNDED_BY_EU_SVG.to_ascii_lowercase();
    for banned in [
        "inkscape",
        "sodipodi",
        "<script",
        "href",
        " on",
        "<!--",
        "<foreignobject",
        "url(",
    ] {
        assert!(!lower.contains(banned), "{banned}");
    }
    assert!(FUNDED_BY_EU_SVG.starts_with("<?xml"));
    assert!(lower.contains("<svg"));
}

/// ADR-034 section 1: the PNG is a canonical opaque RGB image the logo
/// rules accept, and it fills the EU emblem slot of ADR-030.
#[test]
fn adr034_png_fills_the_emblem_slot() {
    assert_eq!(fstp_brand::emblem::EU_EMBLEM_PNG, Some(FUNDED_BY_EU_PNG));
    let info = fstp_brand::image::inspect(FUNDED_BY_EU_PNG).expect("a valid logo");
    assert_eq!((info.width, info.height), (1166, 240));
    let pdf = fstp_brand::image::pdf_image(FUNDED_BY_EU_PNG).expect("PDFs show it");
    assert!(pdf.alpha.is_none(), "opaque on white");
}

/// R-NF-04: the alternative text is the words the logo shows.
#[test]
fn r_nf_04_alt_text_is_funded_by_the_european_union() {
    assert_eq!(FUNDED_BY_EU_ALT, "Funded by the European Union");
}

/// I-70: the card's text and labels meet AA on the card's ground, which
/// is white in both themes, so the official colours always show.
#[test]
fn i70_card_text_meets_aa_in_both_themes() {
    for mode in [ThemeMode::Light, ThemeMode::Dark] {
        let ground = CARD_GROUND.of(mode);
        assert_eq!(
            (ground.r, ground.g, ground.b),
            (0xff, 0xff, 0xff),
            "{mode:?}"
        );
        assert!(meets_aa(CARD_TEXT.of(mode), ground), "{mode:?} text");
        assert!(meets_aa(CARD_LABEL.of(mode), ground), "{mode:?} label");
    }
}

fn card() -> FundingCard {
    FundingCard {
        programme: 7,
        name: "Synthetic programme".to_owned(),
        grant_number: Some("SYNTHETIC-000000000".to_owned()),
        coordinator_name: Some("Synthetic coordinator".to_owned()),
        coordinator_contact: Some("contact@example.org".to_owned()),
    }
}

/// I-69, ADR-034 section 2: a complete card shows the grant agreement
/// number, the coordinator and the contact, in that order.
#[test]
fn i69_card_lines_name_grant_number_coordinator_and_contact() {
    let c = card();
    let lines = c.lines();
    let labels: Vec<&str> = lines.iter().map(|(l, _)| *l).collect();
    assert_eq!(labels, ["Grant agreement number", "Coordinator", "Contact"]);
    assert_eq!(lines[0].1, "SYNTHETIC-000000000");
    assert!(card().complete());
}

/// I-69: a card missing its grant number or coordinator contact is not
/// complete, and its line says the value is not set yet.
#[test]
fn i69_incomplete_card_says_what_is_missing() {
    let mut c = card();
    c.coordinator_contact = None;
    assert!(!c.complete());
    let lines = c.lines();
    assert_eq!(lines[2].1, "Not set yet");
    let mut c = card();
    c.grant_number = Some(String::new());
    assert!(!c.complete());
}

/// ADR-034 section 3: a tenant default is used only where the
/// programme's own value is missing.
#[test]
fn adr034_tenant_default_fills_only_gaps() {
    let d = FundingDefaults::new("Default org", "role@example.org").expect("valid");
    let mut c = card();
    c.coordinator_contact = None;
    let c = c.with_defaults(Some(&d));
    assert_eq!(c.coordinator_contact.as_deref(), Some("role@example.org"));
    assert_eq!(c.coordinator_name.as_deref(), Some("Synthetic coordinator"));
}

/// I-68, ADR-034 section 3: a default is short plain text.
#[test]
fn i68_tenant_defaults_are_plain_text() {
    assert!(FundingDefaults::new("Org", "a@b.example").is_some());
    for bad in [
        "",
        " lead",
        "<b>x</b>",
        "a\nb",
        &"x".repeat(MAX_DEFAULT_BYTES + 1),
    ] {
        assert!(
            FundingDefaults::new(bad, "a@b.example").is_none(),
            "{bad:?}"
        );
        assert!(FundingDefaults::new("Org", bad).is_none(), "{bad:?}");
    }
}

/// I-70, I-69: the stylesheets of the app, public and sign-in pages give
/// the card exactly the checked colours, once, in `:root`, and never for
/// a dark theme, so neither a theme nor a brand token changes them.
#[test]
fn i70_card_colours_in_the_stylesheets_are_the_checked_ones() {
    let hex = |c: fstp_brand::Rgb| format!("#{:02x}{:02x}{:02x}", c.r, c.g, c.b);
    for css in [
        include_str!("../../../web/src/site/tokens.css"),
        include_str!("../../../web/src/auth/tokens.css"),
    ] {
        for (name, colour) in [
            ("--funding-card-ground", CARD_GROUND.of(ThemeMode::Light)),
            ("--funding-card-text", CARD_TEXT.of(ThemeMode::Light)),
            ("--funding-card-label", CARD_LABEL.of(ThemeMode::Light)),
        ] {
            let decl = format!("{name}: {};", hex(colour));
            assert_eq!(css.matches(&decl).count(), 1, "{decl}");
            assert_eq!(
                css.matches(&format!("{name}:")).count(),
                1,
                "{name} set once"
            );
        }
    }
}
