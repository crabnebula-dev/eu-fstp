//! ADR-037 section 1: the tenant's legal details are plain text only
//! (I-68), each field optional, and the placeholder names map to fields.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_brand::legal::{LegalDetails, LegalField, MAX_LEGAL_BYTES};
use fstp_prop::{check, prop_assert};

/// I-68, ADR-037: a value with markup, a control character, outer white
/// space or more than the limit is refused; an empty value is unset.
#[test]
fn i68_adr037_legal_values_are_plain_text() {
    let ok = LegalDetails::from_pairs(&[("legal_name", "Synthetic Org Ltd"), ("vat_number", "")])
        .expect("valid");
    assert_eq!(ok.get(LegalField::LegalName), Some("Synthetic Org Ltd"));
    assert_eq!(ok.get(LegalField::VatNumber), None);
    for bad in [
        "<b>x</b>",
        "a>b",
        "line\nbreak",
        " padded",
        "padded ",
        "nul\u{0}",
    ] {
        assert!(
            LegalDetails::from_pairs(&[("legal_name", bad)]).is_none(),
            "{bad:?}"
        );
    }
    let long = "a".repeat(MAX_LEGAL_BYTES + 1);
    assert!(LegalDetails::from_pairs(&[("address", &long)]).is_none());
    let max = "a".repeat(MAX_LEGAL_BYTES);
    assert!(LegalDetails::from_pairs(&[("address", &max)]).is_some());
    // An unknown key and a key named twice are refused.
    assert!(LegalDetails::from_pairs(&[("nickname", "x")]).is_none());
    assert!(LegalDetails::from_pairs(&[("legal_name", "a"), ("legal_name", "b")]).is_none());
}

/// I-68 (property): whatever string is offered, an accepted value holds
/// no angle bracket and no control character.
#[test]
fn i68_adr037_accepted_values_never_hold_markup() {
    check("i68_adr037_accepted_values_never_hold_markup", |g| {
        let alphabet: Vec<char> = "ab <>\n\t&\"'{}|é\u{7f}".chars().collect();
        let n = g.usize_in(0..=24);
        let s: String = (0..n).map(|_| *g.pick(&alphabet)).collect();
        if let Some(d) = LegalDetails::from_pairs(&[("privacy_contact", &s)])
            && let Some(v) = d.get(LegalField::PrivacyContact)
        {
            prop_assert!(!v.chars().any(|c| c == '<' || c == '>' || c.is_control()));
            prop_assert!(v.len() <= MAX_LEGAL_BYTES);
        }
        Ok(())
    });
}

/// ADR-037 section 1: each field has one key, the keys round-trip, and
/// the placeholder names of the table resolve to their fields.
#[test]
fn adr037_field_keys_and_placeholders() {
    for f in LegalField::ALL {
        assert_eq!(LegalField::from_key(f.key()), Some(f));
    }
    assert_eq!(LegalField::ALL.len(), 12);
    assert_eq!(LegalField::ALL.map(LegalField::key), LegalField::KEYS);
    let d = LegalDetails::from_pairs(&[
        ("legal_name", "Synthetic Org Ltd"),
        ("dpo_name", "Synthetic DPO"),
        ("accessibility_contact", "a11y@example.org"),
    ])
    .unwrap();
    assert_eq!(
        d.placeholder("controller.legal_name"),
        Some("Synthetic Org Ltd")
    );
    assert_eq!(
        d.placeholder("tenant.legal_name"),
        Some("Synthetic Org Ltd")
    );
    assert_eq!(d.placeholder("controller.dpo_name"), Some("Synthetic DPO"));
    assert_eq!(
        d.placeholder("tenant.accessibility_contact"),
        Some("a11y@example.org")
    );
    assert_eq!(d.placeholder("tenant.address"), None);
    assert_eq!(d.placeholder("P-41"), None);
    assert_eq!(d.placeholder("controller.accessibility_contact"), None);
    assert_eq!(d.pairs().count(), 3);
}

/// The platform tokens, as the legal pages use them.
const TOKENS: &str = include_str!("../../../web/src/site/tokens.css");

/// The value of `--name` in the first block of `css` that sets it after
/// byte `from`, as a colour.
fn token(css: &str, name: &str, from: usize) -> fstp_brand::Rgb {
    let rest = &css[from..];
    let at = rest
        .find(&format!("--{name}: #"))
        .unwrap_or_else(|| panic!("{name}"));
    let hex = &rest[at + name.len() + 5..at + name.len() + 11];
    fstp_brand::Rgb::hex(u32::from_str_radix(hex, 16).unwrap_or_else(|_| panic!("{name}")))
}

/// I-70, ADR-037: the text of the draft banner, the pending markers, the
/// "not set" markers and the footer links meets AA on its ground in both
/// themes, read from the platform tokens.
#[test]
fn i70_adr037_legal_page_colours_meet_aa_in_both_themes() {
    let dark = TOKENS
        .find("prefers-color-scheme: dark")
        .expect("a dark block");
    for from in [0, dark] {
        for (text, ground) in [
            ("color-text-1", "color-state-warning-bg"),
            ("color-state-neutral-text", "color-state-neutral-bg"),
            ("color-brand-text", "color-surface-1"),
        ] {
            assert!(
                fstp_brand::meets_aa(token(TOKENS, text, from), token(TOKENS, ground, from)),
                "{text} on {ground} from byte {from}"
            );
        }
    }
}

/// ADR-037 (Daniel, 2026-11-23): the accessibility response time is a
/// legal detail, a `tenant.*` value only. The governing law is not: no
/// draft names it, since the terms of use state it themselves.
#[test]
fn adr037_accessibility_response_time_is_a_field_and_governing_law_is_not() {
    assert!(LegalField::KEYS.contains(&"accessibility_response_time"));
    assert!(!LegalField::KEYS.contains(&"governing_law"));
    assert!(LegalDetails::from_pairs(&[("governing_law", "Synthetic law")]).is_none());
    let d = LegalDetails::from_pairs(&[("accessibility_response_time", "10 working days")])
        .expect("plain text");
    assert_eq!(
        d.placeholder("tenant.accessibility_response_time"),
        Some("10 working days")
    );
    assert_eq!(
        d.placeholder("controller.accessibility_response_time"),
        None
    );
    assert_eq!(d.placeholder("tenant.governing_law"), None);
}
