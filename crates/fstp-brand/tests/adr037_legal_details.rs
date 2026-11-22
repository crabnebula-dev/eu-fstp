//! ADR-037 section 1: the tenant's legal details are plain text only
//! (I-68), each field optional, and the placeholder names map to fields.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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
