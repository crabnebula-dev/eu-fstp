//! I-69: every public page renders the footer of mandatory elements,
//! whatever stylesheet the tenant brand adds (M9 lane B2).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod support;

use fstp_public::{Chrome, render_html};
use support::{all_pages, count, sample_view, traced_pages};

/// The `data-mandatory` keys, one per `MandatoryElement::ALL`.
const KEYS: [&str; 6] = [
    "funder_visibility",
    "ai_disclosure",
    "privacy_notice",
    "accessibility_statement",
    "data_act_information",
    "platform_attribution",
];

/// The text of the element that carries `data-mandatory="key"`.
fn element_text<'h>(html: &'h str, key: &str) -> Option<&'h str> {
    let at = html.find(&format!("data-mandatory=\"{key}\""))?;
    let open_end = html[at..].find('>')? + at + 1;
    let close = html[open_end..].find("</")? + open_end;
    Some(&html[open_end..close])
}

/// I-69: for every page and for pages with and without a brand
/// stylesheet, each mandatory element is present and non-empty, inside
/// the one footer.
#[test]
fn i69_footer_survives_any_branding() {
    let view = sample_view(true);
    let digest = "ab".repeat(32);
    let brand = format!("/brand/{digest}.css");
    let chromes = [
        Chrome { stylesheet: None },
        Chrome {
            stylesheet: Some(brand.clone()),
        },
    ];
    let mut failures = Vec::new();
    for chrome in &chromes {
        for p in traced_pages(&view) {
            let html = match render_html(&view, &p, chrome) {
                Ok(d) => d.as_str().to_owned(),
                Err(e) => {
                    failures.push(format!("{p:?}: {e}"));
                    continue;
                }
            };
            if count(&html, "<footer") != 1 {
                failures.push(format!("{p:?}: not one footer"));
            }
            let footer = html.split("<footer").nth(1).unwrap_or("");
            for k in KEYS {
                match element_text(footer, k) {
                    Some(t) if !t.trim().is_empty() => {}
                    _ => failures.push(format!("{p:?}: {k} missing or empty")),
                }
            }
            if chrome.stylesheet.is_some() && !html.contains(&format!("href=\"{brand}\"")) {
                failures.push(format!("{p:?}: brand stylesheet not linked"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    assert!(all_pages(&view).len() >= traced_pages(&view).len());
}
