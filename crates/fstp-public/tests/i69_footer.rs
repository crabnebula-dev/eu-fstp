//! I-69: every public page renders the footer of mandatory elements,
//! whatever stylesheet the tenant brand adds (M9 lane B2).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod support;

use fstp_public::{Chrome, FunderFooter, render_html};
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
        Chrome {
            stylesheet: None,
            funder: None,
        },
        Chrome {
            stylesheet: Some(brand.clone()),
            funder: None,
        },
        Chrome {
            stylesheet: Some(brand.clone()),
            funder: Some(he_v1()),
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

/// The footer data of the shipped Horizon Europe profile, version 1: its
/// two visibility element keys (`crates/fstp-report/profiles/horizon-europe/profile.v1.json`).
fn he_v1() -> FunderFooter {
    FunderFooter {
        profile: "horizon-europe".to_owned(),
        version: 1,
        elements: vec!["acknowledgement".to_owned(), "emblem".to_owned()],
    }
}

/// The values of every `attr="..."` in `html`, in order.
fn attr_values(html: &str, attr: &str) -> Vec<String> {
    let needle = format!("{attr}=\"");
    html.match_indices(&needle)
        .filter_map(|(at, _)| {
            let start = at + needle.len();
            html[start..]
                .find('"')
                .map(|end| html[start..start + end].to_owned())
        })
        .collect()
}

/// The `data-mandatory` key of the element of profile visibility key `k`.
fn element_key(k: &str) -> String {
    format!("funder_visibility.{k}")
}

/// I-69, M9 design section 2.4: the funder visibility element comes from
/// the pinned funder profile. Every page carries, inside the one footer
/// and inside the funder visibility item, one non-empty element per
/// visibility element key, keyed `funder_visibility.<key>`, whose text
/// names the profile and its version. A page without a pinned profile
/// carries no profile element and keeps the platform element.
#[test]
fn i69_footer_carries_the_pinned_funder_profile_elements() {
    let view = sample_view(true);
    let mut failures = Vec::new();
    for funder in [None, Some(he_v1())] {
        let chrome = Chrome {
            stylesheet: None,
            funder: funder.clone(),
        };
        for p in traced_pages(&view) {
            let html = match render_html(&view, &p, &chrome) {
                Ok(d) => d.as_str().to_owned(),
                Err(e) => {
                    failures.push(format!("{p:?}: {e}"));
                    continue;
                }
            };
            let footer = html.split("<footer").nth(1).unwrap_or("");
            let body = html.split("<footer").next().unwrap_or("");
            if body.contains("data-mandatory=") {
                failures.push(format!("{p:?}: a mandatory element outside the footer"));
            }
            // The funder visibility item: from its platform element to the end of its `li`.
            let item = footer
                .split("data-mandatory=\"funder_visibility\"")
                .nth(1)
                .and_then(|rest| rest.split("</li>").next())
                .unwrap_or("");
            let want: Vec<String> = funder
                .as_ref()
                .map(|f| f.elements.iter().map(|k| element_key(k)).collect())
                .unwrap_or_default();
            if attr_values(item, "data-mandatory") != want {
                failures.push(format!(
                    "{p:?}: funder elements {:?}",
                    attr_values(item, "data-mandatory")
                ));
            }
            let all = attr_values(footer, "data-mandatory");
            if all.len() != KEYS.len() + want.len() {
                failures.push(format!("{p:?}: footer elements {all:?}"));
            }
            if let Some(f) = &funder {
                for k in &want {
                    match element_text(item, k) {
                        Some(t) if t.contains(&f.profile) && t.contains(&f.version.to_string()) => {
                        }
                        t => failures.push(format!("{p:?}: {k} text {t:?}")),
                    }
                }
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
