//! A Guide is generated only when it is complete (I-52, I-51, R-GA-01;
//! M4 design section 3.10).
//!
//! `fstp_public::published_guide` recomputes the template's completeness
//! when it generates the Guide: a template that lacks a required section
//! is refused by that section's name, and a placeholder that does not
//! resolve is refused by its key. The world is the Guide world of
//! `fstp_api_testkit::mc::public_model`. Every value is synthetic.
//!
//! Status: red. The W0 stub of `published_guide` refuses with
//! `PublicError::NotImplemented`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_api_testkit::mc::public_model::{GUIDE_CALL, guide_world};
use fstp_guide::{GuideError, HORIZON_EUROPE, NoStoredTexts, ProfileSource, ShippedProfiles};
use fstp_public::{GuideSource, PublicError, published_guide};

/// The shipped Horizon Europe template text.
fn template_text() -> String {
    ShippedProfiles
        .profile(HORIZON_EUROPE)
        .unwrap_or_else(|e| panic!("profile: {e:?}"))
        .guide_template()
        .to_owned()
}

/// `text` without the section whose heading line starts with `heading`,
/// up to the next level-two heading.
fn without_section(text: &str, heading: &str) -> String {
    let start = text
        .find(heading)
        .unwrap_or_else(|| panic!("no heading {heading:?}"));
    let rest = &text[start + heading.len()..];
    let end = rest
        .find("\n## ")
        .map_or(text.len(), |i| start + heading.len() + i + 1);
    format!("{}{}", &text[..start], &text[end..])
}

/// I-52: a template without its complaints section is refused by the
/// name `fstp_guide::missing_sections` gives it.
#[test]
fn i52_published_guide_refuses_a_template_missing_a_section() {
    let w = guide_world().unwrap_or_else(|e| panic!("{e}"));
    let text = without_section(&template_text(), "## 14. Complaints");
    let t = fstp_guide::parse_template(text.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    let missing = fstp_guide::missing_sections(&t);
    let first = *missing
        .first()
        .unwrap_or_else(|| panic!("nothing is missing"));
    let source = GuideSource {
        template: &t,
        compiled: &w.compiled,
        identifier: "1",
        platform_url: "https://a.fstp.example/",
        data_protection_summary: Some("Synthetic summary. Not a privacy notice."),
        privacy_statement_url: Some("https://privacy.fstp.example/statement"),
        texts: &NoStoredTexts,
    };
    assert_eq!(
        published_guide(&w.published, GUIDE_CALL, &source).map(|_| ()),
        Err(PublicError::GuideSectionMissing(first))
    );
}

/// I-51, I-52: a placeholder with no value is refused by its key, never
/// rendered empty. Here no data protection summary is supplied.
#[test]
fn i52_published_guide_refuses_an_unresolved_placeholder() {
    let w = guide_world().unwrap_or_else(|e| panic!("{e}"));
    let text = template_text();
    let t = fstp_guide::parse_template(text.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    let source = GuideSource {
        template: &t,
        compiled: &w.compiled,
        identifier: "1",
        platform_url: "https://a.fstp.example/",
        data_protection_summary: None,
        privacy_statement_url: Some("https://privacy.fstp.example/statement"),
        texts: &NoStoredTexts,
    };
    match published_guide(&w.published, GUIDE_CALL, &source) {
        Err(PublicError::Guide(GuideError::Unresolved { key, .. })) => {
            assert_eq!(key.as_str(), "gdpr.notice_summary");
        }
        other => panic!("{other:?}"),
    }
}
