//! Fuzz target `legal_markdown` of `fstp-public` (ADR-037 section 2,
//! CLAUDE.md: every in-house parser has a fuzz target from its first
//! commit).
//!
//! Design checks: the Markdown subset parser of the legal drafts never
//! panics, and any input renders as a well-formed page of the writer's
//! subset, with no script, no raw `TODO(legal)` marker and no tenant value
//! written as markup (I-68, R-PB-04).

#![no_main]

use fstp_public::legal::{LegalPage, LegalText, markdown, render_source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(src) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(blocks) = markdown::parse(src) else {
        return;
    };
    let _ = markdown::placeholders(&blocks);
    let _ = markdown::pending_points(&blocks);
    let value = |name: &str| name.len().is_multiple_of(2).then(|| "<b>v</b>".to_owned());
    let page = LegalPage {
        text: LegalText::Privacy,
        approved: data.first().is_some_and(|b| b & 1 == 1),
        value: &value,
        stylesheet: None,
    };
    let html = render_source(&page, src).expect("every parsed source renders");
    let html = html.as_str();
    assert!(fstp_html::check_wellformed(html.as_bytes()).is_ok());
    assert!(!html.contains("<script"));
    assert!(!html.contains("<b>v"));
    assert!(!html.contains("TODO(legal)"));
});
