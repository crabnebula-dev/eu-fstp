//! Review reproducer: the crate table of M4 design section 1.1 says
//! `fstp-signup` holds "the server-rendered sign-up and agreement forms",
//! and lists `fstp-html` as its dependency for that. The lane removed
//! the rendering from the crate doc and renders nothing. `fstp-control`
//! and the J0 browser journey (W5) have no page that carries the field
//! names this decoder requires, nor the `TODO(legal)` agreement
//! placeholders.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

/// TH-46, R-TN-01: some source file of the crate renders through
/// `fstp-html`.
#[test]
fn review_signup_and_agreement_forms_are_rendered() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut renders = false;
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).unwrap();
            renders |= text.contains("fstp_html::");
        }
    }
    assert!(
        renders,
        "no file under {} uses fstp_html: the sign-up and agreement forms are not rendered",
        src.display()
    );
}
