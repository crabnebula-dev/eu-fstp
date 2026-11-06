//! The Guide keeps its pre-check section with a fixed note that the
//! pre-check is not yet available (R-GA-01, R-LA-08; Q38 C, Daniel's
//! answer of 2026-11-06 in section 15.0 of the M4 design).
//!
//! The template is the specification's text byte for byte, so the note
//! comes from the renderer: one paragraph right after the block that
//! describes the pre-check, in the page and in the canonical document the
//! publication digest is taken over. A template without the pre-check
//! description gets no note.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use support::{guide, guide_from, supersafe_inputs};

/// R-GA-01, Q38 C: the page keeps the pre-check step and carries the
/// fixed note after it, once, and the canonical document holds it.
#[test]
fn r_ga_01_q38_guide_notes_the_precheck_is_not_yet_available() {
    let r = guide(&supersafe_inputs().unwrap()).unwrap_or_else(|e| panic!("{e}"));
    let note = fstp_guide::PRECHECK_NOTE;
    assert!(note.contains("not yet available"), "{note}");
    assert_eq!(r.html.matches(note).count(), 1, "{}", r.html);
    let step = r
        .html
        .find("Optionally run the pre-submission check")
        .expect("the pre-check step stays");
    let at = r.html.find(note).unwrap();
    assert!(at > step, "the note comes after the pre-check step");
    let canonical = String::from_utf8(r.canonical.clone()).unwrap();
    assert!(canonical.contains(note), "the digest input lacks the note");
}

/// R-GA-01, Q38 C: a template that does not describe the pre-check gets
/// no note, so the note never stands alone.
#[test]
fn r_ga_01_q38_no_note_without_the_precheck_description() {
    let text = support::SPEC_TEMPLATE;
    let start = text.find("3. Optionally run").unwrap();
    let end = start + text[start..].find('\n').unwrap() + 1;
    let without = format!("{}{}", &text[..start], &text[end..]).replace("4. Submit", "3. Submit");
    let r = guide_from(without.as_bytes(), &supersafe_inputs().unwrap())
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(!r.html.contains(fstp_guide::PRECHECK_NOTE));
}
