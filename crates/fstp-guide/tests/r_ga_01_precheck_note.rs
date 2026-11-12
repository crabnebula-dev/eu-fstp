//! The Guide keeps its pre-check section with a fixed note that the
//! pre-check is not yet available, while the cell has no pre-check
//! provider (R-GA-01, R-LA-08; Q38 C, Daniel's answer of 2026-11-06 in
//! section 15.0 of the M4 design).
//!
//! The template is the specification's text byte for byte, so the note
//! comes from the renderer: one paragraph right after the block that
//! describes the pre-check, in the page and in the canonical document the
//! publication digest is taken over. A template without the pre-check
//! description gets no note.
//!
//! With a pre-check provider (the `Precheck` port present, M7), the note
//! gives way to [`fstp_guide::PRECHECK_AVAILABLE`]: the check is there,
//! it is an AI system, it gives findings and never scores, and each run
//! counts towards the P-23 limits the template states just before. Its
//! disclosure wording is marked [`fstp_guide::PRECHECK_LEGAL`] for
//! approval. A published Guide is stored and never bound again (I-53), so
//! only Guides published after this change carry the new paragraph.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod support;

use support::{Inputs, guide, guide_from, supersafe_inputs};

/// The SuperSAFE inputs with the pre-check provider present or absent.
fn inputs(port: bool) -> Inputs {
    let mut i = supersafe_inputs().unwrap();
    i.precheck_available = port;
    i
}

/// The shipped template without its pre-check step.
fn without_step() -> String {
    let text = support::SPEC_TEMPLATE;
    let start = text.find("3. Optionally run").unwrap();
    let end = start + text[start..].find('\n').unwrap() + 1;
    format!("{}{}", &text[..start], &text[end..]).replace("4. Submit", "3. Submit")
}

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
    assert!(!r.html.contains(fstp_guide::PRECHECK_AVAILABLE));
    assert!(!canonical.contains(fstp_guide::PRECHECK_AVAILABLE));
}

/// R-GA-01, Q38 C: a template that does not describe the pre-check gets
/// no note, so the note never stands alone.
#[test]
fn r_ga_01_q38_no_note_without_the_precheck_description() {
    let r = guide_from(without_step().as_bytes(), &supersafe_inputs().unwrap())
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(!r.html.contains(fstp_guide::PRECHECK_NOTE));
}

/// R-GA-01, R-LA-08, Q38: with the pre-check port present, the page
/// carries the available pre-check paragraph once, right after the step,
/// and its legal marker after that. The "not yet available" note is gone
/// from the page and from the canonical document.
#[test]
fn r_ga_01_r_la_08_q38_port_present_describes_the_available_precheck() {
    let r = guide(&inputs(true)).unwrap_or_else(|e| panic!("{e}"));
    let para = fstp_guide::PRECHECK_AVAILABLE;
    let legal = fstp_guide::PRECHECK_LEGAL;
    assert!(!r.html.contains(fstp_guide::PRECHECK_NOTE), "{}", r.html);
    assert!(!r.html.contains("not yet available"), "{}", r.html);
    assert_eq!(r.html.matches(para).count(), 1, "{}", r.html);
    assert_eq!(r.html.matches(legal).count(), 1, "{}", r.html);
    let step = r
        .html
        .find("Optionally run the pre-submission check")
        .expect("the pre-check step stays");
    let at = r.html.find(para).unwrap();
    assert!(at > step, "the paragraph comes after the pre-check step");
    assert!(r.html.find(legal).unwrap() > at, "the marker follows it");
    let canonical = String::from_utf8(r.canonical.clone()).unwrap();
    assert!(canonical.contains(para), "the digest input lacks the text");
    assert!(
        canonical.contains(legal),
        "the digest input lacks the marker"
    );
    assert!(!canonical.contains(fstp_guide::PRECHECK_NOTE));
}

/// R-LA-08, TH-02, P-23, Q38: the paragraph discloses the AI system,
/// says it gives findings and never a score, and points to the P-23
/// limits. The step before it shows the per-day limit as a locked value
/// bound from P-23, so the paragraph restates no number of its own.
#[test]
fn r_la_08_q38_precheck_paragraph_discloses_ai_and_findings_only() {
    let para = fstp_guide::PRECHECK_AVAILABLE;
    assert!(para.contains("AI system"), "{para}");
    assert!(para.contains("findings"), "{para}");
    assert!(para.contains("never as a score"), "{para}");
    assert!(para.contains("limits above"), "{para}");
    assert!(
        !para.chars().any(|c| c.is_ascii_digit()),
        "the paragraph must not state a P-23 number of its own: {para}"
    );
    assert!(
        fstp_guide::PRECHECK_LEGAL.starts_with(fstp_guide::LEGAL_MARKER),
        "the disclosure wording is marked for legal approval"
    );
    let r = guide(&inputs(true)).unwrap_or_else(|e| panic!("{e}"));
    let per_day: Vec<_> = r.bound.iter().filter(|b| b.key == "P-23.per_day").collect();
    assert_eq!(per_day.len(), 1, "the per-day limit is bound once");
    assert!(!per_day[0].editable, "the P-23 limit is locked (I-51)");
    let step = r
        .html
        .find("Optionally run the pre-submission check")
        .unwrap();
    let value = r.html[step..].find(&per_day[0].text).map(|i| i + step);
    let at = r.html.find(para).unwrap();
    assert!(
        value.is_some_and(|v| v < at),
        "the per-day limit stands in the step before the paragraph"
    );
}

/// I-51, I-52, Q38: the flag changes the canonical document the
/// publication digest is taken over, so the two pages never share a
/// digest. Everything else is the same: every bound value is equal.
#[test]
fn i52_q38_precheck_flag_changes_the_digest_input() {
    let off = guide(&inputs(false)).unwrap_or_else(|e| panic!("{e}"));
    let on = guide(&inputs(true)).unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(off.canonical, on.canonical);
    assert_ne!(off.html, on.html);
    assert_eq!(off.bound, on.bound, "the flag binds no placeholder");
    let again = guide(&inputs(true)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(on.canonical, again.canonical, "rendering is deterministic");
    assert_eq!(on.html, again.html);
}

/// R-GA-01, Q38: a template that does not describe the pre-check gets
/// no pre-check paragraph either, so it never stands alone.
#[test]
fn r_ga_01_q38_no_paragraph_without_the_precheck_description() {
    let r = guide_from(without_step().as_bytes(), &inputs(true)).unwrap_or_else(|e| panic!("{e}"));
    assert!(!r.html.contains(fstp_guide::PRECHECK_AVAILABLE));
    assert!(!r.html.contains(fstp_guide::PRECHECK_LEGAL));
    assert!(!r.html.contains(fstp_guide::PRECHECK_NOTE));
}
