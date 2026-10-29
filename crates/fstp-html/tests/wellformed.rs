//! The well-formedness checker `fstp_html::check_wellformed` (M4 design
//! sections 1.1 and 9; TH-26, H-05, R-PB-04, R-NF-03, I-68).
//!
//! The checker must accept exactly the documents of the writer's subset,
//! which `common::reference` defines (interim reading, pending Daniel).
//! It is used by the fuzz targets of `fstp-html` and `fstp-guide` and by
//! the page tests, so a checker that is too lax would let unsafe output
//! through every one of them.
//!
//! Red against the W0 stub, which refuses every input with
//! `NotImplemented`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::chars::{HOSTILE, is_typed};
use common::{bind, cases, message, reference, serial, spec};
use fstp_html::check_wellformed;
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

fn shown(doc: &[u8]) -> String {
    String::from_utf8_lossy(doc).into_owned()
}

/// TH-26, R-NF-03: the checker accepts each fixed document the subset
/// allows, including spellings the writer may never produce.
#[test]
fn th26_wellformed_check_accepts_each_fixed_acceptance() {
    let mut failures = Vec::new();
    for (allowance, doc) in cases::accepted() {
        if let Err(e) = check_wellformed(&doc) {
            failures.push(format!("{allowance}: {e}"));
        }
    }
    assert!(failures.is_empty(), "refused:\n{}", failures.join("\n"));
}

/// R-PB-04, I-68, TH-26: the checker refuses each fixed document that
/// breaks one rule of the subset, with a typed refusal.
#[test]
fn r_pb_04_wellformed_check_refuses_each_fixed_refusal() {
    let mut failures = Vec::new();
    for (rule, doc) in cases::refused() {
        match check_wellformed(&doc) {
            Ok(()) => failures.push(format!("accepted {rule}: {}", shown(&doc))),
            Err(e) if !is_typed(&e) => failures.push(format!("{rule}: {e}")),
            Err(_) => {}
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// TH-26: the checker accepts every generated document of the subset,
/// written by the reference serializer with random spelling choices.
#[test]
fn th26_wellformed_check_accepts_generated_documents() {
    let cats = message::fixture();
    check("th26_wellformed_check_accepts_generated_documents", |g| {
        let page = spec::page(g, &cats, spec::VALID);
        let tree = spec::expected_tree(&page, &cats)?;
        let doc = serial::document(g, &tree);
        g.note_with(|| shown(&doc));
        check_wellformed(&doc).map_err(|e| format!("refused: {e}"))?;
        Ok(())
    });
}

/// Applies one to three random edits to `doc`.
fn mutate(g: &mut Gen, doc: &mut Vec<u8>) {
    const BYTES: &[u8] = b"<>&\"'/=!-;#xX\n\r\t \0aAP";
    let edits = g.usize_in(1..=3);
    for _ in 0..edits {
        let len = doc.len();
        let at = g.usize_in(0..=len);
        match g.u8_in(0..=5) {
            0 => {
                let frag = g.pick(HOSTILE).as_bytes().to_vec();
                doc.splice(at..at, frag);
            }
            1 => {
                let end = at.saturating_add(g.usize_in(1..=8)).min(len);
                doc.drain(at..end);
            }
            2 if at < len => doc[at] = *g.pick(BYTES),
            3 => {
                let end = at.saturating_add(g.usize_in(1..=16)).min(len);
                let copy = doc[at..end].to_vec();
                let to = g.usize_in(0..=len);
                doc.splice(to..to, copy);
            }
            4 => doc.insert(at, g.u8()),
            5 if at < len && doc[at].is_ascii_alphabetic() => doc[at] ^= 0x20,
            _ => {}
        }
    }
}

/// TH-26, I-68: on documents one to three edits away from the subset,
/// the checker accepts exactly what the reference accepts, and every
/// refusal is typed. A lax checker fails here on the edit that breaks a
/// rule; a strict one fails on the edit that keeps the document valid.
#[test]
fn th26_wellformed_check_agrees_with_reference_on_mutated_documents() {
    let cats = message::fixture();
    check(
        "th26_wellformed_check_agrees_with_reference_on_mutated_documents",
        |g| {
            let page = spec::page(g, &cats, spec::VALID);
            let tree = spec::expected_tree(&page, &cats)?;
            let mut doc = serial::document(g, &tree);
            mutate(g, &mut doc);
            g.note_with(|| shown(&doc));
            let want = reference::parse(&doc);
            g.note("reference", &want);
            match check_wellformed(&doc) {
                Ok(()) => prop_assert!(want.is_ok(), "accepted outside the subset"),
                Err(e) => {
                    prop_assert!(is_typed(&e), "{e}");
                    prop_assert!(want.is_err(), "refused a document of the subset: {e}");
                }
            }
            Ok(())
        },
    );
}

/// TH-26, H-05: the checker is total and deterministic on arbitrary
/// bytes. It never panics, gives the same answer twice, refuses with a
/// typed error, and agrees with the reference.
#[test]
fn th26_wellformed_check_is_total_on_arbitrary_bytes() {
    check("th26_wellformed_check_is_total_on_arbitrary_bytes", |g| {
        let doc = if g.bool() {
            g.bytes(0..=96)
        } else {
            let mut d = b"<!DOCTYPE html><html lang=\"en\">".to_vec();
            d.extend(g.bytes(0..=64));
            d
        };
        g.note_with(|| shown(&doc));
        let first = check_wellformed(&doc);
        prop_assert_eq!(&first, &check_wellformed(&doc));
        match first {
            Ok(()) => prop_assert!(reference::accepts(&doc), "accepted outside the subset"),
            Err(e) => {
                prop_assert!(is_typed(&e), "{e}");
                prop_assert!(
                    !reference::accepts(&doc),
                    "refused a document of the subset"
                );
            }
        }
        Ok(())
    });
}

/// TH-26, I-68 (design section 9, `html_wellformed_check`): the checker
/// accepts every document the writer produces, for any page the writer
/// accepts.
#[test]
fn th26_wellformed_check_accepts_every_writer_document() {
    let cats_spec = message::fixture();
    check("th26_wellformed_check_accepts_every_writer_document", |g| {
        let cats = bind::catalogues(&cats_spec).map_err(|e| e.to_string())?;
        let page = spec::page(g, &cats_spec, spec::ANY);
        match bind::render(&page, &cats) {
            Ok(r) => {
                g.note_with(|| shown(&r.bytes));
                check_wellformed(&r.bytes).map_err(|e| format!("writer output refused: {e}"))?;
            }
            Err(e) => prop_assert!(is_typed(&e), "{e}"),
        }
        Ok(())
    });
}
