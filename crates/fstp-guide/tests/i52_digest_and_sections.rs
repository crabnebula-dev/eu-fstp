//! The inputs of the Guide digest and its required sections (I-52, I-51,
//! R-GA-01, M4 design section 3.10).
//!
//! I-52: "A Guide is generated only when every required section is
//! present." Publication records `GuidePublished { digest }`, a SHA-256
//! over the canonical document. This crate owns that document, so these
//! tests check the digest's input:
//!
//! - the canonical document changes when any bound parameter changes, and
//!   only the text of that parameter changes;
//! - it changes when the call record changes;
//! - rendering is deterministic;
//! - every required section of `SPEC/02-domain/guide-for-applicants.md`
//!   is found in the shipped template, and a missing or renamed section is
//!   reported by its name.
//!
//! The digest itself needs `fstp-crypto`, which `fstp-guide` does not
//! depend on (lane report).
//!
//! The tests were written red against the W0 stubs, before `bind`, the
//! rendered accessors and `missing_sections` existed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::collections::BTreeSet;

use support::{
    MUTATIONS, Rendered, SPEC_TEMPLATE, compile_draft, guide, inputs_over, key_param,
    missing_sections, mutated_spec, reference_placeholders, required_sections, supersafe_inputs,
    supersafe_spec, template_sections, without_section,
};

/// The Guide over `inputs`, or the test fails with the reason.
fn rendered(inputs: &support::Inputs) -> Rendered {
    match guide(inputs) {
        Ok(r) => r,
        Err(e) => panic!("the Guide does not render: {e}"),
    }
}

/// The parameter-bound keys of the shipped template.
fn parameter_keys() -> BTreeSet<String> {
    reference_placeholders(SPEC_TEMPLATE)
        .into_iter()
        .filter(|k| key_param(k).is_some())
        .collect()
}

/// I-52 harness check: the mutation table has one entry for each
/// parameter-bound placeholder of the shipped template.
#[test]
fn i52_mutations_cover_every_parameter_bound_placeholder() {
    let got: Vec<&str> = MUTATIONS.iter().map(|m| m.key).collect();
    let unique: BTreeSet<String> = got.iter().map(|k| (*k).to_owned()).collect();
    assert_eq!(unique.len(), got.len(), "a key has two mutations: {got:?}");
    assert_eq!(unique, parameter_keys());
}

/// I-52 harness check: each mutation is valid, compiles and changes the
/// compiled draft.
#[test]
fn i52_each_fixture_mutation_compiles_and_changes_the_draft() {
    let base = compile_draft(&supersafe_spec().unwrap()).unwrap();
    let mut wrong = Vec::new();
    for m in MUTATIONS {
        match mutated_spec(m.from, m.to).and_then(|s| compile_draft(&s)) {
            Ok(c) if c == base => wrong.push(format!("{}: the draft is unchanged", m.key)),
            Ok(c) if !c.unset.is_empty() => {
                wrong.push(format!("{}: the draft has gaps {:?}", m.key, c.unset));
            }
            Ok(_) => {}
            Err(e) => wrong.push(format!("{}: {e}", m.key)),
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// I-52, I-51: changing any bound parameter changes the canonical Guide.
/// The text of that parameter's placeholder changes, and the text of every
/// other parameter stays as it was.
#[test]
fn i52_canonical_guide_changes_when_any_bound_parameter_changes() {
    let base = rendered(&supersafe_inputs().unwrap());
    let mut wrong = Vec::new();
    for m in MUTATIONS {
        let spec = mutated_spec(m.from, m.to).unwrap();
        let next = rendered(&inputs_over(compile_draft(&spec).unwrap()));
        if next.canonical == base.canonical {
            wrong.push(format!("{}: the canonical Guide is unchanged", m.key));
        }
        match (base.text(m.key), next.text(m.key)) {
            (Ok(a), Ok(b)) if a == b => {
                wrong.push(format!("{}: still shows {a:?}", m.key));
            }
            (Ok(_), Ok(_)) => {}
            (a, b) => wrong.push(format!("{}: {a:?} then {b:?}", m.key)),
        }
        let changed = key_param(m.key);
        for (a, b) in base.bound.iter().zip(next.bound.iter()) {
            if a.param.is_some() && a.param != changed && a.text != b.text {
                wrong.push(format!(
                    "{}: changed the text of {} from {:?} to {:?}",
                    m.key, a.key, a.text, b.text
                ));
            }
        }
        if base.bound.len() != next.bound.len() {
            wrong.push(format!("{}: the bound occurrences changed", m.key));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// I-52: changing the call deadline changes the canonical Guide.
#[test]
fn i52_canonical_guide_changes_when_the_call_record_changes() {
    let inputs = supersafe_inputs().unwrap();
    let base = rendered(&inputs);
    let mut later = inputs.clone();
    later.call.deadline_micros = 1_803_657_600_000_000;
    let next = rendered(&later);
    assert_ne!(
        next.canonical, base.canonical,
        "the deadline is not in the canonical Guide"
    );
    assert_ne!(
        next.text("call.deadline").unwrap(),
        base.text("call.deadline").unwrap()
    );
}

/// I-52: rendering the same inputs twice gives the same HTML and the same
/// canonical document.
#[test]
fn i52_render_is_deterministic() {
    let inputs = supersafe_inputs().unwrap();
    let a = rendered(&inputs);
    let b = rendered(&inputs);
    assert_eq!(a.html, b.html);
    assert_eq!(a.canonical, b.canonical);
    assert_eq!(a.bound, b.bound);
}

/// I-52 harness check: the specification lists 15 required sections, and
/// the shipped template has 15 numbered sections.
#[test]
fn i52_required_sections_read_from_the_spec() {
    let names = required_sections();
    assert_eq!(names.len(), 15, "{names:?}");
    assert_eq!(names[0], "About the programme");
    assert_eq!(names[14], "Contact and FAQ");
    assert_eq!(template_sections(SPEC_TEMPLATE).len(), 15);
}

/// I-52: the shipped template holds every required section.
#[test]
fn i52_shipped_template_holds_every_required_section() {
    match missing_sections(SPEC_TEMPLATE.as_bytes()) {
        Ok(m) => assert!(m.is_empty(), "the shipped template lacks {m:?}"),
        Err(e) => panic!("{e}"),
    }
}

/// I-52: removing any one numbered section of the shipped template is
/// reported as that required section, by its name in the specification.
#[test]
fn i52_each_removed_section_is_reported_by_name() {
    let names = required_sections();
    let headings = template_sections(SPEC_TEMPLATE);
    assert_eq!(names.len(), headings.len());
    let mut wrong = Vec::new();
    for (name, heading) in names.iter().zip(headings.iter()) {
        let text = without_section(SPEC_TEMPLATE, heading).unwrap();
        let want = BTreeSet::from([name.clone()]);
        match missing_sections(text.as_bytes()) {
            Ok(m) if m == want => {}
            Ok(m) => wrong.push(format!(
                "without {heading:?}: reported {m:?}, want {want:?}"
            )),
            Err(e) => wrong.push(format!("without {heading:?}: {e}")),
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// I-52: a section whose heading is renamed is missing, whatever its
/// number.
#[test]
fn i52_renamed_section_is_reported_by_name() {
    let text = SPEC_TEMPLATE.replacen("## 14. Complaints\n", "## 14. Appeals\n", 1);
    assert_ne!(text, SPEC_TEMPLATE);
    match missing_sections(text.as_bytes()) {
        Ok(m) => assert_eq!(m, BTreeSet::from(["Complaints".to_owned()])),
        Err(e) => panic!("{e}"),
    }
}

/// I-52: the crate's table of required sections names exactly the
/// sections of the specification's table, in its order.
#[test]
fn i52_required_section_table_matches_the_spec() {
    let names: Vec<&str> = fstp_guide::REQUIRED_SECTIONS
        .iter()
        .map(|s| s.name)
        .collect();
    assert_eq!(names, required_sections());
}

/// I-52: a section whose heading stands only in the template header, which
/// is never rendered, is missing.
#[test]
fn i52_section_in_the_template_header_is_missing() {
    let body = without_section(SPEC_TEMPLATE, "## 13. Timeline").unwrap();
    let text = body.replacen("\n---\n", "\n## 13. Timeline\n\nIn the header.\n\n---\n", 1);
    assert!(text.find("## 13. Timeline") < text.find("\n---\n"));
    match missing_sections(text.as_bytes()) {
        Ok(m) => assert_eq!(m, BTreeSet::from(["Timeline".to_owned()])),
        Err(e) => panic!("{e}"),
    }
}
