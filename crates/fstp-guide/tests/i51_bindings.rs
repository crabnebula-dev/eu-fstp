//! Guide placeholders, resolvers and locked text (I-51, R-GA-01, M4 design
//! section 3.10).
//!
//! I-51: "Every parameter value in the Guide equals the frozen call
//! policy. Parameter-bound fields cannot be edited by hand."
//!
//! - Every placeholder of the shipped template has exactly one resolver.
//! - A `P-NN` placeholder reads parameter P-NN from the policy.
//! - The shipped template renders with the synthetic SuperSAFE draft, as
//!   well-formed HTML with no placeholder left.
//! - Every parameter-bound occurrence carries its parameter, is not
//!   editable, and shows the policy's value.
//! - A placeholder that does not resolve is refused by its key.
//!
//! The P-05 publication snapshot test (`i51_live_p05_edit_leaves_guide_bytes_unchanged`)
//! needs a published call, so it lives in `fstp-api-testkit` (W2c row of
//! design section 13).
//!
//! The tests were written red against the W0 stubs, before the resolver
//! table, `bind` and the rendered accessors existed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::collections::{BTreeMap, BTreeSet};

use fstp_programme::Field;
use support::{
    Fail, Rendered, SPEC_TEMPLATE, Source, compile_draft, guide, inputs_over, key_param, numbers,
    placeholders, reference_placeholders, resolvers, supersafe_inputs, supersafe_spec,
};

/// The SuperSAFE Guide, rendered, or the test fails with the reason.
fn supersafe_guide() -> Rendered {
    let inputs = supersafe_inputs().unwrap();
    match guide(&inputs) {
        Ok(r) => r,
        Err(e) => panic!("the SuperSAFE Guide does not render: {e}"),
    }
}

/// The resolver rows, or the test fails with the reason.
fn resolver_rows() -> Vec<support::ResolverRow> {
    match resolvers() {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    }
}

/// R-GA-01: the parser finds the same placeholders, in the same order, as
/// a plain scan of the specification's template.
#[test]
fn r_ga_01_template_placeholders_match_the_spec_template() {
    let want = reference_placeholders(SPEC_TEMPLATE);
    assert_eq!(want.len(), 57, "the reference scan of the template changed");
    match placeholders(SPEC_TEMPLATE.as_bytes()) {
        Ok(got) => assert_eq!(got, want),
        Err(e) => panic!("{e}"),
    }
}

/// I-51: every placeholder of the shipped template has exactly one
/// resolver, and no key has two.
#[test]
fn i51_every_shipped_placeholder_has_exactly_one_resolver() {
    let rows = resolver_rows();
    let mut count: BTreeMap<&str, usize> = BTreeMap::new();
    for r in &rows {
        *count.entry(r.key.as_str()).or_default() += 1;
    }
    let doubled: Vec<_> = count.iter().filter(|(_, n)| **n > 1).collect();
    assert!(
        doubled.is_empty(),
        "keys with more than one resolver: {doubled:?}"
    );
    let keys: BTreeSet<String> = reference_placeholders(SPEC_TEMPLATE).into_iter().collect();
    let unbound: Vec<_> = keys
        .iter()
        .filter(|k| count.get(k.as_str()) != Some(&1))
        .collect();
    assert!(
        unbound.is_empty(),
        "placeholders without one resolver: {unbound:?}"
    );
}

/// I-51: a `P-NN` placeholder reads parameter P-NN from the policy, and a
/// placeholder of any other key names no parameter.
#[test]
fn i51_parameter_placeholders_resolve_from_the_policy() {
    let mut wrong = Vec::new();
    for r in resolver_rows() {
        let want = key_param(&r.key);
        if r.param != want {
            wrong.push(format!("{}: parameter {:?}, want {want:?}", r.key, r.param));
        }
        if want.is_some() && r.source != Source::Policy {
            wrong.push(format!("{}: source {:?}, want Policy", r.key, r.source));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// R-GA-01: call placeholders read the call record, and programme
/// placeholders read the programme artefacts (design section 3.10).
#[test]
fn r_ga_01_record_placeholders_resolve_from_their_records() {
    let artefact_keys = [
        "programme.name",
        "programme.narrative",
        "programme.scope",
        "programme.contact",
        "programme.faq",
        "action.number",
        "action.acronym",
        "coordinator.name",
        "eligibility.persons",
        "annexe.amount_criteria",
    ];
    let mut wrong = Vec::new();
    for r in resolver_rows() {
        if r.key.starts_with("call.") && r.source != Source::CallRecord {
            wrong.push(format!("{}: source {:?}, want CallRecord", r.key, r.source));
        }
        if artefact_keys.contains(&r.key.as_str()) && r.source != Source::Artefacts {
            wrong.push(format!("{}: source {:?}, want Artefacts", r.key, r.source));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// R-GA-01, R-GA-02: the shipped template renders with the synthetic
/// SuperSAFE draft as well-formed HTML, with no placeholder left and one
/// bound occurrence per placeholder occurrence.
#[test]
fn r_ga_01_shipped_guide_renders_with_the_synthetic_policy() {
    let r = supersafe_guide();
    if let Err(e) = fstp_html::check_wellformed(r.html.as_bytes()) {
        panic!("the rendered Guide is not well-formed: {e:?}");
    }
    assert!(!r.html.contains("{{"), "a placeholder is left in the HTML");
    assert!(!r.html.contains("}}"), "a placeholder is left in the HTML");
    let got: Vec<&str> = r.bound.iter().map(|b| b.key.as_str()).collect();
    let want = reference_placeholders(SPEC_TEMPLATE);
    assert_eq!(
        got, want,
        "bound occurrences differ from the template's placeholders"
    );
    assert!(!r.canonical.is_empty(), "the canonical document is empty");
}

/// I-51: every parameter-bound occurrence carries its parameter and is not
/// editable by hand.
#[test]
fn i51_parameter_bound_text_carries_its_parameter_and_is_locked() {
    let r = supersafe_guide();
    let mut wrong = Vec::new();
    let mut seen = 0usize;
    for b in &r.bound {
        let want = key_param(&b.key);
        if b.param != want {
            wrong.push(format!("{}: carries {:?}, want {want:?}", b.key, b.param));
        }
        if want.is_some() {
            seen += 1;
            if b.editable {
                wrong.push(format!("{}: parameter-bound text is editable", b.key));
            }
            if b.text.trim().is_empty() {
                wrong.push(format!("{}: parameter-bound text is empty", b.key));
            }
        }
    }
    assert!(seen >= 30, "only {seen} parameter-bound occurrences");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// I-51, ADR-006: the amounts of the Guide are the policy's amounts in
/// their canonical spelling.
#[test]
fn i51_guide_amounts_equal_the_policy() {
    let inputs = supersafe_inputs().unwrap();
    let p = &inputs.compiled.policy;
    let r = supersafe_guide();
    assert_eq!(
        r.text("P-04.min").unwrap(),
        p.frozen.p04.min().amount().to_string()
    );
    assert_eq!(
        r.text("P-04.max").unwrap(),
        p.frozen.p04.max().amount().to_string()
    );
    assert_eq!(r.text("P-05").unwrap(), p.live.p05.amount().to_string());
    assert_eq!(r.text("P-04.min").unwrap(), "5000.00");
    assert_eq!(r.text("P-04.max").unwrap(), "100000.00");
    assert_eq!(r.text("P-05").unwrap(), "400000.00");
}

/// I-51: each numeric parameter shows exactly the policy's number.
#[test]
fn i51_guide_numbers_equal_the_policy() {
    let r = supersafe_guide();
    let p02 = supersafe_inputs()
        .unwrap()
        .compiled
        .policy
        .frozen
        .p02
        .to_string();
    let want: &[(&str, &str)] = &[
        ("P-02", p02.as_str()),
        ("P-03", "2"),
        ("P-07", "28"),
        ("P-08", "5"),
        ("P-23.per_day", "1"),
        ("P-23.per_call", "5"),
        ("P-36", "7"),
        ("P-41", "1"),
        ("P-59", "15"),
        ("P-61", "10"),
        ("P-62", "15"),
        ("P-63", "10"),
        ("P-64", "20"),
    ];
    let mut wrong = Vec::new();
    for (key, n) in want {
        match r.text(key) {
            Ok(t) if numbers(t) == [n.to_string()] => {}
            Ok(t) => wrong.push(format!("{key}: shows {t:?}, want the number {n}")),
            Err(e) => wrong.push(e),
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// I-51: each list parameter shows every item of the policy, with the
/// wording the draft holds.
#[test]
fn i51_guide_lists_equal_the_policy() {
    let r = supersafe_guide();
    let want: &[(&str, &[&str])] = &[
        (
            "P-01.table",
            &[
                "Technical excellence",
                "Relevance and impact",
                "Value for money",
                "30",
                "40",
            ],
        ),
        (
            "P-09.list",
            &[
                "Aligned with Open Internet Stack and SuperSAFE vision",
                "R&D as primary objective",
                "English",
            ],
        ),
        (
            "P-13.list",
            &[
                "Consortium partners, their affiliated entities and staff",
                "IRC members, employers, co-workers, relatives",
            ],
        ),
        (
            "P-26.list",
            &["AGPL-3.0-or-later", "Apache-2.0", "GPL-3.0-or-later", "MIT"],
        ),
        (
            "P-55.list",
            &[
                "Placeholder activity type A, pending the closed list (O-23)",
                "Placeholder activity type B, pending the closed list (O-23)",
            ],
        ),
    ];
    let mut wrong = Vec::new();
    for (key, items) in want {
        match r.text(key) {
            Ok(t) => {
                for item in *items {
                    if !t.contains(item) {
                        wrong.push(format!("{key}: lacks {item:?} in {t:?}"));
                    }
                }
            }
            Err(e) => wrong.push(e),
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// R-GA-01: the programme placeholders show the draft's artefacts, at every
/// place they stand.
#[test]
fn r_ga_01_guide_artefacts_equal_the_draft() {
    let r = supersafe_guide();
    let want: &[(&str, &str)] = &[
        ("programme.name", "SuperSAFE"),
        ("action.acronym", "SuperSAFE"),
        (
            "programme.scope",
            "the Open Internet Stack and the SuperSAFE vision",
        ),
        ("action.number", "SYNTHETIC-000000000"),
        ("coordinator.name", "Synthetic coordinator name"),
    ];
    let mut wrong = Vec::new();
    for (key, text) in want {
        let all: Vec<_> = r.of(key).collect();
        if all.is_empty() {
            wrong.push(format!("{key}: no bound occurrence"));
        }
        for b in all {
            if b.text != *text {
                wrong.push(format!("{key}: shows {:?}, want {text:?}", b.text));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// I-51: a placeholder whose source holds no value is refused by its key,
/// never rendered empty. The FAQ is an artefact the draft leaves unset.
#[test]
fn i51_unresolved_placeholder_is_refused_by_name() {
    let mut spec = supersafe_spec().unwrap();
    spec.comms.faq = Field::Unset;
    let inputs = inputs_over(compile_draft(&spec).unwrap());
    match guide(&inputs) {
        Err(Fail::Refused(m)) => assert!(
            m.contains("programme.faq"),
            "refused without naming programme.faq: {m}"
        ),
        Err(Fail::Missing(m)) => panic!("{m}"),
        Ok(_) => panic!("rendered a Guide with an unresolved programme.faq"),
    }
}

/// I-51: a parameter the draft leaves unset is refused by its key. Compile
/// fills the gap with the profile's placeholder, and the Guide never shows
/// that placeholder as the parameter's value.
#[test]
fn i51_unset_parameter_is_refused_by_name() {
    let mut spec = supersafe_spec().unwrap();
    spec.money.p04_grant_range = Field::Unset;
    let compiled = compile_draft(&spec).unwrap();
    assert!(!compiled.unset.is_empty(), "the gap is not recorded");
    let inputs = inputs_over(compiled);
    match guide(&inputs) {
        Err(Fail::Refused(m)) => assert!(m.contains("P-04"), "refused without naming P-04: {m}"),
        Err(Fail::Missing(m)) => panic!("{m}"),
        Ok(r) => panic!(
            "rendered P-04 from the profile placeholder: {:?} to {:?}",
            r.text("P-04.min"),
            r.text("P-04.max")
        ),
    }
}

/// I-68, I-51: bound text is inserted as text, never as markup.
#[test]
fn i68_bound_text_is_escaped_never_markup() {
    let hostile = "<script>alert(1)</script> & <marquee>x</marquee>";
    let spec = support::mutated_spec(
        r#""name":"SuperSAFE""#,
        &format!(r#""name":"{}""#, hostile.replace('"', "\\\"")),
    )
    .unwrap();
    let inputs = inputs_over(compile_draft(&spec).unwrap());
    let r = match guide(&inputs) {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    if let Err(e) = fstp_html::check_wellformed(r.html.as_bytes()) {
        panic!("the rendered Guide is not well-formed: {e:?}");
    }
    assert!(
        !r.html.contains("<script"),
        "a bound value became a script element"
    );
    assert!(!r.html.contains("<marquee"), "a bound value became markup");
    assert!(
        r.html.contains("&lt;script&gt;"),
        "the bound value is not shown as text"
    );
    let shown: Vec<_> = r.of("programme.name").map(|b| b.text.as_str()).collect();
    assert!(
        !shown.is_empty() && shown.iter().all(|t| *t == hostile),
        "programme.name shows {shown:?}"
    );
}
