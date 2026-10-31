//! Binding inputs, placement and rendering edges of the Guide (I-51, I-52,
//! I-68, ADR-007, R-GA-01, M4 design section 3.10).
//!
//! - An unbound template is never rendered: its first placeholder is
//!   refused by key.
//! - P-05 and P-13 read the publication snapshot when there is one.
//! - Inputs the caller supplies, stored narratives and a disabled
//!   pre-check are refused by key when they give no value.
//! - Placeholders at a place their value cannot stand are refused by key.
//! - Arbitrary bound text renders as well-formed HTML and shows verbatim.
//! - The preview reports every gap at once.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::collections::BTreeSet;

use fstp_domain::id::{ClassId, ContentDigest, TextId, TextRef};
use fstp_domain::policy::{ExclusionClasses, LiveSnapshot};
use fstp_guide::{GuideError, GuideInputs, StoredTexts};
use fstp_programme::{Field, Narrative, StoredText};
use fstp_prop::{check, prop_assert};
use support::{
    SPEC_TEMPLATE, compile_draft, guide_call, guide_inputs, inputs_over, mutated_spec,
    supersafe_inputs, supersafe_spec, without_section,
};

/// The shipped template, parsed.
fn shipped() -> fstp_guide::Template {
    fstp_guide::parse_template(SPEC_TEMPLATE.as_bytes()).unwrap()
}

/// The refusal of `r`, or the test fails.
fn refusal<T: std::fmt::Debug>(r: Result<T, GuideError>) -> String {
    match r {
        Err(e) => e.to_string(),
        Ok(v) => panic!("accepted: {v:?}"),
    }
}

/// I-51: rendering an unbound template is refused by its first
/// placeholder key, never written with the placeholder text.
#[test]
fn i51_unbound_template_render_is_refused_by_its_first_key() {
    let t = shipped();
    assert!(!t.is_bound());
    let m = refusal(fstp_guide::render(&t));
    assert!(m.contains("{{programme.name}}"), "{m}");
}

/// I-51, design section 3.10: P-05 and P-13 read the call's publication
/// snapshot, never the live value, when the snapshot is given.
#[test]
fn i51_p05_and_p13_read_the_publication_snapshot() {
    let inputs = supersafe_inputs().unwrap();
    let call = guide_call(&inputs.call).unwrap();
    let other = compile_draft(
        &mutated_spec(
            r#""p05_recipient_cap":"400000.00""#,
            r#""p05_recipient_cap":"300000.00""#,
        )
        .unwrap(),
    )
    .unwrap();
    let snapshot = LiveSnapshot {
        p05: other.policy.live.p05,
        p13: ExclusionClasses(BTreeSet::from([ClassId::from_raw(2)])),
    };
    let gi = GuideInputs {
        publication: Some(&snapshot),
        ..guide_inputs(&inputs, &call)
    };
    let bound = fstp_guide::bind(&shipped(), &gi).unwrap();
    let r = fstp_guide::render(&bound).unwrap();
    let text = |key: &str| {
        let all: Vec<_> = r.bound().iter().filter(|b| b.key == key).collect();
        assert_eq!(all.len(), 1, "{key}");
        all[0].text.clone()
    };
    assert_eq!(text("P-05"), "300000.00");
    assert_eq!(
        text("P-13.list"),
        "IRC members, employers, co-workers, relatives"
    );
    let unknown = LiveSnapshot {
        p05: other.policy.live.p05,
        p13: ExclusionClasses(BTreeSet::from([ClassId::from_raw(9)])),
    };
    let gi = GuideInputs {
        publication: Some(&unknown),
        ..guide_inputs(&inputs, &call)
    };
    let m = refusal(fstp_guide::bind(&shipped(), &gi));
    assert!(m.contains("{{P-13.list}}"), "{m}");
}

/// I-51: the texts no artefact holds are refused by key when the caller
/// supplies none, never filled with invented wording.
#[test]
fn i51_missing_supplied_texts_are_refused_by_key() {
    let inputs = supersafe_inputs().unwrap();
    let call = guide_call(&inputs.call).unwrap();
    let base = guide_inputs(&inputs, &call);
    let cases: [(&str, GuideInputs<'_>); 5] = [
        (
            "gdpr.notice_summary",
            GuideInputs {
                data_protection_summary: None,
                ..base
            },
        ),
        (
            "gdpr.notice_summary",
            GuideInputs {
                data_protection_summary: Some(" \n\n "),
                ..base
            },
        ),
        (
            "funder.privacy_statement_url",
            GuideInputs {
                privacy_statement_url: None,
                ..base
            },
        ),
        (
            "platform.url",
            GuideInputs {
                platform_url: "javascript:alert(1)",
                ..base
            },
        ),
        (
            "guide.version",
            GuideInputs {
                guide_version: 0,
                ..base
            },
        ),
    ];
    for (key, gi) in cases {
        let m = refusal(fstp_guide::bind(&shipped(), &gi));
        assert!(m.contains(&format!("{{{{{key}}}}}")), "{key}: {m}");
    }
}

/// I-51: call record values that are not valid are refused by key.
#[test]
fn i51_invalid_call_record_values_are_refused_by_key() {
    let inputs = supersafe_inputs().unwrap();
    let good = guide_call(&inputs.call).unwrap();
    let cases = [
        (
            "call.identifier",
            fstp_guide::GuideCall {
                identifier: "  ".to_owned(),
                ..good.clone()
            },
        ),
        (
            "call.opens",
            fstp_guide::GuideCall {
                opens: fstp_domain::time::Timestamp::from_micros(-1),
                ..good.clone()
            },
        ),
        (
            "call.budget",
            fstp_guide::GuideCall {
                budget: "250,000".to_owned(),
                ..good.clone()
            },
        ),
    ];
    for (key, call) in cases {
        let m = refusal(fstp_guide::bind(&shipped(), &guide_inputs(&inputs, &call)));
        assert!(m.contains(&format!("{{{{{key}}}}}")), "{key}: {m}");
    }
}

/// I-51: a disabled pre-check refuses the pre-check limits by key, because
/// the template describes the pre-check (design section 3.10).
#[test]
fn i51_disabled_precheck_is_refused_by_key() {
    let spec = mutated_spec(
        r#""account_cap_across_drafts_in_call":true,"enabled":true"#,
        r#""account_cap_across_drafts_in_call":true,"enabled":false"#,
    )
    .unwrap();
    let inputs = inputs_over(compile_draft(&spec).unwrap());
    let call = guide_call(&inputs.call).unwrap();
    let m = refusal(fstp_guide::bind(&shipped(), &guide_inputs(&inputs, &call)));
    assert!(m.contains("{{P-23.per_day}}"), "{m}");
}

/// A test source of one stored text.
struct OneText(TextRef, &'static str);

impl StoredTexts for OneText {
    fn text(&self, text: TextRef) -> Option<&str> {
        (text == self.0).then_some(self.1)
    }
}

/// ADR-007, I-51: a stored narrative is read from the text source, and is
/// refused by key when the source does not hold it.
#[test]
fn adr007_stored_narratives_are_read_from_the_text_source() {
    let r = TextRef::new(TextId::from_raw(7), ContentDigest::from_bytes([1; 32]));
    let mut spec = supersafe_spec().unwrap();
    spec.comms.faq = Field::Set(Narrative::Stored(StoredText::new(r).unwrap()));
    let inputs = inputs_over(compile_draft(&spec).unwrap());
    let call = guide_call(&inputs.call).unwrap();
    let m = refusal(fstp_guide::bind(&shipped(), &guide_inputs(&inputs, &call)));
    assert!(m.contains("{{programme.faq}}"), "{m}");
    let source = OneText(r, "Synthetic stored FAQ.");
    let gi = GuideInputs {
        texts: &source,
        ..guide_inputs(&inputs, &call)
    };
    let out = fstp_guide::render(&fstp_guide::bind(&shipped(), &gi).unwrap()).unwrap();
    let faq: Vec<_> = out
        .bound()
        .iter()
        .filter(|b| b.key == "programme.faq")
        .collect();
    assert_eq!(faq.len(), 1);
    assert_eq!(faq[0].text, "Synthetic stored FAQ.");
    assert!(faq[0].editable);
}

/// R-GA-01, I-51: a placeholder at a place its value cannot stand is
/// refused by its key.
#[test]
fn r_ga_01_misplaced_placeholders_are_refused_by_key() {
    let cases = [
        ("P-55.list", "Types: {{P-55.list}} here.".to_owned()),
        ("P-55.list", "{{P-55.list}}\nmore text".to_owned()),
        ("P-01.table", "- {{P-01.table}}".to_owned()),
        (
            "platform.url",
            "[Sign up {{platform.url}}](https://a.example/)".to_owned(),
        ),
    ];
    for (key, block) in cases {
        let text = format!("{SPEC_TEMPLATE}\n{block}\n");
        let m = refusal(fstp_guide::parse_template(text.as_bytes()));
        assert!(m.contains(&format!("{{{{{key}}}}}")), "{key}: {m}");
    }
    let header = SPEC_TEMPLATE.replacen(
        "Placeholders in double braces",
        "{{programme.name}} placeholders in double braces",
        1,
    );
    let m = refusal(fstp_guide::parse_template(header.as_bytes()));
    assert!(m.contains("{{programme.name}}"), "{m}");
}

/// The characters bound text is drawn from: markup, references, quotes,
/// Markdown and placeholder syntax, line breaks and controls.
const HOSTILE: &[&str] = &[
    "<script>alert(1)</script>",
    "&lt;",
    "&",
    "\"'",
    "**x**",
    "{{P-04.min}}",
    "\n",
    "\r",
    "\u{0}",
    "\u{85}",
    "\u{fdd0}",
    "]]>",
    "<!--",
    "é",
    " ",
    "SuperSAFE",
];

/// I-68, I-51: any text bound to the programme name, the FAQ and the call
/// identifier renders as well-formed HTML, never as markup, and shows as
/// the text itself. Text with nothing to show is refused by key.
#[test]
fn i68_arbitrary_bound_text_renders_wellformed_and_verbatim() {
    check(
        "i68_arbitrary_bound_text_renders_wellformed_and_verbatim",
        |g| {
            let pick = |g: &mut fstp_prop::Gen| -> String {
                g.vec(1..=6, |g| (*g.pick(HOSTILE)).to_owned()).concat()
            };
            let name = pick(g);
            let faq = pick(g);
            let identifier = pick(g);
            g.note("name", &name);
            g.note("faq", &faq);
            g.note("identifier", &identifier);
            let mut spec = supersafe_spec()?;
            spec.identity.name = Field::Set(Narrative::Inline(name.clone()));
            spec.comms.faq = Field::Set(Narrative::Inline(faq.clone()));
            let inputs = inputs_over(compile_draft(&spec)?);
            let mut call = guide_call(&inputs.call).map_err(|e| e.to_string())?;
            call.identifier = identifier.clone();
            let gi = guide_inputs(&inputs, &call);
            let blank = |s: &str| s.trim().is_empty();
            let refused_key = if blank(&name) {
                Some("programme.name")
            } else if blank(&identifier) || identifier.len() > 128 {
                Some("call.identifier")
            } else if blank(&faq) {
                Some("programme.faq")
            } else {
                None
            };
            match (refused_key, fstp_guide::bind(&shipped(), &gi)) {
                (None, Ok(bound)) => {
                    let r = fstp_guide::render(&bound).map_err(|e| format!("render: {e}"))?;
                    r.check_wellformed().map_err(|e| format!("{e}"))?;
                    let html = r.html().as_str();
                    prop_assert!(!html.contains("<script"), "markup in the page");
                    prop_assert!(!html.contains("<!--"), "a comment in the page");
                    let shown = |key: &str| -> Vec<String> {
                        r.bound()
                            .iter()
                            .filter(|b| b.key == key)
                            .map(|b| b.text.clone())
                            .collect()
                    };
                    prop_assert!(shown("programme.name").iter().all(|t| *t == name));
                    prop_assert!(shown("call.identifier") == [identifier.trim().to_owned()]);
                    let again = fstp_guide::render(&bound).map_err(|e| format!("render: {e}"))?;
                    prop_assert!(again == r, "render is not deterministic");
                    Ok(())
                }
                (None, Err(e)) => Err(format!("refused: {e}")),
                (Some(key), Err(e)) => {
                    prop_assert!(
                        e.to_string().contains(&format!("{{{{{key}}}}}")),
                        "refused without naming {key}: {e}"
                    );
                    Ok(())
                }
                (Some(key), Ok(_)) => Err(format!("bound with an empty {key}")),
            }
        },
    );
}

/// I-52, I-51: the preview reports every missing section and every
/// placeholder that does not resolve, in one pass, and gives no Guide.
#[test]
fn i52_preview_reports_every_gap_by_name() {
    let mut spec = supersafe_spec().unwrap();
    spec.comms.faq = Field::Unset;
    spec.money.p04_grant_range = Field::Unset;
    let inputs = inputs_over(compile_draft(&spec).unwrap());
    let call = guide_call(&inputs.call).unwrap();
    let text = without_section(SPEC_TEMPLATE, "## 13. Timeline").unwrap();
    let t = fstp_guide::parse_template(text.as_bytes()).unwrap();
    let p = fstp_guide::preview(&t, &guide_inputs(&inputs, &call));
    assert_eq!(p.missing_sections, vec!["Timeline"]);
    let keys: Vec<String> = p.unresolved.iter().map(ToString::to_string).collect();
    assert_eq!(keys.len(), 3, "{keys:?}");
    for (got, want) in keys.iter().zip(["P-04.min", "P-04.max", "programme.faq"]) {
        assert!(got.contains(&format!("{{{{{want}}}}}")), "{got}");
    }
    assert!(p.guide.is_err());
    let clean = fstp_guide::preview(
        &shipped(),
        &guide_inputs(&supersafe_inputs().unwrap(), &call),
    );
    assert!(clean.missing_sections.is_empty());
    assert!(clean.unresolved.is_empty());
    assert!(clean.guide.is_ok());
}
