//! The server-rendered sign-up and agreement forms (TH-26, TH-46,
//! R-TN-01, I-68; M4 design sections 1.1, 2.2 J0 and 3.5).
//!
//! The rules these tests fix:
//!
//! - Each rendered page passes the `fstp-html` well-formedness checker.
//! - Each form names exactly the fields its decoder demands, plus the
//!   `form` selector. The submit button has no name, and only
//!   `billing_address` is a `textarea`.
//! - What a browser submits from the rendered form decodes to the values
//!   typed in, and the agreement form names the offered versions.
//! - Each agreement text renders as approved wording that holds a
//!   `TODO(legal)` placeholder, never legal wording.
//!
//! The scanner below reads the writer's own output only. It is not a
//! general HTML parser.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::collections::BTreeMap;

use fstp_html::{MessageKind, TraceEvent, check_wellformed};
use fstp_prop::check;
use fstp_signup::{
    AgreementFields, CpCommand, SIGNUP_LOCALE, SignupFields, SignupForm, agreement_form_page,
    decide, decode_signup_form, render_agreement_form, render_signup_form, signup_catalogues,
};
use support::{AGREEMENT_FIELDS, SIGNUP_FIELDS, T1, V2, body, gen_tenant, gen_versions};

/// One form control of a rendered page.
#[derive(Debug)]
struct Control {
    tag: String,
    attrs: BTreeMap<String, Option<String>>,
}

impl Control {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.get(name).and_then(|v| v.as_deref())
    }
}

fn unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Every `input`, `textarea`, `button` and `select` start tag of `html`,
/// in document order.
fn controls(html: &str) -> Vec<Control> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(at) = rest.find('<') {
        rest = &rest[at + 1..];
        let end = rest.find('>').expect("an unterminated tag");
        let tag_text = &rest[..end];
        rest = &rest[end + 1..];
        let (tag, mut attrs_text) = tag_text.split_once(' ').unwrap_or((tag_text, ""));
        if !["input", "textarea", "button", "select"].contains(&tag) {
            continue;
        }
        let mut attrs = BTreeMap::new();
        loop {
            attrs_text = attrs_text.trim_start();
            if attrs_text.is_empty() {
                break;
            }
            let name_end = attrs_text.find(['=', ' ']).unwrap_or(attrs_text.len());
            let name = attrs_text[..name_end].to_owned();
            attrs_text = &attrs_text[name_end..];
            if let Some(after) = attrs_text.strip_prefix("=\"") {
                let close = after.find('"').expect("an unterminated value");
                attrs.insert(name, Some(unescape(&after[..close])));
                attrs_text = &after[close + 1..];
            } else {
                attrs.insert(name, None);
            }
        }
        out.push(Control {
            tag: tag.to_owned(),
            attrs,
        });
    }
    out
}

/// The pairs a browser submits from `controls` after a person types
/// `typed[name]` into each text control and ticks every checkbox.
fn submit(controls: &[Control], typed: &BTreeMap<&str, String>) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for c in controls {
        let name = c.attr("name");
        match (c.tag.as_str(), c.attr("type")) {
            ("button", _) => assert_eq!(name, None, "a named button adds a field"),
            ("input", Some("hidden" | "checkbox")) => {
                let name = name.expect("a control without a name");
                let value = c.attr("value").expect("a control without a value");
                pairs.push((name.to_owned(), value.to_owned()));
            }
            ("input", Some("text")) | ("textarea", None) => {
                let name = name.expect("a control without a name");
                pairs.push((name.to_owned(), typed[name].clone()));
            }
            other => panic!("an unexpected control {other:?}"),
        }
    }
    pairs
}

fn names(controls: &[Control]) -> Vec<&str> {
    controls.iter().filter_map(|c| c.attr("name")).collect()
}

fn synthetic_signup() -> SignupFields {
    support::synthetic_signup()
}

fn typed_signup(f: &SignupFields) -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        ("legal_name", f.legal_name.clone()),
        ("billing_address", f.billing_address.clone()),
        ("contracting_signatory", f.contracting_signatory.clone()),
    ])
}

/// TH-26, R-TN-01, I-68: the rendered sign-up form is well formed, names
/// exactly the decoder's fields, holds one `textarea` for the billing
/// address, and what it submits decodes to the values typed in.
#[test]
fn th26_rendered_signup_form_submits_what_the_decoder_accepts() {
    let cats = signup_catalogues().unwrap();
    let page = render_signup_form(&cats, SIGNUP_LOCALE).unwrap();
    check_wellformed(page.as_bytes()).unwrap();
    let controls = controls(page.as_str());
    assert_eq!(names(&controls), SIGNUP_FIELDS);
    let textareas: Vec<_> = controls
        .iter()
        .filter(|c| c.tag == "textarea")
        .map(|c| c.attr("name"))
        .collect();
    assert_eq!(textareas, vec![Some("billing_address")]);
    let fields = synthetic_signup();
    let pairs = submit(&controls, &typed_signup(&fields));
    assert_eq!(
        decode_signup_form(&body(&pairs)),
        Ok(SignupForm::Signup(fields))
    );
}

/// TH-26, R-TN-01, I-68: for any tenant and offer, the rendered agreement
/// form is well formed, names exactly the decoder's fields, and what it
/// submits decodes to the tenant and the offered versions. `decide`
/// accepts it against a ledger with that offer.
#[test]
fn th26_rendered_agreement_form_submits_the_offered_versions() {
    let cats = signup_catalogues().unwrap();
    check(
        "th26_rendered_agreement_form_submits_the_offered_versions",
        |g| {
            let tenant = gen_tenant(g);
            let offered = gen_versions(g);
            let page = render_agreement_form(&cats, SIGNUP_LOCALE, tenant, offered)
                .map_err(|e| format!("{e:?}"))?;
            check_wellformed(page.as_bytes()).map_err(|e| format!("{e:?}"))?;
            let controls = controls(page.as_str());
            if names(&controls) != AGREEMENT_FIELDS {
                return Err(format!("fields {:?}", names(&controls)));
            }
            let typed = BTreeMap::from([("accepted_by", "Synthetic Signatory".to_owned())]);
            let pairs = submit(&controls, &typed);
            let want = AgreementFields {
                tenant,
                versions: offered,
                accepted_by: "Synthetic Signatory".to_owned(),
            };
            let got = decode_signup_form(&body(&pairs));
            if got != Ok(SignupForm::Agreements(want.clone())) {
                return Err(format!("{pairs:?} decodes to {got:?}"));
            }
            let mut s = support::offered(offered);
            support::must(&mut s, &support::signup_cmd(tenant));
            decide(&s, &CpCommand::AcceptAgreements { form: want, at: 0 })
                .map(|_| ())
                .map_err(|e| format!("decide refused the rendered form: {e:?}"))
        },
    );
}

/// R-TN-01, I-72: each agreement text renders as approved wording with a
/// `TODO(legal)` placeholder, and the page holds no other approved text.
#[test]
fn r_tn_01_agreement_texts_render_as_todo_legal_placeholders() {
    let cats = signup_catalogues().unwrap();
    let (doc, trace) = agreement_form_page(SIGNUP_LOCALE, T1, V2)
        .unwrap()
        .render_traced(&cats)
        .unwrap();
    let approved: Vec<&str> = trace
        .iter()
        .filter_map(|e| match e {
            TraceEvent::Message {
                kind: MessageKind::Approved,
                id,
                ..
            } => Some(id.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        approved,
        vec![
            "agreements.text.saas_terms",
            "agreements.text.dpa",
            "agreements.text.sub_processors",
        ]
    );
    assert_eq!(doc.as_str().matches("TODO(legal)").count(), 3);
    for (agreement, version) in V2.pairs() {
        let checkbox = format!(
            "type=\"checkbox\" id=\"agreements-{}\" name=\"{}\" value=\"{version}\" required",
            agreement.name().replace('_', "-"),
            agreement.name()
        );
        assert!(doc.as_str().contains(&checkbox), "{checkbox}");
    }
}
