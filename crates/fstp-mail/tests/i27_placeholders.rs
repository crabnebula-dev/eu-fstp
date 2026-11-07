//! I-27 and I-25 for the template layer (M6 design section 5.3, lane
//! L6-MAIL). No message on any channel contains proposal content, scores,
//! deliberation or another person's identity attributes.
//!
//! The placeholder enum is closed. Its payloads are ids, state tags,
//! instants, amounts, links built from ids, and counts. These tests pin
//! that set, so adding a variant that could hold text fails here first.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

mod common;

use std::collections::BTreeSet;

use fstp_domain::StateTag;
use fstp_domain::id::{CallId, ContractId, MilestoneId, ProposalId, RequestId};
use fstp_mail::{
    BANK_DETAILS_SENTENCE, LinkTarget, Moment, Origin, Part, Slot, TEMPLATES, TemplateId, Value,
    ValueKind, compose, parse,
};
use fstp_money::Amount;
use fstp_prop::{check, prop_assert, prop_assert_eq};

const fn assert_copy_static<T: Copy + 'static>() {}

/// I-27: every placeholder type is `Copy` and `'static`. A `Copy` type
/// cannot own a `String`, a `Vec` or a `Box`, so no placeholder can carry
/// free text of any length.
#[test]
fn i_27_placeholder_types_are_copy_and_own_no_text() {
    const _: () = assert_copy_static::<Value>();
    const _: () = assert_copy_static::<Slot>();
    const _: () = assert_copy_static::<LinkTarget>();
    const _: () = assert_copy_static::<Moment>();
}

/// I-27: the enumeration of the placeholder enum. Each arm names the one
/// payload type its variant may hold. A new variant does not compile
/// until it is added here, after review against I-27.
#[test]
fn i_27_placeholder_enum_is_enumerated() {
    fn payload(v: Value) -> ValueKind {
        match v {
            Value::Proposal(x) => {
                let _: ProposalId = x;
                ValueKind::Proposal
            }
            Value::Call(x) => {
                let _: CallId = x;
                ValueKind::Call
            }
            Value::Contract(x) => {
                let _: ContractId = x;
                ValueKind::Contract
            }
            Value::Milestone(x) => {
                let _: MilestoneId = x;
                ValueKind::Milestone
            }
            Value::Request(x) => {
                let _: RequestId = x;
                ValueKind::Request
            }
            Value::State(x) => {
                let _: StateTag = x;
                ValueKind::State
            }
            Value::Moment(x) => {
                let _: Moment = x;
                ValueKind::Moment
            }
            Value::Amount(x) => {
                let _: Amount = x;
                ValueKind::Amount
            }
            Value::Link(x) => {
                let _: LinkTarget = match x {
                    LinkTarget::Notices => x,
                    LinkTarget::Proposal(p) | LinkTarget::ProposalProgress(p) => {
                        let _: ProposalId = p;
                        x
                    }
                    LinkTarget::CallGuide(c) | LinkTarget::NotifiableConflicts(c) => {
                        let _: CallId = c;
                        x
                    }
                };
                ValueKind::Link
            }
            Value::Count(x) => {
                let _: u32 = x;
                ValueKind::Count
            }
        }
    }
    let kinds: BTreeSet<ValueKind> = Slot::ALL.iter().map(|s| s.kind()).collect();
    assert_eq!(kinds.len(), ValueKind::ALL.len(), "every kind has a slot");
    for k in ValueKind::ALL {
        check("i_27_placeholder_enum_is_enumerated", |g| {
            let v = common::value_of(g, k);
            prop_assert_eq!(payload(v), k);
            prop_assert_eq!(v.kind(), k);
            Ok(())
        });
    }
}

/// The closed alphabet a rendered value may use. It has no letters beyond
/// those of fixed labels, so no prose fits in it.
fn closed_alphabet(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b" :/.-_+()".contains(&b))
}

/// I-27: every rendered value is short and uses the closed alphabet.
/// Letters only come from state names, currency codes, `UTC`, URL
/// schemes, the configured origin and the fixed route names.
#[test]
fn i_27_every_value_renders_in_a_closed_alphabet() {
    let origin = Origin::new("https://demo-cell.example").unwrap();
    check("i_27_every_value_renders_in_a_closed_alphabet", |g| {
        let k = *g.pick(&ValueKind::ALL);
        let v = common::value_of(g, k);
        let s = v.render(&origin).map_err(|e| format!("{e}"))?;
        prop_assert!(closed_alphabet(&s), "value outside the alphabet: {s}");
        prop_assert!(s.len() <= 120, "value too long: {s}");
        prop_assert!(!s.is_empty());
        Ok(())
    });
}

/// I-27: the text part of a composed message is exactly the template's
/// fixed text with each slot replaced by its rendered value, then the
/// fixed footer. No other input reaches the body.
#[test]
fn i_27_body_is_template_text_and_closed_values_only() {
    let cfg = common::config();
    check("i_27_body_is_template_text_and_closed_values_only", |g| {
        let m = common::Owned::random(g);
        let mut expected = String::new();
        for part in m.template.body_parts() {
            match part {
                Part::Text(t) => expected.push_str(t),
                Part::Slot(s) => {
                    let v = m.bindings.get(*s).ok_or("missing binding")?;
                    expected.push_str(&v.render(&cfg.origin).map_err(|e| format!("{e}"))?);
                }
            }
        }
        expected.push_str("\n\n");
        expected.push_str(BANK_DETAILS_SENTENCE);
        expected.push('\n');
        let expected = expected.replace('\n', "\r\n");

        let raw = compose(&cfg, &m.message()).map_err(|e| format!("{e}"))?;
        let parsed = parse(&raw).map_err(|e| format!("{e}"))?;
        let text = parsed
            .parts
            .iter()
            .find(|p| p.content_type == "text/plain")
            .ok_or("no text part")?;
        prop_assert_eq!(String::from_utf8_lossy(&text.decoded), expected);
        Ok(())
    });
}

/// I-27 and `notifications.md` content rules: every template's text and
/// HTML parts end with the fixed bank-details sentence.
#[test]
fn i_27_every_message_ends_with_bank_details_sentence() {
    let origin = Origin::new("https://demo-cell.example").unwrap();
    check("i_27_every_message_ends_with_bank_details_sentence", |g| {
        let t = common::template(g);
        let b = common::bindings_for(g, t);
        let r = t.render(&b, &origin).map_err(|e| format!("{e}"))?;
        prop_assert!(r.text.trim_end().ends_with(BANK_DETAILS_SENTENCE));
        prop_assert!(r.html.contains(BANK_DETAILS_SENTENCE));
        Ok(())
    });
}

/// I-27: a template refuses a missing binding, an extra one and one of
/// the wrong kind, so no value lands in a slot it was not reviewed for.
#[test]
fn i_27_bindings_must_match_template_slots() {
    let origin = Origin::new("https://demo-cell.example").unwrap();
    check("i_27_bindings_must_match_template_slots", |g| {
        let t = common::template(g);
        let good = common::bindings_for(g, t);
        prop_assert!(t.render(&good, &origin).is_ok());
        let slots: Vec<Slot> = t.slots().into_iter().collect();
        // Missing.
        let first = *g.pick(&slots);
        let mut missing = fstp_mail::Bindings::new();
        for s in &slots {
            if *s != first {
                missing = missing.with(*s, *good.get(*s).ok_or("binding")?);
            }
        }
        prop_assert!(t.render(&missing, &origin).is_err());
        // Extra.
        if let Some(extra) = Slot::ALL.iter().find(|s| !slots.contains(s)) {
            let v = common::value_of(g, extra.kind());
            prop_assert!(t.render(&good.clone().with(*extra, v), &origin).is_err());
        }
        // Wrong kind.
        let other = *g.pick(&ValueKind::ALL);
        if other != first.kind() {
            let v = common::value_of(g, other);
            prop_assert!(t.render(&good.clone().with(first, v), &origin).is_err());
        }
        Ok(())
    });
}

/// I-25: a template version never changes. Each version's digest is
/// pinned here, so editing a template's text without a new version fails.
#[test]
fn i_25_template_versions_are_pinned() {
    let mut seen = BTreeSet::new();
    for t in TEMPLATES {
        assert!(
            seen.insert((t.id(), t.version(), t.locale())),
            "duplicate template version {:?}",
            t.id()
        );
    }
    for id in TemplateId::ALL {
        assert!(
            TEMPLATES.iter().any(|t| t.id() == id),
            "{id:?} has no template"
        );
    }
    let got: Vec<(String, String)> = TEMPLATES
        .iter()
        .map(|t| {
            (
                format!("{}/{}/{}", t.id().code(), t.version(), t.locale().code()),
                hex(&t.digest()),
            )
        })
        .collect();
    let pinned: Vec<(String, String)> = PINNED
        .iter()
        .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
        .collect();
    assert_eq!(
        got, pinned,
        "a template version changed; add a new version instead"
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const PINNED: &[(&str, &str)] = &[
    (
        "proposal-outcome/1/en",
        "3f03fe251be0ff51f490afc042bb26df46cad2c2a86e72e9fcdf0aa630dae2b2",
    ),
    (
        "irc-concern/1/en",
        "75ad227b2607644e544198db31c324723a2cab0f5cbc96974f99145984196adf",
    ),
    (
        "notifiable-conflict/1/en",
        "6c44a9fc463633091b94cdb480700d5db478d2209db051cc2c349dd998c21442",
    ),
    (
        "milestone-reminder/1/en",
        "96681f2d55e436ba075b548da04ea2ce7d07fd2460e1f12b1e6188034300626d",
    ),
    (
        "milestone-overdue/1/en",
        "64242adc37e59a670e29336918e63087cfdc604439be13c24591632b85868dee",
    ),
    (
        "corrigendum/1/en",
        "7dad65d76400cc11ee5ae82e157579ca522e21e758276dbaa1cbaf90d50985d8",
    ),
    (
        "contract-notice/1/en",
        "c08af0f8b7ae213f44cf4d532214738fd78295132484673c60bfdb70b0f9eb0b",
    ),
    (
        "submission-copy/1/en",
        "cc4726e27f0fe6e1974e3a44dab0706621ef888df38ea261eb15a03a6e444f47",
    ),
];
