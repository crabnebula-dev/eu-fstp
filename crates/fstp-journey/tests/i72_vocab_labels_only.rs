//! I-72, I-94, R-WL-05, R-JV-09: a vocabulary pack overrides interface labels only, and negative outcome wording is fixed data.
//!
//! A pack names keys from one closed list of interface labels
//! (`LABEL_KEYS`). Any other key, such as one of approved wording, a
//! contract, a notice, the Guide, a funder document or an email, is
//! refused. The respectful wording of negative outcomes and of the
//! withdrawal action is fixed (`FIXED`): a pack may repeat it, never
//! change it (`docs/design/07-vocabulary-pack.md`, content rules).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use fstp_journey::vocab::{
    FIXED, LABEL_KEYS, PLAIN_V1, VOYAGE_V1, VocabErrorKind as K, parse, plain_v1, voyage_v1,
};
use fstp_json::Value;

/// The namespaces of interface labels in design 07.
const LABEL_NAMESPACES: [&str; 6] = ["journey.", "vocab.", "place.", "role.", "nav.", "home."];

fn with_label(bytes: &[u8], key: &str, text: &str) -> Vec<u8> {
    let mut v = fstp_json::parse(bytes).unwrap();
    match &mut v {
        Value::Object(o) => match o.get_mut("labels") {
            Some(Value::Object(l)) => {
                l.insert(key, Value::from(text));
            }
            _ => panic!("no labels"),
        },
        _ => panic!("not an object"),
    }
    v.to_compact().into_bytes()
}

/// I-72: every key a pack may name is an interface label of design 07,
/// with no placeholder, and none names approved wording.
#[test]
fn i72_every_pack_key_is_an_interface_label() {
    for key in LABEL_KEYS {
        assert!(
            LABEL_NAMESPACES.iter().any(|n| key.starts_with(n)),
            "I-72: {key} is outside the label namespaces"
        );
        for word in ["approved", "legal", "notice", "email", "funder", "terms"] {
            assert!(!key.contains(word), "I-72: {key} names {word}");
        }
    }
}

/// I-72, I-94: a pack that names approved wording, a contract, a notice,
/// the Guide text, a funder document, an email or any key outside the
/// closed list is refused, in both packs.
#[test]
fn i72_a_pack_naming_approved_or_legal_wording_is_refused() {
    for key in [
        "calls.notice.privacy",
        "applicant.approved.data_protection",
        "footer.privacy_notice",
        "contract.body",
        "notice.termination",
        "guide.section.eligibility",
        "funder.report.title",
        "email.submission_receipt.subject",
        "journey.diary.erased",
        "vocab.unknown",
    ] {
        for bytes in [PLAIN_V1, VOYAGE_V1] {
            let e = parse(&with_label(bytes, key, "Charter")).unwrap_err();
            assert_eq!(e.kind(), K::NotALabel, "I-72: {key}: {e}");
        }
    }
}

/// I-72, design 07 content rule 6: the negative outcomes and the
/// withdrawal action keep fixed wording in both packs. A pack that
/// changes it is refused, so no joke label can replace it.
#[test]
fn i72_negative_outcome_wording_is_fixed_data() {
    let keys: Vec<&str> = FIXED.iter().map(|f| f.key).collect();
    for state in [
        "ineligible",
        "not_selected",
        "declined",
        "withdrawn",
        "terminated",
    ] {
        assert!(
            keys.contains(&format!("journey.node.{state}").as_str()),
            "I-72: {state} is not fixed"
        );
    }
    assert!(keys.contains(&"journey.withdraw.action"));
    let plain = plain_v1().unwrap();
    let voyage = voyage_v1().unwrap();
    for f in FIXED {
        assert!(LABEL_KEYS.contains(&f.key), "{}", f.key);
        assert_eq!(plain.get(f.key), Some(f.plain), "I-72: plain {}", f.key);
        assert!(
            voyage.get(f.key).is_none_or(|t| t == f.voyage),
            "I-72: voyage {}",
            f.key
        );
        for bytes in [PLAIN_V1, VOYAGE_V1] {
            let e = parse(&with_label(bytes, f.key, "Sunk without trace")).unwrap_err();
            assert_eq!(e.kind(), K::FixedWording, "I-72: {}: {e}", f.key);
        }
    }
    assert_eq!(
        FIXED
            .iter()
            .find(|f| f.key == "journey.withdraw.action")
            .map(|f| (f.plain, f.voyage)),
        Some(("Withdraw this proposal", "Withdraw this proposal")),
        "design 07: the action has legal effect, the same in both packs"
    );
}

/// R-JV-09, I-94: no Voyage label that differs from its plain label
/// appears in a Guide for Applicants template of the repository. The
/// contract, notice, funder and email templates arrive with M8, so the
/// Guide profiles are every template that exists.
#[test]
fn r_jv_09_guide_templates_hold_no_voyage_label() {
    let plain = plain_v1().unwrap();
    let voyage = voyage_v1().unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut templates = Vec::new();
    for dir in [
        "crates/fstp-guide/profiles",
        "crates/fstp-api-testkit/profiles",
    ] {
        collect_md(&root.join(dir), &mut templates);
    }
    assert!(!templates.is_empty(), "R-JV-09: no template found");
    for path in &templates {
        let text = std::fs::read_to_string(path).unwrap();
        for (key, label) in voyage.labels() {
            if plain.get(key) == Some(label) {
                continue;
            }
            assert!(
                !text.contains(label),
                "R-JV-09: {} holds the Voyage label {label:?} of {key}",
                path.display()
            );
        }
    }
}

fn collect_md(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries {
        let path = e.unwrap().path();
        if path.is_dir() {
            collect_md(&path, out);
        } else if path.extension().is_some_and(|x| x == "md") {
            out.push(path);
        }
    }
}
