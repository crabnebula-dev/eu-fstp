//! I-72, I-94, R-WL-05, O-55: a tenant terminology pack overrides interface labels only (M9 lane T1).
//!
//! The canary: a tenant pack that maps every key to a canary text shows the
//! canary in labels. It never reaches fixed wording, a key outside the
//! closed list, or any approved text that exists in the repository (the
//! Guide profiles, the contract, notice, mail and funder files).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fstp_journey::vocab::{
    FIXED, LABEL_KEYS, Pack, PackKind, VocabErrorKind as K, Vocabulary, parse, plain_v1, voyage_v1,
};

const CANARY: &str = "Zanzibar canary";

fn canary_labels() -> BTreeMap<String, String> {
    LABEL_KEYS
        .iter()
        .map(|k| {
            let text = match FIXED.iter().find(|f| f.key == *k) {
                Some(f) => f.plain.to_owned(),
                None => format!("{CANARY} {k}"),
            };
            ((*k).to_owned(), text)
        })
        .collect()
}

fn canary_pack() -> Pack {
    Pack::new(PackKind::Tenant, canary_labels()).unwrap()
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries {
        let path = e.unwrap().path();
        if path.is_dir() {
            files(&path, out);
        } else if path
            .extension()
            .is_some_and(|x| matches!(x.to_str(), Some("md" | "txt" | "json" | "html" | "eml")))
        {
            out.push(path);
        }
    }
}

/// I-72, I-94: the canary appears in labels and in no approved or legal
/// text of the repository, and the fixed wording keeps its text.
#[test]
fn i72_tenant_pack_labels_only() {
    let v = Vocabulary::platform(false)
        .unwrap()
        .with_tenant(canary_pack())
        .unwrap();
    for key in LABEL_KEYS {
        let shown = v.label(key).unwrap();
        match FIXED.iter().find(|f| f.key == *key) {
            Some(f) => assert_eq!(shown.plain, f.plain, "I-72: fixed {key}"),
            None => assert_eq!(shown.plain, format!("{CANARY} {key}"), "label {key}"),
        }
    }
    // No key outside the closed list answers, with or without a tenant pack.
    for key in [
        "contract.body",
        "notice.termination",
        "guide.section.eligibility",
        "funder.report.title",
        "email.submission_receipt.subject",
        "footer.privacy_notice",
    ] {
        assert!(v.label(key).is_none(), "I-72: {key} answers");
    }
    // The canary is in no approved or legal text that exists.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut found = Vec::new();
    for dir in [
        "crates/fstp-guide/profiles",
        "crates/fstp-api-testkit/profiles",
        "crates/fstp-contract",
        "crates/fstp-mail",
        "crates/fstp-report/profiles",
        "crates/fstp-html",
    ] {
        files(&root.join(dir), &mut found);
    }
    assert!(!found.is_empty(), "I-72: no approved text found to scan");
    for path in found {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        assert!(
            !text.contains(CANARY),
            "I-72: {} holds the canary",
            path.display()
        );
    }
}

/// I-72, I-94: a tenant pack that names approved wording or any key outside
/// the closed list is refused, and so is changed fixed wording.
#[test]
fn i72_tenant_pack_naming_approved_wording_is_refused() {
    for key in [
        "calls.notice.privacy",
        "applicant.approved.data_protection",
        "footer.privacy_notice",
        "contract.body",
        "notice.termination",
        "guide.section.eligibility",
        "funder.report.title",
        "email.submission_receipt.subject",
        "vocab.unknown",
    ] {
        let mut labels = canary_labels();
        labels.insert(key.to_owned(), "Charter".to_owned());
        let e = Pack::new(PackKind::Tenant, labels).unwrap_err();
        assert_eq!(e.kind(), K::NotALabel, "I-72: {key}");
    }
    for f in FIXED {
        let mut labels = BTreeMap::new();
        labels.insert(f.key.to_owned(), "Sunk without trace".to_owned());
        let e = Pack::new(PackKind::Tenant, labels).unwrap_err();
        assert_eq!(e.kind(), K::FixedWording, "I-72: {}", f.key);
    }
    for bad in ["{x}", "<b>x</b>", " x", "", "a\u{7}b"] {
        let mut labels = BTreeMap::new();
        labels.insert("vocab.team".to_owned(), bad.to_owned());
        assert_eq!(
            Pack::new(PackKind::Tenant, labels).unwrap_err().kind(),
            K::InvalidText,
            "I-68: {bad:?}"
        );
    }
}

/// I-72: a tenant pack may leave keys out, and a file of kind `tenant`
/// round-trips through the parser.
#[test]
fn i72_tenant_pack_is_partial_and_round_trips() {
    let mut labels = BTreeMap::new();
    labels.insert("vocab.call".to_owned(), "Subgrant call".to_owned());
    let pack = Pack::new(PackKind::Tenant, labels).unwrap();
    assert_eq!(parse(pack.encode().as_bytes()).unwrap(), pack);
    let v = Vocabulary::platform(false)
        .unwrap()
        .with_tenant(pack)
        .unwrap();
    assert_eq!(v.label("vocab.call").unwrap().plain, "Subgrant call");
    let plain = plain_v1().unwrap();
    assert_eq!(
        v.label("vocab.team").unwrap().plain,
        plain.get("vocab.team").unwrap()
    );
}

/// O-55, R-WL-05: the lookup order is tenant, then plain. The Voyage line is
/// shown only when the switch is on, and never when it equals the shown label.
#[test]
fn o55_tenant_then_plain_and_voyage_line_only_when_on() {
    let tenant = canary_pack();
    let off = Vocabulary::platform(false)
        .unwrap()
        .with_tenant(tenant.clone())
        .unwrap();
    let on = Vocabulary::platform(true)
        .unwrap()
        .with_tenant(tenant)
        .unwrap();
    let voyage = voyage_v1().unwrap();
    for key in LABEL_KEYS {
        assert!(off.label(key).unwrap().secondary.is_none(), "off: {key}");
        let shown = on.label(key).unwrap();
        let want = voyage.get(key).filter(|t| *t != shown.plain);
        assert_eq!(shown.secondary, want, "on: {key}");
    }
}

/// O-55: a pack of the wrong kind in the tenant place is refused.
#[test]
fn o55_with_tenant_refuses_other_kinds() {
    let e = Vocabulary::platform(false)
        .unwrap()
        .with_tenant(plain_v1().unwrap())
        .unwrap_err();
    assert_eq!(e.kind(), K::InvalidValue);
}
